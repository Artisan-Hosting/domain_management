//! The `TenantSource` service project_Kaelum polls (about every 30 s) to learn which tenants it serves.
//! Contract: `project_Kaelum/docs/06-TENANT-SOURCE-SPEC.md`.
//!
//! A tenant is a `kaelum_tenants` row; its hostnames are the `domains` rows carrying its `kaelum_endpoint_id`.
//! Suspension is the row's manual `suspension` if set, otherwise `out_of_credit` when Billing says the
//! organization is not in good standing. If Billing is unreachable the whole call fails: Kaelum then keeps its last
//! good list, which beats wrongly suspending (or un-suspending) everyone.

use std::collections::HashMap;

use sqlx::{MySqlPool, Row};
use tonic::{Request, Response, Status};

use crate::billing::BillingClient;
use crate::error::{Error, Result};
use crate::proto::tenant_source::tenant_source_server::TenantSource;
use crate::proto::tenant_source::{ListTenantsRequest, ListTenantsResponse, Tenant};

pub struct TenantSourceService {
    pool: MySqlPool,
    billing: BillingClient,
}

impl TenantSourceService {
    pub fn new(pool: MySqlPool, billing: BillingClient) -> Self {
        Self { pool, billing }
    }
}

#[tonic::async_trait]
impl TenantSource for TenantSourceService {
    async fn list_tenants(&self, _: Request<ListTenantsRequest>) -> std::result::Result<Response<ListTenantsResponse>, Status> {
        let rows = sqlx::query("SELECT endpoint_id, organization_id, project_id, suspension FROM kaelum_tenants ORDER BY endpoint_id")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::from(Error::Database(e)))?;

        let hosts = sqlx::query("SELECT kaelum_endpoint_id, fqdn FROM domains WHERE kaelum_endpoint_id IS NOT NULL ORDER BY fqdn")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::from(Error::Database(e)))?;
        let mut by_endpoint: HashMap<String, Vec<String>> = HashMap::new();
        for row in hosts {
            by_endpoint.entry(row.get("kaelum_endpoint_id")).or_default().push(row.get::<String, _>("fqdn").to_ascii_lowercase());
        }

        let mut standing: HashMap<String, bool> = HashMap::new();
        let mut tenants = Vec::new();
        for row in rows {
            let endpoint_id: String = row.get("endpoint_id");
            // Kaelum rejects the whole list over a tenant with no hostname; leave it out rather than break everyone.
            let Some(hostnames) = by_endpoint.remove(&endpoint_id) else { continue };
            let organization_id: String = row.get("organization_id");

            let mut suspension: Option<String> = row.get("suspension");
            if suspension.is_none() {
                if !standing.contains_key(&organization_id) {
                    let ok = self.billing.organization_permits_new_purchases(&organization_id).await.map_err(Status::from)?;
                    standing.insert(organization_id.clone(), ok);
                }
                if !standing[&organization_id] {
                    suspension = Some("out_of_credit".to_owned());
                }
            }

            tenants.push(Tenant {
                endpoint_id,
                hostnames,
                organization_id,
                project_id: row.get("project_id"),
                suspension: suspension.filter(|s| !s.is_empty()),
                ..Default::default()
            });
        }

        Ok(Response::new(ListTenantsResponse { tenants, version: String::new() }))
    }
}

/// `ais_domains kaelum-tenant`: create or update a tenant and point the given domains at it.
/// Every host must already be a recorded domain of the same organization.
pub async fn register(
    pool: &MySqlPool,
    endpoint_id: &str,
    organization_id: &str,
    project_id: &str,
    hosts: &[String],
    suspension: Option<&str>,
) -> Result<()> {
    if endpoint_id.is_empty() || endpoint_id.len() > 64 || !endpoint_id.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
        return Err(Error::Invalid("endpoint id must be 1-64 chars of letters, digits, '-', '_' and '.'".to_owned()));
    }
    if hosts.is_empty() {
        return Err(Error::Invalid("at least one --host is required".to_owned()));
    }

    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO kaelum_tenants (endpoint_id, organization_id, project_id, suspension) VALUES (?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE organization_id = VALUES(organization_id), project_id = VALUES(project_id), \
         suspension = VALUES(suspension)",
    )
    .bind(endpoint_id)
    .bind(organization_id)
    .bind(project_id)
    .bind(suspension.filter(|s| !s.is_empty()))
    .execute(&mut *tx)
    .await?;

    for host in hosts {
        let host = host.to_ascii_lowercase();
        let done = sqlx::query(
            "UPDATE domains SET kaelum_endpoint_id = ? WHERE fqdn = ? AND organization_id = ? \
             AND (kaelum_endpoint_id IS NULL OR kaelum_endpoint_id = ?)",
        )
        .bind(endpoint_id)
        .bind(&host)
        .bind(organization_id)
        .bind(endpoint_id)
        .execute(&mut *tx)
        .await?;
        if done.rows_affected() == 0 {
            return Err(Error::Invalid(format!(
                "{host}: not a recorded domain of organization {organization_id}, or already another tenant's"
            )));
        }
    }
    tx.commit().await?;
    Ok(())
}
