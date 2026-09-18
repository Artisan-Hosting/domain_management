//! Zone lookup and creation.
//!
//! A domain registered through Cloudflare Registrar normally arrives with a
//! zone already attached, but the API beta does not promise it, and BYO
//! domains never have one. Everything here is therefore written as
//! "ensure", not "create".

use serde::{Deserialize, Serialize};

use super::Api;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub name_servers: Vec<String>,
}

#[derive(Debug, Serialize)]
struct NewZone<'a> {
    name: &'a str,
    account: AccountRef<'a>,
    #[serde(rename = "type")]
    zone_type: &'a str,
}

#[derive(Debug, Serialize)]
struct AccountRef<'a> {
    id: &'a str,
}

pub async fn find(api: &Api, name: &str) -> Result<Option<Zone>> {
    let zones: Vec<Zone> = api.get(&format!("zones?name={name}&per_page=1")).await?;
    Ok(zones.into_iter().next())
}

pub async fn create(api: &Api, account_id: &str, name: &str) -> Result<Zone> {
    if account_id.is_empty() {
        return Err(Error::Config("CF_ACCOUNT_ID is not set".to_owned()));
    }

    let body = NewZone { name, account: AccountRef { id: account_id }, zone_type: "full" };
    api.post("zones", &body).await
}

/// The zone for `name`, created if Cloudflare does not already have it.
pub async fn ensure(api: &Api, account_id: &str, name: &str) -> Result<Zone> {
    match find(api, name).await? {
        Some(zone) => Ok(zone),
        None => create(api, account_id, name).await,
    }
}

/// The authoritative nameservers for a zone, used to check a TXT record has
/// actually landed rather than sleeping and hoping.
pub async fn nameservers(api: &Api, name: &str) -> Result<Vec<String>> {
    Ok(find(api, name).await?.map(|zone| zone.name_servers).unwrap_or_default())
}
