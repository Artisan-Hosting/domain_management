//! Cloudflare account member management -- inviting a customer to manage
//! their own domain's DNS, and nothing else.
//!
//! Verified against Cloudflare's current API docs when this module was
//! written (`developers.cloudflare.com/api/resources/accounts/subresources/
//! {members,roles}/`), since the account-member shape is a moving target the
//! rollout plan flagged as needing a fresh check rather than reusing the
//! registrar client's already-verified shape.
//!
//! **This is account-wide, not zone-scoped.** Cloudflare's legacy roles
//! (what `POST .../members` accepts as `roles: [<role id>]`) apply across
//! the whole account -- there is no request field that says "only this
//! customer's zone." What keeps this safe is the *role itself*
//! (`Config::cloudflare::member_role`, "Domain DNS" by default): the
//! narrowest built-in role that can still edit DNS records, with no path to
//! the registrar, transfers, or billing. True zone-scoping exists in
//! Cloudflare's newer IAM policies (`policies` with scoped
//! `resource_groups`, sent instead of `roles`) but is not used here -- if
//! zone-scoping every invite turns out to matter more than the role-based
//! blast-radius limit already gives, that's the API to move to.
//!
//! Role names are resolved to ids via `GET .../roles` on every invite
//! rather than cached, since account roles change rarely and an invite is
//! not a hot path.

use serde::{Deserialize, Serialize};

use super::Api;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MemberUser {
    #[serde(default)]
    pub email: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Member {
    pub id: String,
    /// "accepted" or "pending".
    pub status: String,
    #[serde(default)]
    pub roles: Vec<Role>,
    #[serde(default)]
    pub user: Option<MemberUser>,
}

impl Member {
    /// The invited address, from Cloudflare's own record of who it is --
    /// never trust-on-first-use from whatever this service asked to invite.
    pub fn email(&self) -> &str {
        self.user.as_ref().map(|u| u.email.as_str()).unwrap_or_default()
    }
}

#[derive(Debug, Serialize)]
struct NewMember<'a> {
    email: &'a str,
    roles: Vec<&'a str>,
    status: &'a str,
}

pub async fn list_roles(api: &Api, account_id: &str) -> Result<Vec<Role>> {
    api.get(&format!("accounts/{account_id}/roles?per_page=50")).await
}

/// The role id for a role named exactly `name` (Cloudflare's own display
/// name, case-sensitive -- `"Domain DNS"`, not `"domain dns"`).
pub async fn role_id_for(api: &Api, account_id: &str, name: &str) -> Result<String> {
    let roles = list_roles(api, account_id).await?;
    roles
        .into_iter()
        .find(|role| role.name == name)
        .map(|role| role.id)
        .ok_or_else(|| Error::Cloudflare(format!("no cloudflare role named {name:?} on this account")))
}

/// Invites `email` to the account with `role_id`. Always sent as
/// `status: "pending"` -- Cloudflare's own acceptance flow (an email the
/// customer clicks) is what actually grants access, never this call alone.
pub async fn invite(api: &Api, account_id: &str, email: &str, role_id: &str) -> Result<Member> {
    let body = NewMember { email, roles: vec![role_id], status: "pending" };
    api.post(&format!("accounts/{account_id}/members"), &body).await
}

pub async fn list(api: &Api, account_id: &str) -> Result<Vec<Member>> {
    api.get(&format!("accounts/{account_id}/members?per_page=50")).await
}

#[derive(Debug, Deserialize)]
struct DeletedMember {
    #[allow(dead_code)]
    id: String,
}

pub async fn remove(api: &Api, account_id: &str, member_id: &str) -> Result<()> {
    let _: DeletedMember = api.delete(&format!("accounts/{account_id}/members/{member_id}")).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn mock_server(responses: Vec<(u16, String)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            for (status, body) in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 8192];
                let _ = socket.read(&mut buf).await;

                let response = format!(
                    "HTTP/1.1 {status} status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        format!("http://{addr}")
    }

    fn api(base: &str) -> Api {
        Api::new(base, "test-token", "test", Duration::from_secs(5)).unwrap()
    }

    const ROLES_BODY: &str = r#"{"success":true,"result":[
        {"id":"role-admin","name":"Account Administrator","description":"","permissions":{}},
        {"id":"role-dns","name":"Domain DNS","description":"","permissions":{}}
    ]}"#;

    #[tokio::test]
    async fn resolves_a_role_id_by_its_display_name() {
        let base = mock_server(vec![(200, ROLES_BODY.to_owned())]).await;
        let id = role_id_for(&api(&base), "acct1", "Domain DNS").await.unwrap();
        assert_eq!(id, "role-dns");
    }

    #[tokio::test]
    async fn an_unknown_role_name_is_a_clear_error_not_a_panic() {
        let base = mock_server(vec![(200, ROLES_BODY.to_owned())]).await;
        let err = role_id_for(&api(&base), "acct1", "Nonexistent Role").await.unwrap_err();
        assert!(err.to_string().contains("Nonexistent Role"), "{err}");
    }

    #[tokio::test]
    async fn invite_posts_the_role_id_and_pending_status() {
        let base = mock_server(vec![(
            200,
            r#"{"success":true,"result":{"id":"mem1","status":"pending","roles":[{"id":"role-dns","name":"Domain DNS"}],"user":{"email":"customer@example.com"}}}"#
                .to_owned(),
        )])
        .await;

        let member = invite(&api(&base), "acct1", "customer@example.com", "role-dns").await.unwrap();
        assert_eq!(member.status, "pending");
        assert_eq!(member.email(), "customer@example.com");
        assert_eq!(member.roles[0].id, "role-dns");
    }

    #[tokio::test]
    async fn list_and_remove_round_trip() {
        let base = mock_server(vec![
            (
                200,
                r#"{"success":true,"result":[{"id":"mem1","status":"accepted","roles":[],"user":{"email":"a@example.com"}}]}"#
                    .to_owned(),
            ),
            (200, r#"{"success":true,"result":{"id":"mem1"}}"#.to_owned()),
        ])
        .await;

        let members = list(&api(&base), "acct1").await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].email(), "a@example.com");

        remove(&api(&base), "acct1", "mem1").await.unwrap();
    }
}
