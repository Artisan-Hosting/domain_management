//! Who may touch which domain.
//!
//! `ais_auth` is the platform's policy engine and this service defers to it,
//! but it cannot resolve a *domain* to its organization: the `domains` table
//! lives here, and `ais_auth` calling back into a service that is itself
//! calling `ais_auth` is the cycle Phase 4 deliberately avoided for sessions
//! (`resolve_resource_org` returns `None` for `Session` and `Domain` alike).
//! So the work is split:
//!
//! * **`ais_auth` decides** everything it can resolve on its own -- the owning
//!   runner (a `Project`), and any explicit `Domain` grant (the grant tier
//!   needs no org resolution, which is exactly why it still works here).
//! * **this service decides** only what is a fact about its own row: which
//!   organization a domain belongs to, and whether it is attached to a runner
//!   at all.
//!
//! What is deliberately *not* here: "belongs to the caller's organization"
//! treated as permission to change something. Membership scopes a *listing*
//! ([`scope`]); it is not consent to rewrite a vhost or move a name between
//! tenants. Collapsing those two was the Phase 7 bug in Portal, and it is not
//! repeated here.

use artisan_middleware::api::roles::Role;
use tonic::Status;

/// An organization id that means "none". `ais_auth` leaves the column NULL for
/// an unassigned user and older rows carry `"0"` from before it was a UUID, so
/// both have to be read as *absent* rather than as an org that things can
/// match against -- otherwise two unassigned tenants would look like one.
pub fn real_org(organization_id: &str) -> Option<&str> {
    match organization_id.trim() {
        "" | "0" => None,
        id => Some(id),
    }
}

/// Why a caller was turned away. Separate from the message so the reason can
/// be asserted in a test without pinning the wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// The caller's account is not in an organization at all.
    NoOrg,
    /// The domain belongs to a different tenant.
    OtherOrg,
    /// The domain belongs to nobody yet, and claiming one is an operator's job.
    Unassigned,
    /// `ais_auth` refused, or the caller's role is below the floor.
    NotPermitted,
}

impl Denial {
    pub fn message(self, fqdn: &str) -> String {
        match self {
            Denial::NoOrg => {
                "your account is not in an organization, so it owns no domains".to_owned()
            }
            Denial::OtherOrg => {
                format!("{fqdn} belongs to another organization")
            }
            Denial::Unassigned => format!(
                "{fqdn} is not assigned to an organization yet; an operator must assign it first"
            ),
            Denial::NotPermitted => {
                format!("not permitted to change {fqdn}")
            }
        }
    }

    pub fn into_status(self, fqdn: &str) -> Status {
        Status::permission_denied(self.message(fqdn))
    }
}

/// The organization filter to apply to a listing.
///
/// `None` means "every organization", and only [`Role::Super`] gets it. An
/// `Admin` belongs to exactly one organization -- `ais_auth` scopes them that
/// way -- so an Admin asking for everything is pinned to their own org rather
/// than handed the fleet, which is what this used to do. Everyone else is
/// pinned whatever they asked for, so a crafted `organization_id` cannot widen
/// the view.
pub fn scope(role: Role, caller_org: &str, requested: &str) -> Result<Option<String>, Status> {
    if role == Role::Super {
        return Ok(match requested.trim() {
            "" => None,
            id => Some(id.to_owned()),
        });
    }

    match real_org(caller_org) {
        Some(org) => Ok(Some(org.to_owned())),
        None => Err(Status::permission_denied(Denial::NoOrg.message(""))),
    }
}

/// `ais_auth`'s answer about the runner a domain is, or is about to be,
/// attached to: `Some(true)` allowed, `Some(false)` refused, `None` when there
/// is no runner in play to ask about.
pub type RunnerAccess = Option<bool>;

/// May this caller change this domain record?
///
/// The order matters, and each step is a different denial so the caller is
/// told which wall they hit:
///
/// 1. `Super` is the platform operator and is never org-scoped.
/// 2. A caller with no organization owns nothing.
/// 3. An **unassigned** domain is refused: nothing links it to this caller, and
///    letting the first Admin who asks claim an unowned name is how one tenant
///    takes another's hostname. Assigning it is an operator action (the CLI's
///    `apply`, or `AssignDomain` as `Super`).
/// 4. A domain owned by **another** organization is refused outright.
/// 5. For a domain that *is* theirs, `ais_auth` still decides when a runner is
///    named -- that is the real org policy and grant check, on a resource it
///    can resolve. With no runner named, an org `Admin` may manage their own
///    organization's record; a lesser role may not.
pub fn may_write_domain(
    role: Role,
    caller_org: &str,
    domain_org: Option<&str>,
    runner: RunnerAccess,
) -> Result<(), Denial> {
    if role == Role::Super {
        return Ok(());
    }

    let caller_org = real_org(caller_org).ok_or(Denial::NoOrg)?;

    match domain_org.and_then(real_org) {
        None => return Err(Denial::Unassigned),
        Some(owner) if owner != caller_org => return Err(Denial::OtherOrg),
        Some(_) => {}
    }

    match runner {
        Some(true) => Ok(()),
        Some(false) => Err(Denial::NotPermitted),
        None if role == Role::Admin => Ok(()),
        None => Err(Denial::NotPermitted),
    }
}

/// May this caller read this domain record?
///
/// The lighter, read-only counterpart to [`may_write_domain`]: an
/// unassigned or other-org domain is refused exactly the same way (an fqdn
/// being guessable must never be what decides visibility), but any role
/// within the owning org may read, not just `Admin` -- there is no runner
/// grant to check, since reading changes nothing on either end.
pub fn may_read_domain(role: Role, caller_org: &str, domain_org: Option<&str>) -> Result<(), Denial> {
    if role == Role::Super {
        return Ok(());
    }

    let caller_org = real_org(caller_org).ok_or(Denial::NoOrg)?;

    match domain_org.and_then(real_org) {
        None => Err(Denial::Unassigned),
        Some(owner) if owner != caller_org => Err(Denial::OtherOrg),
        Some(_) => Ok(()),
    }
}

/// Moving a name from one tenant to another, which costs a fresh password.
///
/// Only a real change of owner counts: re-asserting the org a domain already
/// belongs to is not a move, and neither is attaching a runner.
pub fn is_org_move(current: Option<&str>, requested: &str, clear: bool) -> bool {
    let current = current.and_then(real_org);
    if current.is_none() {
        // Nothing to take away from anyone.
        return false;
    }
    if clear {
        return true;
    }
    match real_org(requested) {
        Some(requested) => current != Some(requested),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORG_A: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const ORG_B: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

    #[test]
    fn the_sentinels_are_not_organizations() {
        assert_eq!(real_org(ORG_A), Some(ORG_A));
        assert_eq!(real_org(""), None);
        assert_eq!(real_org("0"), None);
        assert_eq!(real_org("   "), None);
    }

    #[test]
    fn only_super_may_ask_for_every_organization() {
        assert_eq!(scope(Role::Super, ORG_A, "").unwrap(), None);
        assert_eq!(scope(Role::Super, ORG_A, ORG_B).unwrap(), Some(ORG_B.to_owned()));
    }

    #[test]
    fn an_admin_asking_for_everything_is_pinned_to_their_own_org() {
        // The Phase 7 bug: a blank organization_id used to mean "the fleet"
        // for an Admin, which let org A read org B's domains.
        assert_eq!(scope(Role::Admin, ORG_A, "").unwrap(), Some(ORG_A.to_owned()));
        assert_eq!(scope(Role::Admin, ORG_A, ORG_B).unwrap(), Some(ORG_A.to_owned()));
        for role in [Role::Controller, Role::Viewer, Role::Audit, Role::None] {
            assert_eq!(scope(role, ORG_A, ORG_B).unwrap(), Some(ORG_A.to_owned()), "{role:?}");
        }
    }

    #[test]
    fn a_caller_with_no_organization_can_list_nothing() {
        for org in ["", "0"] {
            assert!(scope(Role::Admin, org, "").is_err());
            assert!(scope(Role::Viewer, org, ORG_A).is_err());
        }
        // ...but Super is not org-scoped in the first place.
        assert_eq!(scope(Role::Super, "", "").unwrap(), None);
    }

    #[test]
    fn super_may_write_any_domain_including_an_unassigned_one() {
        assert!(may_write_domain(Role::Super, "", None, None).is_ok());
        assert!(may_write_domain(Role::Super, ORG_A, Some(ORG_B), Some(false)).is_ok());
    }

    #[test]
    fn another_orgs_domain_is_refused_whatever_the_runner_says() {
        for runner in [Some(true), Some(false), None] {
            assert_eq!(
                may_write_domain(Role::Admin, ORG_A, Some(ORG_B), runner),
                Err(Denial::OtherOrg),
                "{runner:?}"
            );
        }
    }

    #[test]
    fn an_unassigned_domain_cannot_be_claimed_by_an_admin() {
        // Even with ais_auth allowing the runner: the domain is nobody's, and
        // the first Admin to ask must not become its owner.
        assert_eq!(
            may_write_domain(Role::Admin, ORG_A, None, Some(true)),
            Err(Denial::Unassigned)
        );
        assert_eq!(may_write_domain(Role::Admin, ORG_A, Some("0"), None), Err(Denial::Unassigned));
    }

    #[test]
    fn on_their_own_domain_ais_auth_decides_the_runner() {
        assert!(may_write_domain(Role::Viewer, ORG_A, Some(ORG_A), Some(true)).is_ok());
        assert_eq!(
            may_write_domain(Role::Admin, ORG_A, Some(ORG_A), Some(false)),
            Err(Denial::NotPermitted)
        );
    }

    #[test]
    fn with_no_runner_in_play_only_an_admin_may_manage_their_own_record() {
        assert!(may_write_domain(Role::Admin, ORG_A, Some(ORG_A), None).is_ok());
        for role in [Role::Controller, Role::Viewer, Role::Audit, Role::None] {
            assert_eq!(
                may_write_domain(role, ORG_A, Some(ORG_A), None),
                Err(Denial::NotPermitted),
                "{role:?}"
            );
        }
    }

    #[test]
    fn a_caller_with_no_organization_may_write_nothing() {
        assert_eq!(may_write_domain(Role::Admin, "", Some(ORG_A), Some(true)), Err(Denial::NoOrg));
        assert_eq!(may_write_domain(Role::Admin, "0", None, None), Err(Denial::NoOrg));
    }

    #[test]
    fn only_a_real_change_of_owner_is_a_move() {
        // Re-asserting the same org, or attaching a runner, is not a move.
        assert!(!is_org_move(Some(ORG_A), ORG_A, false));
        assert!(!is_org_move(Some(ORG_A), "", false));
        // Taking it from one tenant and giving it to another is.
        assert!(is_org_move(Some(ORG_A), ORG_B, false));
        assert!(is_org_move(Some(ORG_A), "", true));
        // An unowned domain has nothing to take away.
        assert!(!is_org_move(None, ORG_B, false));
        assert!(!is_org_move(None, "", true));
        assert!(!is_org_move(Some("0"), "", true));
    }

    #[test]
    fn a_denial_never_leaks_another_tenants_organization_id() {
        let message = Denial::OtherOrg.message("example.com");
        assert!(message.contains("example.com"), "{message}");
        assert!(!message.contains(ORG_B), "{message}");
    }

    #[test]
    fn any_role_in_the_owning_org_may_read_a_domain() {
        for role in [Role::Admin, Role::Controller, Role::Viewer, Role::Audit] {
            assert!(may_read_domain(role, ORG_A, Some(ORG_A)).is_ok(), "{role:?}");
        }
    }

    #[test]
    fn reading_another_orgs_domain_is_refused() {
        assert_eq!(may_read_domain(Role::Admin, ORG_A, Some(ORG_B)), Err(Denial::OtherOrg));
    }

    #[test]
    fn reading_an_unassigned_domain_is_refused_even_for_a_read() {
        assert_eq!(may_read_domain(Role::Admin, ORG_A, None), Err(Denial::Unassigned));
    }

    #[test]
    fn super_may_read_any_domain() {
        assert!(may_read_domain(Role::Super, "", None).is_ok());
        assert!(may_read_domain(Role::Super, ORG_A, Some(ORG_B)).is_ok());
    }
}
