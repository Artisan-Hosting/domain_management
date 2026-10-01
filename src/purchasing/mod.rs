//! Pricing and spending guardrails for the domain purchase flow.
//!
//! Pure, network-free functions wherever possible (`price_for`,
//! `tld_allowed`) so the money math is unit-testable without a database or
//! a live Cloudflare/Billing call -- the same reasoning `inventory::apply`'s
//! `decide_domain` is pure for. `under_caps` is the one function here that
//! touches the database, since a spending cap is inherently a question
//! about this organization's history.

use sqlx::MySqlConnection;

use crate::config::{Pricing, Purchasing};
use crate::error::Result;

/// Applies markup and the minimum margin, then refuses anything over the
/// configured hard cap. `cost_cents` is what the registry actually
/// charges us (from Cloudflare's `domain-check`); the result is what the
/// customer pays.
pub fn price_for(cost_cents: i64, pricing: &Pricing) -> Result<i64> {
    let marked_up = (cost_cents as f64 * (1.0 + pricing.markup_percent / 100.0)).round() as i64;
    let with_margin = marked_up.max(cost_cents.saturating_add(pricing.min_margin_cents));

    if with_margin > pricing.max_price_cents {
        return Err(crate::error::Error::Invalid(format!(
            "price {with_margin}c exceeds the configured cap of {}c",
            pricing.max_price_cents
        )));
    }

    Ok(with_margin)
}

/// Whether `fqdn`'s public suffix is one this platform sells. Cloudflare's
/// own API beta also rejects plenty of extensions on its own terms, but
/// that list is Cloudflare's to change; this one is ours, and is checked
/// first so an unsellable TLD never even reaches a Cloudflare call.
pub fn tld_allowed(fqdn: &str, pricing: &Pricing) -> bool {
    match psl::suffix_str(fqdn) {
        Some(suffix) => pricing.tld_allowlist.iter().any(|allowed| allowed == suffix),
        None => false,
    }
}

/// Whether a new order of `new_order_price_cents` would keep `organization_id`
/// under both its daily order-count cap and its monthly spend cap. Checked
/// together, not as two separate calls.
///
/// This only *reads*: two concurrent orders can both pass it. The caller must
/// hold the organization's order lock (`orders::lock_org_orders`) from this
/// check through the insert it guards, which is what
/// `orders::insert_order_with_job` does.
pub async fn under_caps(
    conn: &mut MySqlConnection,
    organization_id: &str,
    new_order_price_cents: i64,
    purchasing: &Purchasing,
) -> Result<bool> {
    let today_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM domain_orders WHERE organization_id = ? AND created_at >= CURDATE()",
    )
    .bind(organization_id)
    .fetch_one(&mut *conn)
    .await?;
    if today_count >= purchasing.orders_per_org_per_day {
        return Ok(false);
    }

    // Refunded/failed orders never completed a real charge, so they don't
    // count against the monthly cap.
    let month_spent: i64 = sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(price_cents), 0) AS SIGNED) FROM domain_orders \
         WHERE organization_id = ? AND state NOT IN ('refunded', 'failed') \
         AND created_at >= DATE_FORMAT(NOW(), '%Y-%m-01')",
    )
    .bind(organization_id)
    .fetch_one(&mut *conn)
    .await?;
    if month_spent.saturating_add(new_order_price_cents) > purchasing.monthly_cap_cents {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pricing() -> Pricing {
        Pricing {
            markup_percent: 20.0,
            min_margin_cents: 300,
            max_price_cents: 10_000,
            currency: "USD".to_owned(),
            tld_allowlist: vec!["com".to_owned(), "net".to_owned(), "io".to_owned()],
            quote_ttl_secs: 600,
        }
    }

    #[test]
    fn the_minimum_margin_wins_when_markup_alone_would_be_smaller() {
        // 857c * 1.2 = 1028.4 -> rounds to 1028; margin floor is 857+300=1157.
        // Margin floor wins here.
        assert_eq!(price_for(857, &pricing()).unwrap(), 1157);
    }

    #[test]
    fn markup_wins_when_it_exceeds_the_minimum_margin() {
        // A more expensive domain where 20% markup exceeds the flat $3 margin.
        // 5000c * 1.2 = 6000; margin floor = 5000+300=5300. Markup wins.
        assert_eq!(price_for(5000, &pricing()).unwrap(), 6000);
    }

    #[test]
    fn a_price_over_the_hard_cap_is_refused() {
        let err = price_for(9000, &pricing()).unwrap_err();
        assert!(err.to_string().contains("exceeds the configured cap"), "{err}");
    }

    #[test]
    fn allowed_tlds_pass_and_others_are_refused() {
        let pricing = pricing();
        assert!(tld_allowed("example.com", &pricing));
        assert!(tld_allowed("example.io", &pricing));
        assert!(!tld_allowed("example.xyz", &pricing));
    }

    #[test]
    fn a_subdomain_is_judged_by_its_registrable_suffix() {
        let pricing = pricing();
        assert!(tld_allowed("shop.example.com", &pricing));
    }
}
