//! Names nobody may claim on the free zone.
//!
//! The free zone (`arhst.net`) hands out `<name>.arhst.net` to anyone who deploys. Some names are the
//! operator's: `c00000000`-`c99999999` today, and whatever else gets reserved later. The rules live in a
//! table an operator edits through a Super-only API (see `db::reserved`), and every claim is checked
//! against them here, so a rule added today applies to the next claim with no restart.
//!
//! Three kinds only, on purpose: an exact name, a prefix, or a prefix followed by a fixed number of
//! digits within a range. That covers every reservation actually wanted and keeps "what does this rule
//! match" answerable by reading it -- no pattern language to get wrong or to slow a claim down.

use crate::error::{Error, Result};

/// One reservation, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// Exactly this label.
    Exact(String),
    /// Any label starting with this.
    Prefix(String),
    /// `prefix` then exactly `digits` ASCII digits whose value is in `min..=max`.
    /// `c00000000`-`c99999999` is `{prefix: "c", digits: 8, min: 0, max: 99_999_999}`.
    Range { prefix: String, digits: u8, min: u64, max: u64 },
}

impl Rule {
    /// Does this rule reserve `label`? `label` must already be lower-case.
    pub fn matches(&self, label: &str) -> bool {
        match self {
            Rule::Exact(name) => label == name,
            Rule::Prefix(prefix) => label.starts_with(prefix.as_str()),
            Rule::Range { prefix, digits, min, max } => {
                let Some(rest) = label.strip_prefix(prefix.as_str()) else { return false };
                if rest.len() != usize::from(*digits) || !rest.bytes().all(|b| b.is_ascii_digit()) {
                    return false;
                }
                rest.parse::<u64>().is_ok_and(|n| (*min..=*max).contains(&n))
            }
        }
    }

    /// Refuses a rule that could never work as intended, before it is stored.
    pub fn validate(&self) -> Result<()> {
        let bad = |why: &str| Err(Error::Config(format!("reserved rule: {why}")));
        let (text, what) = match self {
            Rule::Exact(s) => (s, "name"),
            Rule::Prefix(s) | Rule::Range { prefix: s, .. } => (s, "prefix"),
        };
        if text.is_empty() || text.len() > 63 {
            return bad(&format!("the {what} must be 1 to 63 characters"));
        }
        if !text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return bad(&format!("the {what} may use only a-z, 0-9 and hyphens (lower case)"));
        }
        if let Rule::Range { prefix, digits, min, max } = self {
            if !(1..=18).contains(digits) {
                return bad("digits must be between 1 and 18");
            }
            if prefix.len() + usize::from(*digits) > 63 {
                return bad("prefix plus digits is longer than a DNS label");
            }
            if min > max {
                return bad("min is above max");
            }
            if *max >= 10u64.pow(u32::from(*digits)) {
                return bad("max has more digits than `digits` allows");
            }
        }
        Ok(())
    }
}

/// Checks a customer-chosen free name and returns it lower-cased, or says why it cannot be used.
/// This is the shape only; whether it is reserved or taken is asked separately.
pub fn free_label(name: &str) -> std::result::Result<String, String> {
    let label = name.trim().to_ascii_lowercase();
    if label.len() < 3 || label.len() > 40 {
        return Err("a name must be 3 to 40 characters".to_owned());
    }
    if !label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        return Err("use only letters, numbers and hyphens".to_owned());
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err("a name cannot start or end with a hyphen".to_owned());
    }
    // `xn--` marks an internationalised name; letting one through lets a lookalike be registered.
    if label.contains("--") {
        return Err("a name cannot contain two hyphens in a row".to_owned());
    }
    Ok(label)
}

/// The first rule that reserves `label`, if any. Case-insensitive.
pub fn reserved_by<'a>(rules: &'a [Rule], label: &str) -> Option<&'a Rule> {
    let label = label.to_ascii_lowercase();
    rules.iter().find(|r| r.matches(&label))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn customer_ids() -> Rule {
        Rule::Range { prefix: "c".into(), digits: 8, min: 0, max: 99_999_999 }
    }

    #[test]
    fn the_customer_id_range_is_exactly_c_and_eight_digits() {
        let r = customer_ids();
        for yes in ["c00000000", "c99999999", "c12345678", "c00000001"] {
            assert!(r.matches(yes), "{yes}");
        }
        for no in ["c0000000", "c000000000", "c1234567a", "d12345678", "c", "cc12345678", "c-1234567", "c1234 5678", ""] {
            assert!(!r.matches(no), "{no}");
        }
    }

    #[test]
    fn a_narrower_range_respects_both_ends() {
        let r = Rule::Range { prefix: "edge".into(), digits: 3, min: 10, max: 250 };
        assert!(r.matches("edge010") && r.matches("edge250") && r.matches("edge100"));
        assert!(!r.matches("edge009") && !r.matches("edge251") && !r.matches("edge10"));
    }

    #[test]
    fn exact_and_prefix() {
        assert!(Rule::Exact("www".into()).matches("www"));
        assert!(!Rule::Exact("www".into()).matches("www2"));
        assert!(Rule::Prefix("ais-".into()).matches("ais-anything"));
        assert!(!Rule::Prefix("ais-".into()).matches("xais-a"));
    }

    #[test]
    fn matching_ignores_case_through_reserved_by() {
        let rules = vec![Rule::Exact("admin".into()), customer_ids()];
        assert_eq!(reserved_by(&rules, "ADMIN"), Some(&rules[0]));
        assert_eq!(reserved_by(&rules, "C00000042"), Some(&rules[1]));
        assert_eq!(reserved_by(&rules, "shop"), None);
    }

    #[test]
    fn a_huge_number_does_not_overflow_or_match() {
        let r = Rule::Range { prefix: "n".into(), digits: 18, min: 0, max: 10u64.pow(18) - 1 };
        assert!(r.matches("n999999999999999999"));
        assert!(!r.matches("n9999999999999999999"));
    }

    #[test]
    fn free_labels_are_checked_for_shape() {
        assert_eq!(free_label("  My-Shop ").as_deref(), Ok("my-shop"));
        assert_eq!(free_label("abc").as_deref(), Ok("abc"));
        for bad in ["ab", "", "-abc", "abc-", "a_b_c", "ab c", "xn--abc", "a--b", "dot.ted", &"a".repeat(41)] {
            assert!(free_label(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn bad_rules_are_refused_before_they_are_stored() {
        let cases = [
            Rule::Exact(String::new()),
            Rule::Exact("Has-Upper".into()),
            Rule::Prefix("under_score".into()),
            Rule::Prefix("a".repeat(64)),
            Rule::Range { prefix: "c".into(), digits: 0, min: 0, max: 0 },
            Rule::Range { prefix: "c".into(), digits: 19, min: 0, max: 1 },
            Rule::Range { prefix: "c".into(), digits: 3, min: 5, max: 4 },
            Rule::Range { prefix: "c".into(), digits: 3, min: 0, max: 1000 },
            Rule::Range { prefix: "a".repeat(60), digits: 8, min: 0, max: 1 },
        ];
        for rule in cases {
            assert!(rule.validate().is_err(), "{rule:?}");
        }
        assert!(customer_ids().validate().is_ok());
    }
}
