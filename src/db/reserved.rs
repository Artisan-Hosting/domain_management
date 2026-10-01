//! The `reserved_names` table: what `crate::reserved` checks every free-zone claim against.

use sqlx::{MySqlPool, Row};

use crate::error::{Error, Result};
use crate::reserved::Rule;

/// A stored rule with the bookkeeping an operator screen shows.
#[derive(Debug, Clone)]
pub struct ReservedRow {
    pub id: u64,
    pub rule: Rule,
    pub note: String,
    pub created_by: Option<String>,
    pub created_at: i64,
}

fn rule_from(kind: &str, prefix: String, digits: u8, min: u64, max: u64) -> Option<Rule> {
    match kind {
        "exact" => Some(Rule::Exact(prefix)),
        "prefix" => Some(Rule::Prefix(prefix)),
        "range" => Some(Rule::Range { prefix, digits, min, max }),
        _ => None,
    }
}

/// `(kind, prefix, digits, min, max)` as stored.
fn columns(rule: &Rule) -> (&'static str, &str, u8, u64, u64) {
    match rule {
        Rule::Exact(s) => ("exact", s, 0, 0, 0),
        Rule::Prefix(s) => ("prefix", s, 0, 0, 0),
        Rule::Range { prefix, digits, min, max } => ("range", prefix, *digits, *min, *max),
    }
}

pub async fn list(pool: &MySqlPool) -> Result<Vec<ReservedRow>> {
    let rows = sqlx::query(
        "SELECT id, kind, prefix, digits, min_value, max_value, note, created_by, UNIX_TIMESTAMP(created_at) AS created_at \
         FROM reserved_names ORDER BY id",
    )
    .fetch_all(pool)
    .await?;

    // A row whose kind this build does not know is skipped, not fatal: a newer binary may have written it.
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let rule = rule_from(
                &row.get::<String, _>("kind"),
                row.get("prefix"),
                row.get("digits"),
                row.get("min_value"),
                row.get("max_value"),
            )?;
            Some(ReservedRow {
                id: row.get("id"),
                rule,
                note: row.get("note"),
                created_by: row.get("created_by"),
                created_at: row.get("created_at"),
            })
        })
        .collect())
}

/// Just the rules, for the claim path.
pub async fn rules(pool: &MySqlPool) -> Result<Vec<Rule>> {
    Ok(list(pool).await?.into_iter().map(|r| r.rule).collect())
}

/// Stores a validated rule. Adding one that already exists is an error naming it, not a silent second row.
pub async fn add(pool: &MySqlPool, rule: &Rule, note: &str, created_by: &str) -> Result<u64> {
    rule.validate()?;
    let (kind, prefix, digits, min, max) = columns(rule);
    let res = sqlx::query(
        "INSERT INTO reserved_names (kind, prefix, digits, min_value, max_value, note, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(kind)
    .bind(prefix)
    .bind(digits)
    .bind(min)
    .bind(max)
    .bind(note.chars().take(255).collect::<String>())
    .bind(created_by)
    .execute(pool)
    .await;
    match res {
        Ok(done) => Ok(done.last_insert_id()),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            Err(Error::Config("that reservation already exists".to_owned()))
        }
        Err(e) => Err(e.into()),
    }
}

/// Whether a row was removed.
pub async fn remove(pool: &MySqlPool, id: u64) -> Result<bool> {
    let done = sqlx::query("DELETE FROM reserved_names WHERE id = ?").bind(id).execute(pool).await?;
    Ok(done.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_columns_round_trip_every_kind() {
        for rule in [
            Rule::Exact("www".into()),
            Rule::Prefix("ais-".into()),
            Rule::Range { prefix: "c".into(), digits: 8, min: 0, max: 99_999_999 },
        ] {
            let (kind, prefix, digits, min, max) = columns(&rule);
            assert_eq!(rule_from(kind, prefix.to_owned(), digits, min, max), Some(rule));
        }
        assert_eq!(rule_from("glob", "x".into(), 0, 0, 0), None);
    }
}
