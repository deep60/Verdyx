//! Live hunts: run people's saved YARA rules on each new upload in their
//! scope, and record the matches.
//!
//! The gateway owns `live_hunts` / `live_hunt_matches` (see
//! `shared::live_hunts` for which hunts cover an upload). For each uploaded
//! file or email, after it's loaded and before the other engines run:
//!
//! 1. The enabled hunts in scope are read, at most
//!    [`shared::live_hunts::MAX_PER_UPLOAD`].
//! 2. Each rule is checked and compiled (with `include` refused, as in
//!    retrohunt), and kept compiled until its text changes.
//! 3. The bytes already in memory are scanned, [`HUNT_TIMEOUT_SECS`] per hunt
//!    and [`UPLOAD_BUDGET`] in all, so hunts can't hold a scan up for long.
//! 4. A match is recorded once per hunt and upload. A rule that doesn't
//!    compile turns its hunt off, with the compiler's message for its owner.
//!
//! Failures here are logged and never fail the scan itself.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use super::retrohunt::{compile, Hunter};

/// Seconds YARA may spend on one hunt for one upload.
pub const HUNT_TIMEOUT_SECS: i32 = 5;
/// Time all hunts together may spend on one upload.
pub const UPLOAD_BUDGET: Duration = Duration::from_secs(20);
/// Compiled rule sets kept in memory.
const CACHE_LIMIT: usize = 200;

/// What happened to one hunt on one upload.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Matched(Vec<String>),
    NoMatch,
    /// The rule doesn't compile; the hunt should be turned off.
    BadRule(String),
    /// YARA failed on this file (a timeout, say). Logged, not recorded.
    ScanFailed(String),
    /// The upload's time budget ran out before this hunt.
    Skipped,
}

type Cache = Mutex<HashMap<[u8; 32], Arc<dyn Hunter>>>;

fn cache() -> &'static Cache {
    static CACHE: OnceLock<Cache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Compile `rule`, reusing an earlier compile of the same text.
fn compiled(rule: &str) -> Result<Arc<dyn Hunter>, String> {
    let key: [u8; 32] = Sha256::digest(rule.as_bytes()).into();
    if let Some(h) = cache().lock().ok().and_then(|c| c.get(&key).cloned()) {
        return Ok(h);
    }
    let hunter: Arc<dyn Hunter> = Arc::from(compile(rule)?);
    if let Ok(mut c) = cache().lock() {
        if c.len() >= CACHE_LIMIT {
            c.clear();
        }
        c.insert(key, hunter.clone());
    }
    Ok(hunter)
}

/// Run `hunts` over `data`, within `budget`. Blocking: call it off the async
/// threads.
pub fn scan_all(hunts: &[(Uuid, String)], data: &[u8], budget: Duration) -> Vec<(Uuid, Outcome)> {
    let started = Instant::now();
    hunts
        .iter()
        .map(|(id, rule)| {
            if started.elapsed() >= budget {
                return (*id, Outcome::Skipped);
            }
            let outcome = match compiled(rule) {
                Err(why) => Outcome::BadRule(why.chars().take(500).collect()),
                Ok(h) => match h.scan_bytes(data, HUNT_TIMEOUT_SECS) {
                    Ok(rules) if rules.is_empty() => Outcome::NoMatch,
                    Ok(rules) => Outcome::Matched(rules),
                    Err(e) => Outcome::ScanFailed(e),
                },
            };
            (*id, outcome)
        })
        .collect()
}

/// Run the live hunts that cover this upload and record what they find.
pub async fn run_for_upload(
    db: &PgPool,
    submission_id: Uuid,
    submitter: Option<Uuid>,
    team: Option<Uuid>,
    data: &[u8],
) {
    // Without YARA every rule would "fail to compile" and be turned off.
    if !cfg!(feature = "yara-engine") || data.is_empty() {
        return;
    }
    // Anonymous uploads with no team are in nobody's scope.
    if submitter.is_none() && team.is_none() {
        return;
    }
    let hunts: Vec<(Uuid, String)> = match sqlx::query_as(shared::live_hunts::IN_SCOPE_SQL)
        .bind(submitter)
        .bind(team)
        .fetch_all(db)
        .await
    {
        Ok(h) => h,
        Err(e) => {
            // Before the gateway's migration has run, the table doesn't exist.
            warn!("live hunts unavailable for {submission_id}: {e}");
            return;
        }
    };
    if hunts.is_empty() {
        return;
    }
    // block_in_place lets YARA read `data` without copying it.
    let outcomes = tokio::task::block_in_place(|| scan_all(&hunts, data, UPLOAD_BUDGET));
    let rules_by_id: HashMap<Uuid, &String> = hunts.iter().map(|(id, r)| (*id, r)).collect();
    for (hunt, outcome) in outcomes {
        let result = match &outcome {
            Outcome::Matched(rules) => {
                info!("live hunt {hunt} matched {submission_id}: {rules:?}");
                record_match(db, hunt, submission_id, rules).await
            }
            Outcome::BadRule(why) => {
                warn!("live hunt {hunt} turned off: {why}");
                turn_off(db, hunt, rules_by_id[&hunt], why).await
            }
            Outcome::ScanFailed(e) => {
                warn!("live hunt {hunt} on {submission_id}: {e}");
                Ok(())
            }
            Outcome::Skipped => {
                warn!("live hunt {hunt} skipped on {submission_id}: time budget used up");
                Ok(())
            }
            Outcome::NoMatch => Ok(()),
        };
        if let Err(e) = result {
            warn!("live hunt {hunt}: could not record the result for {submission_id}: {e}");
        }
    }
}

/// Record a match once per hunt and upload, and count it.
pub async fn record_match(
    db: &PgPool,
    hunt: Uuid,
    submission: Uuid,
    rules: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query(shared::live_hunts::RECORD_MATCH_SQL)
        .bind(hunt)
        .bind(submission)
        .bind(rules)
        .execute(db)
        .await
        .map(|_| ())
}

/// Turn a hunt off because its rule doesn't compile, unless it was edited in
/// the meantime.
pub async fn turn_off(db: &PgPool, hunt: Uuid, rule: &str, why: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE live_hunts SET enabled = FALSE, last_error = $3, updated_at = NOW() \
         WHERE id = $1 AND rule_text = $2",
    )
    .bind(hunt)
    .bind(rule)
    .bind(why)
    .execute(db)
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_that_fail_the_checks_are_bad_rules() {
        let id = Uuid::new_v4();
        let out = scan_all(
            &[(
                id,
                "include \"/etc/passwd\"\nrule a { condition: true }".into(),
            )],
            b"data",
            UPLOAD_BUDGET,
        );
        assert!(matches!(&out[0].1, Outcome::BadRule(why) if why.contains("include")));
    }

    #[test]
    fn an_exhausted_budget_skips_the_rest() {
        let out = scan_all(
            &[(Uuid::new_v4(), "rule a { condition: true }".into())],
            b"x",
            Duration::ZERO,
        );
        assert_eq!(out[0].1, Outcome::Skipped);
    }

    #[cfg(feature = "yara-engine")]
    #[test]
    fn hunts_match_bytes_in_memory() {
        let (hit, miss, bad) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let out = scan_all(
            &[
                (
                    hit,
                    r#"rule Inject { strings: $a = "CreateRemoteThread" nocase condition: $a }"#
                        .into(),
                ),
                (
                    miss,
                    r#"rule Other { strings: $a = "nothing here" condition: $a }"#.into(),
                ),
                (bad, "rule broken { condition: $missing }".into()),
            ],
            b"xx createremotethread xx",
            UPLOAD_BUDGET,
        );
        assert_eq!(out[0], (hit, Outcome::Matched(vec!["Inject".into()])));
        assert_eq!(out[1], (miss, Outcome::NoMatch));
        assert!(
            matches!(&out[2].1, Outcome::BadRule(why) if why.starts_with("the rule doesn't compile"))
        );
    }

    #[cfg(feature = "yara-engine")]
    #[test]
    fn compiled_rules_are_reused() {
        let rule = format!("rule R{} {{ condition: true }}", Uuid::new_v4().simple());
        let a = compiled(&rule).unwrap();
        let b = compiled(&rule).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }
}
