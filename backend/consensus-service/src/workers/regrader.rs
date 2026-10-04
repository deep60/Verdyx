//! Delayed re-grading of finalized consensus results.
//!
//! A finalized consensus is what the crowd believed at the time. It is not
//! truth, and nothing in the original vote can tell you whether it was right --
//! the reputation that weighted the vote was itself earned by agreeing with
//! earlier votes. Left alone, that loop is closed: a confidently wrong majority
//! pays itself and raises its own weight.
//!
//! This worker opens the loop. Once a bounty is `delay_hours` past
//! finalization, its sample is scanned again with today's engines -- rules,
//! signatures, and reputation the original voters did not have. The result is
//! written to `verdict_grades`, and any payout held back at finalization
//! settles against that instead of the original vote.
//!
//! The worker only grades bounties whose `sample_hash` is known. Anything else
//! is left for a retro-scan job or an admin to grade through
//! `ConsensusService::record_grade`.

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::models::{GradableBounty, GradeSource, Verdict};
use crate::services::consensus_service::ConsensusService;

/// Re-scan response from analysis-engine. Only the verdict is needed; the rest
/// of the payload is ignored so the two services can evolve independently.
#[derive(serde::Deserialize)]
struct RescanResponse {
    verdict: String,
}

pub async fn start(service: Arc<ConsensusService>) -> Result<()> {
    let cfg = service.config().grading.clone();

    if !cfg.enabled {
        info!("Regrader disabled (set GRADING_ENABLED=true to turn it on)");
        return Ok(());
    }

    info!(
        "Regrader started: re-checking finalized verdicts {}h after finalization, every {}s",
        cfg.delay_hours, cfg.poll_interval_secs
    );

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.rescan_timeout_secs))
        .build()?;

    let interval = Duration::from_secs(cfg.poll_interval_secs);

    loop {
        tokio::time::sleep(interval).await;

        let due = match service.find_gradable_bounties().await {
            Ok(d) => d,
            Err(e) => {
                error!("Regrader could not query due bounties: {}", e);
                continue;
            }
        };

        if due.is_empty() {
            debug!("Regrader: nothing due");
            continue;
        }

        info!("Regrader: {} bounties due for grading", due.len());

        let mut graded = 0usize;
        let mut overturned = 0usize;

        for bounty in due {
            match grade_one(&service, &http, &cfg.analysis_engine_url, &bounty).await {
                Ok(true) => {
                    graded += 1;
                    overturned += 1;
                }
                Ok(false) => graded += 1,
                Err(e) => {
                    // One bad sample must not stall the queue. The bounty stays
                    // ungraded and is retried on the next pass.
                    warn!("Regrader: bounty {} could not be graded: {}", bounty.bounty_id, e);
                }
            }
        }

        if graded > 0 {
            info!(
                "Regrader pass complete: {} graded, {} overturned",
                graded, overturned
            );
        }
    }
}

/// Grade a single bounty. Returns `true` if the verdict was overturned.
async fn grade_one(
    service: &ConsensusService,
    http: &reqwest::Client,
    engine_url: &str,
    bounty: &GradableBounty,
) -> Result<bool> {
    let hash = bounty
        .sample_hash
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("no sample hash"))?;

    let fresh = rescan_by_hash(http, engine_url, hash).await?;

    let notes = format!(
        "rescan {}h after finalization: engine returned {}",
        service.config().grading.delay_hours,
        fresh.to_string()
    );

    let grade = service
        .record_grade(
            bounty.bounty_id,
            &fresh,
            GradeSource::Rescan,
            Some(hash),
            Some(&notes),
        )
        .await?;

    if grade.verdict_changed {
        // Loud on purpose: this is the crowd being wrong, and it is the signal
        // the whole loop exists to surface.
        warn!(
            "Verdict OVERTURNED for bounty {}: consensus said {}, rescan says {}",
            bounty.bounty_id, grade.original_verdict, grade.graded_verdict
        );
    } else {
        debug!(
            "Bounty {} upheld as {}",
            bounty.bounty_id, grade.graded_verdict
        );
    }

    Ok(grade.verdict_changed)
}

/// Ask analysis-engine to re-scan a sample by hash.
async fn rescan_by_hash(
    http: &reqwest::Client,
    engine_url: &str,
    hash: &str,
) -> Result<Verdict> {
    let url = format!("{}/analyze/hash", engine_url.trim_end_matches('/'));

    let resp = http
        .post(&url)
        .json(&serde_json::json!({ "hash": hash }))
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("analysis-engine returned {} for hash {}", resp.status(), hash);
    }

    let body: RescanResponse = resp.json().await?;
    Ok(parse_verdict_str(&body.verdict))
}

/// Map an engine verdict string onto our `Verdict`.
///
/// Deliberately conservative: anything unrecognised becomes `Unknown` rather
/// than defaulting to `Benign`, so a parsing slip can never silently overturn a
/// malicious verdict into a clean one.
fn parse_verdict_str(s: &str) -> Verdict {
    match s.trim().to_ascii_lowercase().as_str() {
        "malicious" => Verdict::Malicious,
        "benign" | "clean" => Verdict::Benign,
        "suspicious" => Verdict::Suspicious,
        _ => Verdict::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_verdicts() {
        assert_eq!(parse_verdict_str("malicious"), Verdict::Malicious);
        assert_eq!(parse_verdict_str("Malicious"), Verdict::Malicious);
        assert_eq!(parse_verdict_str("  BENIGN "), Verdict::Benign);
        assert_eq!(parse_verdict_str("clean"), Verdict::Benign);
        assert_eq!(parse_verdict_str("suspicious"), Verdict::Suspicious);
    }

    /// An unrecognised verdict must never read as Benign -- that would let a
    /// parsing slip quietly overturn a malicious verdict into a clean one.
    #[test]
    fn unknown_verdicts_do_not_become_benign() {
        for s in ["", "???", "malicous", "null", "error"] {
            assert_eq!(parse_verdict_str(s), Verdict::Unknown, "input: {s:?}");
        }
    }
}
