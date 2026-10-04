//! Client for forwarding analyst votes to consensus-service.
//!
//! Votes are recorded in the gateway's own `submission_votes` table so the
//! voter gets an immediate, durable answer. That table is not what the
//! aggregator reads, though -- consensus-service keeps its own store keyed by
//! bounty, and until something forwards votes into it the aggregator has
//! nothing to aggregate and every downstream feature (consensus, payouts,
//! reputation, delayed re-grading) is inert.
//!
//! Forwarding is deliberately non-fatal: consensus-service being down must
//! never cost a user their vote. It is also deliberately *visible* -- the
//! response carries whether the forward succeeded, because the failure mode
//! this closes was precisely a vote path that silently went nowhere.

use std::time::Duration;

use serde::Serialize;
use uuid::Uuid;

/// How long to wait on consensus-service before giving up on a vote forward.
/// Short on purpose: this sits in a user-facing request.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Serialize)]
struct VotePayload<'a> {
    engine_id: String,
    verdict: &'a str,
    confidence: f64,
    reputation_score: i32,
    /// Hash of the sample being voted on. Carried so the sample can be
    /// re-scanned later and the verdict graded against what we learn.
    #[serde(skip_serializing_if = "Option::is_none")]
    sample_hash: Option<&'a str>,
}

/// Everything needed to mirror one vote into consensus-service.
#[derive(Debug, Clone)]
pub struct ForwardedVote {
    pub bounty_id: Uuid,
    pub voter_id: Uuid,
    pub verdict: String,
    pub confidence: f64,
    pub reputation_score: i32,
    pub sample_hash: Option<String>,
}

fn consensus_base_url() -> String {
    std::env::var("CONSENSUS_SERVICE_URL")
        .unwrap_or_else(|_| "http://consensus-service:8080".to_string())
}

/// Mirror a vote into consensus-service.
///
/// Returns `true` when the vote was accepted. Never returns an error: every
/// failure is logged and reported as `false` so the caller can surface it
/// without failing the user's request.
pub async fn forward_vote(vote: &ForwardedVote) -> bool {
    forward_vote_to(&consensus_base_url(), vote).await
}

/// Testable core of [`forward_vote`], with the target explicit.
pub async fn forward_vote_to(base_url: &str, vote: &ForwardedVote) -> bool {
    let url = format!(
        "{}/api/v1/consensus/bounty/{}/vote",
        base_url.trim_end_matches('/'),
        vote.bounty_id
    );

    let payload = VotePayload {
        // consensus-service keys votes by "engine". For a human analyst that
        // identity is their user id, which keeps one-vote-per-participant
        // working through the same unique constraint engines use.
        engine_id: vote.voter_id.to_string(),
        verdict: &vote.verdict,
        confidence: vote.confidence,
        reputation_score: vote.reputation_score,
        sample_hash: vote.sample_hash.as_deref(),
    };

    let client = match reqwest::Client::builder().timeout(FORWARD_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Could not build consensus client: {e}");
            return false;
        }
    };

    match client.post(&url).json(&payload).send().await {
        Ok(resp) if resp.status().is_success() => {
            if vote.sample_hash.is_none() {
                // Not an error, but worth surfacing: without a hash the bounty
                // can never be re-graded, so the verdict stands forever on the
                // crowd's word alone.
                tracing::warn!(
                    "Vote on bounty {} forwarded without a sample hash; bounty will not be gradable",
                    vote.bounty_id
                );
            }
            true
        }
        Ok(resp) => {
            tracing::error!(
                "consensus-service rejected vote on bounty {}: HTTP {}",
                vote.bounty_id,
                resp.status()
            );
            false
        }
        Err(e) => {
            tracing::error!(
                "Could not forward vote on bounty {} to consensus-service: {e}",
                vote.bounty_id
            );
            false
        }
    }
}

/// Map the gateway's vote vocabulary onto a consensus verdict.
///
/// The gateway accepts `agree`/`disagree`, which are relative to the verdict
/// the submission itself claimed. Consensus-service only understands absolute
/// verdicts, so they are resolved here against `submission_verdict`.
///
/// Returns `None` when the vote cannot be expressed absolutely -- notably
/// "disagree" with a `suspicious` submission, which says what the voter
/// rejects but not what they believe. Those votes stay recorded locally and
/// are simply not forwarded, rather than being guessed into a verdict the
/// voter never cast.
pub fn resolve_verdict(vote_verdict: &str, submission_verdict: Option<&str>) -> Option<String> {
    let v = vote_verdict.trim().to_ascii_lowercase();
    match v.as_str() {
        "malicious" | "benign" | "suspicious" => Some(v),
        "agree" => submission_verdict
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| matches!(s.as_str(), "malicious" | "benign" | "suspicious")),
        "disagree" => match submission_verdict.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("malicious") => Some("benign".to_string()),
            Some("benign") => Some("malicious".to_string()),
            // "not suspicious" is not a verdict.
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_verdicts_pass_through() {
        assert_eq!(resolve_verdict("malicious", None).as_deref(), Some("malicious"));
        assert_eq!(resolve_verdict("BENIGN", None).as_deref(), Some("benign"));
        assert_eq!(resolve_verdict(" suspicious ", None).as_deref(), Some("suspicious"));
    }

    #[test]
    fn agree_takes_the_submissions_verdict() {
        assert_eq!(
            resolve_verdict("agree", Some("malicious")).as_deref(),
            Some("malicious")
        );
        assert_eq!(resolve_verdict("agree", Some("benign")).as_deref(), Some("benign"));
    }

    #[test]
    fn disagree_inverts_a_binary_verdict() {
        assert_eq!(resolve_verdict("disagree", Some("malicious")).as_deref(), Some("benign"));
        assert_eq!(resolve_verdict("disagree", Some("benign")).as_deref(), Some("malicious"));
    }

    fn sample_vote() -> ForwardedVote {
        ForwardedVote {
            bounty_id: Uuid::new_v4(),
            voter_id: Uuid::new_v4(),
            verdict: "malicious".to_string(),
            confidence: 0.9,
            reputation_score: 100,
            sample_hash: Some("abc123".to_string()),
        }
    }

    /// A vote is already committed to the gateway's own table before it is
    /// forwarded. If consensus-service is unreachable the forward must report
    /// failure and return -- never panic, never propagate -- or an outage in a
    /// downstream service would cost users their votes.
    #[tokio::test]
    async fn unreachable_consensus_service_is_not_fatal() {
        // Port 1 is reserved and never listening.
        let recorded = forward_vote_to("http://127.0.0.1:1", &sample_vote()).await;
        assert!(!recorded, "an unreachable service must report a failed forward");
    }

    /// A malformed base URL must fail the same quiet way.
    #[tokio::test]
    async fn malformed_base_url_is_not_fatal() {
        let recorded = forward_vote_to("not a url", &sample_vote()).await;
        assert!(!recorded);
    }

    /// Disagreeing with "suspicious" says what the voter rejects, not what
    /// they believe. Forwarding a guess would put a verdict in their mouth.
    #[test]
    fn ambiguous_votes_are_not_forwarded() {
        assert_eq!(resolve_verdict("disagree", Some("suspicious")), None);
        assert_eq!(resolve_verdict("disagree", None), None);
        assert_eq!(resolve_verdict("agree", None), None);
        assert_eq!(resolve_verdict("agree", Some("nonsense")), None);
        assert_eq!(resolve_verdict("wat", Some("malicious")), None);
    }
}
