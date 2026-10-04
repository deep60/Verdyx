//! The commit-reveal commitment scheme.
//!
//! A commitment is `sha256` over a canonical preimage, hex-encoded:
//!
//! ```text
//! preimage   = "{bounty_id}:{engine_id}:{verdict}:{confidence}:{salt}"
//! commitment = lowercase_hex(sha256(preimage))
//! ```
//!
//! Two of those fields are there for binding, not secrecy:
//!
//! * `bounty_id` stops a commitment being replayed onto a different bounty.
//! * `engine_id` stops one voter lifting another's commitment and claiming it,
//!   which would otherwise let a copier commit without having decided anything
//!   and then reveal whatever the original voter reveals.
//!
//! `salt` is what makes the hash uninvertible. Without it there are only a
//! handful of verdict/confidence pairs, so anyone could enumerate them all and
//! read every vote during the commit phase -- exactly the leak the scheme
//! exists to prevent.
//!
//! Everything is canonicalised before hashing so that a voter's own client
//! cannot lock them out of their reveal through incidental formatting: verdict
//! case, confidence precision, and surrounding whitespace are all normalised
//! identically on both sides.

use rust_decimal::Decimal;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::models::Verdict;

/// Decimal places used when hashing `confidence`.
///
/// Matches `consensus_submissions.confidence DECIMAL(5,4)`. Fixing the
/// precision means `0.9`, `0.90` and `0.9000` all produce one commitment; a
/// voter whose client renders the value differently at reveal time than at
/// commit time still gets in.
const CONFIDENCE_DP: usize = 4;

/// Build the canonical preimage for a vote.
///
/// Public so a client can reproduce it exactly. Any change here is a breaking
/// protocol change: commitments made under the old format stop verifying.
pub fn preimage(
    bounty_id: Uuid,
    engine_id: &str,
    verdict: &Verdict,
    confidence: Decimal,
    salt: &str,
) -> String {
    format!(
        "{}:{}:{}:{:.*}:{}",
        bounty_id,
        engine_id.trim(),
        verdict.to_string(),
        CONFIDENCE_DP,
        confidence,
        salt
    )
}

/// Compute the commitment a voter should send during the commit phase.
pub fn commit(
    bounty_id: Uuid,
    engine_id: &str,
    verdict: &Verdict,
    confidence: Decimal,
    salt: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(preimage(bounty_id, engine_id, verdict, confidence, salt).as_bytes());
    hex::encode(hasher.finalize())
}

/// Check a revealed vote against a stored commitment.
///
/// The comparison is a plain equality check: both sides are public by reveal
/// time and the caller supplies the plaintext, so there is no secret for a
/// timing side-channel to leak.
pub fn verify(
    stored_commitment: &str,
    bounty_id: Uuid,
    engine_id: &str,
    verdict: &Verdict,
    confidence: Decimal,
    salt: &str,
) -> bool {
    let expected = commit(bounty_id, engine_id, verdict, confidence, salt);
    expected.eq_ignore_ascii_case(stored_commitment.trim())
}

/// Whether a string looks like a commitment this service could have produced.
///
/// Checked at commit time so a malformed value is rejected while the voter can
/// still fix it, rather than at reveal time when the window has closed.
pub fn is_well_formed(commitment: &str) -> bool {
    let c = commitment.trim();
    c.len() == 64 && c.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    fn bounty() -> Uuid {
        Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap()
    }

    #[test]
    fn commitment_is_lowercase_hex_sha256() {
        let c = commit(bounty(), "alice", &Verdict::Malicious, d("0.9"), "a-long-enough-salt");
        assert_eq!(c.len(), 64);
        assert!(c.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
        assert!(is_well_formed(&c));
    }

    #[test]
    fn a_correct_reveal_verifies() {
        let salt = "correct-horse-battery";
        let c = commit(bounty(), "alice", &Verdict::Malicious, d("0.9"), salt);
        assert!(verify(&c, bounty(), "alice", &Verdict::Malicious, d("0.9"), salt));
    }

    /// The whole point: changing your mind after committing must not verify.
    #[test]
    fn a_changed_verdict_does_not_verify() {
        let salt = "correct-horse-battery";
        let c = commit(bounty(), "alice", &Verdict::Malicious, d("0.9"), salt);
        assert!(!verify(&c, bounty(), "alice", &Verdict::Benign, d("0.9"), salt));
    }

    #[test]
    fn a_changed_confidence_does_not_verify() {
        let salt = "correct-horse-battery";
        let c = commit(bounty(), "alice", &Verdict::Malicious, d("0.9"), salt);
        assert!(!verify(&c, bounty(), "alice", &Verdict::Malicious, d("0.5"), salt));
    }

    #[test]
    fn a_wrong_salt_does_not_verify() {
        let c = commit(bounty(), "alice", &Verdict::Malicious, d("0.9"), "the-real-salt");
        assert!(!verify(&c, bounty(), "alice", &Verdict::Malicious, d("0.9"), "a-guessed-salt"));
    }

    /// Binding to the voter: Bob must not be able to submit Alice's commitment
    /// as his own and then reveal whatever she reveals. Without engine_id in
    /// the preimage, a copier could vote without deciding anything.
    #[test]
    fn a_commitment_is_bound_to_its_voter() {
        let salt = "shared-salt-somehow";
        let alice = commit(bounty(), "alice", &Verdict::Malicious, d("0.9"), salt);
        let bob = commit(bounty(), "bob", &Verdict::Malicious, d("0.9"), salt);
        assert_ne!(alice, bob, "two voters must not produce the same commitment");
        assert!(
            !verify(&alice, bounty(), "bob", &Verdict::Malicious, d("0.9"), salt),
            "Alice's commitment must not verify for Bob"
        );
    }

    /// Binding to the bounty: a commitment must not be replayable elsewhere.
    #[test]
    fn a_commitment_is_bound_to_its_bounty() {
        let other = Uuid::parse_str("99999999-8888-7777-6666-555555555555").unwrap();
        let salt = "correct-horse-battery";
        let c = commit(bounty(), "alice", &Verdict::Malicious, d("0.9"), salt);
        assert!(!verify(&c, other, "alice", &Verdict::Malicious, d("0.9"), salt));
    }

    /// A voter must not be locked out of their own reveal because their client
    /// rendered 0.9 as 0.9000 the second time.
    #[test]
    fn confidence_formatting_does_not_change_the_commitment() {
        let salt = "correct-horse-battery";
        let base = commit(bounty(), "alice", &Verdict::Malicious, d("0.9"), salt);
        for equivalent in ["0.90", "0.9000", "0.900000"] {
            assert_eq!(
                commit(bounty(), "alice", &Verdict::Malicious, d(equivalent), salt),
                base,
                "{equivalent} must commit identically to 0.9"
            );
        }
    }

    /// Precision beyond the stored column is truncated on both sides, so it
    /// cannot silently break a reveal either.
    #[test]
    fn confidence_beyond_stored_precision_is_canonicalised() {
        let salt = "correct-horse-battery";
        let a = commit(bounty(), "alice", &Verdict::Malicious, d("0.90001"), salt);
        let b = commit(bounty(), "alice", &Verdict::Malicious, d("0.9000"), salt);
        assert_eq!(a, b, "digits below 4dp must not affect the commitment");
    }

    #[test]
    fn engine_id_whitespace_is_ignored() {
        let salt = "correct-horse-battery";
        let c = commit(bounty(), "alice", &Verdict::Malicious, d("0.9"), salt);
        assert!(verify(&c, bounty(), "  alice  ", &Verdict::Malicious, d("0.9"), salt));
    }

    /// Distinct verdicts must never collide.
    #[test]
    fn every_verdict_commits_distinctly() {
        let salt = "correct-horse-battery";
        let mut seen = std::collections::HashSet::new();
        for v in [
            Verdict::Malicious,
            Verdict::Benign,
            Verdict::Suspicious,
            Verdict::Unknown,
        ] {
            assert!(
                seen.insert(commit(bounty(), "alice", &v, d("0.9"), salt)),
                "verdict {v:?} collided with another"
            );
        }
    }

    #[test]
    fn malformed_commitments_are_rejected() {
        assert!(!is_well_formed(""));
        assert!(!is_well_formed("abc"));
        assert!(!is_well_formed(&"a".repeat(63)));
        assert!(!is_well_formed(&"a".repeat(65)));
        assert!(!is_well_formed(&"z".repeat(64)), "non-hex must be rejected");
    }

    /// The preimage is part of the public protocol; pin its exact shape so a
    /// refactor cannot silently invalidate every commitment in flight.
    #[test]
    fn preimage_format_is_stable() {
        assert_eq!(
            preimage(bounty(), "alice", &Verdict::Malicious, d("0.9"), "salty"),
            "11111111-2222-3333-4444-555555555555:alice:malicious:0.9000:salty"
        );
    }
}
