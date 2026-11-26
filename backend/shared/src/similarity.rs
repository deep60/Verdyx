//! Similarity search: fuzzy hashes that stay close when a file changes a little.
//!
//! An exact hash (SHA-256) changes completely when one byte does, so a
//! repacked or recompiled variant of known malware looks brand new. These do
//! not:
//!
//! - **TLSH**: a distance, 0 for the same content, rising as files differ.
//!   Under about 30 is very close; past 100 the files are mostly unrelated.
//! - **ssdeep**: a match score from 0 to 100.
//! - **imphash**: an MD5 of a Windows program's import table. Programs built
//!   from the same code usually share one. It's computed by the analysis
//!   engine, which parses programs.
//!
//! The analysis engine stores the hashes of each upload in `file_similarity`
//! and the gateway compares them when someone asks for similar files. Both use
//! this module, so they agree on what counts as similar.

use serde::Serialize;
use std::str::FromStr;
use uuid::Uuid;

/// Files under this size get no fuzzy hashes: there's too little in them to
/// compare, and TLSH can't hash under 50 bytes anyway.
pub const MIN_BYTES: usize = 64;

/// TLSH distances above this aren't reported.
pub const MAX_TLSH_DISTANCE: i32 = 100;
/// ssdeep scores below this aren't reported.
pub const MIN_SSDEEP_SCORE: u32 = 40;
/// Most similar files returned for one sample.
pub const MAX_RESULTS: usize = 25;
/// Most recent visible files compared against one sample. TLSH and ssdeep
/// can't be indexed in Postgres, so they're compared in the gateway; files
/// with the same imphash are found by index on top of these, at any age.
pub const MAX_CANDIDATES: i64 = 5000;

/// The fuzzy hashes of one file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Hashes {
    pub tlsh: Option<String>,
    pub ssdeep: Option<String>,
    pub imphash: Option<String>,
}

/// TLSH and ssdeep of `data`. Either is `None` when the data is too small or
/// too uniform to hash.
pub fn compute(data: &[u8]) -> Hashes {
    if data.len() < MIN_BYTES {
        return Hashes::default();
    }
    let tlsh = tlsh2::TlshDefaultBuilder::build_from(data)
        .map(|t| String::from_utf8_lossy(&t.hash()).into_owned());
    let ssdeep = Some(fuzzyhash::FuzzyHash::new(data).to_string()).filter(|s| s.contains(':'));
    Hashes {
        tlsh,
        ssdeep,
        imphash: None,
    }
}

/// TLSH distance between two hashes, `None` when either doesn't parse.
pub fn tlsh_distance(a: &str, b: &str) -> Option<i32> {
    let a = tlsh2::TlshDefault::from_str(a).ok()?;
    let b = tlsh2::TlshDefault::from_str(b).ok()?;
    Some(a.diff(&b, true))
}

/// ssdeep match score from 0 to 100, `None` when either doesn't parse.
pub fn ssdeep_score(a: &str, b: &str) -> Option<u32> {
    fuzzyhash::FuzzyHash::compare(a, b).ok()
}

/// How close two files are, in words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Closeness {
    /// The same bytes.
    Identical,
    /// TLSH 30 or under, or ssdeep 80 or over.
    VerySimilar,
    /// TLSH 70 or under, or ssdeep 55 or over.
    Similar,
    /// Within the reporting limits, but further apart.
    Related,
    /// Only the imphash matches: built from the same code, maybe very
    /// different files.
    SameImports,
}

/// Why one file was reported as similar to another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Match {
    pub closeness: Closeness,
    pub tlsh_distance: Option<i32>,
    pub ssdeep_score: Option<u32>,
    pub same_imphash: bool,
}

impl Match {
    /// Sort key: closest first.
    pub fn rank(&self) -> (Closeness, i32, std::cmp::Reverse<u32>) {
        (
            self.closeness,
            self.tlsh_distance.unwrap_or(i32::MAX),
            std::cmp::Reverse(self.ssdeep_score.unwrap_or(0)),
        )
    }
}

fn pair<'a>(x: &'a Option<String>, y: &'a Option<String>) -> Option<(&'a str, &'a str)> {
    Some((x.as_deref()?, y.as_deref()?))
}

/// Compare two files. `None` when they aren't similar enough to report.
pub fn compare(a: &Hashes, a_sha256: &str, b: &Hashes, b_sha256: &str) -> Option<Match> {
    let tlsh = pair(&a.tlsh, &b.tlsh).and_then(|(x, y)| tlsh_distance(x, y));
    let ssdeep = pair(&a.ssdeep, &b.ssdeep).and_then(|(x, y)| ssdeep_score(x, y));
    let same_imphash =
        matches!(pair(&a.imphash, &b.imphash), Some((x, y)) if x.eq_ignore_ascii_case(y));
    let identical = !a_sha256.is_empty() && a_sha256.eq_ignore_ascii_case(b_sha256);

    let t = tlsh.filter(|d| *d <= MAX_TLSH_DISTANCE);
    let s = ssdeep.filter(|s| *s >= MIN_SSDEEP_SCORE);
    let closeness = if identical {
        Closeness::Identical
    } else if t.is_some_and(|d| d <= 30) || s.is_some_and(|s| s >= 80) {
        Closeness::VerySimilar
    } else if t.is_some_and(|d| d <= 70) || s.is_some_and(|s| s >= 55) {
        Closeness::Similar
    } else if t.is_some() || s.is_some() {
        Closeness::Related
    } else if same_imphash {
        Closeness::SameImports
    } else {
        return None;
    };
    Some(Match {
        closeness,
        tlsh_distance: tlsh,
        ssdeep_score: ssdeep,
        same_imphash,
    })
}

/// Store an upload's hashes. `$1` submission, `$2` tlsh, `$3` ssdeep,
/// `$4` imphash.
pub const UPSERT_SQL: &str = r#"
INSERT INTO file_similarity (submission_id, tlsh, ssdeep, imphash)
VALUES ($1, $2, $3, $4)
ON CONFLICT (submission_id) DO UPDATE
  SET tlsh = EXCLUDED.tlsh, ssdeep = EXCLUDED.ssdeep, imphash = EXCLUDED.imphash
"#;

/// Which uploads a caller may see, as a condition on `s` (submissions).
///
/// The same rules as reading a scan (`can_view` in the gateway), minus
/// signed-out uploads: their unguessable link is their only key, so they're
/// never listed for anyone.
///
/// `$1` the caller, `$2` the team of a team API key (NULL otherwise),
/// `$3` whether the caller is an admin.
const VISIBLE: &str = r#"
  s.submitter_id <> '00000000-0000-0000-0000-000000000000'
  AND CASE
    WHEN $2::uuid IS NOT NULL THEN s.organization_id = $2
    ELSE $3
      OR s.submitter_id = $1
      OR EXISTS (SELECT 1 FROM bounties b WHERE b.submission_id = s.id)
      OR (s.organization_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM organization_members m
            WHERE m.organization_id = s.organization_id AND m.user_id = $1))
  END
"#;

const CANDIDATE_COLUMNS: &str = r#"
  f.submission_id, f.tlsh, f.ssdeep, f.imphash, s.file_hash, s.original_filename,
  s.file_size, s.created_at, s.metadata ->> 'consensus_verdict' AS verdict
"#;

/// The most recent visible uploads with hashes, other than `$4`.
pub fn recent_candidates_sql() -> String {
    format!(
        "SELECT {CANDIDATE_COLUMNS} FROM file_similarity f JOIN submissions s ON s.id = f.submission_id
         WHERE f.submission_id <> $4 AND (f.tlsh IS NOT NULL OR f.ssdeep IS NOT NULL) AND {VISIBLE}
         ORDER BY f.created_at DESC LIMIT {MAX_CANDIDATES}"
    )
}

/// Visible uploads, other than `$4`, sharing the imphash `$5`, at any age.
pub fn imphash_candidates_sql() -> String {
    format!(
        "SELECT {CANDIDATE_COLUMNS} FROM file_similarity f JOIN submissions s ON s.id = f.submission_id
         WHERE f.submission_id <> $4 AND f.imphash = $5 AND {VISIBLE}
         ORDER BY f.created_at DESC LIMIT 200"
    )
}

/// One candidate row from the queries above.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Candidate {
    pub submission_id: Uuid,
    pub tlsh: Option<String>,
    pub ssdeep: Option<String>,
    pub imphash: Option<String>,
    pub file_hash: Option<String>,
    pub original_filename: Option<String>,
    pub file_size: Option<i64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub verdict: Option<String>,
}

impl Candidate {
    pub fn hashes(&self) -> Hashes {
        Hashes {
            tlsh: self.tlsh.clone(),
            ssdeep: self.ssdeep.clone(),
            imphash: self.imphash.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pseudo-random but repeatable bytes, so TLSH has something to hash.
    fn sample(len: usize, seed: u32) -> Vec<u8> {
        let mut x = seed.wrapping_mul(2654435761).max(1);
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x % 64) as u8 + b' '
            })
            .collect()
    }

    #[test]
    fn small_files_get_no_hashes() {
        assert_eq!(compute(b"tiny"), Hashes::default());
    }

    #[test]
    fn hashes_round_trip_and_compare() {
        let a = sample(20_000, 1);
        let ha = compute(&a);
        let tlsh = ha.tlsh.clone().expect("tlsh");
        assert!(tlsh.starts_with("T1"), "{tlsh}");
        assert_eq!(tlsh_distance(&tlsh, &tlsh), Some(0));
        let ss = ha.ssdeep.clone().expect("ssdeep");
        assert_eq!(ssdeep_score(&ss, &ss), Some(100));
    }

    #[test]
    fn a_small_change_stays_close_and_other_data_does_not() {
        let a = sample(20_000, 1);
        let mut b = a.clone();
        b[5_000..5_200].copy_from_slice(&sample(200, 9));
        let c = sample(20_000, 2);
        let (ha, hb, hc) = (compute(&a), compute(&b), compute(&c));

        let m = compare(&ha, "aa", &hb, "bb").expect("variant is similar");
        assert!(m.tlsh_distance.unwrap() <= 30, "{m:?}");
        assert!(
            matches!(m.closeness, Closeness::VerySimilar | Closeness::Similar),
            "{m:?}"
        );

        assert_eq!(
            compare(&ha, "aa", &hc, "cc"),
            None,
            "unrelated data isn't reported"
        );
        assert_eq!(
            compare(&ha, "aa", &ha, "AA").unwrap().closeness,
            Closeness::Identical
        );
    }

    #[test]
    fn a_shared_imphash_alone_is_reported() {
        let a = Hashes {
            imphash: Some("ABC".into()),
            ..Default::default()
        };
        let b = Hashes {
            imphash: Some("abc".into()),
            ..Default::default()
        };
        let m = compare(&a, "1", &b, "2").unwrap();
        assert_eq!(m.closeness, Closeness::SameImports);
        assert!(m.same_imphash);
        assert_eq!(compare(&a, "1", &Hashes::default(), "2"), None);
    }

    #[test]
    fn ranking_puts_the_closest_first() {
        let m = |c, d| Match {
            closeness: c,
            tlsh_distance: d,
            ssdeep_score: None,
            same_imphash: false,
        };
        let mut v = [
            m(Closeness::Related, Some(90)),
            m(Closeness::VerySimilar, Some(20)),
            m(Closeness::VerySimilar, Some(5)),
        ];
        v.sort_by_key(Match::rank);
        assert_eq!(
            v.iter()
                .map(|x| x.tlsh_distance.unwrap())
                .collect::<Vec<_>>(),
            [5, 20, 90]
        );
    }

    #[test]
    fn unparseable_hashes_compare_as_nothing() {
        assert_eq!(tlsh_distance("nope", "T1AB"), None);
        assert_eq!(ssdeep_score("nope", "also nope"), None);
    }
}
