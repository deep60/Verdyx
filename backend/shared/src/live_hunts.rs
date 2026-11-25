//! Live hunts: which saved YARA rules run on a new upload.
//!
//! Shared so the analysis engine (which runs them) and the gateway's database
//! tests use the same query.

/// Most enabled hunts one person may have.
pub const MAX_ENABLED_PER_USER: i64 = 10;
/// Most hunts, enabled or not, one person may keep.
pub const MAX_PER_USER: i64 = 25;
/// Most hunts run on one upload. A team upload can be in scope of many
/// people's hunts; past this, the newest hunts are skipped for that upload.
pub const MAX_PER_UPLOAD: i64 = 50;

/// The enabled hunts whose scope covers an upload.
///
/// `$1` is the uploader (NULL for an anonymous upload) and `$2` the team the
/// upload was saved to (NULL for none). A hunt covers:
/// - its owner's own uploads, when it has no team;
/// - its team's uploads, while its owner is still a member.
///
/// So a hunt never sees anyone else's private uploads, and an anonymous
/// upload is in nobody's scope.
pub const IN_SCOPE_SQL: &str = r#"
SELECT h.id, h.rule_text
FROM live_hunts h
WHERE h.enabled
  AND (
        (h.organization_id IS NULL AND $1::uuid IS NOT NULL AND h.user_id = $1)
     OR (h.organization_id IS NOT NULL AND h.organization_id = $2
         AND EXISTS (SELECT 1 FROM organization_members m
                     WHERE m.organization_id = h.organization_id AND m.user_id = h.user_id))
  )
ORDER BY h.created_at
LIMIT 50
"#;

/// Record a match once per hunt and upload, counting it only the first time.
/// `$1` hunt id, `$2` submission id, `$3` the matching rule names.
pub const RECORD_MATCH_SQL: &str = r#"
WITH ins AS (
  INSERT INTO live_hunt_matches (hunt_id, submission_id, rules) VALUES ($1, $2, $3)
  ON CONFLICT DO NOTHING RETURNING 1)
UPDATE live_hunts SET matches = matches + 1, last_match_at = NOW()
WHERE id = $1 AND EXISTS (SELECT 1 FROM ins)
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_query_limit_matches_the_constant() {
        assert!(IN_SCOPE_SQL.contains(&format!("LIMIT {MAX_PER_UPLOAD}")));
    }
}
