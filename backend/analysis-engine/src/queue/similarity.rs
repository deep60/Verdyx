//! Fuzzy hashes for similarity search (see `shared::similarity`).
//!
//! Each uploaded file gets TLSH, ssdeep and, for Windows programs, an
//! imphash, stored in `file_similarity`. The gateway compares them when
//! someone asks for files similar to a scan.

use md5::{Digest, Md5};
use shared::similarity::{self, Hashes};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

/// Files above this size are hashed only up to it. TLSH and ssdeep are
/// linear and fast, but there's no reason to hold a worker on a huge file.
const MAX_HASH_BYTES: usize = 64 * 1024 * 1024;
/// Earlier uploads hashed per engine start, newest first.
const BACKFILL_LIMIT: i64 = 2000;

/// The imphash of a Windows program, `None` for anything else or a program
/// with no imports.
///
/// Follows pefile's `get_imphash`: each import as `library.function`, both
/// lowercased, the library without a `.dll`, `.ocx` or `.sys` extension,
/// joined with commas, then MD5. Imports by ordinal are `ordN`; pefile names
/// a few well-known ordinals from ws2_32, wsock32 and oleaut32, so programs
/// importing those by number get a different imphash here.
pub fn imphash(data: &[u8]) -> Option<String> {
    let pe = goblin::pe::PE::parse(data).ok()?;
    if pe.imports.is_empty() {
        return None;
    }
    let parts: Vec<String> = pe
        .imports
        .iter()
        .map(|i| {
            let dll = i.dll.to_ascii_lowercase();
            let lib = match dll.rsplit_once('.') {
                Some((stem, "dll" | "ocx" | "sys")) => stem.to_string(),
                _ => dll,
            };
            let func = if i.name.starts_with("ORDINAL ") {
                format!("ord{}", i.ordinal)
            } else {
                i.name.to_ascii_lowercase()
            };
            format!("{lib}.{func}")
        })
        .collect();
    Some(hex(&Md5::digest(parts.join(",").as_bytes())))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// All of a file's fuzzy hashes.
pub fn hashes(data: &[u8]) -> Hashes {
    let data = &data[..data.len().min(MAX_HASH_BYTES)];
    Hashes {
        imphash: imphash(data),
        ..similarity::compute(data)
    }
}

/// Hash an upload and store the result. Failures are logged, never fatal:
/// similarity search is extra, the scan goes on without it.
pub async fn record(db: &PgPool, submission_id: Uuid, data: &[u8]) {
    let h = tokio::task::block_in_place(|| hashes(data));
    if h == Hashes::default() {
        return;
    }
    if let Err(e) = store(db, submission_id, &h).await {
        warn!("Could not store similarity hashes for {submission_id}: {e}");
    }
}

async fn store(db: &PgPool, submission_id: Uuid, h: &Hashes) -> sqlx::Result<()> {
    sqlx::query(similarity::UPSERT_SQL)
        .bind(submission_id)
        .bind(&h.tlsh)
        .bind(&h.ssdeep)
        .bind(&h.imphash)
        .execute(db)
        .await
        .map(|_| ())
}

/// Hash earlier uploads that have none yet and whose file is still stored,
/// newest first. Runs once in the background when the engine starts.
pub async fn backfill(db: PgPool, s3: std::sync::Arc<crate::storage::S3Client>) {
    let rows: Vec<(Uuid, String)> = match sqlx::query_as(
        r#"SELECT s.id, s.file_path FROM submissions s
           WHERE s.submission_type <> 'url' AND s.file_path IS NOT NULL AND s.file_path <> ''
             AND s.file_purged_at IS NULL
             AND NOT EXISTS (SELECT 1 FROM file_similarity f WHERE f.submission_id = s.id)
           ORDER BY s.created_at DESC LIMIT $1"#,
    )
    .bind(BACKFILL_LIMIT)
    .fetch_all(&db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!("Similarity backfill skipped: {e}");
            return;
        }
    };
    if rows.is_empty() {
        return;
    }
    let mut done = 0usize;
    for (id, path) in &rows {
        let Ok(data) = super::consumer::load_artifact(&s3, path).await else {
            continue;
        };
        let h = tokio::task::spawn_blocking(move || hashes(&data))
            .await
            .unwrap_or_default();
        // Mark files with nothing to hash too, so they aren't loaded again.
        if store(&db, *id, &h).await.is_ok() {
            done += 1;
        }
    }
    info!(
        "Similarity backfill: hashed {done} of {} earlier uploads",
        rows.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_programs_have_no_imphash() {
        assert_eq!(imphash(b"just text, not a program"), None);
        assert_eq!(imphash(&[0u8; 4096]), None);
    }

    #[test]
    fn small_files_have_no_hashes() {
        assert_eq!(hashes(b"hello"), Hashes::default());
    }

    #[test]
    fn text_files_get_tlsh_and_ssdeep() {
        let text: String = (0..2000)
            .map(|i| format!("line {i} of a sample log, value {}\n", i * 7 % 13))
            .collect();
        let h = hashes(text.as_bytes());
        assert!(h.tlsh.is_some());
        assert!(h.ssdeep.is_some());
        assert_eq!(h.imphash, None);
    }
}
