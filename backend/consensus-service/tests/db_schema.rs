//! Schema/query integration test for consensus-service.
//!
//! Applies the embedded migrations to a real Postgres database and exercises
//! the tables the service reads/writes (consensus_submissions, consensus_results
//! including the finalization columns, consensus_disputes). Guards against the
//! "relation/column does not exist" class of runtime failures that migrations
//! applying successfully does not by itself rule out.
//!
//! Runs only when `CONSENSUS_SERVICE_DATABASE_URL` (or `DATABASE_URL`) is set —
//! CI provides it via scripts/ci/setup-test-databases.sh. Otherwise it is a
//! no-op so local `cargo test` stays green without a database. All writes run
//! inside a transaction that is rolled back.

use sqlx::postgres::PgPoolOptions;

fn test_database_url() -> Option<String> {
    std::env::var("CONSENSUS_SERVICE_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()
        .filter(|s| !s.is_empty())
}

#[tokio::test]
async fn schema_supports_service_queries() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping consensus-service schema test; CONSENSUS_SERVICE_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("connect to test database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations apply cleanly");

    let mut tx = pool.begin().await.expect("begin tx");

    // Mirrors ConsensusService submission insert.
    sqlx::query(
        r#"
        INSERT INTO consensus_submissions
            (bounty_id, engine_id, verdict, confidence, reputation_score)
        VALUES (gen_random_uuid(), 'engine-1', 'malicious', 0.95, 100)
        "#,
    )
    .execute(&mut *tx)
    .await
    .expect("insert into consensus_submissions");

    // Mirrors ConsensusService result insert; validates base columns.
    sqlx::query(
        r#"
        INSERT INTO consensus_results
            (bounty_id, final_verdict, confidence, total_submissions,
             malicious_count, benign_count, suspicious_count, unknown_count)
        VALUES (gen_random_uuid(), 'malicious', 0.9, 3, 2, 1, 0, 0)
        "#,
    )
    .execute(&mut *tx)
    .await
    .expect("insert into consensus_results");

    // Validates the finalization/agreement columns added in migration 2.
    sqlx::query(
        "SELECT agreement_score, is_disputed, is_finalized, finalized_at, \
         participating_engines, verdict_distribution FROM consensus_results LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await
    .expect("select finalization columns from consensus_results");

    // Mirrors dispute insert.
    sqlx::query(
        r#"
        INSERT INTO consensus_disputes
            (bounty_id, initiator_id, disputed_verdict, claimed_verdict, reason)
        VALUES (gen_random_uuid(), gen_random_uuid(), 'malicious', 'benign', 'test dispute')
        "#,
    )
    .execute(&mut *tx)
    .await
    .expect("insert into consensus_disputes");

    tx.rollback().await.expect("rollback tx");
    pool.close().await;
}

/// Exercises the delayed-grading table and the three queries the regrader
/// worker and its handlers depend on.
#[tokio::test]
async fn verdict_grades_supports_regrader_queries() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping verdict_grades test; CONSENSUS_SERVICE_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("connect to test database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations apply cleanly");

    let mut tx = pool.begin().await.expect("begin tx");

    // A finalized result, old enough to be due, with a sample to re-scan.
    let bounty_id: uuid::Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO consensus_results
            (bounty_id, final_verdict, confidence, total_submissions,
             is_finalized, finalized_at, sample_hash)
        VALUES (gen_random_uuid(), 'benign', 0.9100, 5,
                true, NOW() - INTERVAL '40 days', 'abc123')
        RETURNING bounty_id
        "#,
    )
    .fetch_one(&mut *tx)
    .await
    .expect("insert finalized consensus_result with sample_hash");

    // Mirrors ConsensusService::find_gradable_bounties.
    let due: Vec<uuid::Uuid> = sqlx::query_scalar(
        r#"
        SELECT r.bounty_id
        FROM consensus_results r
        LEFT JOIN verdict_grades g ON g.bounty_id = r.bounty_id
        WHERE r.is_finalized = true
          AND g.bounty_id IS NULL
          AND r.sample_hash IS NOT NULL
          AND r.finalized_at IS NOT NULL
          AND r.finalized_at <= NOW() - ($1 || ' hours')::interval
        ORDER BY r.finalized_at ASC
        LIMIT $2
        "#,
    )
    .bind("720")
    .bind(50i64)
    .fetch_all(&mut *tx)
    .await
    .expect("find_gradable_bounties query is valid");
    assert!(
        due.contains(&bounty_id),
        "a 40-day-old finalized result should be due at a 720h (30d) delay"
    );

    // Mirrors ConsensusService::record_grade -- the rescan disagrees.
    let changed: bool = sqlx::query_scalar(
        r#"
        INSERT INTO verdict_grades
            (bounty_id, original_verdict, graded_verdict, verdict_changed,
             grade_source, sample_hash, notes)
        VALUES ($1, 'benign', 'malicious', true, 'rescan', 'abc123', 'test regrade')
        ON CONFLICT (bounty_id) DO UPDATE SET
            graded_verdict  = EXCLUDED.graded_verdict,
            verdict_changed = EXCLUDED.verdict_changed,
            grade_source    = EXCLUDED.grade_source,
            sample_hash     = COALESCE(EXCLUDED.sample_hash, verdict_grades.sample_hash),
            notes           = EXCLUDED.notes,
            graded_at       = NOW()
        RETURNING verdict_changed
        "#,
    )
    .bind(bounty_id)
    .fetch_one(&mut *tx)
    .await
    .expect("insert into verdict_grades");
    assert!(changed, "benign -> malicious must record as overturned");

    // Once graded, the bounty must drop out of the due queue, or the worker
    // would re-scan the same sample forever.
    let due_again: Vec<uuid::Uuid> = sqlx::query_scalar(
        r#"
        SELECT r.bounty_id
        FROM consensus_results r
        LEFT JOIN verdict_grades g ON g.bounty_id = r.bounty_id
        WHERE r.is_finalized = true AND g.bounty_id IS NULL
          AND r.sample_hash IS NOT NULL AND r.finalized_at IS NOT NULL
          AND r.finalized_at <= NOW() - ($1 || ' hours')::interval
        "#,
    )
    .bind("720")
    .fetch_all(&mut *tx)
    .await
    .expect("re-run due query");
    assert!(
        !due_again.contains(&bounty_id),
        "a graded bounty must not be picked up again"
    );

    // The CHECK constraint must reject a row that lies about being changed.
    let bad = sqlx::query(
        r#"
        INSERT INTO verdict_grades
            (bounty_id, original_verdict, graded_verdict, verdict_changed, grade_source)
        VALUES (gen_random_uuid(), 'benign', 'malicious', false, 'admin')
        "#,
    )
    .execute(&mut *tx)
    .await;
    assert!(
        bad.is_err(),
        "verdict_changed=false with differing verdicts must violate the CHECK"
    );

    tx.rollback().await.expect("rollback tx");
    pool.close().await;
}

/// The sample hash must survive the whole path: cast on a vote, promoted onto
/// the finalized result, and then visible to the regrader's due-query. If any
/// link breaks the regrader silently grades nothing.
#[tokio::test]
async fn sample_hash_flows_from_vote_to_regrader_queue() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping sample_hash flow test; CONSENSUS_SERVICE_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("connect to test database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations apply cleanly");

    let mut tx = pool.begin().await.expect("begin tx");
    let bounty_id = uuid::Uuid::new_v4();

    // Mirrors ConsensusService::record_vote -- two engines, same artifact.
    for engine in ["engine-a", "engine-b"] {
        sqlx::query(
            r#"
            INSERT INTO consensus_submissions
                (bounty_id, engine_id, verdict, confidence, reputation_score, sample_hash)
            VALUES ($1, $2, 'benign', 0.8000, 5000, 'deadbeef')
            ON CONFLICT (bounty_id, engine_id)
            DO UPDATE SET sample_hash = COALESCE(EXCLUDED.sample_hash,
                                                 consensus_submissions.sample_hash)
            "#,
        )
        .bind(bounty_id)
        .bind(engine)
        .execute(&mut *tx)
        .await
        .expect("insert vote carrying a sample_hash");
    }

    // A re-vote without a hash must not erase the one already recorded.
    sqlx::query(
        r#"
        INSERT INTO consensus_submissions
            (bounty_id, engine_id, verdict, confidence, reputation_score, sample_hash)
        VALUES ($1, 'engine-a', 'malicious', 0.9000, 5000, NULL)
        ON CONFLICT (bounty_id, engine_id)
        DO UPDATE SET verdict = EXCLUDED.verdict,
                      sample_hash = COALESCE(EXCLUDED.sample_hash,
                                             consensus_submissions.sample_hash)
        "#,
    )
    .bind(bounty_id)
    .execute(&mut *tx)
    .await
    .expect("re-vote without hash");

    let kept: Option<String> = sqlx::query_scalar(
        "SELECT sample_hash FROM consensus_submissions WHERE bounty_id = $1 AND engine_id = 'engine-a'",
    )
    .bind(bounty_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read back sample_hash");
    assert_eq!(
        kept.as_deref(),
        Some("deadbeef"),
        "a hashless re-vote must not clear an existing sample_hash"
    );

    // Mirrors calculate_and_store promoting the hash onto the result.
    sqlx::query(
        r#"
        INSERT INTO consensus_results
            (bounty_id, final_verdict, confidence, total_submissions,
             is_finalized, finalized_at, sample_hash)
        VALUES ($1, 'benign', 0.8500, 2, true, NOW() - INTERVAL '40 days', 'deadbeef')
        ON CONFLICT (bounty_id) DO UPDATE SET
            sample_hash = COALESCE(EXCLUDED.sample_hash, consensus_results.sample_hash)
        "#,
    )
    .bind(bounty_id)
    .execute(&mut *tx)
    .await
    .expect("insert result with promoted sample_hash");

    // The regrader must now see it as due.
    let due: Vec<uuid::Uuid> = sqlx::query_scalar(
        r#"
        SELECT r.bounty_id
        FROM consensus_results r
        LEFT JOIN verdict_grades g ON g.bounty_id = r.bounty_id
        WHERE r.is_finalized = true AND g.bounty_id IS NULL
          AND r.sample_hash IS NOT NULL AND r.finalized_at IS NOT NULL
          AND r.finalized_at <= NOW() - ($1 || ' hours')::interval
        "#,
    )
    .bind("720")
    .fetch_all(&mut *tx)
    .await
    .expect("regrader due query");
    assert!(
        due.contains(&bounty_id),
        "a finalized bounty with a promoted sample_hash must be gradable"
    );

    tx.rollback().await.expect("rollback tx");
    pool.close().await;
}

/// Commit-reveal storage and the phase clock.
///
/// The clock is anchored on a bounty's first commit, so these tests backdate
/// `committed_at` to move a bounty between phases rather than sleeping.
#[tokio::test]
async fn commit_reveal_storage_and_phase_clock() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping commit-reveal test; CONSENSUS_SERVICE_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("connect to test database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations apply cleanly");

    let mut tx = pool.begin().await.expect("begin tx");
    let bounty_id = uuid::Uuid::new_v4();
    let good = "a".repeat(64);

    // Mirrors ConsensusService::commit_vote.
    sqlx::query(
        r#"
        INSERT INTO consensus_vote_commits (bounty_id, engine_id, commitment)
        VALUES ($1, 'alice', $2)
        ON CONFLICT (bounty_id, engine_id) DO UPDATE
            SET commitment = EXCLUDED.commitment, committed_at = NOW()
            WHERE consensus_vote_commits.revealed_at IS NULL
        "#,
    )
    .bind(bounty_id)
    .bind(&good)
    .execute(&mut *tx)
    .await
    .expect("insert commitment");

    // The CHECK must reject anything that is not a hex sha256, at write time.
    for bad in ["not-a-hash", "abc", &"z".repeat(64), &"a".repeat(63)] {
        let res = sqlx::query(
            "INSERT INTO consensus_vote_commits (bounty_id, engine_id, commitment) \
             VALUES ($1, 'mallory', $2)",
        )
        .bind(bounty_id)
        .bind(bad)
        .execute(&mut *tx)
        .await;
        assert!(res.is_err(), "malformed commitment {bad:?} must be rejected");
        // A failed statement poisons the transaction; restart it.
        tx.rollback().await.ok();
        tx = pool.begin().await.expect("re-begin tx");
        sqlx::query(
            "INSERT INTO consensus_vote_commits (bounty_id, engine_id, commitment) \
             VALUES ($1, 'alice', $2) ON CONFLICT DO NOTHING",
        )
        .bind(bounty_id)
        .bind(&good)
        .execute(&mut *tx)
        .await
        .expect("restore commitment");
    }

    // Mirrors ConsensusService::voting_phase.
    let (first, total, revealed): (Option<chrono::DateTime<chrono::Utc>>, i64, i64) =
        sqlx::query_as(
            r#"
            SELECT MIN(committed_at), COUNT(*)::bigint,
                   COUNT(*) FILTER (WHERE revealed_at IS NOT NULL)::bigint
            FROM consensus_vote_commits WHERE bounty_id = $1
            "#,
        )
        .bind(bounty_id)
        .fetch_one(&mut *tx)
        .await
        .expect("phase query is valid");
    assert!(first.is_some(), "a committed bounty must have a phase anchor");
    assert_eq!(total, 1);
    assert_eq!(revealed, 0);

    // Once revealed, the commitment must freeze: the guarded upsert must not
    // overwrite it, or a voter could reveal, watch the tally, and swap in a
    // different commitment.
    sqlx::query("UPDATE consensus_vote_commits SET revealed_at = NOW() WHERE bounty_id = $1")
        .bind(bounty_id)
        .execute(&mut *tx)
        .await
        .expect("mark revealed");

    let other = "b".repeat(64);
    sqlx::query(
        r#"
        INSERT INTO consensus_vote_commits (bounty_id, engine_id, commitment)
        VALUES ($1, 'alice', $2)
        ON CONFLICT (bounty_id, engine_id) DO UPDATE
            SET commitment = EXCLUDED.commitment, committed_at = NOW()
            WHERE consensus_vote_commits.revealed_at IS NULL
        "#,
    )
    .bind(bounty_id)
    .bind(&other)
    .execute(&mut *tx)
    .await
    .expect("guarded upsert runs");

    let stored: String =
        sqlx::query_scalar("SELECT commitment FROM consensus_vote_commits WHERE bounty_id = $1")
            .bind(bounty_id)
            .fetch_one(&mut *tx)
            .await
            .expect("read back commitment");
    assert_eq!(
        stored, good,
        "a revealed commitment must not be rewritable"
    );

    tx.rollback().await.expect("rollback tx");
    pool.close().await;
}
