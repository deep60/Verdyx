//! Schema/query integration test for api-gateway.
//!
//! Applies the embedded migrations to a real Postgres database and exercises the
//! submissions insert used by `create_file_submission`. Runs only when
//! `API_GATEWAY_DATABASE_URL` (or `DATABASE_URL`) is set; otherwise it is a no-op.
//! All writes run inside a rolled-back transaction.

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

fn test_database_url() -> Option<String> {
    std::env::var("API_GATEWAY_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()
        .filter(|s| !s.is_empty())
}

#[tokio::test]
async fn same_file_from_two_users_keeps_both_submissions() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping api-gateway schema test; API_GATEWAY_DATABASE_URL not set");
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
    let file_hash = format!("{:064x}", Uuid::new_v4().as_u128());
    let alice = Uuid::new_v4();
    let bob = Uuid::new_v4();

    // Mirrors the insert in create_file_submission.
    for submitter in [alice, bob] {
        sqlx::query(
            r#"
            INSERT INTO submissions (
                id, submitter_id, original_filename, file_hash, url, file_size,
                mime_type, file_path, submission_type, analysis_status,
                metadata, created_at, updated_at
            )
            VALUES ($1, $2, 'sample.exe', $3, NULL, 4, 'executable', NULL, 'file',
                    'pending', '{}'::jsonb, NOW(), NOW())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(submitter)
        .bind(&file_hash)
        .execute(&mut *tx)
        .await
        .expect("insert submission");
    }

    let owners: Vec<Uuid> = sqlx::query_scalar(
        "SELECT submitter_id FROM submissions WHERE file_hash = $1 ORDER BY submitter_id",
    )
    .bind(&file_hash)
    .fetch_all(&mut *tx)
    .await
    .expect("read submissions");

    let mut expected = vec![alice, bob];
    expected.sort();
    assert_eq!(owners, expected, "each uploader keeps their own submission");

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn seeded_engines_carry_no_invented_stats() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping api-gateway schema test; API_GATEWAY_DATABASE_URL not set");
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

    let rows: Vec<(bool, Option<f64>, Option<i32>)> = sqlx::query_as(
        "SELECT COALESCE(is_active, true), accuracy_rate::FLOAT8, total_analyses
         FROM engines WHERE id::text LIKE '11111111-1111-4111-8111-11111111110_'",
    )
    .fetch_all(&pool)
    .await
    .expect("read seeded engines");

    assert_eq!(rows.len(), 4);
    for (active, accuracy, total) in rows {
        assert!(!active, "seeded engine still listed");
        assert!(
            accuracy.is_none() && total.is_none(),
            "seeded engine keeps made-up stats"
        );
    }
}

/// Which live hunts cover an upload (the analysis engine runs this query).
#[tokio::test]
async fn live_hunts_only_see_their_owners_or_teams_uploads() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping api-gateway schema test; API_GATEWAY_DATABASE_URL not set");
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
    let (alice, bob, carol) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let team = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, name, created_by) VALUES ($1, 'SOC', $2)")
        .bind(team)
        .bind(alice)
        .execute(&mut *tx)
        .await
        .unwrap();
    for (user, role) in [(alice, "owner"), (bob, "member")] {
        sqlx::query(
            "INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, $3)",
        )
        .bind(team)
        .bind(user)
        .bind(role)
        .execute(&mut *tx)
        .await
        .unwrap();
    }

    let hunt = |owner: Uuid, team: Option<Uuid>, enabled: bool| {
        let id = Uuid::new_v4();
        (id, owner, team, enabled)
    };
    let alice_own = hunt(alice, None, true);
    let alice_off = hunt(alice, None, false);
    let bob_team = hunt(bob, Some(team), true);
    let carol_team = hunt(carol, Some(team), true); // carol isn't in the team
    for (id, owner, t, enabled) in [alice_own, alice_off, bob_team, carol_team] {
        sqlx::query(
            "INSERT INTO live_hunts (id, user_id, organization_id, name, rule_text, enabled) \
             VALUES ($1, $2, $3, 'h', 'rule a { condition: true }', $4)",
        )
        .bind(id)
        .bind(owner)
        .bind(t)
        .bind(enabled)
        .execute(&mut *tx)
        .await
        .unwrap();
    }

    let scope_sql = format!(
        "SELECT id FROM ({}) s",
        shared::live_hunts::IN_SCOPE_SQL.replace("SELECT h.id, h.rule_text", "SELECT h.id")
    );
    let in_scope = |submitter: Option<Uuid>, upload_team: Option<Uuid>| {
        sqlx::query_scalar::<_, Uuid>(&scope_sql)
            .bind(submitter)
            .bind(upload_team)
    };

    // Alice's own upload: her enabled personal hunt only.
    let mut ids = in_scope(Some(alice), None)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert_eq!(ids, vec![alice_own.0]);

    // Bob's own upload: nobody's (Bob has no personal hunt; team hunts need a team upload).
    ids = in_scope(Some(bob), None).fetch_all(&mut *tx).await.unwrap();
    assert!(ids.is_empty());

    // An upload saved to the team, by Alice: her personal hunt and Bob's team
    // hunt; never Carol's, who isn't a member.
    ids = in_scope(Some(alice), Some(team))
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    ids.sort();
    let mut want = vec![alice_own.0, bob_team.0];
    want.sort();
    assert_eq!(ids, want);

    // Anonymous upload: nobody's.
    ids = in_scope(None, None).fetch_all(&mut *tx).await.unwrap();
    assert!(ids.is_empty());

    // Bob leaves the team: his team hunt stops matching.
    sqlx::query("DELETE FROM organization_members WHERE user_id = $1")
        .bind(bob)
        .execute(&mut *tx)
        .await
        .unwrap();
    ids = in_scope(Some(alice), Some(team))
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert_eq!(ids, vec![alice_own.0]);

    // A match is recorded once per hunt and upload.
    let sub = Uuid::new_v4();
    for _ in 0..2 {
        sqlx::query(shared::live_hunts::RECORD_MATCH_SQL)
            .bind(alice_own.0)
            .bind(sub)
            .bind(vec!["a".to_string()])
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    let n: i32 = sqlx::query_scalar("SELECT matches FROM live_hunts WHERE id = $1")
        .bind(alice_own.0)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(n, 1);

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn similar_files_only_come_from_uploads_the_caller_may_read() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping api-gateway schema test; API_GATEWAY_DATABASE_URL not set");
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
    let (alice, bob, mallory) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let team = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, name, created_by) VALUES ($1, 'SOC', $2)")
        .bind(team)
        .bind(alice)
        .execute(&mut *tx)
        .await
        .unwrap();
    for user in [alice, bob] {
        sqlx::query(
            "INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, 'member')",
        )
        .bind(team)
        .bind(user)
        .execute(&mut *tx)
        .await
        .unwrap();
    }

    // (submitter, team) for each upload; every one gets the same imphash.
    let anonymous = Uuid::nil();
    let uploads = [
        ("target", alice, None),
        ("alice_own", alice, None),
        ("bob_private", bob, None),
        ("bob_team", bob, Some(team)),
        ("mallory_private", mallory, None),
        ("mallory_bounty", mallory, None),
        ("anonymous", anonymous, None),
    ];
    let mut ids = std::collections::HashMap::new();
    for (name, submitter, org) in uploads {
        let id = Uuid::new_v4();
        ids.insert(name, id);
        sqlx::query(
            "INSERT INTO submissions (id, submitter_id, original_filename, file_hash, file_size, \
             submission_type, analysis_status, organization_id, metadata, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 4, 'file', 'completed', $5, '{}'::jsonb, NOW(), NOW())",
        )
        .bind(id)
        .bind(submitter)
        .bind(name)
        .bind(format!("{:064x}", id.as_u128()))
        .bind(org)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(shared::similarity::UPSERT_SQL)
            .bind(id)
            .bind("T1AAAA")
            .bind(None::<String>)
            .bind("0123456789abcdef0123456789abcdef")
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    sqlx::query(
        "INSERT INTO bounties (creator_id, submission_id, title, reward_amount) VALUES ($1, $2, 'b', 1)",
    )
    .bind(mallory)
    .bind(ids["mallory_bounty"])
    .execute(&mut *tx)
    .await
    .unwrap();

    let names = |rows: Vec<shared::similarity::Candidate>| {
        let mut v: Vec<String> = rows
            .into_iter()
            .map(|c| c.original_filename.unwrap())
            .collect();
        v.sort();
        v
    };
    let target = ids["target"];
    let imphash = "0123456789abcdef0123456789abcdef";

    // alice: her own, her team's and the bounty, never the target itself.
    let recent = shared::similarity::recent_candidates_sql();
    let by_imphash = shared::similarity::imphash_candidates_sql();
    for sql in [&recent, &by_imphash] {
        let mut q = sqlx::query_as(sql)
            .bind(alice)
            .bind(None::<Uuid>)
            .bind(false)
            .bind(target);
        if sql == &by_imphash {
            q = q.bind(imphash);
        }
        let rows = q.fetch_all(&mut *tx).await.unwrap();
        assert_eq!(
            names(rows),
            ["alice_own", "bob_team", "mallory_bounty"],
            "{sql}"
        );
    }

    // A team key sees only the team's uploads.
    let rows = sqlx::query_as(&recent)
        .bind(alice)
        .bind(Some(team))
        .bind(false)
        .bind(target)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert_eq!(names(rows), ["bob_team"]);

    // An admin sees everything but signed-out uploads.
    let rows = sqlx::query_as(&recent)
        .bind(mallory)
        .bind(None::<Uuid>)
        .bind(true)
        .bind(target)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        names(rows),
        [
            "alice_own",
            "bob_private",
            "bob_team",
            "mallory_bounty",
            "mallory_private"
        ]
    );

    // Deleting a scan deletes its hashes.
    sqlx::query("DELETE FROM submissions WHERE id = $1")
        .bind(ids["alice_own"])
        .execute(&mut *tx)
        .await
        .unwrap();
    let left: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM file_similarity WHERE submission_id = $1")
            .bind(ids["alice_own"])
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(left, 0);

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn siem_destinations_keep_their_kind_and_hide_their_credential() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping api-gateway schema test; API_GATEWAY_DATABASE_URL not set");
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
    let user = Uuid::new_v4();

    // Existing webhooks become kind 'webhook' with no settings.
    let plain: (String, serde_json::Value, bool) = sqlx::query_as(
        "INSERT INTO webhooks (user_id, url, events) VALUES ($1, 'https://hooks.example.com/x', '{*}') \
         RETURNING kind, config, has_credential",
    )
    .bind(user)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(plain, ("webhook".into(), serde_json::json!({}), false));

    let splunk: (String, bool) = sqlx::query_as(
        "INSERT INTO webhooks (user_id, url, events, kind, config, credential) \
         VALUES ($1, 'https://splunk.example.com:8088', '{*}', 'splunk', '{\"index\":\"sec\"}', 'v1:sealed') \
         RETURNING kind, has_credential",
    )
    .bind(user)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(splunk, ("splunk".into(), true));

    // has_credential follows the column; it can't be written directly.
    let cleared: bool = sqlx::query_scalar(
        "UPDATE webhooks SET credential = NULL WHERE user_id = $1 AND kind = 'splunk' RETURNING has_credential",
    )
    .bind(user)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(!cleared);

    sqlx::query("SAVEPOINT bad_kind")
        .execute(&mut *tx)
        .await
        .unwrap();
    let refused = sqlx::query(
        "INSERT INTO webhooks (user_id, url, events, kind) VALUES ($1, 'https://x.example.com', '{*}', 'syslog')",
    )
    .bind(user)
    .execute(&mut *tx)
    .await;
    assert!(refused.is_err(), "unknown kinds are refused");
    sqlx::query("ROLLBACK TO SAVEPOINT bad_kind")
        .execute(&mut *tx)
        .await
        .unwrap();

    tx.rollback().await.unwrap();
}
