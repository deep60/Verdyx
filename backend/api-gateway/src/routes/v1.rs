use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};

use crate::{
    handlers::{
        analysis, auth, bounty, consensus_proxy, engines, health, reputation, submission, user,
        wallet, web_intel, webhook,
    },
    middleware::auth as auth_mw,
    AppState,
};

/// Create all routes for API v1
pub fn create_routes(state: AppState) -> Router {
    // ── Public routes (no auth) ──────────────────────────
    let public_routes = Router::new()
        .nest("/health", health_routes())
        .nest("/auth", auth_routes());

    // ── Mixed routes (optional auth) ─────────────────────
    let mixed_routes = Router::new()
        .nest("/bounties", bounty_routes())
        .nest("/analysis", analysis_routes())
        .nest("/engines", engine_routes())
        .nest("/reputation", reputation_routes())
        .nest("/submissions", submission_routes())
        .route(
            "/voting/bounty/{bounty_id}/phase",
            get(consensus_proxy::get_phase),
        )
        .route(
            "/voting/bounty/{bounty_id}/commit",
            post(consensus_proxy::commit_vote),
        )
        .route(
            "/voting/bounty/{bounty_id}/reveal",
            post(consensus_proxy::reveal_vote),
        )
        .route("/disputes/create", post(consensus_proxy::create_dispute))
        .route(
            "/disputes/bounty/{bounty_id}",
            get(consensus_proxy::get_bounty_disputes),
        )
        .route("/grades/{bounty_id}", get(consensus_proxy::get_grade))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_mw::optional_auth_middleware,
        ));

    // ── Protected routes (strict auth) ───────────────────
    let protected_routes = Router::new()
        .nest("/users", user_routes())
        .nest("/wallet", wallet_routes())
        .nest("/webhooks", webhook_routes())
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_mw::auth_middleware,
        ));

    // Merge all route groups and attach state
    Router::new()
        .merge(public_routes)
        .merge(mixed_routes)
        .merge(protected_routes)
        .with_state(state)
}

// ─── Public route groups ────────────────────────────────────────

fn health_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(health::health_check))
        .route("/ready", get(health::readiness_check))
        .route("/live", get(health::liveness_check))
        .route("/metrics", get(health::metrics))
}

fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route("/logout", post(auth::logout))
        .route("/refresh", post(auth::refresh_token))
        .route("/verify", get(auth::verify_token))
        .route("/profile", get(auth::get_profile))
        .route("/verify-email", post(auth::verify_email))
        .route("/forgot-password", post(auth::forgot_password))
        .route("/reset-password", post(auth::reset_password))
        .route("/api-key", post(auth::generate_api_key))
        .route("/wallet/connect", post(auth::collect_wallet))
        .route("/wallet/disconnect", post(auth::disconnect_wallet))
}

// ─── Mixed route groups (optional auth) ─────────────────────────

fn bounty_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(bounty::list_bounties))
        .route("/{bounty_id}", get(bounty::get_bounty))
        .route("/{bounty_id}/stats", get(bounty::get_bounty_stats))
        .route("/active", get(bounty::list_active_bounties))
        .route("/completed", get(bounty::list_completed_bounties))
        .route("/", post(bounty::create_bounty))
        .route("/{bounty_id}", put(bounty::update_bounty))
        .route("/{bounty_id}/cancel", post(bounty::cancel_bounty))
        .route("/{bounty_id}/extend", post(bounty::extend_bounty))
        .route("/{bounty_id}/claim", post(bounty::claim_reward))
        .route("/{bounty_id}/submit", post(bounty::submit_analysis))
        .route("/{bounty_id}/finalize", put(bounty::finalize_bounty))
}

fn analysis_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(analysis::list_analyses))
        .route("/stats", get(analysis::get_analysis_stats))
        .route("/web-intel", get(web_intel::inspect_url_web_intel))
        .route("/{analysis_id}", get(analysis::get_analysis))
        .route("/{analysis_id}/details", get(analysis::get_analysis_details))
        .route(
            "/by-bounty/{bounty_id}",
            get(analysis::get_analyses_by_bounty),
        )
        .route("/by-hash/{file_hash}", get(analysis::get_analyses_by_hash))
        .route("/submit", post(analysis::submit_analysis))
        .route("/{analysis_id}/dispute", post(analysis::dispute_analysis))
}

fn reputation_routes() -> Router<AppState> {
    Router::new()
        .route("/leaderboard", get(reputation::get_leaderboard))
        .route("/leaderboard/top", get(reputation::get_top_analysts))
        .route("/standings", get(reputation::get_standings))
        .route("/user/{user_id}", get(reputation::get_user_reputation))
        .route("/badges", get(reputation::list_available_badges))
        .route("/history/{user_id}", get(reputation::get_reputation_history))
        .route("/claim-badge", post(reputation::claim_badge))
}

// ─── Protected route groups (strict auth) ───────────────────────

fn user_routes() -> Router<AppState> {
    Router::new()
        .route("/me", get(user::get_current_user))
        .route("/me", put(user::update_profile))
        .route("/me", delete(user::delete_account))
        .route("/me/stats", get(user::get_user_stats))
        .route("/{user_id}", get(user::get_user_by_id))
        .route("/{user_id}/stats", get(user::get_user_stats_by_id))
        .route("/me/api-keys", get(user::list_api_keys))
        .route("/me/api-keys/{key_id}", delete(user::revoke_api_key))
}

fn wallet_routes() -> Router<AppState> {
    Router::new()
        .route("/connect", post(wallet::connect_wallet))
        .route("/disconnect", post(wallet::disconnect_wallet))
        .route("/balance", get(wallet::get_balance))
        .route("/balance/{address}", get(wallet::get_balance_by_address))
        .route("/withdraw", post(wallet::withdraw))
        .route("/stake", post(wallet::stake_tokens))
        .route("/unstake/{bounty_id}", post(wallet::unstake_tokens))
        .route("/transactions", get(wallet::get_transactions))
        .route("/claim-rewards", post(wallet::claim_rewards))
}

fn submission_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(submission::list_submissions))
        .route("/{submission_id}", get(submission::get_submission))
        .route("/", post(submission::create_submission))
        .route("/file", post(submission::create_file_submission))
        .route("/{submission_id}/vote", post(submission::vote_on_submission))
        .route(
            "/{submission_id}/verify",
            post(submission::verify_submission),
        )
        .route(
            "/{submission_id}/start-analysis",
            post(submission::start_analysis),
        )
        .route(
            "/{submission_id}/analyses",
            get(submission::get_submission_analyses),
        )
        .route(
            "/{submission_id}/consensus",
            get(submission::get_submission_consensus),
        )
        .route(
            "/{submission_id}/web-intel",
            get(web_intel::get_submission_web_intel),
        )
        .route("/my-submissions", get(submission::get_my_submissions))
}

fn engine_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(engines::list_engines))
        .route("/", post(engines::register_engine))
        .route("/{engine_id}", get(engines::get_engine))
}

fn webhook_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(webhook::list_webhooks))
        .route("/", post(webhook::create_webhook))
        .route("/{webhook_id}", get(webhook::get_webhook))
        .route("/{webhook_id}", put(webhook::update_webhook))
        .route("/{webhook_id}", delete(webhook::delete_webhook))
        .route("/{webhook_id}/test", post(webhook::test_webhook))
        .route(
            "/{webhook_id}/deliveries",
            get(webhook::get_webhook_deliveries),
        )
        .route("/events", get(webhook::list_available_events))
}
