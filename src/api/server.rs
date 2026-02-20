use std::sync::Arc;

use axum::{
    middleware,
    routing::{delete, get, patch, post},
    Router,
};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tracing::info;

use crate::config::Config;
use crate::registry::storage::Database;

use super::auth::require_admin;
use super::handlers;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Config,
}

/// Start the HTTP API server
pub async fn run(bind_addr: String, db: Database, config: Config) -> anyhow::Result<()> {
    let state = Arc::new(AppState { db, config });

    // Public routes (no auth required)
    let public_routes = Router::new().route("/config", get(handlers::get_config));

    // Admin routes (require NIP-98 auth)
    let admin_routes = Router::new()
        .route("/forms", post(handlers::create_form))
        .route("/forms", get(handlers::list_forms))
        .route("/forms/:form_id", get(handlers::get_form))
        .route("/forms/:form_id", patch(handlers::update_form))
        .route("/forms/:form_id", delete(handlers::delete_form))
        .route("/forms/:form_id/embed", get(handlers::get_embed_code))
        .route(
            "/forms/:form_id/submissions",
            get(handlers::list_submissions),
        )
        .route("/submissions/:event_id", get(handlers::get_submission))
        .route(
            "/submissions/:event_id/retry",
            post(handlers::retry_submission),
        )
        .route("/admin/pubkeys", post(handlers::add_admin))
        .route("/admin/pubkeys", get(handlers::list_admins))
        .layer(middleware::from_fn_with_state(state.clone(), require_admin));

    let api_routes = Router::new().merge(public_routes).merge(admin_routes);

    let app = Router::new()
        .nest("/api", api_routes)
        // Serve static files for admin UI
        .nest_service("/admin", ServeDir::new("web/admin"))
        // Serve forms.js SDK
        .route_service(
            "/forms.js",
            tower_http::services::ServeFile::new("web/forms.js"),
        )
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("API server listening on {}", bind_addr);

    axum::serve(listener, app).await?;

    Ok(())
}
