use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::crypto::keys::generate_form_id;
use crate::registry::models::{CreateFormRequest, Form, FormStatus, Submission, UpdateFormRequest};

use super::server::AppState;

type AppResult<T> = Result<T, AppError>;

// Error handling

pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": self.0.to_string()
            })),
        )
            .into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(err: E) -> Self {
        AppError(err.into())
    }
}

// ==================== Config ====================

#[derive(Serialize)]
pub struct ConfigResponse {
    processor_pubkey: Option<String>,
    default_pow_difficulty: u8,
    relay_url: String,
}

pub async fn get_config(State(state): State<Arc<AppState>>) -> AppResult<Json<ConfigResponse>> {
    let processor_pubkey = state.db.get_config("processor_pubkey")?;

    Ok(Json(ConfigResponse {
        processor_pubkey,
        default_pow_difficulty: state.config.default_pow_difficulty,
        relay_url: state.config.relay_url.clone(),
    }))
}

// ==================== Admin Management ====================

#[derive(Deserialize)]
pub struct AddAdminRequest {
    pubkey: String,
}

#[derive(Serialize)]
pub struct AddAdminResponse {
    success: bool,
    pubkey: String,
}

pub async fn add_admin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddAdminRequest>,
) -> AppResult<Json<AddAdminResponse>> {
    // Validate pubkey format (64 hex chars)
    if req.pubkey.len() != 64 || !req.pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!("Invalid pubkey format").into());
    }

    state.db.add_admin(&req.pubkey)?;

    Ok(Json(AddAdminResponse {
        success: true,
        pubkey: req.pubkey,
    }))
}

pub async fn list_admins(State(state): State<Arc<AppState>>) -> AppResult<Json<Vec<String>>> {
    let admins = state.db.list_admins()?;
    Ok(Json(admins))
}

pub async fn remove_admin(
    State(state): State<Arc<AppState>>,
    Path(pubkey): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    if pubkey.len() != 64 || !pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!("Invalid pubkey format").into());
    }
    state.db.remove_admin(&pubkey)?;
    Ok(Json(serde_json::json!({ "success": true, "pubkey": pubkey })))
}

// ==================== Form Handlers ====================

#[derive(Serialize)]
pub struct CreateFormResponse {
    form_id: String,
    name: String,
    notify_pubkey: String,
}

pub async fn create_form(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateFormRequest>,
) -> AppResult<Json<CreateFormResponse>> {
    // Validate notify_pubkey format
    if req.notify_pubkey.len() != 64 || !req.notify_pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!("Invalid notify_pubkey format").into());
    }

    // Generate form ID
    let form_id = generate_form_id();

    let now = chrono::Utc::now().timestamp();

    let form = Form {
        form_id: form_id.clone(),
        name: req.name.clone(),
        notify_pubkey: req.notify_pubkey.clone(),
        pow_difficulty: req
            .pow_difficulty
            .unwrap_or(state.config.default_pow_difficulty),
        rate_limit_per_hour: req.rate_limit_per_hour.unwrap_or(100),
        status: FormStatus::Active,
        created_at: now,
        updated_at: now,
    };

    state.db.create_form(&form)?;

    Ok(Json(CreateFormResponse {
        form_id,
        name: req.name,
        notify_pubkey: req.notify_pubkey,
    }))
}

#[derive(Serialize)]
pub struct FormSummary {
    form_id: String,
    name: String,
    notify_pubkey: String,
    status: FormStatus,
    created_at: i64,
}

pub async fn list_forms(State(state): State<Arc<AppState>>) -> AppResult<Json<Vec<FormSummary>>> {
    let forms = state.db.list_forms()?;

    let summaries: Vec<FormSummary> = forms
        .into_iter()
        .map(|f| FormSummary {
            form_id: f.form_id,
            name: f.name,
            notify_pubkey: f.notify_pubkey,
            status: f.status,
            created_at: f.created_at,
        })
        .collect();

    Ok(Json(summaries))
}

#[derive(Serialize)]
pub struct FormDetail {
    form_id: String,
    name: String,
    notify_pubkey: String,
    pow_difficulty: u8,
    rate_limit_per_hour: u32,
    status: FormStatus,
    created_at: i64,
    updated_at: i64,
}

pub async fn get_form(
    State(state): State<Arc<AppState>>,
    Path(form_id): Path<String>,
) -> AppResult<Json<FormDetail>> {
    let form = state
        .db
        .get_form(&form_id)?
        .ok_or_else(|| anyhow::anyhow!("Form not found"))?;

    Ok(Json(FormDetail {
        form_id: form.form_id,
        name: form.name,
        notify_pubkey: form.notify_pubkey,
        pow_difficulty: form.pow_difficulty,
        rate_limit_per_hour: form.rate_limit_per_hour,
        status: form.status,
        created_at: form.created_at,
        updated_at: form.updated_at,
    }))
}

pub async fn update_form(
    State(state): State<Arc<AppState>>,
    Path(form_id): Path<String>,
    Json(req): Json<UpdateFormRequest>,
) -> AppResult<Json<FormDetail>> {
    let mut form = state
        .db
        .get_form(&form_id)?
        .ok_or_else(|| anyhow::anyhow!("Form not found"))?;

    // Apply updates
    if let Some(name) = req.name {
        form.name = name;
    }
    if let Some(notify_pubkey) = req.notify_pubkey {
        if notify_pubkey.len() != 64 || !notify_pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow::anyhow!("Invalid notify_pubkey format").into());
        }
        form.notify_pubkey = notify_pubkey;
    }
    if let Some(pow) = req.pow_difficulty {
        form.pow_difficulty = pow;
    }
    if let Some(rate) = req.rate_limit_per_hour {
        form.rate_limit_per_hour = rate;
    }
    if let Some(status) = req.status {
        form.status = status;
    }

    form.updated_at = chrono::Utc::now().timestamp();
    state.db.update_form(&form)?;

    Ok(Json(FormDetail {
        form_id: form.form_id,
        name: form.name,
        notify_pubkey: form.notify_pubkey,
        pow_difficulty: form.pow_difficulty,
        rate_limit_per_hour: form.rate_limit_per_hour,
        status: form.status,
        created_at: form.created_at,
        updated_at: form.updated_at,
    }))
}

#[derive(Serialize)]
pub struct DeleteResponse {
    success: bool,
}

pub async fn delete_form(
    State(state): State<Arc<AppState>>,
    Path(form_id): Path<String>,
) -> AppResult<Json<DeleteResponse>> {
    state.db.delete_form(&form_id)?;
    Ok(Json(DeleteResponse { success: true }))
}

#[derive(Serialize)]
pub struct EmbedCodeResponse {
    html: String,
    form_id: String,
    processor_pubkey: Option<String>,
    relay_url: String,
}

pub async fn get_embed_code(
    State(state): State<Arc<AppState>>,
    Path(form_id): Path<String>,
) -> AppResult<Json<EmbedCodeResponse>> {
    let form = state
        .db
        .get_form(&form_id)?
        .ok_or_else(|| anyhow::anyhow!("Form not found"))?;

    let processor_pubkey = state.db.get_config("processor_pubkey")?;
    let relay_url = &state.config.relay_url;

    let html = generate_embed_code(&form.form_id, processor_pubkey.as_deref(), relay_url);

    Ok(Json(EmbedCodeResponse {
        html,
        form_id: form.form_id,
        processor_pubkey,
        relay_url: relay_url.clone(),
    }))
}

// ==================== Submission Handlers ====================

#[derive(Deserialize)]
pub struct ListSubmissionsQuery {
    limit: Option<u32>,
}

pub async fn list_submissions(
    State(state): State<Arc<AppState>>,
    Path(form_id): Path<String>,
    Query(query): Query<ListSubmissionsQuery>,
) -> AppResult<Json<Vec<Submission>>> {
    let limit = query.limit.unwrap_or(50);
    let submissions = state.db.list_submissions(&form_id, limit)?;
    Ok(Json(submissions))
}

pub async fn get_submission(
    State(state): State<Arc<AppState>>,
    Path(event_id): Path<String>,
) -> AppResult<Json<Submission>> {
    let submission = state
        .db
        .get_submission(&event_id)?
        .ok_or_else(|| anyhow::anyhow!("Submission not found"))?;

    Ok(Json(submission))
}

#[derive(Serialize)]
pub struct RetryResponse {
    success: bool,
    message: String,
}

pub async fn retry_submission(
    State(state): State<Arc<AppState>>,
    Path(event_id): Path<String>,
) -> AppResult<Json<RetryResponse>> {
    let _submission = state
        .db
        .get_submission(&event_id)?
        .ok_or_else(|| anyhow::anyhow!("Submission not found"))?;

    // Reset to pending for retry
    state.db.update_submission_status(
        &event_id,
        crate::registry::models::DeliveryStatus::Pending,
        None,
    )?;

    Ok(Json(RetryResponse {
        success: true,
        message: format!("Submission {} queued for retry", event_id),
    }))
}

// ==================== Helpers ====================

fn generate_embed_code(form_id: &str, processor_pubkey: Option<&str>, relay_url: &str) -> String {
    let pubkey = processor_pubkey.unwrap_or("PROCESSOR_PUBKEY_NOT_SET");
    format!(
        r#"<form data-nostr-form="{form_id}">
  <input name="name" placeholder="Your name" required />
  <input name="email" type="email" placeholder="Email" required />
  <textarea name="message" placeholder="Message" required></textarea>
  <button type="submit">Send</button>
</form>
<script src="https://raw.githubusercontent.com/YOUR_USERNAME/nostr-form-rs/main/web/forms.js"></script>
<script>
NostrForms.init({{
  relayUrl: '{relay_url}',
  processorPubkey: '{pubkey}'
}});
</script>"#
    )
}


// ==================== Auth / Login ====================

#[derive(Deserialize)]
pub struct LoginRequest {
    pub pubkey: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_in: u64,
}

/// POST /api/auth/login
///
/// Accepts `{ pubkey }` (64-char hex). Checks the admin table and issues a
/// session token. No signature required — the endpoint is only reachable via
/// SSH tunnel on localhost.
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, &'static str)> {
    if req.pubkey.len() != 64 || !req.pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid pubkey format"));
    }

    let is_admin = state
        .db
        .is_admin(&req.pubkey)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    if !is_admin {
        return Err((StatusCode::FORBIDDEN, "Not an admin"));
    }

    let token = state.sessions.create(&req.pubkey);

    Ok(Json(LoginResponse {
        token,
        expires_in: 8 * 60 * 60,
    }))
}