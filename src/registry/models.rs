use serde::{Deserialize, Serialize};

/// A form definition in the registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Form {
    pub form_id: String,
    pub name: String,
    /// Pubkey that receives decrypted submissions as DM
    pub notify_pubkey: String,
    pub pow_difficulty: u8,
    pub rate_limit_per_hour: u32,
    pub status: FormStatus,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FormStatus {
    Active,
    Paused,
    Deleted,
}

impl Default for FormStatus {
    fn default() -> Self {
        FormStatus::Active
    }
}

/// A form submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Submission {
    pub event_id: String,
    pub form_id: String,
    pub sender_pubkey: String,
    pub submission_type: SubmissionType,
    pub encrypted_content: String,
    pub decrypted_content: Option<String>,
    pub received_at: i64,
    pub processed_at: Option<i64>,
    pub delivery_status: DeliveryStatus,
    pub delivery_attempts: u32,
    pub last_delivery_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubmissionType {
    /// Anonymous submission with ephemeral key
    Anon,
    /// Authenticated submission with real Nostr identity
    Authenticated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Exhausted,
}

impl Default for DeliveryStatus {
    fn default() -> Self {
        DeliveryStatus::Pending
    }
}

/// Decrypted submission payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionPayload {
    /// Schema version
    pub v: u8,
    /// Form ID (also in cleartext tag, but verified here)
    #[serde(default)]
    pub form_id: Option<String>,
    /// Form field values
    pub fields: serde_json::Map<String, serde_json::Value>,
    /// Metadata
    #[serde(default)]
    pub meta: SubmissionMeta,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubmissionMeta {
    pub submitted_at: Option<String>,
    pub user_agent: Option<String>,
    pub referrer: Option<String>,
}

/// Request to create a new form
#[derive(Debug, Deserialize)]
pub struct CreateFormRequest {
    pub name: String,
    /// Pubkey that receives decrypted submissions as DM
    pub notify_pubkey: String,
    pub pow_difficulty: Option<u8>,
    pub rate_limit_per_hour: Option<u32>,
}

/// Request to update a form
#[derive(Debug, Deserialize)]
pub struct UpdateFormRequest {
    pub name: Option<String>,
    pub notify_pubkey: Option<String>,
    pub pow_difficulty: Option<u8>,
    pub rate_limit_per_hour: Option<u32>,
    pub status: Option<FormStatus>,
}
