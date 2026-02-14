use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// WebSocket URL of the Nostr relay
    pub relay_url: String,

    /// Path to SQLite database
    #[serde(default = "default_database_path")]
    pub database_path: String,

    /// Address to bind API server
    #[serde(default = "default_api_bind_addr")]
    pub api_bind_addr: String,

    /// Default proof-of-work difficulty (bits)
    #[serde(default = "default_pow_difficulty")]
    pub default_pow_difficulty: u8,

    /// Bootstrap admin pubkey (first admin, added if admin_pubkeys table is empty)
    pub bootstrap_admin_pubkey: Option<String>,
}

fn default_database_path() -> String {
    "./forms.db".to_string()
}

fn default_api_bind_addr() -> String {
    "127.0.0.1:8081".to_string()
}

fn default_pow_difficulty() -> u8 {
    16
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let config: Config = serde_json::from_str(&content)?;
            Ok(config)
        } else {
            // Return default config if file doesn't exist
            Ok(Config {
                relay_url: "ws://127.0.0.1:8080".to_string(),
                database_path: default_database_path(),
                api_bind_addr: default_api_bind_addr(),
                default_pow_difficulty: default_pow_difficulty(),
                bootstrap_admin_pubkey: None,
            })
        }
    }
}
