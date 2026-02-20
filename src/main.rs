use clap::Parser;
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod api;
mod config;
mod crypto;
mod forwarder;
mod processor;
mod registry;

use config::Config;
use crypto::keys::{generate_keypair, privkey_from_hex, privkey_to_hex, pubkey_to_hex};

#[derive(Parser)]
#[command(name = "nostr-form-rs")]
#[command(about = "Encrypted contact forms for any website, powered by Nostr")]
#[command(version)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.json")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let cli = Cli::parse();

    // Load configuration
    let config = Config::load(&cli.config)?;
    info!("Loaded configuration from {:?}", cli.config);

    // Initialize database
    let db = registry::storage::Database::open(&config.database_path)?;
    info!("Database opened at {:?}", config.database_path);

    // Initialize or load processor keypair
    let processor_privkey = match db.get_config("processor_privkey")? {
        Some(privkey_hex) => {
            info!("Loaded existing processor keypair");
            privkey_from_hex(&privkey_hex)?
        }
        None => {
            info!("Generating new processor keypair");
            let (privkey, pubkey) = generate_keypair();
            let privkey_hex = privkey_to_hex(&privkey);
            let pubkey_hex = pubkey_to_hex(&pubkey);

            db.set_config("processor_privkey", &privkey_hex)?;
            db.set_config("processor_pubkey", &pubkey_hex)?;

            info!("Processor pubkey: {}", pubkey_hex);
            privkey
        }
    };

    // Get processor pubkey for logging
    let processor_pubkey = db.get_config("processor_pubkey")?.unwrap_or_default();
    info!("Processor pubkey: {}", processor_pubkey);

    // Bootstrap admin if configured and no admins exist
    if let Some(ref bootstrap_pubkey) = config.bootstrap_admin_pubkey {
        if db.admin_count()? == 0 {
            info!("Adding bootstrap admin: {}", bootstrap_pubkey);
            db.add_admin(bootstrap_pubkey)?;
        }
    }

    // Log admin count
    let admin_count = db.admin_count()?;
    info!("Admin pubkeys configured: {}", admin_count);
    if admin_count == 0 {
        info!("WARNING: No admin pubkeys configured. Set bootstrap_admin_pubkey in config.json");
    }

    // Start processor worker
    let processor_handle = {
        let relay_url = config.relay_url.clone();
        let db = db.clone();
        let privkey = processor_privkey;
        tokio::spawn(async move {
            if let Err(e) = processor::worker::run(relay_url, db, privkey).await {
                tracing::error!("Processor error: {}", e);
            }
        })
    };

    // Start HTTP API server
    let api_handle = {
        let bind_addr = config.api_bind_addr.clone();
        let db = db.clone();
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = api::server::run(bind_addr, db, config).await {
                tracing::error!("API server error: {}", e);
            }
        })
    };

    info!("nostr-form-rs started");
    info!("API available at http://{}", config.api_bind_addr);
    info!("Admin UI at http://{}/admin", config.api_bind_addr);

    // Wait for shutdown
    tokio::select! {
        _ = processor_handle => {},
        _ = api_handle => {},
        _ = tokio::signal::ctrl_c() => {
            info!("Shutting down...");
        }
    }

    Ok(())
}
