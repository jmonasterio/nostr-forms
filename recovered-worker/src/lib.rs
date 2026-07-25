//! Cloudflare Worker entry point for the Nostr form processor.
//!
//! Two top-level events (wasm only):
//! * `scheduled` — cron-driven poll. Pulls NIP-44 envelopes addressed to
//!   `PROCESSOR_PUBKEY` from the relay via the `RELAY` service binding,
//!   decrypts, deduplicates, and inserts into D1.
//! * `fetch`     — admin HTTP (status, manual replay, submission lookup).
//!
//! Native builds skip the worker-bound modules so unit tests can exercise
//! the pure protocol code (decrypt, schema, booking) without a wasm toolchain.

pub mod alerts;
pub mod booking;
pub mod decrypt;
pub mod form_id;
pub mod schema;

#[cfg(target_arch = "wasm32")]
pub mod admin;
#[cfg(target_arch = "wasm32")]
pub mod booking_routes;
#[cfg(target_arch = "wasm32")]
pub mod notify;
#[cfg(target_arch = "wasm32")]
pub mod poll;
#[cfg(target_arch = "wasm32")]
pub mod storage;

pub mod event;
pub mod nip98;
pub mod pow;
pub mod seal;
pub mod sign;

#[cfg(target_arch = "wasm32")]
mod worker_entry {
    use worker::*;

    #[event(start)]
    fn start() {
        console_error_panic_hook::set_once();
    }

    #[event(fetch)]
    async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
        let path = req.path();

        if path.starts_with("/booking/") {
            return crate::booking_routes::handle(req, env).await;
        }
        if path.starts_with("/admin") {
            return crate::admin::handle(req, env).await;
        }

        match (req.method(), path.as_str()) {
            (Method::Get, "/") | (Method::Get, "/healthz") => Response::ok("nostr-form-rs ok"),
            _ => Response::error("not found", 404),
        }
    }

    #[event(scheduled)]
    async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
        if let Err(e) = crate::poll::run_once(&env).await {
            console_log!("poll cron failed: {e:?}");
        }
    }
}
