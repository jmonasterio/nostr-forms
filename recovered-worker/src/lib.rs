//! Cloudflare Worker entry point for the Nostr form processor.
//!
//! One top-level event (wasm only): `fetch` — public `POST /submit` (the
//! browser SDK's write path), booking slots, and the NIP-98 admin API.
//! There is no cron: the SDK POSTs each submission (see `process.rs`).
//!
//! Native builds skip the worker-bound modules so unit tests can exercise
//! the pure protocol code (decrypt, schema, booking) without a wasm toolchain.

pub mod alerts;
pub mod booking;
pub mod decrypt;
pub mod form_id;
pub mod schema;
pub mod submit;

#[cfg(target_arch = "wasm32")]
pub mod admin;
#[cfg(target_arch = "wasm32")]
pub mod booking_routes;
#[cfg(target_arch = "wasm32")]
pub mod notify;
#[cfg(target_arch = "wasm32")]
pub mod process;
#[cfg(target_arch = "wasm32")]
pub mod storage;
#[cfg(target_arch = "wasm32")]
pub mod submit_route;

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
    async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
        let path = req.path();

        if path.starts_with("/booking/") {
            return crate::booking_routes::handle(req, env).await;
        }
        if path.starts_with("/admin") {
            return crate::admin::handle(req, env).await;
        }
        if path == "/submit" {
            return crate::submit_route::handle(req, env, ctx).await;
        }

        match (req.method(), path.as_str()) {
            (Method::Get, "/") | (Method::Get, "/healthz") => Response::ok("nostr-form-rs ok"),
            _ => Response::error("not found", 404),
        }
    }
}
