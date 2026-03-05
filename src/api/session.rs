use std::collections::HashMap;
use std::sync::Mutex;

/// Session TTL: 8 hours.
const SESSION_TTL_SECS: i64 = 8 * 60 * 60;

#[allow(dead_code)]
struct Entry {
    pubkey: String,
    expires_at: i64,
}

/// Thread-safe, in-memory session store.
/// Sessions are opaque random tokens bound to a pubkey with a TTL.
pub struct SessionStore {
    inner: Mutex<HashMap<String, Entry>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Issue a new session token for the given pubkey. Returns the token.
    pub fn create(&self, pubkey: &str) -> String {
        let token = new_token();
        let expires_at = chrono::Utc::now().timestamp() + SESSION_TTL_SECS;
        let mut map = self.inner.lock().unwrap();
        // Evict stale entries opportunistically.
        let now = chrono::Utc::now().timestamp();
        map.retain(|_, e| e.expires_at > now);
        map.insert(token.clone(), Entry { pubkey: pubkey.to_string(), expires_at });
        token
    }

    /// Returns true if the token exists and has not expired.
    pub fn is_valid(&self, token: &str) -> bool {
        let map = self.inner.lock().unwrap();
        match map.get(token) {
            Some(e) => e.expires_at > chrono::Utc::now().timestamp(),
            None => false,
        }
    }

    /// Remove a specific token (explicit server-side logout).
    #[allow(dead_code)]
    pub fn revoke(&self, token: &str) {
        self.inner.lock().unwrap().remove(token);
    }
}

fn new_token() -> String {
    use rand::RngCore;
    use std::fmt::Write;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(64);
    for b in bytes {
        write!(s, "{:02x}", b).unwrap();
    }
    s
}
