use rusqlite::{params, Connection, Result as SqliteResult};
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::models::{DeliveryStatus, Form, FormStatus, Submission, SubmissionType};

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(Path::new(path))?;
        let db = Database {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_tables()?;
        Ok(db)
    }

    fn init_tables(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();

        // Forms table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS forms (
                form_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                notify_pubkey TEXT NOT NULL,
                pow_difficulty INTEGER DEFAULT 16,
                rate_limit_per_hour INTEGER DEFAULT 100,
                status TEXT DEFAULT 'active',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Submissions table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS submissions (
                event_id TEXT PRIMARY KEY,
                form_id TEXT NOT NULL,
                sender_pubkey TEXT NOT NULL,
                submission_type TEXT NOT NULL,
                encrypted_content TEXT NOT NULL,
                decrypted_content TEXT,
                received_at INTEGER NOT NULL,
                processed_at INTEGER,
                delivery_status TEXT DEFAULT 'pending',
                delivery_attempts INTEGER DEFAULT 0,
                last_delivery_error TEXT,
                FOREIGN KEY (form_id) REFERENCES forms(form_id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_submissions_form ON submissions(form_id)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(delivery_status)",
            [],
        )?;

        // Admin pubkeys table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS admin_pubkeys (
                pubkey TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Processor config table (stores keypair)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS processor_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        // Rate limits table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS rate_limits (
                key TEXT PRIMARY KEY,
                count INTEGER DEFAULT 0,
                window_start INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(())
    }

    // ==================== Processor Config ====================

    pub fn get_config(&self, key: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT value FROM processor_config WHERE key = ?1",
            params![key],
            |row| row.get(0),
        );

        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn set_config(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO processor_config (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    // ==================== Admin Pubkeys ====================

    pub fn is_admin(&self, pubkey: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM admin_pubkeys WHERE pubkey = ?1",
            params![pubkey],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn add_admin(&self, pubkey: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT OR IGNORE INTO admin_pubkeys (pubkey, created_at) VALUES (?1, ?2)",
            params![pubkey, now],
        )?;
        Ok(())
    }

    pub fn list_admins(&self) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT pubkey FROM admin_pubkeys")?;
        let pubkeys = stmt
            .query_map([], |row| row.get(0))?
            .collect::<SqliteResult<Vec<String>>>()?;
        Ok(pubkeys)
    }

    pub fn admin_count(&self) -> anyhow::Result<i64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM admin_pubkeys", [], |row| row.get(0))?;
        Ok(count)
    }

    // ==================== Form Operations ====================

    pub fn create_form(&self, form: &Form) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO forms (
                form_id, name, notify_pubkey, pow_difficulty,
                rate_limit_per_hour, status, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                form.form_id,
                form.name,
                form.notify_pubkey,
                form.pow_difficulty,
                form.rate_limit_per_hour,
                status_to_str(form.status),
                form.created_at,
                form.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_form(&self, form_id: &str) -> anyhow::Result<Option<Form>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT form_id, name, notify_pubkey, pow_difficulty,
                    rate_limit_per_hour, status, created_at, updated_at
             FROM forms WHERE form_id = ?1",
        )?;

        let result = stmt.query_row(params![form_id], |row| {
            Ok(Form {
                form_id: row.get(0)?,
                name: row.get(1)?,
                notify_pubkey: row.get(2)?,
                pow_difficulty: row.get(3)?,
                rate_limit_per_hour: row.get(4)?,
                status: str_to_status(&row.get::<_, String>(5)?),
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        });

        match result {
            Ok(form) => Ok(Some(form)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn list_forms(&self) -> anyhow::Result<Vec<Form>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT form_id, name, notify_pubkey, pow_difficulty,
                    rate_limit_per_hour, status, created_at, updated_at
             FROM forms WHERE status != 'deleted' ORDER BY created_at DESC",
        )?;

        let forms = stmt
            .query_map([], |row| {
                Ok(Form {
                    form_id: row.get(0)?,
                    name: row.get(1)?,
                    notify_pubkey: row.get(2)?,
                    pow_difficulty: row.get(3)?,
                    rate_limit_per_hour: row.get(4)?,
                    status: str_to_status(&row.get::<_, String>(5)?),
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            })?
            .collect::<SqliteResult<Vec<_>>>()?;

        Ok(forms)
    }

    pub fn update_form(&self, form: &Form) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE forms SET
                name = ?2,
                notify_pubkey = ?3,
                pow_difficulty = ?4,
                rate_limit_per_hour = ?5,
                status = ?6,
                updated_at = ?7
             WHERE form_id = ?1",
            params![
                form.form_id,
                form.name,
                form.notify_pubkey,
                form.pow_difficulty,
                form.rate_limit_per_hour,
                status_to_str(form.status),
                form.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn delete_form(&self, form_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "UPDATE forms SET status = 'deleted', updated_at = ?2 WHERE form_id = ?1",
            params![form_id, now],
        )?;
        Ok(())
    }

    // ==================== Submission Operations ====================

    pub fn create_submission(&self, submission: &Submission) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO submissions (
                event_id, form_id, sender_pubkey, submission_type, encrypted_content,
                decrypted_content, received_at, processed_at, delivery_status,
                delivery_attempts, last_delivery_error
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                submission.event_id,
                submission.form_id,
                submission.sender_pubkey,
                submission_type_to_str(submission.submission_type),
                submission.encrypted_content,
                submission.decrypted_content,
                submission.received_at,
                submission.processed_at,
                delivery_status_to_str(submission.delivery_status),
                submission.delivery_attempts,
                submission.last_delivery_error,
            ],
        )?;
        Ok(())
    }

    pub fn get_submission(&self, event_id: &str) -> anyhow::Result<Option<Submission>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT event_id, form_id, sender_pubkey, submission_type, encrypted_content,
                    decrypted_content, received_at, processed_at, delivery_status,
                    delivery_attempts, last_delivery_error
             FROM submissions WHERE event_id = ?1",
        )?;

        let result = stmt.query_row(params![event_id], |row| {
            Ok(Submission {
                event_id: row.get(0)?,
                form_id: row.get(1)?,
                sender_pubkey: row.get(2)?,
                submission_type: str_to_submission_type(&row.get::<_, String>(3)?),
                encrypted_content: row.get(4)?,
                decrypted_content: row.get(5)?,
                received_at: row.get(6)?,
                processed_at: row.get(7)?,
                delivery_status: str_to_delivery_status(&row.get::<_, String>(8)?),
                delivery_attempts: row.get(9)?,
                last_delivery_error: row.get(10)?,
            })
        });

        match result {
            Ok(sub) => Ok(Some(sub)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn list_submissions(&self, form_id: &str, limit: u32) -> anyhow::Result<Vec<Submission>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT event_id, form_id, sender_pubkey, submission_type, encrypted_content,
                    decrypted_content, received_at, processed_at, delivery_status,
                    delivery_attempts, last_delivery_error
             FROM submissions WHERE form_id = ?1 ORDER BY received_at DESC LIMIT ?2",
        )?;

        let submissions = stmt
            .query_map(params![form_id, limit], |row| {
                Ok(Submission {
                    event_id: row.get(0)?,
                    form_id: row.get(1)?,
                    sender_pubkey: row.get(2)?,
                    submission_type: str_to_submission_type(&row.get::<_, String>(3)?),
                    encrypted_content: row.get(4)?,
                    decrypted_content: row.get(5)?,
                    received_at: row.get(6)?,
                    processed_at: row.get(7)?,
                    delivery_status: str_to_delivery_status(&row.get::<_, String>(8)?),
                    delivery_attempts: row.get(9)?,
                    last_delivery_error: row.get(10)?,
                })
            })?
            .collect::<SqliteResult<Vec<_>>>()?;

        Ok(submissions)
    }

    pub fn update_submission_status(
        &self,
        event_id: &str,
        status: DeliveryStatus,
        error: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "UPDATE submissions SET
                delivery_status = ?2,
                delivery_attempts = delivery_attempts + 1,
                processed_at = ?3,
                last_delivery_error = ?4
             WHERE event_id = ?1",
            params![event_id, delivery_status_to_str(status), now, error],
        )?;
        Ok(())
    }

    pub fn update_submission_decrypted(
        &self,
        event_id: &str,
        decrypted_content: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE submissions SET decrypted_content = ?2 WHERE event_id = ?1",
            params![event_id, decrypted_content],
        )?;
        Ok(())
    }

    pub fn submission_exists(&self, event_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM submissions WHERE event_id = ?1",
            params![event_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    // ==================== Rate Limiting ====================

    pub fn check_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_seconds: i64,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();

        // Get current count and window
        let result: Result<(i64, i64), _> = conn.query_row(
            "SELECT count, window_start FROM rate_limits WHERE key = ?1",
            params![key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );

        match result {
            Ok((count, window_start)) => {
                if now - window_start > window_seconds {
                    // Window expired, reset
                    conn.execute(
                        "UPDATE rate_limits SET count = 1, window_start = ?2 WHERE key = ?1",
                        params![key, now],
                    )?;
                    Ok(true)
                } else if count < limit as i64 {
                    // Under limit, increment
                    conn.execute(
                        "UPDATE rate_limits SET count = count + 1 WHERE key = ?1",
                        params![key],
                    )?;
                    Ok(true)
                } else {
                    // Over limit
                    Ok(false)
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                // First request, create entry
                conn.execute(
                    "INSERT INTO rate_limits (key, count, window_start) VALUES (?1, 1, ?2)",
                    params![key, now],
                )?;
                Ok(true)
            }
            Err(e) => Err(e.into()),
        }
    }
}

// Helper functions for enum conversions

fn status_to_str(status: FormStatus) -> &'static str {
    match status {
        FormStatus::Active => "active",
        FormStatus::Paused => "paused",
        FormStatus::Deleted => "deleted",
    }
}

fn str_to_status(s: &str) -> FormStatus {
    match s {
        "active" => FormStatus::Active,
        "paused" => FormStatus::Paused,
        "deleted" => FormStatus::Deleted,
        _ => FormStatus::Active,
    }
}

fn submission_type_to_str(st: SubmissionType) -> &'static str {
    match st {
        SubmissionType::Anon => "anon",
        SubmissionType::Authenticated => "authenticated",
    }
}

fn str_to_submission_type(s: &str) -> SubmissionType {
    match s {
        "anon" => SubmissionType::Anon,
        "authenticated" => SubmissionType::Authenticated,
        _ => SubmissionType::Anon,
    }
}

fn delivery_status_to_str(ds: DeliveryStatus) -> &'static str {
    match ds {
        DeliveryStatus::Pending => "pending",
        DeliveryStatus::Delivered => "delivered",
        DeliveryStatus::Failed => "failed",
        DeliveryStatus::Exhausted => "exhausted",
    }
}

fn str_to_delivery_status(s: &str) -> DeliveryStatus {
    match s {
        "pending" => DeliveryStatus::Pending,
        "delivered" => DeliveryStatus::Delivered,
        "failed" => DeliveryStatus::Failed,
        "exhausted" => DeliveryStatus::Exhausted,
        _ => DeliveryStatus::Pending,
    }
}
