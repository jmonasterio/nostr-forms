//! Booking mode (BOOKING-PLAN.md, Phase 3.6) — pure slot math, native-testable.
//!
//! Availability is recurring weekly rules stored under the `booking` key of
//! `forms.options_json`:
//!
//! ```json
//! {"booking":{"tz":"America/New_York","duration_min":30,
//!   "rules":[{"dow":[1,2,3,4,5],"start":"09:00","end":"17:00"}],
//!   "horizon_weeks":4,"min_notice_min":1440,"blocks":["2026-07-04"]}}
//! ```
//!
//! Open slots are *virtual* — materialized here at read time; only booked
//! slots are persisted (storage layer). All storage and comparison is unix
//! UTC; the timezone is used only for rule expansion and is DST-correct.
//!
//! Timezone support is a deliberate minimal table: UTC + US zones with
//! post-2007 US DST rules (second Sunday of March 02:00 → first Sunday of
//! November 02:00, wall clock). Local wall times inside the spring-forward
//! gap or the fall-back overlap resolve as DST (first occurrence). Extend
//! `ZONES` when a non-US tenant appears; do not add a tz database dep for
//! a table this small.
//!
//! `dow` uses the JS convention: 0 = Sunday … 6 = Saturday.

use serde::Deserialize;

/// Hard cap on the booking horizon (defense against config typos that
/// would otherwise expand thousands of slots per request).
const MAX_HORIZON_WEEKS: u32 = 26;

// ---------- config ----------

#[derive(Debug, Clone)]
pub struct BookingConfig {
    pub tz_name: String,
    tz: Tz,
    pub duration_min: u32,
    rules: Vec<Rule>,
    pub horizon_weeks: u32,
    pub min_notice_min: u32,
    /// Block days as civil day numbers (days since 1970-01-01, local dates).
    blocks: Vec<i64>,
}

#[derive(Debug, Clone)]
struct Rule {
    dow: Vec<u8>,
    start_min: u32, // minutes since local midnight
    end_min: u32,
}

#[derive(Debug, Deserialize)]
struct RawOptions {
    booking: Option<RawBooking>,
}

#[derive(Debug, Deserialize)]
struct RawBooking {
    tz: String,
    duration_min: u32,
    rules: Vec<RawRule>,
    horizon_weeks: u32,
    #[serde(default)]
    min_notice_min: u32,
    #[serde(default)]
    blocks: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    dow: Vec<u8>,
    start: String,
    end: String,
}

/// Parse the `booking` block out of a form's `options_json`.
/// `Ok(None)` = not a booking form. `Err` = booking block present but bad.
pub fn parse_config(options_json: &str) -> Result<Option<BookingConfig>, String> {
    let raw: RawOptions =
        serde_json::from_str(options_json).map_err(|e| format!("options_json: {e}"))?;
    let Some(b) = raw.booking else { return Ok(None) };

    let tz = tz_by_name(&b.tz).ok_or_else(|| format!("unsupported tz '{}'", b.tz))?;
    if b.duration_min == 0 || b.duration_min > 24 * 60 {
        return Err(format!("bad duration_min {}", b.duration_min));
    }
    if b.horizon_weeks == 0 || b.horizon_weeks > MAX_HORIZON_WEEKS {
        return Err(format!("horizon_weeks must be 1..={MAX_HORIZON_WEEKS}"));
    }
    if b.rules.is_empty() {
        return Err("rules must be non-empty".into());
    }
    let mut rules = Vec::with_capacity(b.rules.len());
    for r in &b.rules {
        let start_min = parse_hhmm(&r.start).ok_or_else(|| format!("bad start '{}'", r.start))?;
        let end_min = parse_hhmm(&r.end).ok_or_else(|| format!("bad end '{}'", r.end))?;
        if start_min >= end_min {
            return Err(format!("start {} >= end {}", r.start, r.end));
        }
        if r.dow.iter().any(|&d| d > 6) {
            return Err("dow values must be 0..=6 (0=Sunday)".into());
        }
        rules.push(Rule { dow: r.dow.clone(), start_min, end_min });
    }
    let mut blocks = Vec::with_capacity(b.blocks.len());
    for s in &b.blocks {
        blocks.push(parse_ymd(s).ok_or_else(|| format!("bad block date '{s}'"))?);
    }
    Ok(Some(BookingConfig {
        tz_name: b.tz,
        tz,
        duration_min: b.duration_min,
        rules,
        horizon_weeks: b.horizon_weeks,
        min_notice_min: b.min_notice_min,
        blocks,
    }))
}

// ---------- slot expansion ----------

/// All open-slot start times (unix UTC, sorted, deduped) from `now`
/// through the horizon, honoring min-notice and block days. The caller
/// subtracts persisted booked slots.
pub fn expand_slots(cfg: &BookingConfig, now: i64) -> Vec<i64> {
    let earliest = now + cfg.min_notice_min as i64 * 60;
    let today = local_day(cfg.tz, now);
    let horizon_days = cfg.horizon_weeks as i64 * 7;

    let mut out: Vec<i64> = Vec::new();
    for day in today..=today + horizon_days {
        if cfg.blocks.contains(&day) {
            continue;
        }
        let dow = weekday_from_days(day);
        for rule in &cfg.rules {
            if !rule.dow.contains(&dow) {
                continue;
            }
            let mut t = rule.start_min;
            while t + cfg.duration_min <= rule.end_min {
                let starts_at = local_to_unix(cfg.tz, day, t);
                if starts_at >= earliest {
                    out.push(starts_at);
                }
                t += cfg.duration_min;
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Deterministic slot id: `<form_slug>:<starts_at_unix>`.
pub fn slot_id(form_slug: &str, starts_at: i64) -> String {
    format!("{form_slug}:{starts_at}")
}

/// Parse a slot id back into (form_slug, starts_at).
pub fn parse_slot_id(id: &str) -> Option<(&str, i64)> {
    let (slug, ts) = id.rsplit_once(':')?;
    if slug.is_empty() {
        return None;
    }
    Some((slug, ts.parse().ok()?))
}

/// Top-level `slot_id` field from a decrypted submission payload —
/// presence routes the submission down the booking path (poll handler).
pub fn extract_slot_id(plaintext: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(plaintext)
        .ok()?
        .get("slot_id")?
        .as_str()
        .map(String::from)
}

/// Is `slot` a currently-offerable slot id for this form? (right slug,
/// inside the rule set + horizon, not blocked, satisfies min-notice).
/// Membership in the expansion is the single source of truth so the
/// claim path can never honor a slot the public route would not offer.
pub fn slot_is_valid(cfg: &BookingConfig, form_slug: &str, slot: &str, now: i64) -> Option<i64> {
    let (slug, starts_at) = parse_slot_id(slot)?;
    if slug != form_slug {
        return None;
    }
    expand_slots(cfg, now).binary_search(&starts_at).ok().map(|_| starts_at)
}

// ---------- ICS ----------

/// Minimal RFC 5545 VEVENT calendar. UTC times, CRLF line endings.
pub fn ics_vevent(uid: &str, starts_at: i64, duration_min: u32, summary: &str, description: &str) -> String {
    let dtstart = format_utc(starts_at);
    let dtstamp = dtstart.clone();
    let summary = ics_escape(summary);
    let description = ics_escape(description);
    format!(
        "BEGIN:VCALENDAR\r\n\
         VERSION:2.0\r\n\
         PRODID:-//nostr-form-rs//booking//EN\r\n\
         METHOD:PUBLISH\r\n\
         BEGIN:VEVENT\r\n\
         UID:{uid}@forms.argw.com\r\n\
         DTSTAMP:{dtstamp}\r\n\
         DTSTART:{dtstart}\r\n\
         DURATION:PT{duration_min}M\r\n\
         SUMMARY:{summary}\r\n\
         DESCRIPTION:{description}\r\n\
         END:VEVENT\r\n\
         END:VCALENDAR\r\n"
    )
}

fn ics_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            _ => out.push(c),
        }
    }
    out
}

/// `YYYYMMDDTHHMMSSZ` for a unix timestamp.
pub fn format_utc(unix: i64) -> String {
    let days = unix.div_euclid(86400);
    let secs = unix.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

// ---------- timezone (minimal table, US DST rules) ----------

#[derive(Debug, Clone, Copy, PartialEq)]
struct Tz {
    /// Standard-time offset from UTC in seconds (negative = west).
    std_offset: i64,
    /// Observes post-2007 US DST rules.
    us_dst: bool,
}

fn tz_by_name(name: &str) -> Option<Tz> {
    Some(match name {
        "UTC" => Tz { std_offset: 0, us_dst: false },
        "America/New_York" => Tz { std_offset: -5 * 3600, us_dst: true },
        "America/Chicago" => Tz { std_offset: -6 * 3600, us_dst: true },
        "America/Denver" => Tz { std_offset: -7 * 3600, us_dst: true },
        "America/Phoenix" => Tz { std_offset: -7 * 3600, us_dst: false },
        "America/Los_Angeles" => Tz { std_offset: -8 * 3600, us_dst: true },
        _ => return None,
    })
}

/// Is US DST in effect for local wall time (`day`, `min_of_day`)?
/// DST = [second Sunday of March 02:00, first Sunday of November 02:00).
fn us_dst_active(day: i64, min_of_day: u32) -> bool {
    let (y, _, _) = civil_from_days(day);
    let dst_start = nth_sunday(y, 3, 2); // second Sunday of March
    let dst_end = nth_sunday(y, 11, 1); // first Sunday of November
    let t = day * 1440 + min_of_day as i64;
    t >= dst_start * 1440 + 120 && t < dst_end * 1440 + 120
}

/// Civil day of the nth Sunday (1-based) of `month` in `year`.
fn nth_sunday(year: i64, month: u32, n: i64) -> i64 {
    let first = days_from_civil(year, month, 1);
    let first_sunday = first + ((7 - weekday_from_days(first) as i64) % 7);
    first_sunday + (n - 1) * 7
}

/// Local wall time (civil day + minutes) → unix UTC.
fn local_to_unix(tz: Tz, day: i64, min_of_day: u32) -> i64 {
    let mut offset = tz.std_offset;
    if tz.us_dst && us_dst_active(day, min_of_day) {
        offset += 3600;
    }
    day * 86400 + min_of_day as i64 * 60 - offset
}

/// Unix UTC → local civil day. Two-pass to get DST right near transitions.
fn local_day(tz: Tz, unix: i64) -> i64 {
    let guess = unix + tz.std_offset;
    let day = guess.div_euclid(86400);
    let min = (guess.rem_euclid(86400) / 60) as u32;
    let mut offset = tz.std_offset;
    if tz.us_dst && us_dst_active(day, min) {
        offset += 3600;
    }
    (unix + offset).div_euclid(86400)
}

// ---------- civil date math (Howard Hinnant's algorithms) ----------

/// Days since 1970-01-01 for a civil date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64; // [0, 399]
    let mp = ((m + 9) % 12) as i64; // March = 0
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Civil date for days since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = ((mp + 2) % 12 + 1) as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 0 = Sunday … 6 = Saturday (1970-01-01 was a Thursday).
fn weekday_from_days(z: i64) -> u8 {
    ((z + 4).rem_euclid(7)) as u8
}

// ---------- small parsers ----------

fn parse_hhmm(s: &str) -> Option<u32> {
    let (h, m) = s.split_once(':')?;
    let h: u32 = h.parse().ok()?;
    let m: u32 = m.parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some(h * 60 + m)
}

/// "YYYY-MM-DD" → civil day number.
fn parse_ymd(s: &str) -> Option<i64> {
    let mut it = s.splitn(3, '-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: u32 = it.next()?.parse().ok()?;
    let d: u32 = it.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86400;

    fn cfg(json: &str) -> BookingConfig {
        parse_config(json).expect("parse").expect("booking block")
    }

    /// Mon–Fri 9–17 ET, 30-min slots, 2-week horizon, no notice.
    fn et_weekdays() -> BookingConfig {
        cfg(r#"{"booking":{"tz":"America/New_York","duration_min":30,
            "rules":[{"dow":[1,2,3,4,5],"start":"09:00","end":"17:00"}],
            "horizon_weeks":2}}"#)
    }

    /// 2026-03-02 00:00 UTC (Monday). US DST 2026: starts Mar 8, ends Nov 1.
    fn now_pre_dst() -> i64 {
        days_from_civil(2026, 3, 2) * DAY
    }

    #[test]
    fn civil_roundtrip_and_weekday() {
        for &(y, m, d, wd) in &[(1970, 1, 1, 4u8), (2026, 3, 8, 0), (2026, 11, 1, 0), (2026, 6, 11, 4)] {
            let z = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(z), (y, m, d));
            assert_eq!(weekday_from_days(z), wd);
        }
    }

    #[test]
    fn weekday_rules_skip_weekends() {
        let slots = expand_slots(&et_weekdays(), now_pre_dst());
        assert!(!slots.is_empty());
        for s in &slots {
            let dow = weekday_from_days(local_day(tz_by_name("America/New_York").unwrap(), *s));
            assert!((1..=5).contains(&dow), "slot {s} fell on dow {dow}");
        }
        // Mon 9:00 ET pre-DST = 14:00 UTC.
        assert_eq!(slots[0], now_pre_dst() + 14 * 3600);
        // 16 slots/day (9:00–16:30 starts). now = Mar 2 00:00 UTC is still
        // Sunday Mar 1 in ET, so the local 14-day horizon (Mar 1..=Mar 15)
        // holds exactly 10 weekdays.
        assert_eq!(slots.len(), 16 * 10);
    }

    #[test]
    fn dst_spring_forward_shifts_utc_offset() {
        let c = et_weekdays();
        let slots = expand_slots(&c, now_pre_dst());
        // First slot of Fri Mar 6 (EST) vs Fri Mar 13 (EDT): a wall-clock
        // week apart but one hour less in UTC.
        let fri1 = days_from_civil(2026, 3, 6);
        let fri2 = days_from_civil(2026, 3, 13);
        let s1 = local_to_unix(tz_by_name("America/New_York").unwrap(), fri1, 9 * 60);
        let s2 = local_to_unix(tz_by_name("America/New_York").unwrap(), fri2, 9 * 60);
        assert!(slots.contains(&s1) && slots.contains(&s2));
        assert_eq!(s2 - s1, 7 * DAY - 3600);
    }

    #[test]
    fn dst_fall_back_shifts_utc_offset() {
        let tz = tz_by_name("America/New_York").unwrap();
        let fri_edt = days_from_civil(2026, 10, 30);
        let fri_est = days_from_civil(2026, 11, 6);
        let s1 = local_to_unix(tz, fri_edt, 9 * 60);
        let s2 = local_to_unix(tz, fri_est, 9 * 60);
        assert_eq!(s2 - s1, 7 * DAY + 3600);
    }

    #[test]
    fn phoenix_has_no_dst() {
        let tz = tz_by_name("America/Phoenix").unwrap();
        let s1 = local_to_unix(tz, days_from_civil(2026, 3, 6), 9 * 60);
        let s2 = local_to_unix(tz, days_from_civil(2026, 3, 13), 9 * 60);
        assert_eq!(s2 - s1, 7 * DAY);
    }

    #[test]
    fn horizon_edge_is_inclusive_and_bounded() {
        let c = et_weekdays();
        let now = now_pre_dst();
        let slots = expand_slots(&c, now);
        let last_day = local_day(tz_by_name("America/New_York").unwrap(), *slots.last().unwrap());
        let today = local_day(tz_by_name("America/New_York").unwrap(), now);
        assert!(last_day <= today + 14);
        assert!(last_day > today + 7, "horizon truncated early");
    }

    #[test]
    fn min_notice_drops_near_slots() {
        let c = cfg(r#"{"booking":{"tz":"America/New_York","duration_min":30,
            "rules":[{"dow":[1,2,3,4,5],"start":"09:00","end":"17:00"}],
            "horizon_weeks":2,"min_notice_min":1440}}"#);
        // Monday 13:00 UTC = 08:00 ET, an hour before Monday slots start.
        let now = now_pre_dst() + 13 * 3600;
        let slots = expand_slots(&c, now);
        // Nothing before Tuesday 08:00 ET (now + 24h).
        assert!(slots[0] >= now + 1440 * 60);
        // Monday's slots are all gone.
        let monday_900 = now_pre_dst() + 14 * 3600;
        assert!(!slots.contains(&monday_900));
    }

    #[test]
    fn block_days_remove_whole_day() {
        let c = cfg(r#"{"booking":{"tz":"America/New_York","duration_min":30,
            "rules":[{"dow":[1,2,3,4,5],"start":"09:00","end":"17:00"}],
            "horizon_weeks":2,"blocks":["2026-03-06"]}}"#);
        let blocked = days_from_civil(2026, 3, 6);
        let slots = expand_slots(&c, now_pre_dst());
        let tz = tz_by_name("America/New_York").unwrap();
        assert!(slots.iter().all(|s| local_day(tz, *s) != blocked));
    }

    #[test]
    fn slots_fit_inside_window() {
        // 45-min slots in a 9:00–12:00 window: starts 9:00, 9:45, 10:30, 11:15.
        let c = cfg(r#"{"booking":{"tz":"UTC","duration_min":45,
            "rules":[{"dow":[3],"start":"09:00","end":"12:00"}],
            "horizon_weeks":1}}"#);
        let now = days_from_civil(2026, 6, 8) * DAY; // Monday
        let slots = expand_slots(&c, now);
        let wed = days_from_civil(2026, 6, 10) * DAY;
        assert_eq!(slots, vec![wed + 9 * 3600, wed + 9 * 3600 + 2700, wed + 10 * 3600 + 1800, wed + 11 * 3600 + 900]);
    }

    #[test]
    fn slot_id_roundtrip_and_validation() {
        let c = et_weekdays();
        let now = now_pre_dst();
        let starts = expand_slots(&c, now)[0];
        let id = slot_id("booking", starts);
        assert_eq!(parse_slot_id(&id), Some(("booking", starts)));
        // Valid slot accepted.
        assert_eq!(slot_is_valid(&c, "booking", &id, now), Some(starts));
        // Foreign slug rejected.
        assert_eq!(slot_is_valid(&c, "other", &id, now), None);
        // Misaligned time rejected.
        assert_eq!(slot_is_valid(&c, "booking", &slot_id("booking", starts + 60), now), None);
        // Past min-notice/now rejected (ask again an hour after the slot).
        assert_eq!(slot_is_valid(&c, "booking", &id, starts + 3600), None);
        // Garbage rejected.
        assert_eq!(slot_is_valid(&c, "booking", "nonsense", now), None);
        assert_eq!(parse_slot_id(":123"), None);
    }

    #[test]
    fn non_booking_form_is_none_and_bad_config_errs() {
        assert!(parse_config("{}").unwrap().is_none());
        assert!(parse_config(r#"{"other":1}"#).unwrap().is_none());
        assert!(parse_config(r#"{"booking":{"tz":"Mars/Olympus","duration_min":30,
            "rules":[{"dow":[1],"start":"09:00","end":"10:00"}],"horizon_weeks":2}}"#).is_err());
        assert!(parse_config(r#"{"booking":{"tz":"UTC","duration_min":30,
            "rules":[{"dow":[1],"start":"10:00","end":"09:00"}],"horizon_weeks":2}}"#).is_err());
        assert!(parse_config(r#"{"booking":{"tz":"UTC","duration_min":30,
            "rules":[],"horizon_weeks":2}}"#).is_err());
        assert!(parse_config(r#"{"booking":{"tz":"UTC","duration_min":30,
            "rules":[{"dow":[7],"start":"09:00","end":"10:00"}],"horizon_weeks":2}}"#).is_err());
        assert!(parse_config(r#"{"booking":{"tz":"UTC","duration_min":30,
            "rules":[{"dow":[1],"start":"09:00","end":"10:00"}],"horizon_weeks":99}}"#).is_err());
    }

    #[test]
    fn ics_vevent_shape() {
        let starts = days_from_civil(2026, 6, 17) * DAY + 13 * 3600; // 2026-06-17 13:00Z
        let ics = ics_vevent("booking:1781787600", starts, 30, "Call; with, Bob", "line1\nline2");
        assert!(ics.contains("DTSTART:20260617T130000Z"));
        assert!(ics.contains("DURATION:PT30M"));
        assert!(ics.contains("UID:booking:1781787600@forms.argw.com"));
        assert!(ics.contains("SUMMARY:Call\\; with\\, Bob"));
        assert!(ics.contains("DESCRIPTION:line1\\nline2"));
        assert!(ics.ends_with("END:VCALENDAR\r\n"));
        for line in ics.lines() {
            assert!(line.len() <= 74, "ICS line too long: {line}");
        }
    }
}
