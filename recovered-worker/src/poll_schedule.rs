//! The adaptive `/admin/poll` cadence: when the cron tick is allowed to
//! cost the relay a request, and when it is not.
//!
//! Lives apart from `poll.rs` for the reason the crate root gives: `poll`
//! is wasm-only (it needs `worker::Env`, D1 and the service binding), and
//! a schedule that can only be checked by deploying it is a schedule
//! nobody can reason about. Everything here is pure integer arithmetic and
//! is unit-tested on the host, exactly like `booking` and `form_id`.

/// Safety margin subtracted from the poll's own wall-clock time before it
/// is written back as the cursor, covering clock drift between this
/// Worker's `Date::now()` and the relay DO's. Not a hedge against event
/// backdating — the relay's `since` filters its own arrival time, which a
/// sender's `created_at` cannot affect.
pub const CURSOR_OVERLAP_SECS: i64 = 10;

// ------------------------------------------------- adaptive poll cadence
//
// The cron fires every minute and each tick used to hand the relay one
// `/admin/poll`. Measured off a 4h04m `wrangler tail` of `nostr-relay`
// (muthr/tools/tail2.json, 480 matching log lines): every poll bills the
// relay TWICE — one stateless Worker request and one Durable Object
// request, 240 of each. That is ~1,440 DO requests/day on a 100,000/day
// free-tier cap, paid whether or not a single form was submitted, and
// this form has taken 15 submissions in its lifetime.
//
// The cron schedule itself is left alone: a Cloudflare cron cannot fire
// less often than once a minute with any useful granularity, changing it
// needs a deploy, and the tick is not what costs the relay anything. What
// costs the relay is the fetch, so the fetch is what gets gated. A gated
// tick reaches `storage::get_poll_gate` and returns — zero relay requests.

/// Tightest cadence, and the one used whenever anything is happening. Equal
/// to the cron period because the cron is the clock: asking for less than
/// 60s here would be a lie the scheduler cannot honour.
pub const POLL_FLOOR_SECS: i64 = 60;

/// Idle ceiling. Bounded from ABOVE by the relay, not by taste: `handle_poll`
/// clamps a caller-supplied `since` to `MAX_POLL_LOOKBACK_SECS = 15 * 60`
/// (../../nostr-relay-rs/src/relay.rs). The cursor only advances on a poll
/// that actually runs, so every second spent gated widens the next window by
/// the same amount — at a ceiling of 15 minutes or more the relay would
/// silently refuse part of the window and submissions would vanish. 5
/// minutes leaves a 3x margin, which also absorbs a couple of missed ticks.
///
/// The cost side is a form-submission notification arriving up to 5 minutes
/// late instead of up to 1. That is the whole downside, it only applies to
/// the first submission after a quiet stretch, and the 34 minutes of silence
/// needed to reach the ceiling means an in-progress exchange never sees it.
pub const POLL_CEILING_SECS: i64 = 300;

/// Empty polls per rung of the ladder. Streak 1-4 stays at the floor, 5-9
/// doubles, 10-14 doubles again, 15+ is the ceiling — so the walk up is
/// 4x60 + 5x120 + 5x240 = 2,040s, i.e. 34 minutes of no submissions at all.
pub const POLL_IDLE_POLLS_PER_STEP: i64 = 5;

/// Seconds to wait after `idle_streak` consecutive empty polls.
///
/// Pure and total, which is the point: the gate is persisted state and a
/// schedule that could only be checked by deploying it is a schedule nobody
/// can reason about. Doubles a rung at a time, never below the floor, never
/// above the ceiling, saturating rather than overflowing on a streak that
/// has been running for months.
pub fn poll_interval_secs(idle_streak: i64) -> i64 {
    if idle_streak <= 0 {
        return POLL_FLOOR_SECS;
    }
    let step = (idle_streak / POLL_IDLE_POLLS_PER_STEP).min(32) as u32;
    POLL_FLOOR_SECS
        .saturating_mul(1i64 << step)
        .clamp(POLL_FLOOR_SECS, POLL_CEILING_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Replay the streak the way `run_once` drives it: one entry per poll,
    /// each the interval that poll schedules for the next one.
    fn walk(empty_polls: usize) -> Vec<i64> {
        let mut streak: i64 = 0;
        (0..empty_polls)
            .map(|_| {
                streak += 1;
                poll_interval_secs(streak)
            })
            .collect()
    }

    #[test]
    fn a_run_of_empty_polls_widens_monotonically_and_stops_at_the_ceiling() {
        let ladder = walk(400);
        assert!(
            ladder.windows(2).all(|w| w[1] >= w[0]),
            "the interval may only widen while idle"
        );
        assert_eq!(*ladder.first().unwrap(), POLL_FLOOR_SECS);
        assert_eq!(*ladder.last().unwrap(), POLL_CEILING_SECS);
        assert_eq!(*ladder.iter().max().unwrap(), POLL_CEILING_SECS);

        let mut rungs: Vec<i64> = ladder.clone();
        rungs.dedup();
        assert_eq!(rungs, vec![60, 120, 240, 300]);
    }

    #[test]
    fn the_interval_is_never_below_the_floor() {
        // The guard against "inbound latency is too high, poll faster".
        // The cron cannot fire faster than the floor anyway, so a shorter
        // interval would only mean the gate never gates anything.
        for streak in -5..1000 {
            assert!(
                poll_interval_secs(streak) >= POLL_FLOOR_SECS,
                "streak {streak} produced {}",
                poll_interval_secs(streak)
            );
        }
    }

    #[test]
    fn the_ceiling_stays_clear_of_the_relays_since_clamp() {
        // `handle_poll` in nostr-relay-rs clamps a caller `since` to
        // MAX_POLL_LOOKBACK_SECS = 900. The cursor only advances on a poll
        // that ran, so the widest window this schedule can ever ask for is
        // one ceiling-length interval plus the overlap. Past 900 the relay
        // would silently truncate it and submissions would be lost.
        const RELAY_MAX_POLL_LOOKBACK_SECS: i64 = 15 * 60;
        let widest = POLL_CEILING_SECS + CURSOR_OVERLAP_SECS;
        assert!(
            widest * 2 <= RELAY_MAX_POLL_LOOKBACK_SECS,
            "the ceiling needs margin for a missed tick, got {widest}"
        );
    }

    #[test]
    fn activity_returns_the_next_poll_to_the_floor() {
        // `run_once` sets the streak to 0 on any event or pending row; that
        // is the only reset, and it must land exactly on the floor.
        let relaxed = walk(40);
        assert_eq!(*relaxed.last().unwrap(), POLL_CEILING_SECS);
        assert_eq!(poll_interval_secs(0), POLL_FLOOR_SECS);
    }

    #[test]
    fn a_saturated_streak_does_not_overflow_into_a_short_interval() {
        // A streak that has been running for months is a real state: this
        // form has taken 15 submissions in its lifetime. `1 << step` must
        // not wrap and hand the cron a tiny — or negative — interval.
        for streak in [1_000i64, 100_000, i64::MAX / 2, i64::MAX] {
            let secs = poll_interval_secs(streak);
            assert_eq!(secs, POLL_CEILING_SECS, "streak {streak}");
        }
    }

    #[test]
    fn the_walk_to_the_ceiling_is_half_an_hour_of_silence() {
        // The number that makes the ceiling defensible: a submission during
        // any ordinary stretch of activity never meets the relaxed cadence.
        let mut elapsed = 0i64;
        let mut streak = 0i64;
        // Bounded, so a schedule that never reaches the ceiling fails here
        // rather than hanging the suite.
        for _ in 0..1_000 {
            streak += 1;
            let secs = poll_interval_secs(streak);
            if secs == POLL_CEILING_SECS {
                break;
            }
            elapsed += secs;
        }
        assert_eq!(elapsed, 2_040, "34 minutes of no submissions to relax fully");
    }

    #[test]
    fn an_idle_day_costs_a_fifth_of_the_requests_a_fixed_minute_does() {
        // The reason any of this exists. One poll bills the relay one DO
        // request plus one Worker request (measured: 240 of each over a
        // 4h04m tail), so polls/day is the whole story.
        //
        // The `> 0` assert is not decoration. A schedule that returns 0 —
        // the shape any "just divide it down" edit produces — makes this
        // simulation spin forever instead of failing, and a test that hangs
        // reports nothing at all.
        const DAY: i64 = 86_400;
        let mut elapsed = 0i64;
        let mut streak = 0i64;
        let mut polls = 0i64;
        while elapsed < DAY {
            streak += 1;
            polls += 1;
            let secs = poll_interval_secs(streak);
            assert!(secs > 0, "streak {streak} scheduled a {secs}s interval");
            elapsed += secs;
        }
        assert_eq!(DAY / POLL_FLOOR_SECS, 1_440, "the cadence being replaced");
        assert_eq!(polls, 296);
    }
}

