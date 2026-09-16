//! A record of who has been using Curfew, and from where.
//!
//! This answers "has anyone else been controlling this?" — whether someone
//! signed into the web panel, tried a wrong password, performed an action, or
//! tried to start a second copy of Curfew on this machine.
//!
//! # What is deliberately *not* recorded
//!
//! **Never the password, and never a hash of it.** A failed attempt is logged
//! as a failure with the address it came from, nothing more. An audit log that
//! captured credentials would itself become the most sensitive file on the
//! machine, and anyone who read it would learn the password of everyone who
//! ever mistyped it.
//!
//! Session tokens aren't recorded either — only a short prefix, for telling
//! sessions apart in the UI.
//!
//! # Storage
//!
//! One line per event in `<CONFIG_DIR>/access.log`:
//!
//! ```text
//! <epoch>|<kind>|<actor>|<detail>
//! ```
//!
//! The file is owner-only (`paths::restrict`) and compacted to the most recent
//! [`MAX_ENTRIES`] on load, so a long-running install can't grow it without
//! bound. A line that can't be parsed is skipped rather than discarding the
//! file.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// How many events to keep. Enough for weeks of household use.
const MAX_ENTRIES: usize = 500;

/// The actor used for actions taken at this machine's own keyboard, as
/// opposed to over the network.
pub const ACTOR_TERMINAL: &str = "this computer";

/// What happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Curfew started.
    Started,
    /// Curfew stopped and restored the network.
    Stopped,
    /// Someone signed into the web panel.
    SignedIn,
    /// Someone tried to sign in and got the password wrong.
    SignInFailed,
    /// Someone signed out.
    SignedOut,
    /// The owner ended another person's session.
    SessionRevoked,
    /// A setting was changed.
    Action,
    /// Someone tried to start a second Curfew on this machine.
    LockContention,
    /// Another Curfew control panel is running on this network.
    OtherPanel,
    /// The gateway's hardware address changed, which is what happens when
    /// something else starts impersonating it.
    GatewayChanged,
    /// Something on the network is spoofing ARP — the signature of another
    /// tool intercepting and throttling traffic.
    Spoofing,
    /// Curfew's defense pinned an address, or was toggled.
    Defense,
}

impl Kind {
    /// Stable token for the log file. Never renumber or reword these — old
    /// lines have to keep parsing.
    fn code(self) -> &'static str {
        match self {
            Kind::Started => "started",
            Kind::Stopped => "stopped",
            Kind::SignedIn => "signin",
            Kind::SignInFailed => "signin_failed",
            Kind::SignedOut => "signout",
            Kind::SessionRevoked => "session_revoked",
            Kind::Action => "action",
            Kind::LockContention => "lock_contention",
            Kind::OtherPanel => "other_panel",
            Kind::GatewayChanged => "gateway_changed",
            Kind::Spoofing => "spoofing",
            Kind::Defense => "defense",
        }
    }

    fn from_code(code: &str) -> Option<Kind> {
        Some(match code {
            "started" => Kind::Started,
            "stopped" => Kind::Stopped,
            "signin" => Kind::SignedIn,
            "signin_failed" => Kind::SignInFailed,
            "signout" => Kind::SignedOut,
            "session_revoked" => Kind::SessionRevoked,
            "action" => Kind::Action,
            "lock_contention" => Kind::LockContention,
            "other_panel" => Kind::OtherPanel,
            "gateway_changed" => Kind::GatewayChanged,
            "spoofing" => Kind::Spoofing,
            "defense" => Kind::Defense,
            _ => return None,
        })
    }

    /// A short label for the log view.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Started => "started",
            Kind::Stopped => "stopped",
            Kind::SignedIn => "signed in",
            Kind::SignInFailed => "WRONG PASSWORD",
            Kind::SignedOut => "signed out",
            Kind::SessionRevoked => "signed out by owner",
            Kind::Action => "changed",
            Kind::LockContention => "SECOND COPY TRIED",
            Kind::OtherPanel => "OTHER PANEL FOUND",
            Kind::GatewayChanged => "GATEWAY ADDRESS CHANGED",
            Kind::Spoofing => "SOMEONE IS SPOOFING YOUR NETWORK",
            Kind::Defense => "defense",
        }
    }

    /// True for things worth catching the owner's eye: a failed password, a
    /// second copy, another panel on the network, or something impersonating
    /// the router.
    ///
    /// Successful sign-ins are deliberately *not* flagged here — the owner
    /// signs in constantly, and an alert that fires every time is one people
    /// learn to ignore. Sign-ins are shown in the log and summarised in the
    /// dashboard instead.
    pub fn is_alert(self) -> bool {
        matches!(
            self,
            Kind::SignInFailed
                | Kind::LockContention
                | Kind::OtherPanel
                | Kind::GatewayChanged
                | Kind::Spoofing
        )
    }
}

/// One logged event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Unix epoch seconds.
    pub at: u64,
    pub kind: Kind,
    /// An IP address, or [`ACTOR_TERMINAL`].
    pub actor: String,
    /// Free text: what was changed, how many attempts, and so on.
    pub detail: String,
}

impl Entry {
    pub fn new(at: u64, kind: Kind, actor: &str, detail: &str) -> Self {
        Entry {
            at,
            kind,
            actor: actor.to_string(),
            detail: detail.to_string(),
        }
    }

    /// When it happened, as "16 Sep 19:04" — the date included, because an
    /// audit log is read days later.
    pub fn when(&self) -> String {
        when_text(self.at)
    }

    /// A one-line description for the terminal and the panel.
    pub fn describe(&self) -> String {
        let mut line = format!("{}  {}", self.when(), self.kind.label());
        if self.actor != ACTOR_TERMINAL {
            line.push_str(&format!(" from {}", self.actor));
        } else {
            line.push_str(" at this computer");
        }
        if !self.detail.is_empty() {
            line.push_str(&format!(" — {}", self.detail));
        }
        line
    }

    fn to_line(&self) -> String {
        // Detail may contain anything a user typed, so newlines and the field
        // separator are stripped to keep one event on one line.
        let clean = |text: &str| -> String {
            text.replace(['\n', '\r', '|'], " ").trim().to_string()
        };
        format!(
            "{}|{}|{}|{}",
            self.at,
            self.kind.code(),
            clean(&self.actor),
            clean(&self.detail)
        )
    }

    fn parse(line: &str) -> Option<Entry> {
        let mut fields = line.splitn(4, '|');
        let at: u64 = fields.next()?.trim().parse().ok()?;
        let kind = Kind::from_code(fields.next()?.trim())?;
        let actor = fields.next()?.trim().to_string();
        let detail = fields.next().unwrap_or("").trim().to_string();
        Some(Entry {
            at,
            kind,
            actor,
            detail,
        })
    }
}

fn log_file() -> PathBuf {
    std::path::Path::new(crate::paths::CONFIG_DIR).join("access.log")
}

/// Formats an epoch second as "16 Sep 19:04", including the date because an
/// audit log is read days later.
pub fn when_text(at: u64) -> String {
    use chrono::TimeZone;
    chrono::Local
        .timestamp_opt(at as i64, 0)
        .single()
        .map(|t| t.format("%-d %b %H:%M").to_string())
        .unwrap_or_else(|| "unknown time".to_string())
}

/// The in-memory log, newest last.
#[derive(Default)]
pub struct AccessLog {
    entries: VecDeque<Entry>,
}

impl AccessLog {
    /// Records an event, appending it to disk as well as memory.
    pub fn record(&mut self, event: Entry) {
        // Persist first: if the process dies shortly after, the record of what
        // happened matters more than the in-memory copy.
        append_to_file(&event);
        self.entries.push_back(event);
        while self.entries.len() > MAX_ENTRIES {
            self.entries.pop_front();
        }
    }

    /// The most recent entries, newest first.
    pub fn recent(&self, limit: usize) -> Vec<&Entry> {
        self.entries.iter().rev().take(limit).collect()
    }

    /// Everything, newest first.
    pub fn all_recent(&self) -> Vec<&Entry> {
        self.entries.iter().rev().collect()
    }

    /// The most recent entries worth alerting on, newest first.
    pub fn alerts(&self, limit: usize) -> Vec<&Entry> {
        self.entries
            .iter()
            .rev()
            .filter(|entry| entry.kind.is_alert())
            .take(limit)
            .collect()
    }

    /// How many failed sign-ins have come from `actor`.
    pub fn failures_from(&self, actor: &str) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.kind == Kind::SignInFailed && entry.actor == actor)
            .count()
    }

    /// The most recent successful sign-in, if any.
    pub fn last_sign_in(&self) -> Option<&Entry> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.kind == Kind::SignedIn)
    }

    /// Every address that has signed in, most recent first, deduplicated.
    /// This is the "who has been using this?" list.
    pub fn sign_in_sources(&self) -> Vec<(String, usize, u64)> {
        let mut seen: Vec<(String, usize, u64)> = Vec::new();
        for entry in self.entries.iter().rev() {
            if entry.kind != Kind::SignedIn {
                continue;
            }
            match seen.iter_mut().find(|(actor, _, _)| *actor == entry.actor) {
                Some((_, count, _)) => *count += 1,
                None => seen.push((entry.actor.clone(), 1, entry.at)),
            }
        }
        seen
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Reads the log from disk, keeping only the newest entries.
    pub fn load() -> Self {
        let content = std::fs::read_to_string(log_file()).unwrap_or_default();
        let parsed = parse_all(&content);
        AccessLog {
            entries: parsed,
        }
    }

    /// Rewrites the on-disk log from memory. Called once at startup so the
    /// file can't grow past [`MAX_ENTRIES`] over a long install.
    pub fn compact(&self) {
        crate::paths::ensure_dir();
        let path = log_file();
        let content: String = self.entries.iter().map(|e| e.to_line() + "\n").collect();
        if std::fs::write(&path, content).is_ok() {
            crate::paths::restrict(&path.to_string_lossy());
        }
    }
}

/// Parses a whole log file, skipping unusable lines and keeping only the
/// newest [`MAX_ENTRIES`].
pub fn parse_all(content: &str) -> VecDeque<Entry> {
    let mut entries: VecDeque<Entry> = content.lines().filter_map(Entry::parse).collect();
    while entries.len() > MAX_ENTRIES {
        entries.pop_front();
    }
    entries
}

fn append_to_file(entry: &Entry) {
    use std::io::Write;

    crate::paths::ensure_dir();
    let path = log_file();
    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(file) => file,
        // A failure to write the audit log must never take Curfew down; the
        // network being shaped matters more than the record of it.
        Err(_) => return,
    };
    if writeln!(file, "{}", entry.to_line()).is_ok() {
        crate::paths::restrict(&path.to_string_lossy());
    }
}

static LOG: OnceLock<Mutex<AccessLog>> = OnceLock::new();

fn log() -> &'static Mutex<AccessLog> {
    LOG.get_or_init(|| Mutex::new(AccessLog::load()))
}

/// Records an event, tolerating a poisoned mutex so a panic elsewhere can't
/// stop the audit trail.
pub fn record(kind: Kind, actor: &str, detail: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut guard = log().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.record(Entry::new(now, kind, actor, detail));
}

/// Runs `f` against the log.
pub fn with_log<T>(f: impl FnOnce(&AccessLog) -> T) -> T {
    let guard = log().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&guard)
}

/// Rewrites the on-disk log, dropping the oldest entries. Called once at
/// startup.
pub fn compact() {
    let guard = log().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.compact();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AccessLog {
        let mut log = AccessLog::default();
        log.record(Entry::new(1000, Kind::Started, ACTOR_TERMINAL, ""));
        log.record(Entry::new(1100, Kind::SignedIn, "192.168.1.31", ""));
        log.record(Entry::new(1200, Kind::SignInFailed, "192.168.1.44", ""));
        log.record(Entry::new(1300, Kind::SignInFailed, "192.168.1.44", ""));
        log.record(Entry::new(1400, Kind::SignedIn, "192.168.1.31", ""));
        log.record(Entry::new(
            1500,
            Kind::Action,
            "192.168.1.31",
            "blocked 192.168.1.27",
        ));
        log
    }

    #[test]
    fn entries_round_trip_through_the_file_format() {
        for kind in [
            Kind::Started,
            Kind::SignedIn,
            Kind::SignInFailed,
            Kind::Action,
            Kind::LockContention,
            Kind::OtherPanel,
            Kind::GatewayChanged,
        ] {
            let entry = Entry::new(1_700_000_000, kind, "192.168.1.27", "some detail");
            let parsed = Entry::parse(&entry.to_line()).expect("should parse back");
            assert_eq!(parsed, entry, "{kind:?} did not round-trip");
        }
    }

    #[test]
    fn every_kind_has_a_stable_unique_code() {
        // Old log lines must keep parsing across versions, so codes can't
        // drift or collide.
        let all = [
            Kind::Started,
            Kind::Stopped,
            Kind::SignedIn,
            Kind::SignInFailed,
            Kind::SignedOut,
            Kind::SessionRevoked,
            Kind::Action,
            Kind::LockContention,
            Kind::OtherPanel,
            Kind::GatewayChanged,
            Kind::Spoofing,
            Kind::Defense,
        ];
        let mut codes = std::collections::HashSet::new();
        for kind in all {
            assert!(codes.insert(kind.code()), "duplicate code {:?}", kind.code());
            assert_eq!(Kind::from_code(kind.code()), Some(kind));
        }
        assert_eq!(codes.len(), all.len());
    }

    #[test]
    fn skips_corrupt_lines_without_losing_the_rest() {
        let content = "\
not a line
|missing|fields|
1700000000|not_a_kind|1.2.3.4|detail
1700000001|signin|192.168.1.31|
1700000002|action|192.168.1.31|did something
";
        let entries = parse_all(content);
        assert_eq!(entries.len(), 2, "only the valid lines survive");
        assert_eq!(entries[0].kind, Kind::SignedIn);
        assert_eq!(entries[1].detail, "did something");
    }

    #[test]
    fn a_detail_containing_a_separator_cannot_forge_a_new_field() {
        // Detail is user-supplied free text in places; it must not be able to
        // shift the fields of the line it lives on.
        let entry = Entry::new(
            1,
            Kind::Action,
            "192.168.1.31",
            "weird|text\nsecond line",
        );
        let line = entry.to_line();
        assert_eq!(line.lines().count(), 1, "one event, one line");
        let parsed = Entry::parse(&line).unwrap();
        assert_eq!(parsed.kind, Kind::Action);
        assert_eq!(parsed.actor, "192.168.1.31");
        assert!(parsed.detail.contains("weird text"), "got {:?}", parsed.detail);
    }

    #[test]
    fn only_real_concerns_are_flagged_as_alerts() {
        for kind in [
            Kind::SignInFailed,
            Kind::LockContention,
            Kind::OtherPanel,
            Kind::GatewayChanged,
            Kind::Spoofing,
        ] {
            assert!(kind.is_alert(), "{kind:?} should alert");
        }
        // Routine use must not alert, or the alert becomes noise people learn
        // to ignore.
        for kind in [Kind::SignedIn, Kind::SignedOut, Kind::Action, Kind::Started] {
            assert!(!kind.is_alert(), "{kind:?} should not alert");
        }
    }

    #[test]
    fn reports_the_most_recent_entries_newest_first() {
        let log = sample();
        let recent = log.recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].at, 1500, "newest first");
        assert_eq!(recent[1].at, 1400);
        assert_eq!(recent[2].at, 1300, "the newest three, not the oldest");
        // And a limit larger than the log returns everything, newest first.
        let all = log.recent(100);
        assert_eq!(all.len(), 6);
        assert_eq!(all[5].at, 1000);
    }

    #[test]
    fn collects_only_the_alerts() {
        let log = sample();
        let alerts = log.alerts(10);
        assert_eq!(alerts.len(), 2, "the two failed sign-ins");
        assert!(alerts.iter().all(|e| e.kind == Kind::SignInFailed));
    }

    #[test]
    fn counts_failed_attempts_per_address() {
        // The number that tells the owner whether someone was guessing.
        let log = sample();
        assert_eq!(log.failures_from("192.168.1.44"), 2);
        assert_eq!(log.failures_from("192.168.1.31"), 0);
        assert_eq!(log.failures_from("10.0.0.1"), 0);
    }

    #[test]
    fn reports_the_last_sign_in() {
        let log = sample();
        let last = log.last_sign_in().expect("a sign-in");
        assert_eq!(last.at, 1400);
        assert_eq!(last.actor, "192.168.1.31");
    }

    #[test]
    fn lists_who_has_signed_in_and_how_often() {
        // This is the "is someone else using this?" answer.
        let log = sample();
        let sources = log.sign_in_sources();
        assert_eq!(sources.len(), 1, "one address signed in");
        assert_eq!(sources[0].0, "192.168.1.31");
        assert_eq!(sources[0].1, 2, "twice");
    }

    #[test]
    fn collapses_an_unknown_actor_into_a_single_row() {
        let mut log = AccessLog::default();
        log.record(Entry::new(1, Kind::SignedIn, "10.0.0.9", ""));
        log.record(Entry::new(2, Kind::SignedIn, "10.0.0.9", ""));
        log.record(Entry::new(3, Kind::SignedIn, "10.0.0.8", ""));
        let sources = log.sign_in_sources();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].0, "10.0.0.8", "most recent first");
        assert_eq!(sources[1].1, 2);
    }

    #[test]
    fn caps_what_it_keeps_in_memory() {
        let mut log = AccessLog::default();
        for i in 0..(MAX_ENTRIES + 250) {
            log.record(Entry::new(i as u64, Kind::Action, "this computer", "x"));
        }
        assert_eq!(log.len(), MAX_ENTRIES);
        // The oldest must be what was dropped.
        assert_eq!(log.recent(1)[0].at, (MAX_ENTRIES + 249) as u64);
    }

    #[test]
    fn caps_what_it_loads_from_disk() {
        let content: String = (0..(MAX_ENTRIES * 2))
            .map(|i| format!("{i}|action|this computer|\n"))
            .collect();
        let entries = parse_all(&content);
        assert_eq!(entries.len(), MAX_ENTRIES);
        assert_eq!(
            entries.front().unwrap().at,
            MAX_ENTRIES as u64,
            "keeps the newest, drops the oldest"
        );
    }

    #[test]
    fn describes_an_event_for_a_human() {
        let entry = Entry::new(1_700_000_000, Kind::SignInFailed, "192.168.1.44", "");
        let text = entry.describe();
        assert!(text.contains("WRONG PASSWORD"), "got {text}");
        assert!(text.contains("from 192.168.1.44"), "got {text}");

        let local = Entry::new(1_700_000_000, Kind::Action, ACTOR_TERMINAL, "blocked a device");
        let text = local.describe();
        assert!(text.contains("at this computer"), "got {text}");
        assert!(text.contains("blocked a device"), "got {text}");
    }

    #[test]
    fn a_terminal_action_does_not_claim_to_come_from_an_address() {
        let entry = Entry::new(1, Kind::Action, ACTOR_TERMINAL, "");
        assert!(!entry.describe().contains("from this computer"));
    }

    #[test]
    fn never_stores_a_password_even_if_one_is_passed_as_detail() {
        // A guard on the call sites more than the code, but worth pinning:
        // failures are recorded as a count, and the detail string is what the
        // caller chose to put there.
        let log = sample();
        for entry in log.all_recent() {
            assert!(
                !entry.detail.to_lowercase().contains("password"),
                "an entry mentions a password: {:?}",
                entry.detail
            );
        }
    }
}
