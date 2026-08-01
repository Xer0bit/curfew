//! Optional daily curfew window: throttling is only active between `start`
//! and `end` (HH:MM, 24h) and pauses automatically outside it. Windows that
//! cross midnight (e.g. 20:00-07:00) are supported. No schedule means
//! throttling is always active — the original, simpler behavior.

use crate::system::run;

const SCHEDULE_FILE: &str = "/etc/curfew/schedule";

pub type Window = (String, String);

pub fn load() -> Option<Window> {
    let content = std::fs::read_to_string(SCHEDULE_FILE).ok()?;
    let (start, end) = content.trim().split_once('-')?;
    Some((start.to_string(), end.to_string()))
}

pub fn save(start: &str, end: &str) {
    std::fs::create_dir_all("/etc/curfew").unwrap();
    std::fs::write(SCHEDULE_FILE, format!("{start}-{end}")).unwrap();
}

pub fn clear() {
    let _ = std::fs::remove_file(SCHEDULE_FILE);
}

/// Accepts 24-hour `HH:MM`.
pub fn valid(t: &str) -> bool {
    let bytes = t.as_bytes();
    if bytes.len() != 5 || bytes[2] != b':' {
        return false;
    }
    match (t[0..2].parse::<u32>(), t[3..5].parse::<u32>()) {
        (Ok(h), Ok(m)) => h < 24 && m < 60,
        _ => false,
    }
}

fn now_hm() -> String {
    run("date", &["+%H:%M"])
}

/// True if there's no schedule (always active) or the current time falls
/// within it.
pub fn is_active(schedule: &Option<Window>) -> bool {
    let (start, end) = match schedule {
        None => return true,
        Some(s) => s,
    };
    let now = now_hm();
    if start <= end {
        now.as_str() >= start.as_str() && now.as_str() < end.as_str()
    } else {
        // Overnight window, e.g. 20:00-07:00.
        now.as_str() >= start.as_str() || now.as_str() < end.as_str()
    }
}
