//! Bedtime windows: when throttling should be active.
//!
//! Supports several windows, each attached to a set of days, so a household
//! can express "school nights are 20:00-07:00 but weekends are 22:00-09:00".
//! Windows that cross midnight (e.g. 20:00-07:00) are handled, including the
//! part of the window that falls on the following day.
//!
//! On-disk format, one window per line:
//!
//! ```text
//! mon,tue,wed,thu,sun 20:00-07:00
//! sat,sun 22:00-09:00
//! ```
//!
//! A line with no day list (`20:00-07:00`) means every day, which is also the
//! format older versions of Curfew wrote — so an existing config keeps
//! working untouched. No windows at all means throttling is always on.

use crate::paths::CONFIG_DIR;
use chrono::{Datelike, Local, Weekday};

fn schedule_file() -> std::path::PathBuf {
    std::path::Path::new(CONFIG_DIR).join("schedule")
}

/// A set of weekdays, as a 7-bit mask with Monday as bit 0.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DaySet(u8);

impl DaySet {
    pub const EVERY: DaySet = DaySet(0b0111_1111);
    pub const WEEKDAYS: DaySet = DaySet(0b0001_1111);
    pub const WEEKENDS: DaySet = DaySet(0b0110_0000);

    /// Monday-first index, matching `chrono::Weekday::num_days_from_monday`.
    fn has_index(&self, index: u8) -> bool {
        index < 7 && self.0 & (1 << index) != 0
    }

    pub fn contains(&self, day: Weekday) -> bool {
        self.has_index(day.num_days_from_monday() as u8)
    }

    /// Compact form for the config file: `mon,tue,sat`.
    pub fn encode(&self) -> String {
        self.indices()
            .map(|i| ABBREV[i as usize])
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Human form for the dashboard and menus.
    pub fn label(&self) -> String {
        match *self {
            DaySet::EVERY => "every day".to_string(),
            DaySet::WEEKDAYS => "weekdays".to_string(),
            DaySet::WEEKENDS => "weekends".to_string(),
            _ => self
                .indices()
                .map(|i| NAMES[i as usize])
                .collect::<Vec<_>>()
                .join(", "),
        }
    }

    fn indices(&self) -> impl Iterator<Item = u8> + '_ {
        (0..7u8).filter(move |i| self.has_index(*i))
    }

    /// Parses a day list. Accepts abbreviations and full names, comma lists,
    /// inclusive ranges (including ones that wrap, like `fri-mon`), and the
    /// words `every`/`daily`, `weekdays`, `weekends`.
    pub fn parse(input: &str) -> Option<DaySet> {
        let lower = input.trim().to_lowercase();
        match lower.as_str() {
            "all" | "every" | "everyday" | "daily" => return Some(DaySet::EVERY),
            "weekday" | "weekdays" => return Some(DaySet::WEEKDAYS),
            "weekend" | "weekends" => return Some(DaySet::WEEKENDS),
            "" => return None,
            _ => {}
        }

        let mut bits = 0u8;
        for part in lower.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            match part.split_once('-') {
                Some((from, to)) => {
                    let (from, to) = (day_index(from)?, day_index(to)?);
                    let mut i = from;
                    loop {
                        bits |= 1 << i;
                        if i == to {
                            break;
                        }
                        i = (i + 1) % 7;
                    }
                }
                None => bits |= 1 << day_index(part)?,
            }
        }

        if bits == 0 {
            None
        } else {
            Some(DaySet(bits))
        }
    }
}

const ABBREV: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
const NAMES: [&str; 7] = [
    "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun",
];

fn day_index(token: &str) -> Option<u8> {
    let token = token.trim();
    ABBREV
        .iter()
        .position(|a| *a == token)
        .or_else(|| {
            // Also accept full names ("monday") and the two-letter forms some
            // people type ("mo").
            ABBREV.iter().position(|a| {
                let full = match *a {
                    "mon" => "monday",
                    "tue" => "tuesday",
                    "wed" => "wednesday",
                    "thu" => "thursday",
                    "fri" => "friday",
                    "sat" => "saturday",
                    _ => "sunday",
                };
                full == token || (&full[..2] == token)
            })
        })
        .map(|i| i as u8)
}

/// One bedtime window: a time range that applies on a set of days.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    pub days: DaySet,
    /// `HH:MM`, 24-hour.
    pub start: String,
    /// `HH:MM`, 24-hour. May be earlier than `start` (overnight window).
    pub end: String,
}

impl Window {
    pub fn new(days: DaySet, start: &str, end: &str) -> Self {
        Window {
            days,
            start: start.to_string(),
            end: end.to_string(),
        }
    }

    fn overnight(&self) -> bool {
        self.start > self.end
    }

    /// True if `now` falls inside this window, given the current and previous
    /// weekday. `yesterday` is needed because the tail of an overnight window
    /// (00:00 through `end`) belongs to the day the window *started*.
    fn matches(&self, today: Weekday, yesterday: Weekday, now: &str) -> bool {
        if self.overnight() {
            (self.days.contains(today) && now >= self.start.as_str())
                || (self.days.contains(yesterday) && now < self.end.as_str())
        } else {
            self.days.contains(today) && now >= self.start.as_str() && now < self.end.as_str()
        }
    }

    /// How the window reads in a summary line, e.g.
    /// "Mon, Tue 20:00-07:00".
    pub fn describe(&self) -> String {
        format!("{} {}-{}", self.days.label(), self.start, self.end)
    }
}

/// Every configured window. An empty schedule means "always active".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Schedule {
    pub windows: Vec<Window>,
}

pub fn load() -> Option<Schedule> {
    let content = std::fs::read_to_string(schedule_file()).ok()?;
    let windows = parse(&content);
    if windows.is_empty() {
        None
    } else {
        Some(Schedule { windows })
    }
}

/// Parses config file contents into windows, skipping lines it can't
/// understand rather than discarding the whole schedule.
pub fn parse(content: &str) -> Vec<Window> {
    content.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<Window> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // "<days> <start>-<end>" or, from older versions, just "<start>-<end>".
    let (days, range) = match line.split_once(char::is_whitespace) {
        Some((days, range)) => (DaySet::parse(days)?, range.trim()),
        None => (DaySet::EVERY, line),
    };
    let (start, end) = range.split_once('-')?;
    let (start, end) = (start.trim(), end.trim());
    if !valid(start) || !valid(end) {
        return None;
    }
    Some(Window::new(days, start, end))
}

pub fn save(schedule: &Schedule) {
    crate::paths::ensure_dir();
    let content: String = schedule
        .windows
        .iter()
        .map(|w| format!("{} {}-{}\n", w.days.encode(), w.start, w.end))
        .collect();
    let path = schedule_file();
    if std::fs::write(&path, content).is_ok() {
        crate::paths::restrict(&path.to_string_lossy());
    }
}

pub fn clear() {
    let _ = std::fs::remove_file(schedule_file());
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
    Local::now().format("%H:%M").to_string()
}

/// True if throttling should be active right now. No schedule, or an empty
/// one, means always active — the original, simpler behavior.
pub fn is_active(schedule: &Option<Schedule>) -> bool {
    is_active_at(schedule, Local::now().weekday(), &now_hm())
}

/// The testable core of [`is_active`]: no clock reads, so it can be exercised
/// against any day and time.
pub fn is_active_at(schedule: &Option<Schedule>, today: Weekday, now: &str) -> bool {
    let Some(schedule) = schedule else {
        return true;
    };
    if schedule.windows.is_empty() {
        return true;
    }
    let yesterday = today.pred();
    schedule
        .windows
        .iter()
        .any(|w| w.matches(today, yesterday, now))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(lines: &[&str]) -> Option<Schedule> {
        let windows = parse(&lines.join("\n"));
        if windows.is_empty() {
            None
        } else {
            Some(Schedule { windows })
        }
    }

    #[test]
    fn no_schedule_means_always_active() {
        assert!(is_active_at(&None, Weekday::Mon, "12:00"));
        assert!(is_active_at(&None, Weekday::Sun, "03:00"));
    }

    #[test]
    fn empty_window_list_means_always_active() {
        let empty = Some(Schedule::default());
        assert!(is_active_at(&empty, Weekday::Mon, "12:00"));
    }

    #[test]
    fn accepts_24h_times() {
        assert!(valid("00:00"));
        assert!(valid("23:59"));
        assert!(!valid("24:00"));
        assert!(!valid("20:60"));
        assert!(!valid("8:00"));
        assert!(!valid("20-00"));
        assert!(!valid(""));
    }

    #[test]
    fn reads_the_legacy_single_window_format() {
        // What older versions wrote: no day list, applies every day.
        let s = schedule(&["20:00-07:00"]);
        assert!(is_active_at(&s, Weekday::Mon, "22:00"));
        assert!(is_active_at(&s, Weekday::Sun, "03:00"));
        assert!(!is_active_at(&s, Weekday::Mon, "12:00"));
        assert_eq!(s.unwrap().windows[0].days, DaySet::EVERY);
    }

    #[test]
    fn plain_window_is_active_only_between_start_and_end() {
        let s = schedule(&["09:00-11:00"]);
        assert!(!is_active_at(&s, Weekday::Mon, "08:59"));
        assert!(is_active_at(&s, Weekday::Mon, "09:00"));
        assert!(is_active_at(&s, Weekday::Mon, "10:59"));
        assert!(!is_active_at(&s, Weekday::Mon, "11:00"));
    }

    #[test]
    fn overnight_window_covers_both_sides_of_midnight() {
        let s = schedule(&["20:00-07:00"]);
        assert!(is_active_at(&s, Weekday::Mon, "23:30"), "before midnight");
        assert!(is_active_at(&s, Weekday::Tue, "02:00"), "after midnight");
        assert!(!is_active_at(&s, Weekday::Tue, "07:00"), "exclusive end");
        assert!(!is_active_at(&s, Weekday::Tue, "19:59"));
    }

    #[test]
    fn day_filtering_applies() {
        let s = schedule(&["mon,tue 20:00-23:00"]);
        assert!(is_active_at(&s, Weekday::Mon, "21:00"));
        assert!(is_active_at(&s, Weekday::Tue, "21:00"));
        assert!(!is_active_at(&s, Weekday::Wed, "21:00"));
    }

    #[test]
    fn overnight_window_uses_the_starting_days_for_its_tail() {
        // Saturday 20:00 - Sunday 07:00 must NOT run on Monday morning,
        // which is the bug a naive "check today only" implementation has.
        let s = schedule(&["sat 20:00-07:00"]);
        assert!(is_active_at(&s, Weekday::Sat, "23:00"));
        assert!(is_active_at(&s, Weekday::Sun, "02:00"));
        assert!(!is_active_at(&s, Weekday::Mon, "02:00"));
        assert!(!is_active_at(&s, Weekday::Sun, "23:00"), "Sun isn't in the set");
    }

    #[test]
    fn multiple_windows_are_any_of() {
        let s = schedule(&["mon,tue,wed,thu,sun 20:00-07:00", "sat,sun 22:00-09:00"]);
        assert!(is_active_at(&s, Weekday::Wed, "21:00"));
        assert!(is_active_at(&s, Weekday::Sat, "23:00"));
        assert!(!is_active_at(&s, Weekday::Fri, "21:00"));
    }

    #[test]
    fn parses_day_expressions() {
        assert_eq!(DaySet::parse("mon"), Some(DaySet(0b0000_0001)));
        assert_eq!(DaySet::parse("monday"), Some(DaySet(0b0000_0001)));
        assert_eq!(DaySet::parse("mo"), Some(DaySet(0b0000_0001)));
        assert_eq!(DaySet::parse("mon-fri"), Some(DaySet::WEEKDAYS));
        assert_eq!(DaySet::parse("weekdays"), Some(DaySet::WEEKDAYS));
        assert_eq!(DaySet::parse("weekends"), Some(DaySet::WEEKENDS));
        assert_eq!(DaySet::parse("everyday"), Some(DaySet::EVERY));
        assert_eq!(DaySet::parse("sat,sun"), Some(DaySet::WEEKENDS));
        assert_eq!(DaySet::parse("nonsense"), None);
    }

    #[test]
    fn day_ranges_may_wrap_around_the_week() {
        // fri-mon covers Fri, Sat, Sun, Mon.
        let set = DaySet::parse("fri-mon").unwrap();
        assert!(set.contains(Weekday::Fri));
        assert!(set.contains(Weekday::Sat));
        assert!(set.contains(Weekday::Sun));
        assert!(set.contains(Weekday::Mon));
        assert!(!set.contains(Weekday::Tue));
    }

    #[test]
    fn day_sets_round_trip_through_the_config_format() {
        for set in [
            DaySet::EVERY,
            DaySet::WEEKDAYS,
            DaySet::WEEKENDS,
            DaySet::parse("mon,thu").unwrap(),
        ] {
            assert_eq!(DaySet::parse(&set.encode()), Some(set), "failed on {set:?}");
        }
    }

    #[test]
    fn skips_bad_lines_without_dropping_good_ones() {
        let windows = parse("garbage\nmon 20:00-07:00\n\n# comment\nxx:yy-zz:ww");
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].start, "20:00");
    }

    #[test]
    fn describes_a_window_for_the_dashboard() {
        let s = schedule(&["mon,tue 20:00-07:00"]).unwrap();
        assert_eq!(s.windows[0].describe(), "Mon, Tue 20:00-07:00");
        let weekend = schedule(&["weekends 22:00-09:00"]).unwrap();
        assert_eq!(weekend.windows[0].describe(), "weekends 22:00-09:00");
    }
}
