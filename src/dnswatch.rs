//! Watching what sites devices actually ask for.
//!
//! Curfew already sits in the middle of every throttled device's traffic (that
//! is what the ARP spoofing is for), so their DNS lookups pass through this
//! machine. `tcpdump` is used to observe them, the same "shell out to a system
//! tool" approach the rest of Curfew takes.
//!
//! # Why DNS and not the actual requests
//!
//! Nearly all web traffic is HTTPS, whose contents — and the requested URL —
//! are encrypted. The one readable signal left is the DNS lookup that
//! precedes a connection: it tells you *which site* a device is trying to
//! reach, even though the page itself stays private. That is exactly the
//! question being asked here ("what requests are being made"), so it is what
//! this module collects.
//!
//! Two honest limitations, both surfaced in the UI rather than hidden:
//!
//! - Only devices being throttled are visible. An exempt device isn't routed
//!   through this machine, so its lookups aren't seen.
//! - A device using DNS-over-HTTPS or a hardcoded resolver bypasses this
//!   entirely. It shows what ordinary devices ask for, not everything.

use crate::colors::{DIM, RESET};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// How many recent lookups to keep per device. Enough to see a pattern,
/// small enough that memory stays flat on a busy network.
const PER_DEVICE_HISTORY: usize = 40;

/// How many devices to track. Beyond this, new devices are ignored rather
/// than growing memory without bound.
const MAX_TRACKED_DEVICES: usize = 200;

/// One observed lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    pub domain: String,
    /// Unix epoch seconds.
    pub at: u64,
}

/// Parses one line of `tcpdump -n -l -q port 53` output.
///
/// Lines look like:
///
/// ```text
/// 19:04:02.123456 IP 192.168.1.27.54321 > 192.168.1.1.53: 12345+ A? www.youtube.com. (34)
/// 19:04:02.234567 IP 192.168.1.27.54321 > 192.168.1.1.53: 12345+ AAAA? yt3.ggpht.com. (32)
/// ```
///
/// Returns the querying IP and the domain. Non-query lines (responses, other
/// record types, malformed output) return `None`.
pub fn parse_query_line(line: &str) -> Option<(String, String)> {
    // Only questions, marked by the `?` in `A?` / `AAAA?`. Responses lack it,
    // and counting both would double every entry.
    let query_index = line.find('?')?;
    let before_question = line[..query_index].trim_end();

    // The record type is the token just before the `?`.
    let record_type = before_question.split_whitespace().last()?;
    if !matches!(
        record_type,
        "A" | "AAAA" | "CNAME" | "PTR" | "MX" | "TXT" | "SRV" | "HTTPS"
    ) {
        return None;
    }

    // The domain is the token after the `?`, with the trailing dot removed.
    let after_question = line[query_index + 1..].trim_start();
    let domain_token = after_question.split_whitespace().next()?;
    let domain = domain_token.trim_end_matches('.').to_lowercase();
    if domain.is_empty() {
        return None;
    }

    // The source address is `IP <addr>.<port> >`. tcpdump appends the port
    // with a dot, not a colon, so the address is everything before the last
    // dot — then parsed to reject anything that isn't really an IPv4 address.
    let ip_marker = before_question.find(" IP ")?;
    let source = before_question[ip_marker + 4..].split_whitespace().next()?;
    let (address, _port) = source.rsplit_once('.')?;
    if address.parse::<std::net::Ipv4Addr>().is_err() {
        return None;
    }

    Some((address.to_string(), domain))
}

/// True for names that say nothing useful about what a device is doing:
/// reverse lookups, local service discovery, and query noise.
pub fn is_noise(domain: &str) -> bool {
    const NOISE_SUFFIXES: &[&str] = &[
        ".in-addr.arpa",
        ".ip6.arpa",
        ".local",
        ".localdomain",
        ".lan",
        ".home",
        ".arpa",
    ];
    const NOISE_EXACT: &[&str] = &["localhost", "_dns.resolver.arpa", "time.android.com"];
    if NOISE_EXACT.contains(&domain) {
        return true;
    }
    if NOISE_SUFFIXES.iter().any(|suffix| domain.ends_with(suffix)) {
        return true;
    }
    // Bare hostnames with no dot are usually LAN chatter.
    !domain.contains('.')
}

/// A device's recent lookups, newest last.
#[derive(Default)]
pub struct WatchLog {
    by_ip: HashMap<String, VecDeque<Lookup>>,
    /// Counted separately so a capped history still reports an honest total.
    totals: HashMap<String, u64>,
}

impl WatchLog {
    /// Records one lookup. Duplicates of the most recent entry for that device
    /// are collapsed — resolvers retry, and a wall of identical lines hides
    /// everything else.
    pub fn record(&mut self, ip: &str, domain: &str, at: u64) {
        if is_noise(domain) {
            return;
        }

        let tracked = self.by_ip.contains_key(ip) || self.by_ip.len() < MAX_TRACKED_DEVICES;
        if !tracked {
            return;
        }

        *self.totals.entry(ip.to_string()).or_insert(0) += 1;

        let history = self.by_ip.entry(ip.to_string()).or_default();
        if history.back().is_some_and(|last| last.domain == domain) {
            // Same site again straight away; don't repeat it.
            if let Some(last) = history.back_mut() {
                last.at = at;
            }
            return;
        }
        history.push_back(Lookup {
            domain: domain.to_string(),
            at,
        });
        while history.len() > PER_DEVICE_HISTORY {
            history.pop_front();
        }
    }

    /// A device's recent lookups, newest first.
    pub fn recent_for(&self, ip: &str) -> Vec<Lookup> {
        self.by_ip
            .get(ip)
            .map(|history| history.iter().rev().cloned().collect())
            .unwrap_or_default()
    }

    /// How many lookups we've seen from a device in total, even if the
    /// history itself has rolled over.
    pub fn total_for(&self, ip: &str) -> u64 {
        self.totals.get(ip).copied().unwrap_or(0)
    }

    /// The distinct domains a device has asked for recently.
    pub fn domains_for(&self, ip: &str) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for lookup in self.recent_for(ip) {
            if !seen.contains(&lookup.domain) {
                seen.push(lookup.domain);
            }
        }
        seen
    }

    /// The most-asked-for domains across every device.
    pub fn top_domains(&self, limit: usize) -> Vec<(String, u64)> {
        let mut counts: HashMap<&str, u64> = HashMap::new();
        for history in self.by_ip.values() {
            for lookup in history {
                *counts.entry(lookup.domain.as_str()).or_insert(0) += 1;
            }
        }
        let mut ranked: Vec<(String, u64)> = counts
            .into_iter()
            .map(|(domain, count)| (domain.to_string(), count))
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        ranked.truncate(limit);
        ranked
    }

    /// Forgets a device's history.
    pub fn forget(&mut self, ip: &str) {
        self.by_ip.remove(ip);
        self.totals.remove(ip);
    }

    /// Forgets devices that are no longer being tracked, so a long-running
    /// session doesn't accumulate history for devices that left.
    pub fn retain_only(&mut self, ips: &[String]) {
        self.by_ip.retain(|ip, _| ips.contains(ip));
        self.totals.retain(|ip, _| ips.contains(ip));
    }

    pub fn tracked_devices(&self) -> usize {
        self.by_ip.len()
    }
}

/// The running observer, if one is active.
struct Observer {
    child: Child,
    stop: Arc<AtomicBool>,
}

static OBSERVER: OnceLock<Mutex<Option<Observer>>> = OnceLock::new();
static LOG: OnceLock<Mutex<WatchLog>> = OnceLock::new();

fn log() -> &'static Mutex<WatchLog> {
    LOG.get_or_init(|| Mutex::new(WatchLog::default()))
}

fn observer_slot() -> &'static Mutex<Option<Observer>> {
    OBSERVER.get_or_init(|| Mutex::new(None))
}

/// Runs `f` against the shared log, tolerating a poisoned mutex so one panic
/// doesn't permanently stop observation.
pub fn with_log<T>(f: impl FnOnce(&mut WatchLog) -> T) -> T {
    let mut guard = log()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut guard)
}

/// True if `tcpdump` is on `PATH`. Without it, request visibility is simply
/// unavailable and the UI says so.
pub fn available() -> bool {
    crate::system::tool_exists("tcpdump")
}

/// Starts observing DNS on `iface`. Does nothing if already running or if
/// `tcpdump` is missing. Returns false when unavailable.
pub fn start(iface: &str) -> bool {
    let mut slot = observer_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_some() {
        return true; // already watching
    }
    if !available() {
        return false;
    }

    // -n: don't resolve names (we want the wire values)
    // -l: line-buffered, so results appear immediately
    // -q: less noise per packet
    // port 53 on the Wi-Fi interface, which is where spoofed traffic arrives.
    let mut child = match Command::new("tcpdump")
        .args([
            "-n", "-l", "-q", "-i", iface, "-s", "512", "port", "53",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("{DIM}Request log unavailable: could not start tcpdump ({e}){RESET}");
            return false;
        }
    };

    // Moving the pipe's handle into the reader thread lets the `Child` stay
    // here so shutdown can still kill the process.
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return false;
    };

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = Arc::clone(&stop);
    *slot = Some(Observer { child, stop });

    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if stop_for_thread.load(Ordering::Relaxed) {
                break;
            }
            let Ok(line) = line else { break };
            if let Some((ip, domain)) = parse_query_line(&line) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                with_log(|log| log.record(&ip, &domain, now));
            }
        }
    });

    true
}

/// Explains why request visibility isn't available, or `None` if it is.
pub fn unavailability_reason() -> Option<String> {
    if !available() {
        return Some(
            "Install tcpdump to see which sites your devices ask for (Debian/Ubuntu: \
             sudo apt install tcpdump)."
                .to_string(),
        );
    }
    None
}

/// Stops observing and reaps the helper process.
pub fn stop() {
    let mut slot = observer_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(mut observer) = slot.take() {
        observer.stop.store(true, Ordering::Relaxed);
        let _ = observer.child.kill();
        let _ = observer.child.wait();
    }
}

/// True if the observer is currently running.
pub fn is_running() -> bool {
    let slot = observer_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    slot.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_a_query() {
        let line = "19:04:02.123456 IP 192.168.1.27.54321 > 192.168.1.1.53: 12345+ A? www.youtube.com. (34)";
        assert_eq!(
            parse_query_line(line),
            Some(("192.168.1.27".to_string(), "www.youtube.com".to_string()))
        );
    }

    #[test]
    fn parses_quad_a_and_other_record_types() {
        for (line, domain) in [
            (
                "19:04:02.234567 IP 192.168.1.27.54321 > 192.168.1.1.53: 12345+ AAAA? yt3.ggpht.com. (32)",
                "yt3.ggpht.com",
            ),
            (
                "19:04:03.1 IP 192.168.1.27.5000 > 192.168.1.1.53: 1+ CNAME? cdn.example.org. (30)",
                "cdn.example.org",
            ),
            (
                "19:04:04.1 IP 192.168.1.27.5001 > 192.168.1.1.53: 2+ MX? mail.example.org. (30)",
                "mail.example.org",
            ),
        ] {
            let parsed = parse_query_line(line).unwrap_or_else(|| panic!("failed on {line}"));
            assert_eq!(parsed.1, domain);
        }
    }

    #[test]
    fn normalises_the_domain() {
        // Trailing root dot stripped, case folded.
        let line = "19:04:02.1 IP 192.168.1.27.5 > 192.168.1.1.53: 1+ A? WWW.Example.COM. (30)";
        assert_eq!(parse_query_line(line).unwrap().1, "www.example.com");
    }

    #[test]
    fn ignores_responses_not_just_queries() {
        // A response has no `?`; counting responses would double every entry.
        let line = "19:04:02.3 IP 192.168.1.1.53 > 192.168.1.27.54321: 12345 3/0/0 A 142.250.1.1 (48)";
        assert_eq!(parse_query_line(line), None);
    }

    #[test]
    fn ignores_lines_it_does_not_understand() {
        for line in [
            "",
            "listening on wlan0, link-type EN10MB",
            "19:04:02.1 IP 192.168.1.27.5 > 192.168.1.1.53: 1+ ZZZ? example.com. (30)",
            "tcpdump: verbose output suppressed",
        ] {
            assert_eq!(parse_query_line(line), None, "should ignore {line:?}");
        }
    }

    #[test]
    fn identifies_lan_and_reverse_lookup_noise() {
        for noisy in [
            "localhost",
            "1.1.168.192.in-addr.arpa",
            "printer.local",
            "nas.localdomain",
            "router.lan",
            "appletv.home",
            "time.android.com",
            "no-dot-hostname",
        ] {
            assert!(is_noise(noisy), "{noisy} should be filtered as noise");
        }
    }

    #[test]
    fn keeps_ordinary_web_lookups() {
        for real in [
            "www.youtube.com",
            "api.github.com",
            "cdn.jsdelivr.net",
            "example.co.uk",
        ] {
            assert!(!is_noise(real), "{real} should be kept");
        }
    }

    #[test]
    fn records_and_returns_recent_lookups_newest_first() {
        let mut log = WatchLog::default();
        log.record("192.168.1.27", "a.com", 100);
        log.record("192.168.1.27", "b.com", 200);
        log.record("192.168.1.27", "c.com", 300);
        let recent: Vec<String> = log.recent_for("192.168.1.27").into_iter().map(|l| l.domain).collect();
        assert_eq!(recent, vec!["c.com", "b.com", "a.com"]);
    }

    #[test]
    fn keeps_history_separate_per_device() {
        let mut log = WatchLog::default();
        log.record("192.168.1.27", "kids-site.com", 100);
        log.record("192.168.1.42", "work-site.com", 100);
        assert_eq!(log.domains_for("192.168.1.27"), vec!["kids-site.com"]);
        assert_eq!(log.domains_for("192.168.1.42"), vec!["work-site.com"]);
    }

    #[test]
    fn collapses_repeated_lookups_of_the_same_site() {
        // Resolvers retry constantly; a wall of identical entries would hide
        // everything else.
        let mut log = WatchLog::default();
        for _ in 0..20 {
            log.record("192.168.1.27", "youtube.com", 100);
        }
        assert_eq!(log.recent_for("192.168.1.27").len(), 1);
        assert_eq!(log.total_for("192.168.1.27"), 20, "the total stays honest");
    }

    #[test]
    fn does_not_collapse_a_visit_interleaved_with_others() {
        let mut log = WatchLog::default();
        log.record("192.168.1.27", "a.com", 1);
        log.record("192.168.1.27", "b.com", 2);
        log.record("192.168.1.27", "a.com", 3);
        assert_eq!(log.recent_for("192.168.1.27").len(), 3);
    }

    #[test]
    fn history_is_capped_but_the_total_is_not() {
        let mut log = WatchLog::default();
        for i in 0..(PER_DEVICE_HISTORY * 3) {
            log.record("192.168.1.27", &format!("site{i}.com"), i as u64);
        }
        assert_eq!(log.recent_for("192.168.1.27").len(), PER_DEVICE_HISTORY);
        assert_eq!(log.total_for("192.168.1.27"), (PER_DEVICE_HISTORY * 3) as u64);
    }

    #[test]
    fn noise_never_reaches_the_log() {
        let mut log = WatchLog::default();
        log.record("192.168.1.27", "1.1.168.192.in-addr.arpa", 100);
        log.record("192.168.1.27", "printer.local", 100);
        assert!(log.recent_for("192.168.1.27").is_empty());
        assert_eq!(log.total_for("192.168.1.27"), 0);
    }

    #[test]
    fn stops_tracking_beyond_the_device_cap() {
        let mut log = WatchLog::default();
        for i in 0..(MAX_TRACKED_DEVICES + 50) {
            log.record(&format!("10.0.0.{i}"), "example.com", 1);
        }
        assert!(log.tracked_devices() <= MAX_TRACKED_DEVICES);
    }

    #[test]
    fn retains_only_devices_still_being_tracked() {
        let mut log = WatchLog::default();
        log.record("10.0.0.1", "a.com", 1);
        log.record("10.0.0.2", "b.com", 1);
        log.retain_only(&["10.0.0.1".to_string()]);
        assert_eq!(log.tracked_devices(), 1);
        assert!(log.domains_for("10.0.0.2").is_empty());
    }

    #[test]
    fn ranks_the_most_asked_for_domains() {
        let mut log = WatchLog::default();
        log.record("10.0.0.1", "popular.com", 1);
        log.record("10.0.0.1", "other.com", 2);
        log.record("10.0.0.1", "popular.com", 3);
        log.record("10.0.0.2", "popular.com", 4);
        let top = log.top_domains(5);
        assert_eq!(top.first(), Some(&("popular.com".to_string(), 3)));
    }

    #[test]
    fn forgetting_a_device_clears_its_history() {
        let mut log = WatchLog::default();
        log.record("10.0.0.1", "a.com", 1);
        log.forget("10.0.0.1");
        assert!(log.domains_for("10.0.0.1").is_empty());
        assert_eq!(log.total_for("10.0.0.1"), 0);
    }
}
