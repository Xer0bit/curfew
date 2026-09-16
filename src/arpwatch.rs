//! Detecting ARP spoofing on your network.
//!
//! This is the active version of "is someone doing this to me?": rather than
//! noticing that another Curfew has a panel listening, it watches the ARP
//! traffic itself and reports when something is claiming a device's address.
//!
//! # How the detection works
//!
//! ARP is the part of Ethernet that answers "which hardware address owns this
//! IP?". Normally a device answers only for its own address, so a stable
//! mapping holds: one IP, one hardware address, forever. Every form of
//! throttling-by-interception breaks that in a way that is visible from the
//! wire — which is exactly what Curfew itself does:
//!
//! 1. **A claimed address changes.** Something announces that a device's IP is
//!    at a *different* hardware address than before. This is the definitive
//!    signature of ARP spoofing, and how Curfew redirects a device's traffic.
//! 2. **One machine claims many addresses.** A real device owns one IP. Any
//!    machine claiming a handful of them is impersonating several devices at
//!    once — again, precisely what a throttling tool does.
//! 3. **A claimed address is repeated constantly.** A device re-announces its
//!    address rarely. Spoofing tools deliberately repeat it about once a
//!    second to win the race against the real device, which stands out
//!    sharply against normal traffic.
//!
//! # This watches for Curfew itself, on purpose — so it has to exclude it
//!
//! Curfew spoofs every throttled device, so all three patterns describe its
//! own behaviour. Left alone, the detector would alert about itself
//! continuously and be worthless notice-board noise.
//!
//! So [`ArpWatcher`] is told this machine's own hardware address and **never
//! raises a finding that its own activity explains** — a conflict or flood
//! involving our address, or our address claiming many IPs, is us doing our
//! job. What's left is another machine doing the same thing, which is the
//! question being asked.
//!
//! Everything here only reports. Nothing is blocked, un-spoofed, or fought
//! over.

use crate::colors::RESET;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;

/// How long a claimed address must be re-announced within to count as a
/// flood. One minute is long enough to be stable, short enough to notice.
pub const FLOOD_WINDOW_SECS: u64 = 60;

/// Announcements for one address within the window before it counts as a
/// flood.
///
/// A device re-announces its address at most a handful of times a minute
/// (usually after waking or renewing a lease), while a spoofing tool repeats
/// it every second — around 60 a minute. 20 sits clearly between the two.
pub const FLOOD_MIN_REPEATS: usize = 20;

/// Distinct IPs one machine must claim before that counts as impersonation.
/// A real device owns one, occasionally two; a tool suppressing several
/// devices claims as many as it is throttling.
pub const IMPERSONATION_MIN_IPS: usize = 3;

/// How many findings to keep for display.
const MAX_FINDINGS: usize = 100;

/// Addresses to track. A home network has tens.
const MAX_BINDINGS: usize = 512;

/// One address and the hardware addresses that have claimed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArpBinding {
    pub ip: String,
    /// Every distinct hardware address seen claiming this IP, oldest first.
    /// More than one entry means someone is lying about this address.
    pub macs: Vec<String>,
    /// Total announcements seen for this address.
    pub announcements: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Something suspicious observed in ARP traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub at: u64,
    pub kind: FindingKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FindingKind {
    /// One IP, claimed by two different hardware addresses.
    Conflict {
        ip: String,
        was: String,
        now: String,
    },
    /// One machine claiming several different IPs.
    Impersonation { mac: String, claimed: Vec<String> },
    /// One address re-announced far more often than a device ever would.
    Flood { ip: String, mac: String, repeats: usize },
}

impl Finding {
    /// A stable key used to avoid reporting the same situation over and over.
    fn dedup_key(&self) -> String {
        match &self.kind {
            FindingKind::Conflict { ip, was, now } => format!("conflict:{ip}:{was}:{now}"),
            FindingKind::Impersonation { mac, .. } => format!("impostor:{mac}"),
            FindingKind::Flood { ip, mac, .. } => format!("flood:{ip}:{mac}"),
        }
    }

    /// A plain-language sentence for the terminal and the panel.
    pub fn describe(&self) -> String {
        match &self.kind {
            FindingKind::Conflict { ip, was, now } => format!(
                "{ip} is now being claimed by {now}, but it belongs to {was} \
                 — something is intercepting that device's traffic"
            ),
            FindingKind::Impersonation { mac, claimed } => format!(
                "{mac} is claiming {} different addresses ({}) — one machine \
                 pretending to be several devices",
                claimed.len(),
                claimed.join(", ")
            ),
            FindingKind::Flood { ip, mac, repeats } => format!(
                "{mac} is re-announcing {ip} {repeats} times a minute — devices \
                 don't do that, throttling tools do"
            ),
        }
    }

    /// A short label for the audit log.
    pub fn summary(&self) -> String {
        match &self.kind {
            FindingKind::Conflict { ip, was, now } => {
                format!("address conflict for {ip}: {was} vs {now}")
            }
            FindingKind::Impersonation { mac, claimed } => {
                format!("{mac} claiming {} addresses", claimed.len())
            }
            FindingKind::Flood { ip, mac, repeats } => {
                format!("{mac} flooding announcements for {ip} ({repeats}/min)")
            }
        }
    }
}

/// Extracts `(ip, mac)` from one line of `tcpdump ... arp` output.
///
/// Only *replies* are parsed, because only a reply asserts a binding. Both
/// tcpdump layouts are accepted:
///
/// ```text
/// 19:04:02.123456 ARP, Reply 192.168.1.1 is-at aa:bb:cc:dd:ee:ff, length 28
/// 19:04:02.123456 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66, ethertype ARP (0x0806),
///     length 42: Reply 192.168.1.1 is-at aa:bb:cc:dd:ee:ff, length 28
/// ```
///
/// A request ("Request who-has 192.168.1.1 tell 192.168.1.27") asserts nothing
/// and is skipped.
pub fn parse_arp_reply(line: &str) -> Option<(String, String)> {
    // "is-at" is what separates "this address" from "belongs to this hardware".
    let marker = line.find("is-at ")?;

    let claimed = line[..marker].split_whitespace().next_back()?;
    // Reject anything that isn't really an address, so a reply about an
    // unusual protocol can't be mistaken for one about IPv4.
    if claimed.parse::<Ipv4Addr>().is_err() {
        return None;
    }

    let after = &line[marker + "is-at ".len()..];
    let hardware = after
        .split(|c: char| c == ',' || c.is_whitespace())
        .next()?;
    let mac = crate::oui::normalize_mac(hardware)?;

    Some((claimed.to_string(), mac))
}

/// True if `mac` is this machine's own interface address — the machine doing
/// the legitimate throttling.
///
/// A free function rather than a method so it can be called while a binding is
/// borrowed mutably.
fn is_ours(my_mac: &str, mac: &str) -> bool {
    !my_mac.is_empty() && mac == my_mac
}

/// Watches ARP announcements for signs of interference.
pub struct ArpWatcher {
    bindings: HashMap<String, ArpBinding>,
    /// Announcement times per `(ip, mac)`, for the rate check. Kept here
    /// rather than on [`ArpBinding`] because that struct is part of the shape
    /// shown in the UI.
    recent: HashMap<(String, String), VecDeque<u64>>,
    findings: VecDeque<Finding>,
    /// Findings already raised, so a standing situation is reported once
    /// rather than on every announcement.
    reported: std::collections::HashSet<String>,
    /// This machine's own hardware address, so its own spoofing is never
    /// mistaken for someone else's.
    my_mac: String,
}

impl ArpWatcher {
    pub fn new(my_mac: &str) -> Self {
        ArpWatcher {
            bindings: HashMap::new(),
            recent: HashMap::new(),
            findings: VecDeque::new(),
            reported: std::collections::HashSet::new(),
            my_mac: crate::oui::normalize_mac(my_mac).unwrap_or_default(),
        }
    }

    /// Records an announcement and returns any *new* findings.
    ///
    /// Repeated calls with the same situation return nothing after the first,
    /// so the log records that something started rather than that it
    /// continued.
    pub fn observe(&mut self, ip: &str, mac: &str, at: u64) -> Vec<Finding> {
        let Some(key) = crate::oui::normalize_mac(mac) else {
            return Vec::new();
        };
        let my_mac = self.my_mac.clone();

        if self.bindings.len() >= MAX_BINDINGS && !self.bindings.contains_key(ip) {
            // Bound memory on a busy or hostile network rather than growing
            // without limit.
            self.evict_oldest();
        }

        // Update the binding in its own scope, so the borrow ends before the
        // checks below need the map again.
        {
            let binding = self
                .bindings
                .entry(ip.to_string())
                .or_insert_with(|| ArpBinding {
                    ip: ip.to_string(),
                    macs: Vec::new(),
                    announcements: 0,
                    first_seen: at,
                    last_seen: at,
                });
            binding.last_seen = at;
            binding.announcements += 1;
            if !binding.macs.contains(&key) {
                binding.macs.push(key.clone());
            }
        }

        let mut findings: Vec<Finding> = Vec::new();

        // A contested address — one IP claimed by two machines — is the
        // definitive signature of interception.
        //
        // Evaluated from the current state rather than only when a new
        // claimant appears, so that dismissing a finding doesn't silence a
        // problem that is still going on: the next announcement of that
        // address raises it again. The dedup set keeps it from being repeated
        // every second while it continues.
        if let Some(binding) = self.bindings.get(ip) {
            if binding.macs.len() > 1 {
                let was = binding.macs[0].clone();
                let now = binding.macs[1].clone();
                // If either side of that is us, it's our own throttling.
                if !is_ours(&my_mac, &was) && !is_ours(&my_mac, &now) {
                    findings.push(Finding {
                        at,
                        kind: FindingKind::Conflict {
                            ip: ip.to_string(),
                            was,
                            now,
                        },
                    });
                }
            }
        }

        // One machine claiming several addresses. A real device owns one.
        if !is_ours(&my_mac, &key) {
            let claimed: Vec<String> = self
                .bindings
                .iter()
                .filter(|(_, binding)| binding.macs.contains(&key))
                .map(|(ip, _)| ip.clone())
                .collect();
            if claimed.len() >= IMPERSONATION_MIN_IPS {
                findings.push(Finding {
                    at,
                    kind: FindingKind::Impersonation {
                        mac: key.clone(),
                        claimed,
                    },
                });
            }

            // An address re-announced far more often than a device would.
            if let Some(repeats) = self.rate(ip, &key, at) {
                findings.push(Finding {
                    at,
                    kind: FindingKind::Flood {
                        ip: ip.to_string(),
                        mac: key.clone(),
                        repeats,
                    },
                });
            }
        }

        // Drop anything already reported, then remember what's left.
        let fresh: Vec<Finding> = findings
            .into_iter()
            .filter(|finding| self.reported.insert(finding.dedup_key()))
            .collect();

        for finding in &fresh {
            self.findings.push_back(finding.clone());
        }
        while self.findings.len() > MAX_FINDINGS {
            self.findings.pop_front();
        }

        fresh
    }

    /// Returns the number of announcements for `(ip, mac)` inside the window
    /// if that count has just crossed the flood threshold, resetting the
    /// window so one burst reports once rather than once per packet for the
    /// rest of the minute.
    fn rate(&mut self, ip: &str, mac: &str, at: u64) -> Option<usize> {
        let times = self
            .recent
            .entry((ip.to_string(), mac.to_string()))
            .or_default();

        times.push_back(at);
        while times
            .front()
            .is_some_and(|oldest| at.saturating_sub(*oldest) > FLOOD_WINDOW_SECS)
        {
            times.pop_front();
        }

        if times.len() >= FLOOD_MIN_REPEATS {
            let count = times.len();
            times.clear();
            return Some(count);
        }
        None
    }

    /// Forgets the oldest-tracked address when the cap is reached.
    fn evict_oldest(&mut self) {
        let oldest = self
            .bindings
            .iter()
            .min_by_key(|(_, binding)| binding.last_seen)
            .map(|(ip, _)| ip.clone());
        if let Some(ip) = oldest {
            self.bindings.remove(&ip);
            self.recent.retain(|(recent_ip, _), _| *recent_ip != ip);
        }
    }

    /// Every address seen, and who claimed it.
    pub fn bindings(&self) -> Vec<&ArpBinding> {
        let mut all: Vec<&ArpBinding> = self.bindings.values().collect();
        all.sort_by(|a, b| a.ip.cmp(&b.ip));
        all
    }

    /// Addresses that more than one machine has claimed — the ones being
    /// interfered with.
    pub fn contested(&self) -> Vec<&ArpBinding> {
        self.bindings
            .values()
            .filter(|binding| binding.macs.len() > 1)
            .collect()
    }

    /// Findings, newest first.
    pub fn findings(&self, limit: usize) -> Vec<&Finding> {
        self.findings.iter().rev().take(limit).collect()
    }

    /// Drops remembered findings, so a situation that ended and returned is
    /// reported again.
    pub fn clear_findings(&mut self) {
        self.findings.clear();
        self.reported.clear();
    }
}

/// The `recent` field needs to live on the watcher, not the binding, because
/// `ArpBinding` is part of the public shape shown in the UI.
impl std::fmt::Debug for ArpWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArpWatcher")
            .field("bindings", &self.bindings.len())
            .field("findings", &self.findings.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// The running watcher
// ---------------------------------------------------------------------------

use std::sync::{Arc, Mutex, OnceLock};

/// The live watcher and the capture feeding it.
struct Running {
    /// Shared with the capture's reader thread, which is why it's an `Arc`
    /// rather than a plain field.
    watcher: Arc<Mutex<ArpWatcher>>,
    capture: crate::capture::LineCapture,
}

static RUNNING: OnceLock<Mutex<Option<Running>>> = OnceLock::new();

fn running() -> &'static Mutex<Option<Running>> {
    RUNNING.get_or_init(|| Mutex::new(None))
}

/// Runs `f` against the live watcher, or `None` if it isn't running.
///
/// Poisoned mutexes are recovered from rather than propagated: a panic
/// elsewhere must not stop the network being watched.
pub fn with_watcher<T>(f: impl FnOnce(&ArpWatcher) -> T) -> Option<T> {
    let guard = running().lock().unwrap_or_else(|p| p.into_inner());
    let running = guard.as_ref()?;
    let watcher = running.watcher.lock().unwrap_or_else(|p| p.into_inner());
    Some(f(&watcher))
}

/// Like [`with_watcher`], but hands over mutable access. Needed to dismiss
/// findings once the owner has read them.
pub fn with_watcher_mut<T>(f: impl FnOnce(&mut ArpWatcher) -> T) -> Option<T> {
    let guard = running().lock().unwrap_or_else(|p| p.into_inner());
    let running = guard.as_ref()?;
    let mut watcher = running.watcher.lock().unwrap_or_else(|p| p.into_inner());
    Some(f(&mut watcher))
}

/// True if ARP is being watched, so the UI can tell "nothing found" apart from
/// "not looking".
pub fn is_running() -> bool {
    running()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_some()
}

/// Starts watching ARP on `iface`, reporting new findings through `on_finding`.
///
/// `my_mac` is this machine's own hardware address — the one whose spoofing
/// must not be reported as somebody else's activity. Pass `None` only if this
/// machine isn't spoofing anything.
///
/// Returns false if the capture couldn't start.
pub fn start(
    iface: &str,
    my_mac: Option<&str>,
    on_finding: impl Fn(&Finding) + Send + 'static,
) -> bool {
    let mut guard = running().lock().unwrap_or_else(|p| p.into_inner());
    if guard.is_some() {
        return true; // already watching
    }

    let watcher = Arc::new(Mutex::new(ArpWatcher::new(my_mac.unwrap_or(""))));
    let watcher_for_lines = Arc::clone(&watcher);

    let capture = crate::capture::LineCapture::start(
        iface,
        &["arp"],
        "Spoofing watch",
        move |line| {
            let Some((ip, mac)) = parse_arp_reply(line) else {
                return;
            };
            let at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            // The lock is released before the callback runs, so a callback
            // that reads the watcher can't deadlock against this.
            let findings = {
                let mut watcher = watcher_for_lines.lock().unwrap_or_else(|p| p.into_inner());
                watcher.observe(&ip, &mac, at)
            };
            for finding in findings {
                on_finding(&finding);
            }
        },
    );

    match capture {
        Some(capture) => {
            *guard = Some(Running { watcher, capture });
            true
        }
        None => false,
    }
}

/// Stops watching and reaps the capture.
pub fn stop() {
    let mut guard = running().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(mut running) = guard.take() {
        running.capture.stop();
    }
}

/// Explains why this isn't available, or `None` if it is.
pub fn unavailability_reason() -> Option<String> {
    if !crate::capture::available() {
        return Some(
            "Install tcpdump to have Curfew watch for someone else spoofing your network \
             (Debian/Ubuntu: sudo apt install tcpdump)."
                .to_string(),
        );
    }
    None
}

/// Prints a finding, for the terminal.
pub fn report(finding: &Finding) {
    use crate::colors::{BOLD, DIM, RED, YELLOW};
    println!();
    println!("{RED}{BOLD}Someone is interfering with your network.{RESET}");
    println!("  {YELLOW}{}{RESET}", finding.describe());
    println!("{DIM}  This is a report only - Curfew hasn't changed anything.{RESET}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A machine that is not us.
    const THEM: &str = "aa:bb:cc:00:00:01";
    /// Our own interface address.
    const US: &str = "aa:bb:cc:dd:ee:ff";
    /// A real device.
    const DEVICE: &str = "00:14:51:11:22:33";

    fn watcher() -> ArpWatcher {
        ArpWatcher::new(US)
    }

    // -- parsing ----------------------------------------------------------

    #[test]
    fn parses_a_plain_reply() {
        let line = "19:04:02.123456 ARP, Reply 192.168.1.1 is-at aa:bb:cc:dd:ee:ff, length 28";
        assert_eq!(
            parse_arp_reply(line),
            Some(("192.168.1.1".to_string(), "aa:bb:cc:dd:ee:ff".to_string()))
        );
    }

    #[test]
    fn parses_a_reply_with_ethernet_headers() {
        // What `-e` prints; both layouts have to work.
        let line = "19:04:02.123456 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66, \
                    ethertype ARP (0x0806), length 42: \
                    Reply 192.168.1.1 is-at aa:bb:cc:dd:ee:ff, length 28";
        assert_eq!(
            parse_arp_reply(line),
            Some(("192.168.1.1".to_string(), "aa:bb:cc:dd:ee:ff".to_string()))
        );
    }

    #[test]
    fn normalises_the_hardware_address() {
        let line = "ARP, Reply 10.0.0.1 is-at AA-BB-CC-DD-EE-FF, length 28";
        assert_eq!(
            parse_arp_reply(line).map(|(_, mac)| mac),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn ignores_requests_because_they_assert_nothing() {
        // "who-has ... tell ..." is a question, not a claim. Counting it would
        // make every device look like it was claiming other addresses.
        let line = "19:04:02.1 ARP, Request who-has 192.168.1.1 tell 192.168.1.27, length 28";
        assert_eq!(parse_arp_reply(line), None);
    }

    #[test]
    fn ignores_lines_it_cannot_understand() {
        for line in [
            "",
            "tcpdump: listening on wlan0",
            "19:04:02.1 IP 192.168.1.27.54321 > 192.168.1.1.53: 1+ A? example.com. (30)",
            // A reply about an address that isn't IPv4.
            "ARP, Reply fe80::1 is-at aa:bb:cc:dd:ee:ff, length 28",
            // Hardware address isn't one.
            "ARP, Reply 192.168.1.1 is-at not-a-mac, length 28",
            "ARP, Reply 192.168.1.1, length 28",
        ] {
            assert_eq!(parse_arp_reply(line), None, "should ignore {line:?}");
        }
    }

    // -- the core detection ----------------------------------------------

    #[test]
    fn a_predictable_device_raises_nothing() {
        let mut watch = watcher();
        for i in 0..5 {
            assert!(watch.observe("192.168.1.27", DEVICE, 1000 + i).is_empty());
        }
    }

    #[test]
    fn a_changed_claim_is_reported_as_a_conflict() {
        // The definitive signature: the address a device owned is now being
        // claimed by a different machine.
        let mut watch = watcher();
        watch.observe("192.168.1.27", DEVICE, 1000);
        let findings = watch.observe("192.168.1.27", THEM, 1010);
        assert_eq!(findings.len(), 1);
        match &findings[0].kind {
            FindingKind::Conflict { ip, was, now } => {
                assert_eq!(ip, "192.168.1.27");
                assert_eq!(was, DEVICE);
                assert_eq!(now, THEM);
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
        // The description must be readable by someone non-technical.
        let text = findings[0].describe();
        assert!(text.contains("192.168.1.27"), "got {text}");
        assert!(text.contains("intercepting"), "got {text}");
    }

    #[test]
    fn our_own_spoofing_is_never_reported_as_a_conflict() {
        // This is the difference between a useful detector and a notice board
        // that cries wolf about itself: Curfew spoofs every throttled device,
        // so it must not flag its own work.
        let mut watch = watcher();
        watch.observe("192.168.1.27", DEVICE, 1000);
        let findings = watch.observe("192.168.1.27", US, 1010);
        assert!(
            findings.is_empty(),
            "our own spoofing was reported: {findings:?}"
        );
    }

    #[test]
    fn a_conflict_the_other_way_round_is_also_ignored_when_we_are_involved() {
        // We start first, then the real device answers. Still us.
        let mut watch = watcher();
        watch.observe("192.168.1.27", US, 1000);
        let findings = watch.observe("192.168.1.27", DEVICE, 1010);
        assert!(findings.is_empty(), "got {findings:?}");
    }

    #[test]
    fn one_machine_claiming_several_addresses_is_impersonation() {
        let mut watch = watcher();
        // Below the threshold: one address is normal.
        watch.observe("192.168.1.27", THEM, 1000);
        watch.observe("192.168.1.28", THEM, 1000);
        let findings = watch.observe("192.168.1.29", THEM, 1000);
        let impostor = findings
            .iter()
            .find(|f| matches!(f.kind, FindingKind::Impersonation { .. }))
            .expect("the third address should look like impersonation");
        match &impostor.kind {
            FindingKind::Impersonation { mac, claimed } => {
                assert_eq!(mac, THEM);
                assert_eq!(claimed.len(), 3);
            }
            other => panic!("expected impersonation, got {other:?}"),
        }
    }

    #[test]
    fn our_own_many_addresses_are_not_impersonation() {
        // Curfew claims an address for every device it throttles. That is the
        // whole point of it, and must never be reported.
        let mut watch = watcher();
        for last in 20..30 {
            let findings = watch.observe(&format!("192.168.1.{last}"), US, 1000);
            assert!(
                findings.is_empty(),
                "our own suppression of .{last} was reported: {findings:?}"
            );
        }
    }

    #[test]
    fn a_repeatedly_reannounced_address_is_a_flood() {
        // Spoofing tools re-announce about once a second to keep winning the
        // race; devices announce rarely.
        let mut watch = watcher();
        let mut findings = Vec::new();
        for i in 0..FLOOD_MIN_REPEATS {
            findings.extend(watch.observe("192.168.1.1", THEM, 1000 + i as u64));
        }
        let flood = findings
            .iter()
            .find(|f| matches!(f.kind, FindingKind::Flood { .. }))
            .expect("a flood should have been reported");
        assert!(flood.describe().contains("re-announcing"), "got {}", flood.describe());
    }

    #[test]
    fn a_normal_announcement_rate_is_not_a_flood() {
        let mut watch = watcher();
        for i in 0..5 {
            let findings = watch.observe("192.168.1.1", THEM, 1000 + i * 60);
            assert!(findings.is_empty(), "slow announcements flagged: {findings:?}");
        }
    }

    #[test]
    fn our_own_flooding_is_not_reported() {
        // Curfew re-announces every throttled address once a second, so its
        // own traffic looks exactly like a flood.
        let mut watch = watcher();
        for i in 0..(FLOOD_MIN_REPEATS * 2) {
            let findings = watch.observe("192.168.1.27", US, 1000 + i as u64);
            assert!(findings.is_empty(), "our own flooding was reported: {findings:?}");
        }
    }

    // -- reporting behaviour ---------------------------------------------

    #[test]
    fn a_standing_situation_is_reported_once_not_repeatedly() {
        // Otherwise one spoofer fills the log with the same line.
        let mut watch = watcher();
        watch.observe("192.168.1.27", DEVICE, 1000);
        let first = watch.observe("192.168.1.27", THEM, 1010);
        assert_eq!(first.len(), 1);
        for i in 0..10 {
            let again = watch.observe("192.168.1.27", THEM, 1020 + i);
            assert!(again.is_empty(), "repeat at {i}: {again:?}");
        }
        // But the situation is still recorded for display.
        assert_eq!(watch.contested().len(), 1);
    }

    #[test]
    fn clearing_findings_lets_a_recurrence_be_reported() {
        let mut watch = watcher();
        watch.observe("192.168.1.27", DEVICE, 1000);
        assert_eq!(watch.observe("192.168.1.27", THEM, 1010).len(), 1);
        watch.clear_findings();
        // A new conflict for the same address is worth hearing about again.
        assert_eq!(watch.observe("192.168.1.27", DEVICE, 1020).len(), 1);
    }

    #[test]
    fn findings_are_listed_newest_first() {
        let mut watch = watcher();
        watch.observe("192.168.1.1", DEVICE, 1);
        watch.observe("192.168.1.1", THEM, 2);
        watch.observe("192.168.1.2", DEVICE, 3);
        watch.observe("192.168.1.2", THEM, 4);
        let listed = watch.findings(10);
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].at, 4, "newest first");
        assert_eq!(listed[1].at, 2);
    }

    #[test]
    fn reports_which_addresses_are_being_interfered_with() {
        let mut watch = watcher();
        watch.observe("192.168.1.27", DEVICE, 1000);
        watch.observe("192.168.1.27", THEM, 1010);
        watch.observe("192.168.1.28", DEVICE, 1000);

        let contested = watch.contested();
        assert_eq!(contested.len(), 1);
        assert_eq!(contested[0].ip, "192.168.1.27");
        assert_eq!(contested[0].macs.len(), 2);
    }

    #[test]
    fn tracks_how_often_each_address_is_announced() {
        let mut watch = watcher();
        for i in 0..3 {
            watch.observe("192.168.1.27", DEVICE, 1000 + i);
        }
        let bindings = watch.bindings();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].announcements, 3);
        assert_eq!(bindings[0].macs, vec![DEVICE.to_string()]);
    }

    #[test]
    fn an_unusable_address_is_ignored() {
        let mut watch = watcher();
        assert!(watch.observe("192.168.1.27", "not-a-mac", 1000).is_empty());
        assert!(watch.bindings().is_empty());
    }

    #[test]
    fn caps_how_many_addresses_it_tracks() {
        let mut watch = watcher();
        for i in 0..(MAX_BINDINGS + 40) {
            watch.observe(&format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256), DEVICE, i as u64);
        }
        assert!(watch.bindings().len() <= MAX_BINDINGS);
    }

    #[test]
    fn caps_how_many_findings_it_keeps() {
        let mut watch = watcher();
        for i in 0..(MAX_FINDINGS * 2) {
            let ip = format!("10.0.{}.{}", i / 256, i % 256);
            watch.observe(&ip, DEVICE, i as u64);
            watch.observe(&ip, THEM, i as u64);
        }
        assert!(watch.findings(MAX_FINDINGS * 4).len() <= MAX_FINDINGS);
    }

    #[test]
    fn findings_have_stable_summaries_for_the_log() {
        let finding = Finding {
            at: 1,
            kind: FindingKind::Conflict {
                ip: "192.168.1.27".into(),
                was: DEVICE.into(),
                now: THEM.into(),
            },
        };
        let summary = finding.summary();
        assert!(summary.contains("192.168.1.27"));
        assert!(summary.contains(DEVICE));
        assert!(summary.contains(THEM));
        // The log line must be a single line.
        assert_eq!(summary.lines().count(), 1);
    }
}
