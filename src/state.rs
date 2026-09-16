//! Shared runtime state, the persisted exempt list, device nicknames,
//! per-device overrides, and the activity log.

use crate::network::lookup_mac;
use crate::paths::CONFIG_DIR;
use crate::schedule::{self, Schedule};
use crate::spoof::SpoofSession;
use crate::tc::DeviceSpec;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const MAX_LOG_LINES: usize = 200;

/// How long a resolved MAC is trusted before we look it up again.
///
/// This cache used to be permanent, which was a real correctness hole: a
/// device that left the network and had its DHCP lease handed to a different
/// device would leave the *new* device holding the old one's MAC — and
/// therefore the old one's full-speed exemption.
const MAC_CACHE_TTL: Duration = Duration::from_secs(60);

fn allowed_file() -> std::path::PathBuf {
    std::path::Path::new(CONFIG_DIR).join("allowed_macs")
}

fn names_file() -> std::path::PathBuf {
    std::path::Path::new(CONFIG_DIR).join("names")
}

fn modes_file() -> std::path::PathBuf {
    std::path::Path::new(CONFIG_DIR).join("device_modes")
}

/// A per-device override, persisted against the device's MAC so it follows
/// the device rather than an IP address the router may reassign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceMode {
    /// No usable internet at all.
    Block,
    /// A specific speed instead of the household default.
    Rate(String),
}

impl DeviceMode {
    fn encode(&self) -> String {
        match self {
            DeviceMode::Block => "block".to_string(),
            DeviceMode::Rate(rate) => rate.clone(),
        }
    }

    fn decode(value: &str) -> Option<Self> {
        match value.trim() {
            "" => None,
            "block" => Some(DeviceMode::Block),
            rate => Some(DeviceMode::Rate(rate.to_string())),
        }
    }
}

/// A cached MAC lookup, with the time it was resolved.
struct MacEntry {
    mac: String,
    resolved: Instant,
}

pub struct State {
    pub iface: String,
    pub gateway: String,
    /// The household's default throttle rate.
    pub rate: String,
    /// IPs currently being managed (ARP-spoofed, and shaped into some slow
    /// lane).
    pub devices: Vec<String>,
    /// IPs currently online whose MAC is exempt — full speed, shown alongside
    /// `devices` in the dashboard so exempt devices have a visible presence
    /// too. Rebuilt from scratch on every scan rather than appended to, so it
    /// can't accumulate stale entries for devices that have gone away.
    pub exempt_online: Vec<String>,
    /// MAC addresses permanently exempt from throttling, persisted to disk.
    pub allowed_macs: Vec<String>,
    /// Optional daily window during which throttling is active.
    pub schedule: Option<Schedule>,
    pub arpspoof_sessions: HashMap<String, SpoofSession>,
    /// IP -> last-resolved MAC, with a TTL (see [`MAC_CACHE_TTL`]).
    macs: HashMap<String, MacEntry>,
    /// MAC -> friendly name (e.g. "Timmy's iPad"), persisted to disk.
    pub names: HashMap<String, String>,
    /// MAC -> per-device override, persisted to disk.
    pub modes: HashMap<String, DeviceMode>,
    pub logs: Vec<String>,
    /// Number of scan cycles completed since startup — proof the background
    /// monitor thread is alive, shown in the header as a heartbeat.
    pub scan_count: u64,
    /// If set and still in the future, everyone gets full speed until then
    /// (a temporary "break" the owner granted); the monitor clears it once
    /// it passes.
    pub pause_until: Option<Instant>,
    /// How many devices the last scan saw, for the dashboard.
    pub last_scan_devices: usize,
    /// Consecutive scans in which a managed device wasn't seen. Devices that
    /// stay missing get released (see [`crate::devices::release`]); counting
    /// first avoids flapping on a device that is merely asleep.
    pub missed: HashMap<String, u32>,
    /// Devices whose traffic we're currently failing to intercept, because
    /// they have working IPv6 and Curfew only spoofs IPv4. Surfaced in the
    /// UI rather than silently pretending they're throttled.
    pub ipv6_bypass: Vec<String>,
}

impl State {
    pub fn new(iface: String, gateway: String, rate: String) -> Self {
        State {
            iface,
            gateway,
            rate,
            devices: Vec::new(),
            exempt_online: Vec::new(),
            allowed_macs: load_allowed(),
            schedule: schedule::load(),
            arpspoof_sessions: HashMap::new(),
            macs: HashMap::new(),
            names: load_names(),
            modes: load_modes(),
            logs: Vec::new(),
            scan_count: 0,
            pause_until: None,
            last_scan_devices: 0,
            missed: HashMap::new(),
            ipv6_bypass: Vec::new(),
        }
    }

    /// The cached MAC for `ip`, if one is known and still fresh.
    pub fn mac_of(&self, ip: &str) -> Option<String> {
        self.macs
            .get(ip)
            .filter(|entry| entry.resolved.elapsed() < MAC_CACHE_TTL)
            .map(|entry| entry.mac.clone())
    }

    /// The override that applies to `ip`, looked up via its MAC.
    fn mode_of(&self, ip: &str) -> Option<&DeviceMode> {
        let mac = self.mac_of(ip)?;
        self.modes.get(&mac)
    }

    /// The full shaping plan: every device we're managing, and which lane it
    /// belongs in. Blocking wins over a per-device rate, and either wins over
    /// the household default.
    ///
    /// Every device gets a lane of its own — even at the household rate — so
    /// the dashboard can report per-device traffic. A single shared lane's
    /// counter can't be attributed to the devices using it.
    pub fn shaping_plan(&self) -> Vec<(String, DeviceSpec)> {
        self.devices
            .iter()
            .map(|ip| {
                let spec = match self.mode_of(ip) {
                    Some(DeviceMode::Block) => DeviceSpec::Block,
                    Some(DeviceMode::Rate(rate)) => DeviceSpec::ThrottleAt(rate.clone()),
                    None => DeviceSpec::ThrottleAt(self.rate.clone()),
                };
                (ip.clone(), spec)
            })
            .collect()
    }

    /// True if `ip` is currently blocked outright.
    pub fn is_blocked(&self, ip: &str) -> bool {
        matches!(self.mode_of(ip), Some(DeviceMode::Block))
    }

    /// The rate shown for `ip` in the dashboard: its override, or the
    /// household default.
    pub fn effective_rate(&self, ip: &str) -> String {
        match self.mode_of(ip) {
            Some(DeviceMode::Rate(rate)) => rate.clone(),
            _ => self.rate.clone(),
        }
    }
}

pub fn load_allowed() -> Vec<String> {
    std::fs::read_to_string(allowed_file())
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

pub fn save_allowed(macs: &[String]) {
    write_private(&allowed_file(), &(macs.join("\n") + "\n"), "full-speed list");
}

fn load_names() -> HashMap<String, String> {
    std::fs::read_to_string(names_file())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(mac, name)| (mac.to_string(), name.to_string()))
        .collect()
}

pub fn save_names(names: &HashMap<String, String>) {
    let content: String = names
        .iter()
        .map(|(mac, name)| format!("{mac}={name}\n"))
        .collect();
    write_private(&names_file(), &content, "nicknames");
}

fn load_modes() -> HashMap<String, DeviceMode> {
    std::fs::read_to_string(modes_file())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once('='))
        .filter_map(|(mac, value)| DeviceMode::decode(value).map(|m| (mac.to_string(), m)))
        .collect()
}

pub fn save_modes(modes: &HashMap<String, DeviceMode>) {
    let content: String = modes
        .iter()
        .map(|(mac, mode)| format!("{mac}={}\n", mode.encode()))
        .collect();
    write_private(&modes_file(), &content, "device settings");
}

/// Writes a config file with owner-only permissions. A failure here is worth
/// telling the user about (their setting silently won't survive a restart)
/// but is not worth aborting the program over.
fn write_private(path: &std::path::Path, content: &str, what: &str) {
    crate::paths::ensure_dir();
    match std::fs::write(path, content) {
        Ok(()) => crate::paths::restrict(&path.to_string_lossy()),
        Err(e) => eprintln!("Warning: could not save {what} to {}: {e}", path.display()),
    }
}

fn timestamp() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

/// Locks the shared state, tolerating a poisoned mutex.
///
/// A panic in one thread must not take the monitor down with it: if that
/// happened, Curfew would stop re-applying the throttle and the network would
/// quietly drift back to full speed while the UI still claimed it was on.
/// The state behind the lock is plain data, so reading it after a panic is
/// still meaningful.
pub fn lock_state(state: &Arc<Mutex<State>>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn log_event(state: &Arc<Mutex<State>>, msg: &str) {
    let mut st = lock_state(state);
    st.logs.push(format!("[{}] {msg}", timestamp()));
    if st.logs.len() > MAX_LOG_LINES {
        let excess = st.logs.len() - MAX_LOG_LINES;
        st.logs.drain(0..excess);
    }
}

/// Records a MAC we learned from somewhere other than a lookup.
///
/// nmap often reports a device's MAC directly during the scan, which is both
/// cheaper and available before the kernel's ARP table has warmed up. Seeding
/// the cache with it means the rest of the program doesn't need its own
/// lookup for that device at all.
pub fn remember_mac(state: &Arc<Mutex<State>>, ip: &str, mac: &str) {
    if crate::oui::normalize_mac(mac).is_none() {
        return;
    }
    lock_state(state).macs.insert(
        ip.to_string(),
        MacEntry {
            mac: mac.to_string(),
            resolved: Instant::now(),
        },
    );
}

/// Returns a device's MAC address, resolving it if the cache has expired.
pub fn get_mac(state: &Arc<Mutex<State>>, iface: &str, ip: &str) -> String {
    if let Some(mac) = lock_state(state).mac_of(ip) {
        return mac;
    }
    let mac = lookup_mac(iface, ip);
    lock_state(state).macs.insert(
        ip.to_string(),
        MacEntry {
            mac: mac.clone(),
            resolved: Instant::now(),
        },
    );
    mac
}


/// Drops any currently-online IPs for `mac` from the exempt-online list, so a
/// revoked device is picked up and throttled again on the next scan instead
/// of staying excluded forever.
pub fn purge_exempt_online(state: &Arc<Mutex<State>>, mac: &str) {
    let mut st = lock_state(state);
    let matching: Vec<String> = st
        .macs
        .iter()
        .filter(|(_, entry)| entry.mac == mac)
        .map(|(ip, _)| ip.clone())
        .collect();
    st.exempt_online.retain(|ip| !matching.contains(ip));
}

/// Returns a device's nickname if one is set, otherwise its MAC address.
pub fn display_name(state: &Arc<Mutex<State>>, iface: &str, ip: &str) -> String {
    let mac = get_mac(state, iface, ip);
    lock_state(state)
        .names
        .get(&mac)
        .cloned()
        .unwrap_or(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with(devices: &[&str], modes: &[(&str, DeviceMode)]) -> State {
        let mut st = State::new("wlan0".into(), "192.168.1.1".into(), "10kbit".into());
        st.devices = devices.iter().map(|d| d.to_string()).collect();
        for (ip, mode) in modes {
            let mac = format!("mac-{ip}");
            st.macs.insert(
                ip.to_string(),
                MacEntry {
                    mac: mac.clone(),
                    resolved: Instant::now(),
                },
            );
            st.modes.insert(mac, mode.clone());
        }
        st
    }

    #[test]
    fn devices_without_an_override_use_the_household_rate() {
        let st = state_with(&["192.168.1.42"], &[]);
        assert_eq!(
            st.shaping_plan(),
            vec![(
                "192.168.1.42".to_string(),
                DeviceSpec::ThrottleAt("10kbit".to_string())
            )]
        );
    }

    #[test]
    fn every_device_gets_its_own_lane() {
        // Two devices at the same (household) rate must still be separate
        // lanes, otherwise their traffic figures can't be told apart.
        let st = state_with(&["192.168.1.42", "192.168.1.7"], &[]);
        let plan = st.shaping_plan();
        assert_eq!(plan.len(), 2);
        assert_eq!(crate::tc::device_classid("192.168.1.42"), Some(142));
        assert_eq!(crate::tc::device_classid("192.168.1.7"), Some(107));
    }

    #[test]
    fn a_per_device_rate_becomes_its_own_lane() {
        let st = state_with(
            &["192.168.1.42"],
            &[("192.168.1.42", DeviceMode::Rate("1mbit".into()))],
        );
        assert_eq!(
            st.shaping_plan(),
            vec![(
                "192.168.1.42".to_string(),
                DeviceSpec::ThrottleAt("1mbit".to_string())
            )]
        );
    }

    #[test]
    fn blocking_wins_over_a_rate() {
        let st = state_with(&["192.168.1.42"], &[("192.168.1.42", DeviceMode::Block)]);
        assert_eq!(
            st.shaping_plan(),
            vec![("192.168.1.42".to_string(), DeviceSpec::Block)]
        );
        assert!(st.is_blocked("192.168.1.42"));
    }

    #[test]
    fn an_expired_mac_does_not_grant_an_override() {
        // The exemption-leak scenario: a stale MAC must stop counting.
        let mut st = state_with(&["192.168.1.42"], &[("192.168.1.42", DeviceMode::Block)]);
        assert!(st.is_blocked("192.168.1.42"));
        st.macs.get_mut("192.168.1.42").unwrap().resolved =
            Instant::now() - MAC_CACHE_TTL - Duration::from_secs(1);
        assert!(!st.is_blocked("192.168.1.42"));
        assert_eq!(st.mac_of("192.168.1.42"), None);
    }

    #[test]
    fn effective_rate_falls_back_to_the_household_default() {
        let st = state_with(
            &["192.168.1.42", "192.168.1.7"],
            &[("192.168.1.42", DeviceMode::Rate("5mbit".into()))],
        );
        assert_eq!(st.effective_rate("192.168.1.42"), "5mbit");
        assert_eq!(st.effective_rate("192.168.1.7"), "10kbit");
    }

    #[test]
    fn mode_encoding_round_trips() {
        for mode in [DeviceMode::Block, DeviceMode::Rate("256kbit".into())] {
            assert_eq!(DeviceMode::decode(&mode.encode()), Some(mode));
        }
        assert_eq!(DeviceMode::decode(""), None);
    }
}
