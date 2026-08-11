//! Shared runtime state, the persisted exempt list, device nicknames, and
//! the activity log.

use crate::network::lookup_mac;
use crate::paths::CONFIG_DIR;
use crate::schedule::{self, Window};
use crate::spoof::SpoofSession;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const MAX_LOG_LINES: usize = 200;

fn allowed_file() -> std::path::PathBuf {
    std::path::Path::new(CONFIG_DIR).join("allowed_macs")
}

fn names_file() -> std::path::PathBuf {
    std::path::Path::new(CONFIG_DIR).join("names")
}

pub struct State {
    pub iface: String,
    pub gateway: String,
    pub rate: String,
    /// IPs currently throttled (ARP-spoofed + tc-filtered).
    pub devices: Vec<String>,
    /// IPs currently online whose MAC is exempt — full speed, shown alongside
    /// `devices` in the dashboard so exempt devices have a visible presence too.
    pub exempt_online: Vec<String>,
    /// MAC addresses permanently exempt from throttling, persisted to disk.
    pub allowed_macs: Vec<String>,
    /// Optional daily window during which throttling is active; `None` means
    /// always active.
    pub schedule: Option<Window>,
    pub arpspoof_sessions: HashMap<String, SpoofSession>,
    macs: HashMap<String, String>,
    /// MAC -> friendly name (e.g. "Timmy's iPad"), persisted to disk.
    pub names: HashMap<String, String>,
    pub logs: Vec<String>,
    /// Number of scan cycles completed since startup — proof the background
    /// monitor thread is alive, shown in the header as a heartbeat.
    pub scan_count: u64,
    /// If set and still in the future, everyone gets full speed until then
    /// (a temporary "break" the owner granted); the monitor clears it once
    /// it passes.
    pub pause_until: Option<std::time::Instant>,
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
            logs: Vec::new(),
            scan_count: 0,
            pause_until: None,
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
    crate::paths::ensure_dir();
    let path = allowed_file();
    std::fs::write(&path, macs.join("\n") + "\n").unwrap();
    crate::paths::restrict(&path.to_string_lossy());
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
    crate::paths::ensure_dir();
    let path = names_file();
    let content: String = names
        .iter()
        .map(|(mac, name)| format!("{mac}={name}\n"))
        .collect();
    std::fs::write(&path, content).unwrap();
    crate::paths::restrict(&path.to_string_lossy());
}

fn timestamp() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

pub fn log_event(state: &Arc<Mutex<State>>, msg: &str) {
    let mut st = state.lock().unwrap();
    st.logs.push(format!("[{}] {msg}", timestamp()));
    if st.logs.len() > MAX_LOG_LINES {
        let excess = st.logs.len() - MAX_LOG_LINES;
        st.logs.drain(0..excess);
    }
}

/// Returns a device's MAC address, caching the lookup in `State`.
pub fn get_mac(state: &Arc<Mutex<State>>, iface: &str, ip: &str) -> String {
    {
        let st = state.lock().unwrap();
        if let Some(mac) = st.macs.get(ip) {
            return mac.clone();
        }
    }
    let mac = lookup_mac(iface, ip);
    state
        .lock()
        .unwrap()
        .macs
        .insert(ip.to_string(), mac.clone());
    mac
}

/// Drops any currently-online IPs for `mac` from the exempt-online list, so a
/// revoked device is picked up and throttled again on the next scan instead
/// of staying excluded forever.
pub fn purge_exempt_online(state: &Arc<Mutex<State>>, mac: &str) {
    let mut st = state.lock().unwrap();
    let macs_cache = st.macs.clone();
    st.exempt_online
        .retain(|ip| macs_cache.get(ip).map(|m| m != mac).unwrap_or(true));
}

/// Returns a device's nickname if one is set, otherwise its MAC address.
pub fn display_name(state: &Arc<Mutex<State>>, iface: &str, ip: &str) -> String {
    let mac = get_mac(state, iface, ip);
    state
        .lock()
        .unwrap()
        .names
        .get(&mac)
        .cloned()
        .unwrap_or(mac)
}
