//! Shared runtime state, the persisted exempt list, device nicknames, and
//! the activity log.

use crate::network::lookup_mac;
use crate::schedule::{self, Window};
use crate::system::run;
use std::collections::HashMap;
use std::process::Child;
use std::sync::{Arc, Mutex};

const MAX_LOG_LINES: usize = 200;
const ALLOWED_FILE: &str = "/etc/curfew/allowed_macs";
const NAMES_FILE: &str = "/etc/curfew/names";

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
    pub arpspoof_children: HashMap<String, (Child, Child)>,
    macs: HashMap<String, String>,
    /// MAC -> friendly name (e.g. "Timmy's iPad"), persisted to disk.
    pub names: HashMap<String, String>,
    pub logs: Vec<String>,
    /// Number of scan cycles completed since startup — proof the background
    /// monitor thread is alive, shown in the header as a heartbeat.
    pub scan_count: u64,
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
            arpspoof_children: HashMap::new(),
            macs: HashMap::new(),
            names: load_names(),
            logs: Vec::new(),
            scan_count: 0,
        }
    }
}

pub fn load_allowed() -> Vec<String> {
    std::fs::read_to_string(ALLOWED_FILE)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

pub fn save_allowed(macs: &[String]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all("/etc/curfew").unwrap();
    std::fs::write(ALLOWED_FILE, macs.join("\n") + "\n").unwrap();
    std::fs::set_permissions(ALLOWED_FILE, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn load_names() -> HashMap<String, String> {
    std::fs::read_to_string(NAMES_FILE)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(mac, name)| (mac.to_string(), name.to_string()))
        .collect()
}

pub fn save_names(names: &HashMap<String, String>) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all("/etc/curfew").unwrap();
    let content: String = names
        .iter()
        .map(|(mac, name)| format!("{mac}={name}\n"))
        .collect();
    std::fs::write(NAMES_FILE, content).unwrap();
    std::fs::set_permissions(NAMES_FILE, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn timestamp() -> String {
    run("date", &["+%H:%M:%S"])
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
