//! What we know about each device, remembered across restarts.
//!
//! Keyed by MAC address, so a device keeps its history when the router hands
//! it a different IP. Each record answers the questions the dashboard can't
//! get from a single scan:
//!
//! - when was this device first ever seen?
//! - when was it last seen, and is it online now?
//! - what is it called, and who made it?
//! - how much has it been slowed, and how often has it been blocked?
//!
//! Storage is a small hand-rolled line format rather than a serialisation
//! crate, matching the rest of the project:
//!
//! ```text
//! <mac>|<first_seen_epoch>|<last_seen_epoch>|<hostname>|<throttled_bytes>|<blocked_seconds>
//! ```
//!
//! Unknown fields are tolerated and a corrupt line is skipped, so a partially
//! written file costs one device's history rather than all of it.

use crate::oui;
use std::collections::HashMap;
use std::path::PathBuf;

/// How many devices to remember. A home network has tens; the cap stops a
/// busy or hostile network from growing the file without bound.
const MAX_DEVICES: usize = 500;

fn inventory_file() -> PathBuf {
    std::path::Path::new(crate::paths::CONFIG_DIR).join("devices")
}

/// Everything remembered about one device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    pub mac: String,
    /// Unix epoch seconds.
    pub first_seen: u64,
    pub last_seen: u64,
    /// Self-reported by the device, so often absent or duplicated.
    pub hostname: Option<String>,
    /// Cumulative bytes that passed through this device's slow lane.
    pub throttled_bytes: u64,
    /// Total seconds this device has spent blocked.
    pub blocked_seconds: u64,
    /// True if the device appeared in the most recent scan.
    pub online: bool,
}

impl DeviceRecord {
    pub fn new(mac: &str, now: u64) -> Self {
        DeviceRecord {
            mac: mac.to_string(),
            first_seen: now,
            last_seen: now,
            hostname: None,
            throttled_bytes: 0,
            blocked_seconds: 0,
            online: false,
        }
    }

    /// Vendor, looked up on demand rather than stored, so the table can be
    /// updated without rewriting history.
    pub fn vendor(&self) -> Option<String> {
        oui::vendor(&self.mac)
    }

    /// True if this device's MAC rotates, meaning rules keyed to it will not
    /// reliably keep matching.
    pub fn has_randomised_mac(&self) -> bool {
        oui::is_randomised(&self.mac)
    }

    pub fn kind(&self) -> Option<&'static str> {
        oui::guess_kind(self.hostname.as_deref(), self.vendor().as_deref())
    }

    /// A human label: nickname, else hostname, else vendor, else the MAC.
    /// Nicknames live in `State::names` and are applied by the caller, which
    /// is why this stops at the hostname.
    pub fn label(&self) -> String {
        match (&self.hostname, self.vendor()) {
            (Some(host), _) if !host.is_empty() => host.clone(),
            (_, Some(vendor)) => vendor,
            _ => self.mac.clone(),
        }
    }

    /// A phrase for how long ago it was seen, for the UI.
    pub fn last_seen_phrase(&self, now: u64) -> String {
        if self.online {
            return "online now".to_string();
        }
        humanise_age(now.saturating_sub(self.last_seen))
    }

    fn to_line(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.mac,
            self.first_seen,
            self.last_seen,
            self.hostname.as_deref().unwrap_or(""),
            self.throttled_bytes,
            self.blocked_seconds
        )
    }

    /// Parses one line. `None` for anything unusable, so one bad line doesn't
    /// discard the file. Fields after `last_seen` are optional, so a file
    /// written by an earlier version still loads.
    fn parse(line: &str) -> Option<DeviceRecord> {
        let mut fields = line.split('|');
        let mac = oui::normalize_mac(fields.next()?)?;
        let first_seen = fields.next()?.parse().ok()?;
        let last_seen = fields.next()?.parse().ok()?;
        let hostname = fields
            .next()
            .map(str::to_string)
            .filter(|h| !h.is_empty());
        let throttled_bytes = fields.next().and_then(|f| f.parse().ok()).unwrap_or(0);
        let blocked_seconds = fields.next().and_then(|f| f.parse().ok()).unwrap_or(0);

        Some(DeviceRecord {
            mac,
            first_seen,
            last_seen,
            hostname,
            throttled_bytes,
            blocked_seconds,
            online: false,
        })
    }
}

/// Every device we've seen, keyed by normalised MAC.
#[derive(Default)]
pub struct Inventory {
    devices: HashMap<String, DeviceRecord>,
}

impl Inventory {
    pub fn load() -> Self {
        let content = std::fs::read_to_string(inventory_file()).unwrap_or_default();
        Inventory { devices: parse(&content) }
    }

    pub fn save(&self) {
        crate::paths::ensure_dir();
        let path = inventory_file();
        let content: String = self.devices.values().map(|r| r.to_line() + "\n").collect();
        if std::fs::write(&path, content).is_ok() {
            crate::paths::restrict(&path.to_string_lossy());
        }
    }

    pub fn get(&self, mac: &str) -> Option<&DeviceRecord> {
        let key = oui::normalize_mac(mac)?;
        self.devices.get(&key)
    }

    /// Every record, sorted by most recently seen.
    pub fn recent(&self) -> Vec<&DeviceRecord> {
        let mut all: Vec<&DeviceRecord> = self.devices.values().collect();
        // Newest first.
        all.sort_by_key(|record| std::cmp::Reverse(record.last_seen));
        all
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// Records that a device was seen just now, creating it on first sight.
    /// Returns true if this was the first time we'd ever seen it.
    pub fn seen(&mut self, mac: &str, hostname: Option<&str>, now: u64) -> bool {
        let Some(key) = oui::normalize_mac(mac) else {
            return false;
        };
        // A device we've genuinely never seen shouldn't be dropped by the cap,
        // but an unknown/huge MAC would otherwise let the map grow unbounded.
        if !self.devices.contains_key(&key) && self.devices.len() >= MAX_DEVICES {
            self.evict_oldest();
        }

        match self.devices.get_mut(&key) {
            Some(record) => {
                record.last_seen = now;
                record.online = true;
                if let Some(host) = hostname.filter(|h| !h.is_empty()) {
                    record.hostname = Some(host.to_string());
                }
                false
            }
            None => {
                let mut record = DeviceRecord::new(&key, now);
                record.online = true;
                if let Some(host) = hostname.filter(|h| !h.is_empty()) {
                    record.hostname = Some(host.to_string());
                }
                self.devices.insert(key, record);
                true
            }
        }
    }

    /// Marks every device offline. Called at the start of a scan, so devices
    /// that don't reappear correctly show as offline.
    pub fn mark_all_offline(&mut self) {
        for record in self.devices.values_mut() {
            record.online = false;
        }
    }

    /// Adds to a device's cumulative slowed bytes and blocked time.
    ///
    /// Deltas rather than absolutes, because the counters they come from
    /// reset whenever the shaping tree is rebuilt.
    pub fn add_traffic(&mut self, mac: &str, bytes_delta: u64, blocked_seconds_delta: u64) {
        let Some(key) = oui::normalize_mac(mac) else {
            return;
        };
        if let Some(record) = self.devices.get_mut(&key) {
            record.throttled_bytes = record.throttled_bytes.saturating_add(bytes_delta);
            record.blocked_seconds = record.blocked_seconds.saturating_add(blocked_seconds_delta);
        }
    }

    /// Drops the least recently seen devices when the cap is hit.
    fn evict_oldest(&mut self) {
        let mut by_age: Vec<(String, u64)> = self
            .devices
            .iter()
            .map(|(mac, record)| (mac.clone(), record.last_seen))
            .collect();
        by_age.sort_by_key(|(_, last_seen)| *last_seen);
        let excess = self.devices.len().saturating_sub(MAX_DEVICES) + 1;
        for (mac, _) in by_age.into_iter().take(excess) {
            self.devices.remove(&mac);
        }
    }

    /// Forget one device entirely.
    pub fn forget(&mut self, mac: &str) {
        if let Some(key) = oui::normalize_mac(mac) {
            self.devices.remove(&key);
        }
    }
}

/// Parses a whole inventory file, skipping unusable lines.
pub fn parse(content: &str) -> HashMap<String, DeviceRecord> {
    content
        .lines()
        .filter_map(DeviceRecord::parse)
        .map(|record| (record.mac.clone(), record))
        .collect()
}

/// Turns a number of seconds into "just now", "12 minutes ago", "3 days ago".
///
/// The one shared age formatter. `web.rs` and `ui.rs` re-export it under
/// shorter names rather than keeping their own copies, which had drifted into
/// three different formats for the same information.
pub fn humanise_age(seconds: u64) -> String {
    match seconds {
        0..=59 => "just now".to_string(),
        60..=119 => "1 minute ago".to_string(),
        120..=3599 => format!("{} minutes ago", seconds / 60),
        3600..=7199 => "1 hour ago".to_string(),
        7200..=86_399 => format!("{} hours ago", seconds / 3600),
        86_400..=172_799 => "yesterday".to_string(),
        _ => format!("{} days ago", seconds / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: &str = "00:14:51:11:22:33";
    /// A locally-administered MAC, i.e. what a phone with a private address
    /// looks like.
    const RANDOM_MAC: &str = "0a:11:22:33:44:55";

    fn inventory_from(lines: &[&str]) -> Inventory {
        Inventory {
            devices: parse(&lines.join("\n")),
        }
    }

    #[test]
    fn a_new_device_is_recorded_and_reported_as_new() {
        let mut inventory = Inventory::default();
        assert!(inventory.seen(MAC, Some("kids-ipad"), 1000));
        let record = inventory.get(MAC).unwrap();
        assert_eq!(record.first_seen, 1000);
        assert_eq!(record.last_seen, 1000);
        assert_eq!(record.hostname.as_deref(), Some("kids-ipad"));
        assert!(record.online);
    }

    #[test]
    fn seeing_a_device_again_keeps_its_first_seen_date() {
        let mut inventory = Inventory::default();
        inventory.seen(MAC, None, 1000);
        assert!(!inventory.seen(MAC, None, 5000), "not new the second time");
        let record = inventory.get(MAC).unwrap();
        assert_eq!(record.first_seen, 1000, "first sighting must not move");
        assert_eq!(record.last_seen, 5000, "last sighting must advance");
    }

    #[test]
    fn a_later_hostname_replaces_an_absent_one_but_an_absent_one_does_not_erase_it() {
        // nmap often returns no hostname on a later scan; that must not wipe
        // the name we already learned.
        let mut inventory = Inventory::default();
        inventory.seen(MAC, Some("kids-ipad"), 1000);
        inventory.seen(MAC, None, 2000);
        assert_eq!(inventory.get(MAC).unwrap().hostname.as_deref(), Some("kids-ipad"));
        inventory.seen(MAC, Some("timmy-ipad"), 3000);
        assert_eq!(inventory.get(MAC).unwrap().hostname.as_deref(), Some("timmy-ipad"));
    }

    #[test]
    fn hosts_are_matched_regardless_of_separator_or_case() {
        let mut inventory = Inventory::default();
        inventory.seen("00:14:51:11:22:33", None, 1000);
        inventory.seen("00-14-51-11-22-33", None, 2000);
        inventory.seen("001451112233", None, 3000);
        assert_eq!(inventory.len(), 1, "one device, three spellings");
        assert_eq!(inventory.get(MAC).unwrap().last_seen, 3000);
    }

    #[test]
    fn an_unusable_mac_is_ignored_rather_than_stored() {
        let mut inventory = Inventory::default();
        assert!(!inventory.seen("unknown", None, 1000));
        assert!(!inventory.seen("", None, 1000));
        assert_eq!(inventory.len(), 0);
    }

    #[test]
    fn a_scan_clears_the_online_flag_for_absent_devices() {
        let mut inventory = Inventory::default();
        inventory.seen(MAC, None, 1000);
        inventory.mark_all_offline();
        assert!(!inventory.get(MAC).unwrap().online);
        // History survives going offline.
        assert_eq!(inventory.get(MAC).unwrap().last_seen, 1000);
    }

    #[test]
    fn traffic_counters_accumulate_across_shaping_rebuilds() {
        // The OS counters reset whenever the tree is rebuilt, so the
        // inventory has to accumulate deltas itself.
        let mut inventory = Inventory::default();
        inventory.seen(MAC, None, 1000);
        inventory.add_traffic(MAC, 500, 10);
        inventory.add_traffic(MAC, 250, 5);
        let record = inventory.get(MAC).unwrap();
        assert_eq!(record.throttled_bytes, 750);
        assert_eq!(record.blocked_seconds, 15);
    }

    #[test]
    fn traffic_for_an_unknown_device_is_ignored() {
        let mut inventory = Inventory::default();
        inventory.add_traffic("de:ad:be:ef:00:01", 500, 10);
        assert_eq!(inventory.len(), 0);
    }

    #[test]
    fn records_round_trip_through_the_file_format() {
        let mut inventory = Inventory::default();
        inventory.seen(MAC, Some("kids-ipad"), 1000);
        inventory.add_traffic(MAC, 4096, 60);
        inventory.mark_all_offline();

        let content: String = inventory.devices.values().map(|r| r.to_line() + "\n").collect();
        let reloaded = inventory_from(&[content.trim_end()]);
        let record = reloaded.get(MAC).unwrap();
        assert_eq!(record.first_seen, 1000);
        assert_eq!(record.hostname.as_deref(), Some("kids-ipad"));
        assert_eq!(record.throttled_bytes, 4096);
        assert_eq!(record.blocked_seconds, 60);
        assert!(!record.online, "online is runtime state, not stored");
    }

    #[test]
    fn a_device_with_no_hostname_round_trips() {
        let mut inventory = Inventory::default();
        inventory.seen(MAC, None, 1000);
        let line = inventory.get(MAC).unwrap().to_line();
        assert_eq!(inventory_from(&[&line]).get(MAC).unwrap().hostname, None);
    }

    #[test]
    fn skips_corrupt_lines_without_losing_the_good_ones() {
        let good = "00:14:51:11:22:33|1000|2000|ipad|100|5";
        let loaded = inventory_from(&[
            "garbage",
            "|||",
            "00:14:51:11:22:33|not-a-number|2000|ipad",
            good,
        ]);
        assert_eq!(loaded.len(), 1);
        assert!(loaded.get(MAC).is_some());
    }

    #[test]
    fn loads_a_file_written_by_an_earlier_version_with_fewer_fields() {
        // Only mac/first/last existed initially; the rest must default.
        let loaded = inventory_from(&["00:14:51:11:22:33|1000|2000"]);
        let record = loaded.get(MAC).unwrap();
        assert_eq!(record.throttled_bytes, 0);
        assert_eq!(record.blocked_seconds, 0);
        assert_eq!(record.hostname, None);
    }

    #[test]
    fn prunes_the_least_recently_seen_when_full() {
        let mut inventory = Inventory::default();
        // Fill to the cap, oldest first.
        for i in 0..MAX_DEVICES {
            let mac = format!("00:14:51:{:02x}:{:02x}:{:02x}", i / 256, i % 256, 0);
            inventory.seen(&mac, None, 1000 + i as u64);
        }
        assert_eq!(inventory.len(), MAX_DEVICES);

        // One more device must evict the oldest, not grow without bound.
        inventory.seen("aa:bb:cc:dd:ee:ff", None, 999_999);
        assert!(inventory.len() <= MAX_DEVICES);
        assert!(inventory.get("aa:bb:cc:dd:ee:ff").is_some(), "new device kept");
    }

    #[test]
    fn recent_orders_by_last_seen() {
        let mut inventory = Inventory::default();
        inventory.seen("00:14:51:00:00:01", None, 1000);
        inventory.seen("00:14:51:00:00:02", None, 3000);
        inventory.seen("00:14:51:00:00:03", None, 2000);
        let ordered: Vec<u64> = inventory.recent().iter().map(|r| r.last_seen).collect();
        assert_eq!(ordered, vec![3000, 2000, 1000]);
    }

    #[test]
    fn humanises_ages_for_the_ui() {
        assert_eq!(humanise_age(0), "just now");
        assert_eq!(humanise_age(30), "just now");
        assert_eq!(humanise_age(60), "1 minute ago");
        assert_eq!(humanise_age(120), "2 minutes ago");
        assert_eq!(humanise_age(3599), "59 minutes ago");
        assert_eq!(humanise_age(3600), "1 hour ago");
        assert_eq!(humanise_age(7200), "2 hours ago");
        assert_eq!(humanise_age(86_400), "yesterday");
        assert_eq!(humanise_age(86_400 * 3), "3 days ago");
    }

    #[test]
    fn a_randomised_mac_is_surfaced_on_the_record() {
        // The whole point: the UI must be able to warn that this device's
        // identity will change, so MAC-based rules won't stick.
        let mut inventory = Inventory::default();
        inventory.seen(RANDOM_MAC, None, 1000);
        let record = inventory.get(RANDOM_MAC).unwrap();
        assert!(record.has_randomised_mac());

        inventory.seen(MAC, None, 1000);
        assert!(!inventory.get(MAC).unwrap().has_randomised_mac());
    }

    #[test]
    fn label_falls_back_from_hostname_to_vendor_to_mac() {
        let mut inventory = Inventory::default();
        // A locally-administered address is unregistered, so it has no vendor
        // and the chain ends at the MAC itself. Using a real hardware prefix
        // here would make this test depend on whether the machine happens to
        // have a vendor table installed.
        inventory.seen(RANDOM_MAC, None, 1000);
        assert_eq!(inventory.get(RANDOM_MAC).unwrap().label(), RANDOM_MAC);
        inventory.seen(RANDOM_MAC, Some("kids-ipad"), 2000);
        assert_eq!(inventory.get(RANDOM_MAC).unwrap().label(), "kids-ipad");
    }

    #[test]
    fn a_hostname_is_preferred_over_a_vendor_name() {
        let mut inventory = Inventory::default();
        inventory.seen(MAC, Some("kids-ipad"), 1000);
        assert_eq!(
            inventory.get(MAC).unwrap().label(),
            "kids-ipad",
            "a human-chosen name beats a vendor lookup"
        );
    }

    #[test]
    fn forget_removes_a_device() {
        let mut inventory = Inventory::default();
        inventory.seen(MAC, None, 1000);
        inventory.forget(MAC);
        assert_eq!(inventory.len(), 0);
    }
}
