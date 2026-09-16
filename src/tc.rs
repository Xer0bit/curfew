//! Traffic shaping: four lanes — full speed (unshaped), the household's
//! shared throttle lane, an optional per-device lane at its own rate, and a
//! blocked lane — with devices routed into one of them by IP.
//!
//! Linux uses `tc`/HTB, macOS uses `pfctl`+`dnctl` (dummynet), Windows uses a
//! WinDivert-based userspace token bucket (see [`crate::winshape`]) because
//! Windows has no built-in packet-shaping primitive.
//!
//! The family of roads worth knowing about on Linux:
//!
//! ```text
//!   1:1  root (link speed)
//!    ├── 1:10  shared throttle lane  (household default rate)
//!    ├── 1:20  full-speed lane       (unmatched traffic lands here)
//!    ├── 1:99  blocked lane          (1 kbit/s)
//!    └── 1:NNN per-device lane       (100 + last IP octet)
//! ```

#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(target_os = "windows")]
pub use windows::*;

/// What should happen to one device's traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceSpec {
    /// A dedicated lane at this rate. Every managed device gets one, which is
    /// what makes per-device traffic figures possible — a shared lane's
    /// counter can't be split between the devices using it.
    ThrottleAt(String),
    /// No usable internet.
    Block,
}

// Note there is deliberately no "full speed" variant: an exempt device is one
// that simply isn't in the plan at all, so it falls through to the unshaped
// fast lane rather than being explicitly routed somewhere.

/// Speed of the "no internet" lane. Not a literal `0bit` because `tc` rejects
/// zero; 1 kbit/s is already far below anything a device can work over.
pub const BLOCK_RATE: &str = "1kbit";

/// Classid reserved for [`DeviceSpec::Block`] on Linux (and the matching
/// dummynet pipe id on macOS).
pub const BLOCK_CLASSID: u16 = 99;

/// Link speed assumed when the NIC won't report one. Most Wi-Fi drivers
/// report "unknown", so this is the common case — deliberately far above any
/// home connection so the fast lane is never the bottleneck.
pub const FALLBACK_LINK_MBIT: u32 = 10_000;

/// The dedicated-lane id for a device, derived from the last octet of `ip`.
///
/// Deterministic and stateless, so a full rebuild can recreate every lane
/// without remembering what it assigned last time. The `+100` offset keeps
/// these clear of the reserved ids 10 (shared), 20 (fast) and 99 (blocked).
pub fn device_classid(ip: &str) -> Option<u16> {
    let last: u16 = ip.rsplit('.').next()?.parse().ok()?;
    Some(100 + last)
}

/// A single reading of the shaping counters.
pub struct Snapshot {
    /// Bytes that passed through the slow lanes.
    pub throttled_bytes: u64,
    /// Bytes that passed through the full-speed lane.
    pub fast_bytes: u64,
    /// Raw `classid -> bytes` pairs, for per-device lookups.
    pub classes: Vec<(String, u64)>,
    /// False on backends that can't report byte counters at all, so the
    /// dashboard can omit the figures instead of showing a misleading `0B`.
    pub available: bool,
}

impl Snapshot {
    /// Bytes seen on one device's dedicated lane, if it has one.
    pub fn for_device(&self, ip: &str) -> Option<u64> {
        let classid = device_classid(ip)?;
        let want = format!("1:{classid}");
        self.classes
            .iter()
            .find(|(id, _)| *id == want)
            .map(|(_, bytes)| *bytes)
    }
}

/// Converts the OS's cumulative per-lane counters into per-device deltas.
///
/// The counters live in the kernel and **reset to zero every time the shaping
/// tree is rebuilt** — which happens on any settings change. Without this,
/// traffic figures would jump backwards or restart, and the inventory would
/// record nonsense.
#[derive(Default)]
pub struct TrafficTracker {
    previous: std::collections::HashMap<String, u64>,
}

impl TrafficTracker {
    /// Bytes each of `ips` has moved since the previous call, omitting devices
    /// with nothing new. Drops devices no longer in `ips`.
    pub fn deltas(&mut self, snapshot: &Snapshot, ips: &[String]) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        for ip in ips {
            let current = snapshot.for_device(ip).unwrap_or(0);
            let previous = self.previous.get(ip).copied().unwrap_or(0);
            // A smaller counter means the tree was rebuilt and counting
            // started over, so the whole current value is new traffic.
            let delta = if current >= previous {
                current - previous
            } else {
                current
            };
            if delta > 0 {
                out.push((ip.clone(), delta));
            }
            self.previous.insert(ip.clone(), current);
        }
        self.previous.retain(|ip, _| ips.contains(ip));
        out
    }
}

/// Parses `tc -s class show` output into `(classid, bytes_sent)` pairs.
///
/// The output is one stanza per class: a header naming the class, then a
/// stats line starting `Sent <bytes> bytes`. Kept tolerant of the optional
/// `backlog` / `lended` / `tokens` lines, whose presence varies by kernel and
/// driver.
pub fn parse_class_stats(output: &str) -> Vec<(String, u64)> {
    let mut stats = Vec::new();
    let mut current: Option<String> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("class ") {
            // "htb 1:10 parent 1:1 leaf 10: ..." / "htb 1:1 root ..."
            current = rest.split_whitespace().nth(1).map(str::to_string);
        } else if let Some(rest) = trimmed.strip_prefix("Sent ") {
            if let Some(id) = current.take() {
                if let Some(bytes) = rest.split_whitespace().next().and_then(|b| b.parse().ok()) {
                    stats.push((id, bytes));
                }
            }
        }
    }
    stats
}

/// Splits parsed class stats into `(throttled, full_speed)` totals.
///
/// The HTB root class `1:1` is skipped: its counter already includes every
/// child, so counting it would double the reported figures.
pub fn split_class_stats(stats: &[(String, u64)]) -> (u64, u64) {
    let mut throttled = 0u64;
    let mut fast = 0u64;
    for (id, bytes) in stats {
        match id.as_str() {
            "1:1" => {}
            "1:20" => fast += bytes,
            _ => throttled += bytes,
        }
    }
    (throttled, fast)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        device_classid, split_class_stats, DeviceSpec, Snapshot, BLOCK_CLASSID, BLOCK_RATE,
        FALLBACK_LINK_MBIT,
    };
    use crate::system::{run_quiet, run_status, try_run};

    /// Root class, shared throttle lane, full-speed lane.
    const ROOT: &str = "1:1";
    const SHARED: &str = "1:10";
    const FAST: &str = "1:20";
    /// Parent for filters: the qdisc handle, not a class.
    const ROOT_QDISC: &str = "1:0";

    /// The fixed part of the shaping tree: tear down, then build the root,
    /// shared, full-speed and blocked lanes, in that order.
    ///
    /// Pure, so the exact command sequence can be asserted in tests. That
    /// matters because this is the one part of Curfew that can't be exercised
    /// without root and a live interface — and it's where a hardcoded 100mbit
    /// link ceiling used to hide.
    fn base_commands(iface: &str, default_rate: &str, link: &str) -> Vec<Vec<String>> {
        let strings =
            |parts: &[&str]| -> Vec<String> { parts.iter().map(|p| p.to_string()).collect() };
        let blocked = format!("1:{BLOCK_CLASSID}");
        vec![
            strings(&["qdisc", "del", "dev", iface, "root"]),
            strings(&[
                "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "20",
            ]),
            strings(&[
                "class", "add", "dev", iface, "parent", "1:", "classid", ROOT, "htb", "rate", link,
                "quantum", "60000",
            ]),
            strings(&[
                "class", "add", "dev", iface, "parent", ROOT, "classid", SHARED, "htb", "rate",
                default_rate, "ceil", default_rate, "quantum", "1600",
            ]),
            strings(&[
                "class", "add", "dev", iface, "parent", ROOT, "classid", FAST, "htb", "rate", link,
                "ceil", link, "quantum", "60000",
            ]),
            strings(&[
                "class", "add", "dev", iface, "parent", ROOT, "classid", &blocked, "htb", "rate",
                BLOCK_RATE, "ceil", BLOCK_RATE, "quantum", "1600",
            ]),
        ]
    }

    /// Where the root class sits in [`base_commands`]: everything else hangs
    /// off it, so its creation is the one step worth checking.
    const ROOT_CLASS_INDEX: usize = 2;

    /// Routes `ip`'s traffic into `classid`. Both directions, because traffic
    /// the device sends *and* receives has to be shaped.
    fn filter_commands(iface: &str, ip: &str, classid: &str) -> Vec<Vec<String>> {
        ["dst", "src"]
            .iter()
            .map(|direction| {
                [
                    "filter", "add", "dev", iface, "protocol", "ip", "parent", ROOT_QDISC, "prio",
                    "1", "u32", "match", "ip", direction, ip, "flowid", classid,
                ]
                .iter()
                .map(|p| p.to_string())
                .collect()
            })
            .collect()
    }

    /// The commands giving `ip` a dedicated lane at `rate`: the class first,
    /// then its filters.
    fn device_lane_commands(iface: &str, ip: &str, classid: &str, rate: &str) -> Vec<Vec<String>> {
        let mut commands: Vec<Vec<String>> = vec![[
            "class", "add", "dev", iface, "parent", ROOT, "classid", classid, "htb", "rate", rate,
            "ceil", rate, "quantum", "1600",
        ]
        .iter()
        .map(|p| p.to_string())
        .collect()];
        commands.extend(filter_commands(iface, ip, classid));
        commands
    }

    fn as_args(argv: &[String]) -> Vec<&str> {
        argv.iter().map(String::as_str).collect()
    }

    fn run_all(commands: &[Vec<String>]) {
        for argv in commands {
            run_status("tc", &as_args(argv));
        }
    }

    /// Rebuilds the shaping tree for `iface` and applies `targets`.
    ///
    /// Always a full rebuild: `tc` filters can't be removed individually in a
    /// way that survives a re-`add`, so a delta update would silently
    /// accumulate duplicate filters for the same IP.
    pub fn reshape(iface: &str, default_rate: &str, targets: &[(String, DeviceSpec)]) {
        // Never let the fast lane become the bottleneck. Ask the NIC what it
        // can actually do; if it won't say (the usual answer on Wi-Fi), use a
        // ceiling far above any real connection. This replaces a hardcoded
        // 100mbit that silently capped the whole household — owner and exempt
        // devices included — on any faster connection.
        let link = match crate::network::link_speed_mbit(iface) {
            Some(mbit) => format!("{mbit}mbit"),
            None => format!("{FALLBACK_LINK_MBIT}mbit"),
        };

        let base = base_commands(iface, default_rate, &link);
        run_quiet("tc", &["qdisc", "del", "dev", iface, "root"]);
        run_all(&base[1..ROOT_CLASS_INDEX]);
        // `default 20` sends anything without a matching filter — yourself,
        // exempt devices — to the full-speed lane. If the root class can't be
        // created there is no tree to attach anything to, so stop rather than
        // leave a half-built one behind.
        if !crate::system::run_ok("tc", &as_args(&base[ROOT_CLASS_INDEX])) {
            return;
        }
        run_all(&base[ROOT_CLASS_INDEX + 1..]);

        let blocked = format!("1:{BLOCK_CLASSID}");
        for (ip, spec) in targets {
            match spec {
                DeviceSpec::Block => run_all(&filter_commands(iface, ip, &blocked)),
                DeviceSpec::ThrottleAt(rate) => match device_classid(ip) {
                    Some(classid) => {
                        let classid = format!("1:{classid}");
                        let commands = device_lane_commands(iface, ip, &classid, rate);
                        // Filters must never point at a class that doesn't
                        // exist, so only attach them once the lane is really
                        // there; otherwise fall back to the shared lane,
                        // which always exists.
                        if crate::system::run_ok("tc", &as_args(&commands[0])) {
                            run_all(&commands[1..]);
                        } else {
                            run_all(&filter_commands(iface, ip, SHARED));
                        }
                    }
                    None => run_all(&filter_commands(iface, ip, SHARED)),
                },
            }
        }
    }

    /// Reads the shaping counters for `iface`.
    pub fn snapshot(iface: &str) -> Snapshot {
        let raw = try_run("tc", &["-s", "class", "show", "dev", iface]).unwrap_or_default();
        let classes = super::parse_class_stats(&raw);
        let (throttled_bytes, fast_bytes) = split_class_stats(&classes);
        Snapshot {
            throttled_bytes,
            fast_bytes,
            classes,
            available: true,
        }
    }

    pub fn teardown_all(iface: &str) {
        run_quiet("tc", &["qdisc", "del", "dev", iface, "root"]);
        run_quiet("tc", &["qdisc", "del", "dev", iface, "ingress"]);
    }

    #[cfg(test)]
    mod linux_tests {
        use super::*;

        fn joined(commands: &[Vec<String>]) -> Vec<String> {
            commands.iter().map(|c| c.join(" ")).collect()
        }

        /// `classid 1:1` is a prefix of `classid 1:10`, so match with the
        /// trailing token to keep the assertions honest.
        fn has_classid(commands: &[String], classid: &str) -> bool {
            commands
                .iter()
                .any(|c| c.contains(&format!("classid {classid} ")))
        }

        #[test]
        fn fast_lane_uses_the_real_link_speed_not_a_fixed_cap() {
            let cmds = joined(&base_commands("wlan0", "10kbit", "2500mbit"));
            assert!(
                cmds.iter().any(|c| c.contains("rate 2500mbit")),
                "the root/fast lane must use the detected link speed: {cmds:?}"
            );
            assert!(
                !cmds.iter().any(|c| c.contains("100mbit")),
                "the old hardcoded 100mbit cap is back: {cmds:?}"
            );
        }

        #[test]
        fn base_lanes_all_get_distinct_classids() {
            let cmds = joined(&base_commands("wlan0", "10kbit", "1000mbit"));
            for classid in ["1:1", "1:10", "1:20", &format!("1:{BLOCK_CLASSID}")] {
                assert!(has_classid(&cmds, classid), "no lane for {classid}");
            }
        }

        #[test]
        fn the_household_rate_is_applied_only_to_the_shared_lane() {
            let cmds = joined(&base_commands("wlan0", "256kbit", "1000mbit"));
            let shared = cmds
                .iter()
                .find(|c| c.contains("classid 1:10 "))
                .expect("shared lane");
            assert!(shared.contains("rate 256kbit"));
            // The fast lane must not be limited to the household speed.
            let fast = cmds
                .iter()
                .find(|c| c.contains("classid 1:20 "))
                .expect("fast lane");
            assert!(!fast.contains("256kbit"));
        }

        #[test]
        fn unmatched_traffic_falls_through_to_the_fast_lane() {
            let cmds = joined(&base_commands("wlan0", "10kbit", "1000mbit"));
            assert!(cmds.iter().any(|c| c.contains("htb default 20")));
        }

        #[test]
        fn a_device_gets_its_own_lane_and_both_filter_directions() {
            let cmds = joined(&device_lane_commands("wlan0", "192.168.1.42", "1:142", "1mbit"));
            assert_eq!(cmds.len(), 3, "one class plus two filters");
            assert!(cmds[0].contains("classid 1:142 ") && cmds[0].contains("rate 1mbit"));
            assert!(cmds[1].contains("match ip dst 192.168.1.42"));
            assert!(cmds[1].contains("flowid 1:142"));
            assert!(cmds[2].contains("match ip src 192.168.1.42"));
            assert!(cmds[2].contains("flowid 1:142"));
        }

        #[test]
        fn a_device_lane_is_parented_to_the_root() {
            let cmds = joined(&device_lane_commands("wlan0", "192.168.1.42", "1:142", "1mbit"));
            assert!(cmds[0].contains("parent 1:1 "));
        }

        #[test]
        fn blocked_devices_are_routed_to_the_block_lane() {
            let blocked = format!("1:{BLOCK_CLASSID}");
            let cmds = joined(&filter_commands("wlan0", "192.168.1.42", &blocked));
            assert_eq!(cmds.len(), 2, "both directions");
            for c in &cmds {
                assert!(c.contains(&format!("flowid {blocked}")));
            }
        }

        #[test]
        fn filters_target_the_qdisc_handle_not_a_class() {
            let cmds = joined(&filter_commands("wlan0", "192.168.1.42", "1:142"));
            for c in &cmds {
                assert!(c.contains("parent 1:0 "), "filters attach to {ROOT_QDISC}");
            }
        }

        #[test]
        fn a_high_last_octet_still_produces_a_valid_classid() {
            let commands = joined(&filter_commands("wlan0", "10.0.0.255", "1:355"));
            assert!(commands.iter().all(|c| c.contains("10.0.0.255")));
            assert!(commands.iter().all(|c| c.contains("flowid 1:355")));
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    //! `dnctl` (dummynet) carries the throttled lanes; anything not matched by
    //! a `pfctl` dummynet rule passes at full speed, the same "explicit
    //! throttle list, implicit fast lane" shape as the Linux HTB setup.
    //! Requires Homebrew's `arpspoof` (`brew install dsniff`) for the MITM
    //! side — this module only handles shaping.
    //!
    //! Not verified on real hardware: the `pfctl`/`dnctl` invocations follow
    //! documented syntax but should be treated as a first pass to validate on
    //! an actual Mac.

    use super::{device_classid, DeviceSpec, Snapshot, BLOCK_CLASSID, BLOCK_RATE};
    use crate::paths::CONFIG_DIR;
    use crate::rate;
    use crate::system::{run_quiet, run_status};
    use std::path::PathBuf;

    /// dummynet pipe carrying the household's shared throttle rate.
    const SHARED_PIPE: u16 = 10;

    fn pf_conf_file() -> PathBuf {
        std::path::Path::new(CONFIG_DIR).join("pf.curfew.conf")
    }

    fn configure_pipe(pipe: u16, rate: &str) {
        run_status(
            "dnctl",
            &["pipe", &pipe.to_string(), "config", "bw", &rate::to_dnctl(rate)],
        );
    }

    pub fn reshape(iface: &str, default_rate: &str, targets: &[(String, DeviceSpec)]) {
        run_quiet("pfctl", &["-E"]); // enable pf; harmless if already on

        // Clean slate, so lanes belonging to devices that are no longer
        // throttled don't linger and keep shaping traffic.
        run_quiet("dnctl", &["-q", "flush"]);

        configure_pipe(SHARED_PIPE, default_rate);
        configure_pipe(BLOCK_CLASSID, BLOCK_RATE);

        let mut rules = String::new();
        for (ip, spec) in targets {
            let pipe = match spec {
                DeviceSpec::Block => BLOCK_CLASSID,
                DeviceSpec::ThrottleAt(rate) => match device_classid(ip) {
                    Some(pipe) => {
                        configure_pipe(pipe, rate);
                        pipe
                    }
                    None => SHARED_PIPE,
                },
            };
            rules.push_str(&format!(
                "dummynet in  quick on {iface} proto ip from any to {ip} pipe {pipe}\n"
            ));
            rules.push_str(&format!(
                "dummynet out quick on {iface} proto ip from {ip} to any pipe {pipe}\n"
            ));
        }

        crate::paths::ensure_dir();
        let conf = pf_conf_file();
        let _ = std::fs::write(&conf, rules);
        run_status("pfctl", &["-q", "-f", &conf.to_string_lossy()]);
    }

    /// dummynet doesn't expose byte counters through `dnctl pipe show` in a
    /// format stable enough to parse across macOS versions. Rather than
    /// invent a number, report the figures as unavailable so the dashboard
    /// can leave them out.
    pub fn snapshot(_iface: &str) -> Snapshot {
        Snapshot {
            throttled_bytes: 0,
            fast_bytes: 0,
            classes: Vec::new(),
            available: false,
        }
    }

    pub fn teardown_all(_iface: &str) {
        run_quiet("pfctl", &["-q", "-F", "rules"]);
        run_quiet("dnctl", &["-q", "flush"]);
        let _ = std::fs::remove_file(pf_conf_file());
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::{DeviceSpec, Snapshot};

    pub fn reshape(_iface: &str, default_rate: &str, targets: &[(String, DeviceSpec)]) {
        crate::winshape::configure(default_rate, targets);
    }

    pub fn snapshot(_iface: &str) -> Snapshot {
        let (throttled_bytes, fast_bytes) = crate::winshape::stats();
        Snapshot {
            throttled_bytes,
            fast_bytes,
            classes: Vec::new(),
            available: true,
        }
    }

    pub fn teardown_all(_iface: &str) {
        crate::winshape::teardown_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_lanes_avoid_the_reserved_ids() {
        for last in 0..=255u16 {
            let id = device_classid(&format!("192.168.1.{last}")).unwrap();
            assert!(id >= 100, "classid {id} collides with a reserved lane");
            assert_ne!(id, BLOCK_CLASSID);
            assert_ne!(id, 20);
            assert_ne!(id, 10);
        }
    }

    #[test]
    fn device_lanes_are_unique_per_address() {
        // Two devices on the same subnet must never share a lane.
        let mut seen = std::collections::HashSet::new();
        for last in 0..=255 {
            let id = device_classid(&format!("192.168.1.{last}")).unwrap();
            assert!(seen.insert(id), "classid collision at .{last}");
        }
    }

    #[test]
    fn rejects_addresses_without_a_numeric_last_octet() {
        assert_eq!(device_classid("not-an-ip"), None);
        assert_eq!(device_classid(""), None);
        assert_eq!(device_classid("192.168.1."), None);
    }

    #[test]
    fn parses_real_tc_class_output() {
        let sample = "\
class htb 1:1 root rate 1Gbit ceil 1Gbit burst 0b cburst 0b
 Sent 3000000 bytes 3000 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
 lended: 0 borrowed: 0 giants: 0
 tokens: 0 ctokens: 0

class htb 1:10 parent 1:1 leaf 10: prio 0 rate 10Kbit ceil 10Kbit burst 0b cburst 0b
 Sent 4242 bytes 42 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0

class htb 1:20 parent 1:1 leaf 20: prio 0 rate 1Gbit ceil 1Gbit burst 0b cburst 0b
 Sent 2995758 bytes 2958 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
";
        let stats = parse_class_stats(sample);
        assert_eq!(stats.len(), 3);
        assert!(stats.contains(&("1:10".to_string(), 4242)));
        assert!(stats.contains(&("1:20".to_string(), 2_995_758)));
        assert!(stats.contains(&("1:1".to_string(), 3_000_000)));
    }

    #[test]
    fn root_class_is_excluded_from_totals() {
        // The root counter already includes its children; counting it would
        // double every figure on the dashboard.
        let stats = vec![
            ("1:1".to_string(), 3_000_000),
            ("1:10".to_string(), 4242),
            ("1:20".to_string(), 2_995_758),
        ];
        let (throttled, fast) = split_class_stats(&stats);
        assert_eq!(throttled, 4242);
        assert_eq!(fast, 2_995_758);
    }

    #[test]
    fn blocked_and_per_device_lanes_count_as_throttled() {
        let stats = vec![
            ("1:10".to_string(), 100),
            ("1:99".to_string(), 200),
            ("1:142".to_string(), 300),
            ("1:20".to_string(), 999),
        ];
        let (throttled, fast) = split_class_stats(&stats);
        assert_eq!(throttled, 600);
        assert_eq!(fast, 999);
    }

    #[test]
    fn empty_output_yields_no_stats() {
        assert!(parse_class_stats("").is_empty());
        assert!(parse_class_stats("qdisc htb 1: root\n").is_empty());
    }

    #[test]
    fn snapshot_finds_a_devices_own_lane() {
        let snapshot = Snapshot {
            throttled_bytes: 0,
            fast_bytes: 0,
            classes: vec![("1:142".to_string(), 777)],
            available: true,
        };
        assert_eq!(snapshot.for_device("192.168.1.42"), Some(777));
        assert_eq!(snapshot.for_device("192.168.1.7"), None);
    }

    fn snapshot_with(bytes: &[(&str, u64)]) -> Snapshot {
        Snapshot {
            throttled_bytes: 0,
            fast_bytes: 0,
            classes: bytes
                .iter()
                .map(|(id, n)| (id.to_string(), *n))
                .collect(),
            available: true,
        }
    }

    #[test]
    fn reports_only_new_traffic_between_readings() {
        let mut tracker = TrafficTracker::default();
        let ips = vec!["192.168.1.42".to_string()];

        let first = tracker.deltas(&snapshot_with(&[("1:142", 1000)]), &ips);
        assert_eq!(first, vec![("192.168.1.42".to_string(), 1000)]);

        let second = tracker.deltas(&snapshot_with(&[("1:142", 1500)]), &ips);
        assert_eq!(second, vec![("192.168.1.42".to_string(), 500)], "only the increase");

        let unchanged = tracker.deltas(&snapshot_with(&[("1:142", 1500)]), &ips);
        assert!(unchanged.is_empty(), "nothing new to report");
    }

    #[test]
    fn treats_a_counter_reset_as_new_traffic_not_negative() {
        // The shaping tree is rebuilt on every settings change, which zeroes
        // the kernel counters. A naive subtraction would go negative (or
        // panic on underflow) and corrupt the running total.
        let mut tracker = TrafficTracker::default();
        let ips = vec!["192.168.1.42".to_string()];
        tracker.deltas(&snapshot_with(&[("1:142", 9_000)]), &ips);
        let after_rebuild = tracker.deltas(&snapshot_with(&[("1:142", 250)]), &ips);
        assert_eq!(after_rebuild, vec![("192.168.1.42".to_string(), 250)]);
    }

    #[test]
    fn forgets_devices_that_are_no_longer_tracked() {
        let mut tracker = TrafficTracker::default();
        tracker.deltas(
            &snapshot_with(&[("1:142", 500)]),
            &["192.168.1.42".to_string()],
        );
        // Device leaves, then comes back with the counter at zero.
        tracker.deltas(&snapshot_with(&[]), &[]);
        let returned = tracker.deltas(
            &snapshot_with(&[("1:142", 300)]),
            &["192.168.1.42".to_string()],
        );
        assert_eq!(returned, vec![("192.168.1.42".to_string(), 300)]);
    }

    #[test]
    fn a_device_with_no_lane_yet_reports_nothing() {
        let mut tracker = TrafficTracker::default();
        let ips = vec!["192.168.1.42".to_string()];
        assert!(tracker.deltas(&snapshot_with(&[]), &ips).is_empty());
    }
}
