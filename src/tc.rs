//! Traffic shaping: a fast lane (default, full speed) and a throttled lane,
//! with devices routed into one or the other by IP. Linux uses `tc`/HTB,
//! macOS uses `pfctl`+`dnctl` (dummynet), Windows uses a WinDivert-based
//! userspace token bucket (see [`crate::winshape`]) since Windows has no
//! built-in packet-shaping primitive.

#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(target_os = "linux")]
mod linux {
    use crate::system::{run, run_quiet, run_status};

    pub fn add_tc_filters(iface: &str, ip: &str) {
        run_status(
            "tc",
            &[
                "filter", "add", "dev", iface, "protocol", "ip", "parent", "1:0", "prio", "1",
                "u32", "match", "ip", "dst", ip, "flowid", "1:10",
            ],
        );
        run_status(
            "tc",
            &[
                "filter", "add", "dev", iface, "protocol", "ip", "parent", "1:0", "prio", "1",
                "u32", "match", "ip", "src", ip, "flowid", "1:10",
            ],
        );
    }

    /// (Re)builds the base qdisc and classes: `1:1` root, `1:10` throttled
    /// leaf at `rate`, `1:20` fast leaf at full speed. `default 20` sends any
    /// traffic without a matching filter (yourself included) to the fast lane.
    pub fn rebuild_tc_base(iface: &str, rate: &str) {
        run_status("tc", &["qdisc", "del", "dev", iface, "root"]);
        run_status(
            "tc",
            &["qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "20"],
        );
        run_status(
            "tc",
            &[
                "class", "add", "dev", iface, "parent", "1:", "classid", "1:1", "htb", "rate",
                "100mbit", "quantum", "60000",
            ],
        );
        run_status(
            "tc",
            &[
                "class", "add", "dev", iface, "parent", "1:1", "classid", "1:10", "htb", "rate",
                rate, "ceil", rate, "quantum", "1600",
            ],
        );
        run_status(
            "tc",
            &[
                "class", "add", "dev", iface, "parent", "1:1", "classid", "1:20", "htb", "rate",
                "100mbit", "ceil", "100mbit", "quantum", "60000",
            ],
        );
    }

    /// Bytes actually seen by the throttled lane (1:10) vs. the fast lane
    /// (1:20) since the qdisc was built. Diagnostic: if throttled-lane bytes
    /// stay near zero while a "throttled" device is clearly using the
    /// network, ARP spoofing isn't intercepting its traffic. If bytes climb
    /// there but the device still feels fast, traffic is classified
    /// correctly but the kernel isn't enforcing the rate (a known quirk on
    /// some Wi-Fi drivers).
    pub fn class_stats(iface: &str) -> (u64, u64) {
        let out = run("tc", &["-s", "class", "show", "dev", iface]);
        let mut throttled = 0u64;
        let mut fast = 0u64;
        let mut lines = out.lines().peekable();
        while let Some(line) = lines.next() {
            if line.contains("1:10") {
                throttled = lines.peek().map(sent_bytes).unwrap_or(0);
            } else if line.contains("1:20") {
                fast = lines.peek().map(sent_bytes).unwrap_or(0);
            }
        }
        (throttled, fast)
    }

    fn sent_bytes(line: &&str) -> u64 {
        let words: Vec<&str> = line.split_whitespace().collect();
        words
            .iter()
            .position(|&w| w == "Sent")
            .and_then(|i| words.get(i + 1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    pub fn teardown_all(iface: &str) {
        run_quiet("tc", &["qdisc", "del", "dev", iface, "root"]);
        run_quiet("tc", &["qdisc", "del", "dev", iface, "ingress"]);
    }
}

#[cfg(target_os = "macos")]
mod macos {
    //! `dnctl` (dummynet) pipe 10 carries throttled traffic; anything not
    //! matched by a `pfctl` dummynet rule passes at full speed, the same
    //! "explicit throttle list, implicit fast lane" shape as the Linux HTB
    //! setup. Requires Homebrew's `arpspoof` (`brew install dsniff`) for the
    //! MITM side — this file only handles shaping.
    //!
    //! Not verified on real hardware in this session (no macOS build/test
    //! environment available) — the `pfctl`/`dnctl` invocations follow
    //! documented syntax but should be treated as a first pass to validate
    //! on an actual Mac.

    use crate::paths::CONFIG_DIR;
    use crate::system::{run, run_quiet, run_status};
    use std::path::PathBuf;

    fn targets_file() -> PathBuf {
        std::path::Path::new(CONFIG_DIR).join("pf_targets")
    }

    fn pf_conf_file() -> PathBuf {
        std::path::Path::new(CONFIG_DIR).join("pf.curfew.conf")
    }

    fn load_targets() -> Vec<String> {
        std::fs::read_to_string(targets_file())
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    }

    fn save_targets(ips: &[String]) {
        crate::paths::ensure_dir();
        let _ = std::fs::write(targets_file(), ips.join("\n") + "\n");
    }

    /// Converts a `tc`-style rate string ("10kbit") to `dnctl`'s format
    /// ("10Kbit/s").
    fn to_dnctl_rate(rate: &str) -> String {
        let lower = rate.to_lowercase();
        let split_at = lower.find(|c: char| c.is_alphabetic()).unwrap_or(lower.len());
        let (num, unit) = lower.split_at(split_at);
        let unit = match unit {
            "kbit" | "kbps" => "Kbit/s",
            "mbit" | "mbps" => "Mbit/s",
            "bit" | "bps" => "bit/s",
            _ => "Kbit/s",
        };
        format!("{num}{unit}")
    }

    fn write_pf_rules(iface: &str) {
        let mut rules = String::new();
        for ip in load_targets() {
            rules.push_str(&format!("dummynet in  quick on {iface} proto ip from any to {ip} pipe 10\n"));
            rules.push_str(&format!("dummynet out quick on {iface} proto ip from {ip} to any pipe 10\n"));
        }
        crate::paths::ensure_dir();
        let _ = std::fs::write(pf_conf_file(), rules);
        run_status("pfctl", &["-q", "-f", &pf_conf_file().to_string_lossy()]);
    }

    pub fn rebuild_tc_base(iface: &str, rate: &str) {
        run_quiet("pfctl", &["-E"]); // enable pf; harmless if already on
        run_status("dnctl", &["pipe", "10", "config", "bw", &to_dnctl_rate(rate)]);
        save_targets(&[]);
        write_pf_rules(iface);
    }

    pub fn add_tc_filters(iface: &str, ip: &str) {
        let mut targets = load_targets();
        if !targets.iter().any(|t| t == ip) {
            targets.push(ip.to_string());
        }
        save_targets(&targets);
        write_pf_rules(iface);
    }

    /// Best-effort: `dnctl pipe show` output format isn't stable across
    /// macOS versions, so this reads whatever byte counter it can find
    /// rather than asserting a fixed column layout. Returns `(throttled, 0)`
    /// — dummynet doesn't separately meter the fast lane since it's simply
    /// unshaped traffic.
    pub fn class_stats(_iface: &str) -> (u64, u64) {
        let out = run("dnctl", &["pipe", "show"]);
        let mut throttled = 0u64;
        for line in out.lines() {
            if line.contains("00010") || line.to_lowercase().contains("pipe 10") {
                if let Some(n) = line.split_whitespace().filter_map(|w| w.parse::<u64>().ok()).max() {
                    throttled = throttled.max(n);
                }
            }
        }
        (throttled, 0)
    }

    pub fn teardown_all(_iface: &str) {
        run_quiet("pfctl", &["-q", "-F", "rules"]);
        run_quiet("dnctl", &["-q", "flush"]);
        let _ = std::fs::remove_file(targets_file());
        let _ = std::fs::remove_file(pf_conf_file());
    }
}

#[cfg(target_os = "windows")]
mod windows {
    pub use crate::winshape::{add_target as add_tc_filters, stats as class_stats, teardown_all};

    pub fn rebuild_tc_base(_iface: &str, rate: &str) {
        crate::winshape::start(rate);
    }
}
