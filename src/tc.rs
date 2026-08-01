//! Linux traffic control (`tc`) setup: a fast lane (default, full speed) and
//! a throttled lane, with per-device filters routing traffic into one or the
//! other by IP.

use crate::system::{run, run_status};

pub fn add_tc_filters(iface: &str, ip: &str) {
    run_status(
        "tc",
        &[
            "filter", "add", "dev", iface, "protocol", "ip", "parent", "1:0", "prio", "1", "u32",
            "match", "ip", "dst", ip, "flowid", "1:10",
        ],
    );
    run_status(
        "tc",
        &[
            "filter", "add", "dev", iface, "protocol", "ip", "parent", "1:0", "prio", "1", "u32",
            "match", "ip", "src", ip, "flowid", "1:10",
        ],
    );
}

/// (Re)builds the base qdisc and classes: `1:1` root, `1:10` throttled leaf at
/// `rate`, `1:20` fast leaf at full speed. The qdisc's `default 20` sends any
/// traffic without a matching filter (yourself included) to the fast lane.
pub fn rebuild_tc_base(iface: &str, rate: &str) {
    run_status("tc", &["qdisc", "del", "dev", iface, "root"]);
    run_status(
        "tc",
        &[
            "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "20",
        ],
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
            "class", "add", "dev", iface, "parent", "1:1", "classid", "1:10", "htb", "rate", rate,
            "ceil", rate, "quantum", "1600",
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

/// Bytes actually seen by the throttled lane (1:10) vs. the fast lane (1:20)
/// since the qdisc was built. Diagnostic: if throttled-lane bytes stay near
/// zero while a "throttled" device is clearly using the network, the ARP
/// spoofing isn't actually intercepting its traffic — the rate limit was
/// never the problem. If bytes climb there but the device still feels fast,
/// the traffic is being classified correctly but the kernel isn't actually
/// enforcing the rate (a known quirk on some Wi-Fi drivers).
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
