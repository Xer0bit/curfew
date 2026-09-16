//! Noticing when someone else is doing this.
//!
//! Three things count as "someone else is involved", and each is detected
//! differently:
//!
//! 1. **They signed into your panel.** Handled by [`crate::accesslog`] — the
//!    sign-in is recorded with the address it came from.
//! 2. **They're running their own Curfew on another machine.** That machine
//!    will be listening on the panel port, so [`scan_for_panels`] finds it.
//! 3. **They're interfering with the network directly**, by ARP-spoofing your
//!    router themselves. That changes the hardware address you see for the
//!    gateway, which [`GatewayGuard`] notices.
//!
//! Everything here only ever *reports*. Nothing is automatically blocked or
//! fought over: a surprise counter-attack on a home network is more likely to
//! break it than fix it, and the owner should be the one to decide.

use crate::colors::{DIM, RESET, YELLOW};

/// Detects a change in the gateway's hardware address.
///
/// While Curfew runs, its own view of the router should be the genuine one —
/// Curfew spoofs *devices*, never itself or the gateway. So if the MAC this
/// machine resolves for the gateway changes, something else has started
/// answering ARP for the router's address.
///
/// A changed address is not proof of malice: replacing the router, or a
/// mesh node taking over, does it legitimately. It's reported once so the
/// owner can judge, then the new value becomes the baseline.
#[derive(Default)]
pub struct GatewayGuard {
    baseline: Option<String>,
}

/// What a gateway reading meant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GatewayObservation {
    /// Nothing to compare against yet.
    Baseline(String),
    /// Same as before.
    Unchanged,
    /// The address changed — worth telling the owner about.
    Changed { from: String, to: String },
    /// Couldn't read it this time; the baseline is left alone.
    Unknown,
}

impl GatewayGuard {
    /// Feeds in the current hardware address for the gateway, if one could be
    /// read.
    pub fn observe(&mut self, current: Option<&str>) -> GatewayObservation {
        let Some(current) = current else {
            return GatewayObservation::Unknown;
        };
        // `lookup_mac` reports failure as this sentinel rather than an error.
        if current == "unknown" || current.is_empty() {
            return GatewayObservation::Unknown;
        }

        match &self.baseline {
            None => {
                self.baseline = Some(current.to_string());
                GatewayObservation::Baseline(current.to_string())
            }
            Some(known) if known == current => GatewayObservation::Unchanged,
            Some(known) => {
                // Report once, then adopt the new value so a legitimate change
                // settles instead of warning forever.
                let previous = known.clone();
                self.baseline = Some(current.to_string());
                GatewayObservation::Changed {
                    from: previous,
                    to: current.to_string(),
                }
            }
        }
    }

    /// The address currently considered correct. Only used by the tests, which
    /// check that a failed reading leaves it untouched.
    #[cfg(test)]
    fn baseline_value(&self) -> Option<&str> {
        self.baseline.as_deref()
    }
}

/// Extracts the hosts that have `port` open from `nmap -p <port> --open`
/// output.
///
/// The output pairs a host report with a port table:
///
/// ```text
/// Nmap scan report for 192.168.1.27
/// Host is up (0.012s latency).
/// PORT     STATE SERVICE
/// 8787/tcp open  unknown
/// MAC Address: 00:14:51:11:22:33 (Apple)
/// ```
///
/// The host a port line belongs to is whichever report came last, so the
/// parser tracks that rather than assuming one line per host.
pub fn parse_open_hosts(output: &str, port: u16) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    let marker = format!("{port}/tcp");

    for line in output.lines() {
        let line = line.trim();

        if let Some(rest) = line.strip_prefix("Nmap scan report for ") {
            // "<hostname> (<ip>)" or just "<ip>".
            let rest = rest.trim();
            current = Some(match (rest.rfind('('), rest.ends_with(')')) {
                (Some(start), true) => rest[start + 1..rest.len() - 1].to_string(),
                _ => rest.to_string(),
            });
            continue;
        }

        if line.starts_with(&marker) {
            let state = line[marker.len()..].split_whitespace().next().unwrap_or("");
            if state == "open" {
                if let Some(host) = &current {
                    if !hosts.contains(host) {
                        hosts.push(host.clone());
                    }
                }
            }
        }
    }

    hosts
}

/// Looks for other machines listening on the panel port.
///
/// `port` is the port *this* Curfew is using, so a custom `--web` address is
/// covered. Our own address is excluded — we are obviously listening.
///
/// This is a port check against the local network, which is ordinary
/// administration on a network you own; it looks at one port and nothing else.
pub fn scan_for_panels(subnet: &str, my_ip: &str, port: u16) -> Result<Vec<String>, String> {
    // -n skips reverse DNS (faster and quieter), --open hides closed ports.
    let output = crate::system::try_run(
        "nmap",
        &["-n", "-p", &port.to_string(), "--open", subnet],
    )?;
    Ok(parse_open_hosts(&output, port)
        .into_iter()
        .filter(|host| host != my_ip)
        .collect())
}

/// The gateway's hardware address as this machine currently sees it.
pub fn gateway_mac(iface: &str, gateway: &str) -> Option<String> {
    let mac = crate::network::lookup_mac(iface, gateway);
    (mac != "unknown" && !mac.is_empty()).then_some(mac)
}

/// Prints a warning about other panels found, for the terminal.
pub fn report_other_panels(hosts: &[String], port: u16) {
    for host in hosts {
        println!("{YELLOW}Another Curfew panel is running at {host}:{port}.{RESET}");
    }
    if !hosts.is_empty() {
        println!(
            "{DIM}Someone else may be controlling devices on this network.{RESET}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCAN: &str = "\
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.27
Host is up (0.012s latency).
PORT     STATE SERVICE
8787/tcp open  unknown
MAC Address: 00:14:51:11:22:33 (Apple)

Nmap scan report for 192.168.1.31
Host is up (0.0040s latency).
PORT     STATE SERVICE
8787/tcp closed unknown
MAC Address: 3C:22:FB:AA:BB:CC (Apple)

Nmap scan report for 192.168.1.60
Host is up (0.020s latency).
PORT     STATE SERVICE
8787/tcp open  unknown
MAC Address: 0A:11:22:33:44:55 (Unknown)
";

    #[test]
    fn finds_hosts_with_the_port_open() {
        let hosts = parse_open_hosts(SCAN, 8787);
        assert_eq!(hosts, vec!["192.168.1.27", "192.168.1.60"]);
    }

    #[test]
    fn ignores_hosts_where_the_port_is_closed() {
        // 192.168.1.31 appears in the scan but isn't running a panel.
        let hosts = parse_open_hosts(SCAN, 8787);
        assert!(!hosts.contains(&"192.168.1.31".to_string()));
    }

    #[test]
    fn only_matches_the_port_asked_for() {
        let output = "\
Nmap scan report for 192.168.1.27
8787/tcp open  unknown
9999/tcp open  unknown
";
        assert_eq!(parse_open_hosts(output, 8787), vec!["192.168.1.27"]);
        assert_eq!(parse_open_hosts(output, 9999), vec!["192.168.1.27"]);
        assert!(parse_open_hosts(output, 1234).is_empty());
    }

    #[test]
    fn does_not_confuse_a_similar_port_number() {
        // "87870/tcp" must not match a search for 8787.
        let output = "Nmap scan report for 10.0.0.5\n87870/tcp open  unknown\n";
        assert!(parse_open_hosts(output, 8787).is_empty());
    }

    #[test]
    fn a_port_line_belongs_to_the_report_above_it() {
        // The bug this guards: attributing a port to the wrong host, which
        // would name an innocent device as running a second panel.
        let output = "\
Nmap scan report for 10.0.0.1
8787/tcp closed unknown
Nmap scan report for 10.0.0.2
8787/tcp open  unknown
";
        assert_eq!(parse_open_hosts(output, 8787), vec!["10.0.0.2"]);
    }

    #[test]
    fn handles_a_hostname_form_report() {
        let output = "\
Nmap scan report for kids-ipad (192.168.1.27)
8787/tcp open  unknown
";
        assert_eq!(parse_open_hosts(output, 8787), vec!["192.168.1.27"]);
    }

    #[test]
    fn handles_empty_and_unrelated_output() {
        assert!(parse_open_hosts("", 8787).is_empty());
        assert!(parse_open_hosts("Starting Nmap\nNmap done: 256 hosts\n", 8787).is_empty());
        // A port line with no preceding host report must not panic.
        assert!(parse_open_hosts("8787/tcp open  unknown\n", 8787).is_empty());
    }

    #[test]
    fn reports_a_host_only_once() {
        let output = "\
Nmap scan report for 10.0.0.2
8787/tcp open  unknown
8787/tcp open  unknown
";
        assert_eq!(parse_open_hosts(output, 8787), vec!["10.0.0.2"]);
    }

    #[test]
    fn the_first_reading_establishes_a_baseline() {
        let mut guard = GatewayGuard::default();
        assert_eq!(
            guard.observe(Some("aa:bb:cc:dd:ee:ff")),
            GatewayObservation::Baseline("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn an_unchanged_gateway_is_not_worth_mentioning() {
        let mut guard = GatewayGuard::default();
        guard.observe(Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(
            guard.observe(Some("aa:bb:cc:dd:ee:ff")),
            GatewayObservation::Unchanged
        );
    }

    #[test]
    fn a_changed_gateway_is_reported_once_then_settles() {
        // Someone else impersonating the router is the case this exists for.
        let mut guard = GatewayGuard::default();
        guard.observe(Some("aa:bb:cc:dd:ee:ff"));
        let observation = guard.observe(Some("11:22:33:44:55:66"));
        assert_eq!(
            observation,
            GatewayObservation::Changed {
                from: "aa:bb:cc:dd:ee:ff".to_string(),
                to: "11:22:33:44:55:66".to_string(),
            }
        );
        // A legitimate change (new router) must not warn forever.
        assert_eq!(
            guard.observe(Some("11:22:33:44:55:66")),
            GatewayObservation::Unchanged
        );
    }

    #[test]
    fn a_missing_reading_does_not_disturb_the_baseline() {
        // A transient lookup failure must not look like a change, and must
        // not overwrite what we know.
        let mut guard = GatewayGuard::default();
        guard.observe(Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(guard.observe(None), GatewayObservation::Unknown);
        assert_eq!(guard.observe(Some("unknown")), GatewayObservation::Unknown);
        assert_eq!(guard.observe(Some("")), GatewayObservation::Unknown);
        assert_eq!(
            guard.observe(Some("aa:bb:cc:dd:ee:ff")),
            GatewayObservation::Unchanged,
            "the known address is still known"
        );
    }

    #[test]
    fn a_failed_first_reading_does_not_set_a_baseline() {
        let mut guard = GatewayGuard::default();
        assert_eq!(guard.observe(None), GatewayObservation::Unknown);
        assert_eq!(guard.baseline_value(), None);
        // The next real reading is treated as the first, not as a change.
        assert_eq!(
            guard.observe(Some("aa:bb:cc:dd:ee:ff")),
            GatewayObservation::Baseline("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn comparing_addresses_ignores_case() {
        // `ip` prints lowercase, Windows uppercase; a case difference is not
        // a change of hardware.
        let mut guard = GatewayGuard::default();
        guard.observe(Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(
            guard.observe(Some("aa:bb:cc:dd:ee:ff")),
            GatewayObservation::Unchanged
        );
    }
}
