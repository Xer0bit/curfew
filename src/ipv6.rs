//! IPv6 awareness.
//!
//! Curfew intercepts traffic with ARP spoofing, which is IPv4-only. On a
//! dual-stack network a throttled device can therefore reach the internet at
//! full speed over IPv6, completely bypassing the shaping rules — the packet
//! goes straight to the router and never passes through this machine.
//!
//! Making that *actually* blocked needs NDP/RA forgery (the IPv6 equivalent
//! of ARP spoofing) or router-side firewall rules. Neither can be validated
//! without real hardware, so rather than ship unverified raw-socket packet
//! crafting that could disrupt a household's IPv6, Curfew does the next most
//! useful thing: it detects the situation and says so, clearly, instead of
//! quietly showing a device as "slowed down" when it isn't.
//!
//! Everything here is pure parsing plus one `ip -6 neigh` call, so the logic
//! is unit-tested.

/// A parsed IPv6 neighbour-table entry: the address, and the MAC it resolved
/// to (absent for entries the kernel couldn't complete).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbour {
    pub address: String,
    pub mac: Option<String>,
}

/// Parses the output of `ip -6 neigh show dev <iface>`.
///
/// Example lines:
///
/// ```text
/// fe80::1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff router STALE
/// 2409:40d0:3f:9a::4 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
/// fe80::9 dev wlan0  FAILED
/// ```
pub fn parse_neighbours(output: &str) -> Vec<Neighbour> {
    output
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let address = words.next()?.to_string();
            let mut mac = None;
            while let Some(word) = words.next() {
                if word == "lladdr" {
                    mac = words.next().map(|m| m.to_lowercase());
                    break;
                }
            }
            Some(Neighbour { address, mac })
        })
        .collect()
}

/// The IPv6 addresses belonging to the device with `mac`, out of an
/// already-parsed neighbour list.
pub fn addresses_in(neighbours: &[Neighbour], mac: &str) -> Vec<String> {
    let wanted = mac.to_lowercase();
    neighbours
        .iter()
        .filter(|n| n.mac.as_deref() == Some(wanted.as_str()))
        .map(|n| n.address.clone())
        .collect()
}

/// True if `address` is a global (internet-routable) or unique-local address,
/// as opposed to link-local or multicast.
///
/// A device only has one of these because the router advertised a prefix, so
/// its presence is a strong signal that IPv6 internet access is available —
/// which is exactly when the bypass matters.
pub fn is_global(address: &str) -> bool {
    let lower = address.to_lowercase();
    if lower.is_empty() {
        return false;
    }
    // Link-local, multicast, loopback, and the unspecified address.
    if lower.starts_with("fe80") || lower.starts_with("ff") || lower == "::1" || lower == "::" {
        return false;
    }
    lower.contains(':')
}

/// True if any address in `addresses` would give the device internet access
/// over IPv6.
pub fn has_global(addresses: &[String]) -> bool {
    addresses.iter().any(|a| is_global(a))
}

/// The kernel's IPv6 neighbour table for `iface`, read once per scan (one
/// `ip` call instead of one per device). Empty if `ip` is unavailable or the
/// table is empty.
#[cfg(unix)]
pub fn neighbours(iface: &str) -> Vec<Neighbour> {
    let output =
        crate::system::try_run("ip", &["-6", "neigh", "show", "dev", iface]).unwrap_or_default();
    parse_neighbours(&output)
}

/// Windows has no `ip -6 neigh`; `netsh interface ipv6 show neighbors`
/// prints a different table that isn't parsed here, so Windows reports no
/// addresses rather than guessing.
#[cfg(not(unix))]
pub fn neighbours(_iface: &str) -> Vec<Neighbour> {
    Vec::new()
}

/// Fills the kernel's IPv6 neighbour table by pinging the all-nodes multicast
/// address, so the next [`neighbours`] call has something to match against.
/// Best-effort and silent: a failure just means we learn nothing this scan.
#[cfg(unix)]
pub fn prime_neighbour_table(iface: &str) {
    crate::system::run_quiet(
        "ping",
        &["-6", "-c", "1", "-W", "1", "-I", iface, "ff02::1"],
    );
}

#[cfg(not(unix))]
pub fn prime_neighbour_table(_iface: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
fe80::1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff router STALE
2409:40d0:3f:9a::4 dev wlan0 lladdr 11:22:33:44:55:66 REACHABLE
fe80::9 dev wlan0  FAILED
2409:40d0:3f:9a::9 dev wlan0 lladdr AA:BB:CC:DD:EE:FF DELAY
";

    #[test]
    fn parses_entries_with_and_without_a_mac() {
        let neighbours = parse_neighbours(SAMPLE);
        assert_eq!(neighbours.len(), 4);
        assert_eq!(
            neighbours[0],
            Neighbour {
                address: "fe80::1".into(),
                mac: Some("aa:bb:cc:dd:ee:ff".into()),
            }
        );
        assert_eq!(neighbours[2].mac, None, "FAILED entries have no lladdr");
    }

    #[test]
    fn finds_a_devices_addresses_by_mac() {
        let found = addresses_in(&parse_neighbours(SAMPLE), "aa:bb:cc:dd:ee:ff");
        assert_eq!(found, vec!["fe80::1", "2409:40d0:3f:9a::9"]);
    }

    #[test]
    fn matches_macs_case_insensitively() {
        // `ip` prints lowercase, Windows prints uppercase; a device must not
        // be missed because of case.
        assert_eq!(
            addresses_in(&parse_neighbours(SAMPLE), "11:22:33:44:55:66"),
            vec!["2409:40d0:3f:9a::4"]
        );
    }

    #[test]
    fn unknown_mac_finds_nothing() {
        assert!(addresses_in(&parse_neighbours(SAMPLE), "de:ad:be:ef:00:01").is_empty());
    }

    #[test]
    fn link_local_and_multicast_are_not_internet_access() {
        assert!(!is_global("fe80::1"));
        assert!(!is_global("FE80::ABCD"));
        assert!(!is_global("ff02::1"));
        assert!(!is_global("::1"));
        assert!(!is_global(""));
        assert!(!is_global("192.168.1.5"), "an IPv4 address isn't IPv6");
    }

    #[test]
    fn global_and_unique_local_addresses_count() {
        assert!(is_global("2409:40d0:3f:9a::4"));
        assert!(is_global("2a00:1450:4009:80b::200e"));
        assert!(is_global("fd00::1"), "unique-local still routes");
    }

    #[test]
    fn bypass_is_flagged_only_when_a_real_address_exists() {
        assert!(has_global(&["2409:40d0:3f:9a::4".to_string()]));
        assert!(!has_global(&["fe80::1".to_string(), "ff02::1".to_string()]));
        assert!(!has_global(&[]));
    }

    #[test]
    fn a_link_local_only_device_is_not_flagged() {
        // Every IPv6-capable NIC has a link-local address even with no IPv6
        // internet, so flagging on that alone would cry wolf constantly.
        let addresses = addresses_in(&parse_neighbours(SAMPLE), "aa:bb:cc:dd:ee:ff");
        assert!(has_global(&addresses));
        let link_local_only = vec!["fe80::1".to_string()];
        assert!(!has_global(&link_local_only));
    }
}
