//! Reading the local network: interfaces, addressing, and discovering
//! devices. Device discovery (`nmap -sn`) is identical everywhere; interface
//! enumeration, own-IP, gateway, subnet, and MAC lookup are OS-specific
//! because each OS names and reports them through different tools.

use crate::colors::{RED, RESET};
use crate::system::{prompt, try_run};

/// One device found by a scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub ip: String,
    /// Reverse-DNS/hostname nmap resolved, if any.
    pub hostname: Option<String>,
    /// MAC, when nmap could read it. Only available on the local segment and
    /// only when running with raw-socket privileges — which Curfew has, being
    /// root — so this is usually Some on Linux, and saves a separate lookup.
    pub mac: Option<String>,
}

/// Parses `nmap -sn` output.
///
/// Two line shapes matter:
///
/// ```text
/// Nmap scan report for kids-ipad (192.168.1.27)
/// Host is up (0.012s latency).
/// MAC Address: 00:14:51:11:22:33 (Apple)
///
/// Nmap scan report for 192.168.1.1
/// Host is up.
/// ```
///
/// The `MAC Address:` line belongs to the report above it, so the parser
/// tracks the device it's currently filling in.
pub fn parse_nmap_output(output: &str) -> Vec<DiscoveredDevice> {
    let mut devices: Vec<DiscoveredDevice> = Vec::new();

    for line in output.lines() {
        let line = line.trim();

        if let Some(rest) = line.strip_prefix("Nmap scan report for ") {
            let rest = rest.trim();
            // "<hostname> (<ip>)" when reverse DNS resolved, "<ip>" otherwise.
            let (hostname, ip) = match (rest.rfind('('), rest.ends_with(')')) {
                (Some(start), true) => {
                    let host = rest[..start].trim();
                    let ip = &rest[start + 1..rest.len() - 1];
                    let host = (!host.is_empty()).then(|| host.to_string());
                    (host, ip.to_string())
                }
                _ => (None, rest.to_string()),
            };
            devices.push(DiscoveredDevice {
                ip,
                hostname,
                mac: None,
            });
            continue;
        }

        if let Some(rest) = line.strip_prefix("MAC Address: ") {
            // "00:14:51:11:22:33 (Apple)"
            let mac = rest.split_whitespace().next().unwrap_or_default();
            if let (Some(device), Some(mac)) = (devices.last_mut(), crate::oui::normalize_mac(mac))
            {
                device.mac = Some(mac);
            }
        }
    }

    devices
}

/// Lists devices on `subnet`, skipping anything in `exclude`. `Err` means the
/// scan itself failed to run (e.g. `nmap` missing or crashed) — distinct from
/// a clean scan that simply found no devices. Same on every OS: `nmap` prints
/// identical `-sn` output on Linux, macOS, and Windows.
pub fn scan_devices(subnet: &str, exclude: &[String]) -> Result<Vec<DiscoveredDevice>, String> {
    let out = try_run("nmap", &["-sn", subnet])?;
    Ok(parse_nmap_output(&out)
        .into_iter()
        .filter(|device| !exclude.contains(&device.ip))
        .collect())
}

pub fn select_interface() -> String {
    let ifaces = list_wifi_interfaces();
    if ifaces.is_empty() {
        eprintln!("{RED}No Wi-Fi found on this computer. Make sure you're connected to your home Wi-Fi, then try again.{RESET}");
        std::process::exit(1);
    }
    // Almost every home computer has exactly one Wi-Fi — pick it automatically
    // so there's nothing to answer.
    if ifaces.len() == 1 {
        return ifaces[0].clone();
    }
    println!("You have more than one Wi-Fi connection. Which one are you using?");
    for (i, name) in ifaces.iter().enumerate() {
        println!("  {}) {}", i + 1, name);
    }
    loop {
        let choice = prompt("Type its number and press Enter: ");
        if let Ok(n) = choice.parse::<usize>() {
            if n >= 1 && n <= ifaces.len() {
                return ifaces[n - 1].clone();
            }
        }
        println!("{RED}That wasn't one of the numbers above. Please try again.{RESET}");
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use crate::colors::{RED, RESET};
    use crate::system::{run, try_run};

    pub fn list_wifi_interfaces() -> Vec<String> {
        let out = run("iw", &["dev"]);
        let mut ifaces = Vec::new();
        for line in out.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("Interface ") {
                ifaces.push(rest.trim().to_string());
            }
        }
        ifaces
    }

    pub fn get_own_ip(iface: &str) -> String {
        let out = run("ip", &["-4", "addr", "show", iface]);
        for line in out.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("inet ") {
                if let Some(ip) = rest.split('/').next() {
                    return ip.to_string();
                }
            }
        }
        eprintln!("{RED}Could not detect IP on {iface}. Exiting.{RESET}");
        std::process::exit(1);
    }

    pub fn get_gateway() -> String {
        let out = run("ip", &["route"]);
        for line in out.lines() {
            if line.starts_with("default") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(pos) = parts.iter().position(|&w| w == "via") {
                    if let Some(gw) = parts.get(pos + 1) {
                        return gw.to_string();
                    }
                }
            }
        }
        eprintln!("{RED}Could not detect default gateway. Exiting.{RESET}");
        std::process::exit(1);
    }

    pub fn get_subnet(iface: &str) -> String {
        let out = run("ip", &["-o", "-f", "inet", "addr", "show", iface]);
        let parts: Vec<&str> = out.split_whitespace().collect();
        for (i, p) in parts.iter().enumerate() {
            if *p == "inet" {
                if let Some(cidr) = parts.get(i + 1) {
                    return cidr.to_string();
                }
            }
        }
        eprintln!("{RED}Could not detect subnet. Exiting.{RESET}");
        std::process::exit(1);
    }

    /// Looks up a device's MAC address via the kernel's neighbor (ARP) table.
    pub fn lookup_mac(iface: &str, ip: &str) -> String {
        let out = try_run("ip", &["neigh", "show", ip, "dev", iface]).unwrap_or_default();
        out.split_whitespace()
            .position(|w| w == "lladdr")
            .and_then(|i| out.split_whitespace().nth(i + 1))
            .unwrap_or("unknown")
            .to_string()
    }

    /// Link speed in Mbit/s, straight from sysfs. Wi-Fi drivers routinely
    /// report `-1` (or the sentinel `65535`) because the rate varies per
    /// packet, so `None` is a normal answer here, not an error — see
    /// `parse_link_speed` for the decoding.
    pub fn link_speed_mbit(iface: &str) -> Option<u32> {
        let raw = std::fs::read_to_string(format!("/sys/class/net/{iface}/speed")).ok()?;
        super::parse_link_speed(&raw)
    }

    /// This interface's own hardware address. Read straight from sysfs, so it
    /// is available without a lookup and can't be confused with a neighbour.
    pub fn own_mac(iface: &str) -> Option<String> {
        let raw = std::fs::read_to_string(format!("/sys/class/net/{iface}/address")).ok()?;
        super::parse_sysfs_mac(&raw)
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use crate::colors::{RED, RESET};
    use crate::system::{run, try_run};

    pub fn list_wifi_interfaces() -> Vec<String> {
        // `networksetup -listallhardwareports` prints blocks like:
        //   Hardware Port: Wi-Fi
        //   Device: en0
        let out = run("networksetup", &["-listallhardwareports"]);
        let mut ifaces = Vec::new();
        let mut is_wifi = false;
        for line in out.lines() {
            if let Some(port) = line.strip_prefix("Hardware Port: ") {
                is_wifi = port.trim() == "Wi-Fi" || port.trim() == "AirPort";
            } else if is_wifi {
                if let Some(dev) = line.strip_prefix("Device: ") {
                    ifaces.push(dev.trim().to_string());
                    is_wifi = false;
                }
            }
        }
        ifaces
    }

    pub fn get_own_ip(iface: &str) -> String {
        let out = run("ipconfig", &["getifaddr", iface]);
        if out.is_empty() {
            eprintln!("{RED}Could not detect IP on {iface}. Exiting.{RESET}");
            std::process::exit(1);
        }
        out
    }

    pub fn get_gateway() -> String {
        let out = run("route", &["-n", "get", "default"]);
        for line in out.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("gateway: ") {
                return rest.trim().to_string();
            }
        }
        eprintln!("{RED}Could not detect default gateway. Exiting.{RESET}");
        std::process::exit(1);
    }

    /// Converts a dotted netmask ("255.255.255.0") to a CIDR prefix length.
    fn netmask_to_prefix(mask: &str) -> u32 {
        mask.split('.')
            .filter_map(|o| o.parse::<u8>().ok())
            .map(|o| o.count_ones())
            .sum()
    }

    pub fn get_subnet(iface: &str) -> String {
        let out = run("ifconfig", &[iface]);
        let mut ip = None;
        let mut mask_hex = None;
        for line in out.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("inet ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                ip = parts.first().map(|s| s.to_string());
                if let Some(pos) = parts.iter().position(|&w| w == "netmask") {
                    mask_hex = parts.get(pos + 1).map(|s| s.to_string());
                }
                break;
            }
        }
        match (ip, mask_hex) {
            (Some(ip), Some(hex)) => {
                // macOS prints the netmask as a hex string like "0xffffff00".
                let prefix = u32::from_str_radix(hex.trim_start_matches("0x"), 16)
                    .map(|m| m.count_ones())
                    .unwrap_or_else(|_| netmask_to_prefix(&hex));
                format!("{ip}/{prefix}")
            }
            _ => {
                eprintln!("{RED}Could not detect subnet. Exiting.{RESET}");
                std::process::exit(1);
            }
        }
    }

    /// Looks up a device's MAC via `arp -n <ip>`:
    /// "? (192.168.1.5) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
    pub fn lookup_mac(_iface: &str, ip: &str) -> String {
        let out = try_run("arp", &["-n", ip]).unwrap_or_default();
        out.split_whitespace()
            .position(|w| w == "at")
            .and_then(|i| out.split_whitespace().nth(i + 1))
            .filter(|m| *m != "(incomplete)")
            .unwrap_or("unknown")
            .to_string()
    }

    /// Best-effort link speed from the `media:` line of `ifconfig`, e.g.
    /// "media: autoselect (1000baseT <full-duplex>)" -> 1000. Wi-Fi reports a
    /// bare "autoselect" with no rate, so this returns `None` on a wireless
    /// interface — which is why callers must have their own fallback.
    pub fn link_speed_mbit(iface: &str) -> Option<u32> {
        let out = run("ifconfig", &[iface]);
        let media = out.lines().find(|l| l.contains("media:"))?;
        let base = media.find("base")?;
        let digits: String = media[..base]
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        digits.chars().rev().collect::<String>().parse().ok()
    }

    /// This interface's own hardware address, from `ifconfig`'s `ether` line.
    pub fn own_mac(iface: &str) -> Option<String> {
        let out = run("ifconfig", &[iface]);
        for line in out.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("ether ") {
                return crate::oui::normalize_mac(rest.split_whitespace().next()?);
            }
        }
        None
    }
}

#[cfg(target_os = "windows")]
mod imp {
    use crate::colors::{RED, RESET};
    use crate::system::{run, try_run};

    pub fn list_wifi_interfaces() -> Vec<String> {
        // `netsh interface show interface` lists all interfaces; filter to
        // ones netsh's wlan module knows about (actual Wi-Fi adapters).
        let wlan_out = run("netsh", &["wlan", "show", "interfaces"]);
        let mut ifaces = Vec::new();
        for line in wlan_out.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("Name") {
                if let Some(name) = rest.trim_start_matches([':', ' ']).split(':').last() {
                    let name = name.trim();
                    if !name.is_empty() {
                        ifaces.push(name.to_string());
                    }
                }
            }
        }
        ifaces
    }

    pub fn get_own_ip(iface: &str) -> String {
        let out = run("netsh", &["interface", "ip", "show", "address", iface]);
        for line in out.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("IP Address:") {
                return rest.trim().to_string();
            }
        }
        eprintln!("{RED}Could not detect IP on {iface}. Exiting.{RESET}");
        std::process::exit(1);
    }

    pub fn get_gateway() -> String {
        let out = run("netsh", &["interface", "ip", "show", "config"]);
        for line in out.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("Default Gateway:") {
                let gw = rest.trim();
                if !gw.is_empty() && gw != "None" {
                    return gw.to_string();
                }
            }
        }
        eprintln!("{RED}Could not detect default gateway. Exiting.{RESET}");
        std::process::exit(1);
    }

    fn netmask_to_prefix(mask: &str) -> u32 {
        mask.split('.')
            .filter_map(|o| o.parse::<u8>().ok())
            .map(|o| o.count_ones())
            .sum()
    }

    pub fn get_subnet(iface: &str) -> String {
        let out = run("netsh", &["interface", "ip", "show", "address", iface]);
        let mut ip = None;
        let mut mask = None;
        for line in out.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("IP Address:") {
                ip = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("Subnet Prefix:") {
                // e.g. "192.168.1.0/24 (mask 255.255.255.0)"
                if let Some(m) = rest.split("mask ").nth(1) {
                    mask = Some(m.trim_end_matches(')').trim().to_string());
                }
            }
        }
        match (ip, mask) {
            (Some(ip), Some(mask)) => format!("{ip}/{}", netmask_to_prefix(&mask)),
            _ => {
                eprintln!("{RED}Could not detect subnet. Exiting.{RESET}");
                std::process::exit(1);
            }
        }
    }

    /// Looks up a device's MAC via `arp -a <ip>`. Windows prints MACs with
    /// dashes ("aa-bb-cc-dd-ee-ff"); normalized to colons for consistency
    /// with the persisted exempt-MAC list format.
    pub fn lookup_mac(_iface: &str, ip: &str) -> String {
        let out = try_run("arp", &["-a", ip]).unwrap_or_default();
        for line in out.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.first() == Some(&ip) {
                if let Some(mac) = parts.get(1) {
                    return mac.replace('-', ":").to_lowercase();
                }
            }
        }
        "unknown".to_string()
    }

    /// Best-effort: the currently negotiated Wi-Fi receive rate. This is a
    /// per-packet PHY rate that moves around, not the link's capacity, so it
    /// is only ever used as an upper-bound hint.
    pub fn link_speed_mbit(_iface: &str) -> Option<u32> {
        let out = run("netsh", &["wlan", "show", "interfaces"]);
        for line in out.lines() {
            let line = line.trim();
            if line.starts_with("Receive rate") {
                return line.split(':').nth(1).and_then(|v| v.trim().parse().ok());
            }
        }
        None
    }

    /// This adapter's own hardware address, from `getmac`'s CSV output.
    ///
    /// Unverified on real hardware, like the rest of this backend. `getmac`
    /// prints every adapter, so the row whose name mentions `iface` is
    /// preferred, falling back to the first hardware address found.
    pub fn own_mac(iface: &str) -> Option<String> {
        let out = run("getmac", &["/v", "/fo", "csv", "/nh"]);
        let wanted = iface.to_lowercase();
        let mut fallback = None;
        for line in out.lines() {
            let fields: Vec<String> = line
                .split(',')
                .map(|f| f.trim().trim_matches('"').to_string())
                .collect();
            // Columns are: Connection Name, Network Adapter, Physical Address, ...
            let Some(address) = fields.get(2) else { continue };
            let Some(mac) = crate::oui::normalize_mac(address) else {
                continue;
            };
            if fields
                .first()
                .is_some_and(|name| name.to_lowercase().contains(&wanted))
            {
                return Some(mac);
            }
            fallback.get_or_insert(mac);
        }
        fallback
    }
}

/// Decodes the text of Linux's `/sys/class/net/<iface>/speed`. Split out from
/// the imp module so the sentinel handling is testable without a network
/// interface: the kernel uses `-1` (and historically `65535`) to mean
/// "unknown", which is what most Wi-Fi drivers report.
pub fn parse_link_speed(raw: &str) -> Option<u32> {
    let speed: i64 = raw.trim().parse().ok()?;
    if speed <= 0 || speed == 65535 {
        return None;
    }
    u32::try_from(speed).ok()
}

/// Decodes the text of Linux's `/sys/class/net/<iface>/address`.
///
/// Returns `None` for the all-zero address, which is what an interface that
/// hasn't come up yet reports — treating that as a real address would make
/// the ARP watcher ignore everything.
pub fn parse_sysfs_mac(raw: &str) -> Option<String> {
    let mac = crate::oui::normalize_mac(raw.trim())?;
    let all_zero = mac.split(':').all(|octet| octet == "00");
    (!all_zero).then_some(mac)
}

pub use imp::{
    get_gateway, get_own_ip, get_subnet, link_speed_mbit, list_wifi_interfaces, lookup_mac, own_mac,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_speeds() {
        assert_eq!(parse_link_speed("1000\n"), Some(1000));
        assert_eq!(parse_link_speed("100"), Some(100));
        assert_eq!(parse_link_speed(" 2500 "), Some(2500));
    }

    #[test]
    fn treats_unknown_sentinels_as_absent() {
        // What Wi-Fi drivers actually report.
        assert_eq!(parse_link_speed("-1"), None);
        assert_eq!(parse_link_speed("65535"), None);
        assert_eq!(parse_link_speed("0"), None);
        assert_eq!(parse_link_speed(""), None);
        assert_eq!(parse_link_speed("unknown"), None);
    }

    #[test]
    fn reads_an_interface_hardware_address() {
        assert_eq!(
            parse_sysfs_mac("aa:bb:cc:dd:ee:ff\n"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            parse_sysfs_mac("AA:BB:CC:DD:EE:FF"),
            Some("aa:bb:cc:dd:ee:ff".to_string()),
            "normalised"
        );
    }

    #[test]
    fn an_interface_that_is_not_up_has_no_address() {
        // A down interface reports all zeroes; treating that as real would
        // make the ARP watcher match every packet against it.
        assert_eq!(parse_sysfs_mac("00:00:00:00:00:00"), None);
        assert_eq!(parse_sysfs_mac(""), None);
        assert_eq!(parse_sysfs_mac("not-a-mac"), None);
    }

    const SCAN: &str = "\
Starting Nmap 7.94 ( https://nmap.org ) at 2026-09-16 19:04 UTC
Nmap scan report for kids-ipad (192.168.1.27)
Host is up (0.012s latency).
MAC Address: 00:14:51:11:22:33 (Apple)
Nmap scan report for 192.168.1.1
Host is up (0.0031s latency).
MAC Address: 3C:22:FB:AA:BB:CC (Apple)
Nmap scan report for unknown-device.local (192.168.1.144)
Host is up (0.020s latency).
Nmap scan report for 192.168.1.200
Host is up (0.050s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 6.21 seconds
";

    #[test]
    fn extracts_ip_hostname_and_mac() {
        let devices = parse_nmap_output(SCAN);
        assert_eq!(devices.len(), 4);

        assert_eq!(devices[0].ip, "192.168.1.27");
        assert_eq!(devices[0].hostname.as_deref(), Some("kids-ipad"));
        assert_eq!(devices[0].mac.as_deref(), Some("00:14:51:11:22:33"));

        assert_eq!(devices[1].ip, "192.168.1.1");
        assert_eq!(devices[1].hostname, None, "a bare IP has no hostname");
        assert_eq!(devices[1].mac.as_deref(), Some("3c:22:fb:aa:bb:cc"), "lowercased");
    }

    #[test]
    fn handles_a_hostname_that_has_no_mac_line() {
        let devices = parse_nmap_output(SCAN);
        let device = devices.iter().find(|d| d.ip == "192.168.1.144").unwrap();
        assert_eq!(device.hostname.as_deref(), Some("unknown-device.local"));
        assert_eq!(device.mac, None, "nmap didn't report one");
    }

    #[test]
    fn does_not_attach_a_mac_to_the_wrong_device() {
        // 192.168.1.200 follows a device that *does* have a MAC; the parser
        // must not carry it over.
        let devices = parse_nmap_output(SCAN);
        let last = devices.iter().find(|d| d.ip == "192.168.1.200").unwrap();
        assert_eq!(last.mac, None);
    }

    #[test]
    fn ignores_the_header_and_footer() {
        let devices = parse_nmap_output(SCAN);
        assert!(devices.iter().all(|d| !d.ip.contains("Nmap")));
    }

    #[test]
    fn handles_empty_and_malformed_output() {
        assert!(parse_nmap_output("").is_empty());
        assert!(parse_nmap_output("Nmap done: 256 IP addresses\n").is_empty());
        // A MAC line with no preceding report must not panic.
        assert!(parse_nmap_output("MAC Address: 00:14:51:11:22:33 (Apple)\n").is_empty());
        // A MAC line that nmap printed as unknown.
        let devices = parse_nmap_output(
            "Nmap scan report for 192.168.1.5\nMAC Address: 00:00:00:00:00:00 (Unknown)\n",
        );
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].mac.as_deref(), Some("00:00:00:00:00:00"));
    }

    #[test]
    fn a_skipped_mac_line_does_not_break_the_next_device() {
        let devices = parse_nmap_output(
            "Nmap scan report for 192.168.1.5\n\
             MAC Address: not-a-mac\n\
             Nmap scan report for 192.168.1.6\n\
             MAC Address: 00:14:51:11:22:33 (Apple)\n",
        );
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].mac, None, "unparseable MAC left empty");
        assert_eq!(devices[1].mac.as_deref(), Some("00:14:51:11:22:33"));
    }
}
