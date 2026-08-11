//! Reading the local network: interfaces, addressing, and discovering
//! devices. Device discovery (`nmap -sn`) is identical everywhere; interface
//! enumeration, own-IP, gateway, subnet, and MAC lookup are OS-specific
//! because each OS names and reports them through different tools.

use crate::colors::{RED, RESET};
use crate::system::{prompt, try_run};

/// Lists device IPs on `subnet`, skipping anything in `exclude`. `Err` means
/// the scan itself failed to run (e.g. `nmap` missing or crashed) — distinct
/// from a clean scan that simply found no devices. Same on every OS: `nmap`
/// prints identical `-sn` output on Linux, macOS, and Windows.
pub fn scan_devices(subnet: &str, exclude: &[String]) -> Result<Vec<String>, String> {
    let out = try_run("nmap", &["-sn", subnet])?;
    let mut devices = Vec::new();
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix("Nmap scan report for ") {
            let rest = rest.trim();
            // nmap prints "<hostname> (<ip>)" when reverse DNS resolves, "<ip>" otherwise.
            let ip = match (rest.rfind('('), rest.ends_with(')')) {
                (Some(start), true) => rest[start + 1..rest.len() - 1].to_string(),
                _ => rest.to_string(),
            };
            if !exclude.contains(&ip) {
                devices.push(ip);
            }
        }
    }
    Ok(devices)
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
}

pub use imp::{get_gateway, get_own_ip, get_subnet, list_wifi_interfaces, lookup_mac};
