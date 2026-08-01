//! Reading the local network: interfaces, addressing, and discovering devices.

use crate::colors::{RED, RESET};
use crate::system::{prompt, run, try_run};

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

pub fn select_interface() -> String {
    let ifaces = list_wifi_interfaces();
    if ifaces.is_empty() {
        eprintln!("{RED}No wireless interfaces found. Exiting.{RESET}");
        std::process::exit(1);
    }
    println!("Wireless interfaces:");
    for (i, name) in ifaces.iter().enumerate() {
        println!("  {}) {}", i + 1, name);
    }
    loop {
        let choice = prompt("Select interface number: ");
        if let Ok(n) = choice.parse::<usize>() {
            if n >= 1 && n <= ifaces.len() {
                return ifaces[n - 1].clone();
            }
        }
        println!("{RED}Invalid selection, try again.{RESET}");
    }
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

/// Lists device IPs on `subnet`, skipping anything in `exclude`. `Err` means
/// the scan itself failed to run (e.g. `nmap` missing or crashed) — distinct
/// from a clean scan that simply found no devices.
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

/// Looks up a device's MAC address via the kernel's neighbor (ARP) table.
/// Returns "unknown" if the lookup tool fails or the entry isn't found.
pub fn lookup_mac(iface: &str, ip: &str) -> String {
    let out = try_run("ip", &["neigh", "show", ip, "dev", iface]).unwrap_or_default();
    out.split_whitespace()
        .position(|w| w == "lladdr")
        .and_then(|i| out.split_whitespace().nth(i + 1))
        .unwrap_or("unknown")
        .to_string()
}
