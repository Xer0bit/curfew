//! Per-device actions: start throttling a device, release one device, or
//! restore everything (full shutdown).

use crate::colors::{GREEN, RESET};
use crate::spoof;
use crate::state::{get_mac, log_event, State};
use crate::system::spin_while;
use crate::tc::{add_tc_filters, rebuild_tc_base, teardown_all};
use std::sync::{Arc, Mutex};

/// Starts ARP-spoofing + throttling a device. No-ops (and logs) if spoofing
/// fails to start, leaving the device untouched so the next scan retries it.
pub fn throttle_device(iface: &str, gateway: &str, ip: &str, state: &Arc<Mutex<State>>) {
    let Some(session) = spoof::start_spoof(iface, gateway, ip, state) else {
        return;
    };

    {
        let mut st = state.lock().unwrap();
        st.arpspoof_sessions.insert(ip.to_string(), session);
        st.devices.push(ip.to_string());
    }

    add_tc_filters(iface, ip);
    let mac = get_mac(state, iface, ip);
    log_event(state, &format!("Throttled {ip} ({mac})"));
}

/// Stops throttling a single device and restores its ARP entry, leaving
/// every other throttled device untouched.
pub fn unblock_device(iface: &str, ip: &str, state: &Arc<Mutex<State>>) {
    let (rate, remaining, session) = {
        let mut st = state.lock().unwrap();
        let session = st.arpspoof_sessions.remove(ip);
        st.devices.retain(|d| d != ip);
        (st.rate.clone(), st.devices.clone(), session)
    };
    if let Some(session) = session {
        spoof::stop_spoof(session);
    }

    let iface_owned = iface.to_string();
    let ip_owned = ip.to_string();
    spin_while("Giving full speed", move || {
        // Individual per-device filters can't be reliably removed in
        // isolation on every backend, so shaping is rebuilt from the
        // remaining throttled devices.
        rebuild_tc_base(&iface_owned, &rate);
        for d in &remaining {
            add_tc_filters(&iface_owned, d);
        }
        spoof::restore_arp(&iface_owned, &ip_owned);
    });

    log_event(state, &format!("Unblocked {ip}"));
}

/// Full shutdown: stops all ARP spoofing, tears down traffic shaping, restores
/// ARP for every affected device, disables IP forwarding, and exits.
pub fn cleanup(state: &Arc<Mutex<State>>) {
    println!("\nCleaning up, restoring normal internet for everyone...");

    let state_owned = Arc::clone(state);
    spin_while("Restoring everyone's internet", move || {
        let (iface, devices, gateway, sessions) = {
            let mut st = state_owned.lock().unwrap();
            (
                st.iface.clone(),
                st.devices.clone(),
                st.gateway.clone(),
                std::mem::take(&mut st.arpspoof_sessions),
            )
        };

        for (_, session) in sessions {
            spoof::stop_spoof(session);
        }
        spoof::kill_all(&iface);

        teardown_all(&iface);

        for ip in &devices {
            spoof::restore_arp(&iface, ip);
        }
        spoof::restore_arp(&iface, &gateway);

        crate::system::disable_ip_forward();
    });

    println!("{GREEN}All devices restored to normal. Forwarding disabled. Exiting.{RESET}");
    std::process::exit(0);
}
