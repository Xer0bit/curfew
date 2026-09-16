//! Per-device actions: start throttling a device, release one device, or
//! restore everything (full shutdown).
//!
//! Shaping is always applied in one shot from the current device list (see
//! [`apply_shaping`]) rather than incrementally per device, because no
//! backend can remove a single device's rules in place: Linux `tc` filters
//! can't be deleted by reference, and the macOS rules file is rewritten
//! wholesale. Rebuilding also makes every operation idempotent.

use crate::colors::{GREEN, RESET, YELLOW};
use crate::lock;
use crate::spoof;
use crate::state::{get_mac, log_event, State};
use crate::system::spin_while;
use crate::tc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Re-exported so callers have one obvious way to take the lock safely.
pub use crate::state::lock_state;

/// Set once cleanup begins, so a second Ctrl+C doesn't re-enter it.
static CLEANUP_STARTED: AtomicBool = AtomicBool::new(false);

/// Pushes the current shaping plan to the OS.
pub fn apply_shaping(iface: &str, state: &Arc<Mutex<State>>) {
    let (rate, plan) = {
        let st = lock_state(state);
        (st.rate.clone(), st.shaping_plan())
    };
    tc::reshape(iface, &rate, &plan);
}

/// Gives `ip`'s device permanent full speed, by MAC so it survives a new IP.
/// Returns the MAC that was exempted.
///
/// Shared by the terminal menu and the web UI so the two can't drift.
pub fn grant_full_speed(iface: &str, ip: &str, state: &Arc<Mutex<State>>) -> String {
    let mac = get_mac(state, iface, ip);
    unblock_device(iface, ip, state);
    {
        let mut st = lock_state(state);
        if !st.allowed_macs.contains(&mac) {
            st.allowed_macs.push(mac.clone());
        }
        // An explicit per-device setting would contradict "full speed", so
        // clear it rather than leaving a rule that says two things.
        st.modes.remove(&mac);
        crate::state::save_allowed(&st.allowed_macs);
        crate::state::save_modes(&st.modes);
    }
    log_event(state, &format!("Gave {ip} ({mac}) full speed"));
    mac
}

/// Removes a device from the full-speed list. It is throttled again on the
/// next scan, once its IP is seen.
pub fn revoke_full_speed(mac: &str, state: &Arc<Mutex<State>>) {
    {
        let mut st = lock_state(state);
        st.allowed_macs.retain(|m| m != mac);
        crate::state::save_allowed(&st.allowed_macs);
    }
    crate::state::purge_exempt_online(state, mac);
    log_event(state, &format!("Took full speed away from {mac}"));
}

/// Sets (or clears, with `None`) a per-device override and re-applies shaping.
pub fn set_device_mode(
    iface: &str,
    ip: &str,
    mac: &str,
    mode: Option<crate::state::DeviceMode>,
    state: &Arc<Mutex<State>>,
) {
    {
        let mut st = lock_state(state);
        match mode {
            Some(mode) => {
                st.modes.insert(mac.to_string(), mode);
            }
            None => {
                st.modes.remove(mac);
            }
        }
        crate::state::save_modes(&st.modes);
    }
    // A per-device setting only applies to a device we're actually managing;
    // make sure it is, so the change takes effect immediately rather than at
    // the next scan.
    let unmanaged = !lock_state(state).devices.iter().any(|d| d == ip);
    if unmanaged {
        let gateway = lock_state(state).gateway.clone();
        if !gateway.is_empty() {
            start_throttling(iface, &gateway, ip, state);
        }
    }
    apply_shaping(iface, state);
}

/// Changes the household rate and re-applies shaping to everyone.
pub fn set_household_rate(iface: &str, rate: &str, state: &Arc<Mutex<State>>) {
    lock_state(state).rate = rate.to_string();
    crate::paths::save_setting("rate", rate);
    apply_shaping(iface, state);
    log_event(state, &format!("Household speed set to {rate}"));
}

/// Grants everyone a temporary full-speed break, or ends one early when
/// `minutes` is `None`. The monitor thread clears the break once it lapses.
pub fn set_pause(state: &Arc<Mutex<State>>, minutes: Option<u64>) {
    match minutes {
        Some(minutes) => {
            lock_state(state).pause_until =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(minutes * 60));
            log_event(state, &format!("Break started for {minutes} minute(s)"));
        }
        None => {
            lock_state(state).pause_until = None;
            log_event(state, "Break ended early");
        }
    }
}

/// Starts ARP-spoofing `ip` and adds it to the managed set.
///
/// Shaping is deliberately *not* applied here — callers that manage several
/// devices at once should batch, then call [`apply_shaping`] once, since each
/// call rebuilds the entire shaping tree.
///
/// Returns true only if the device was *newly* added. A device already being
/// managed returns false so callers don't re-apply shaping or re-log it, and
/// a failure to start spoofing returns false so the next scan retries.
pub fn start_throttling(
    iface: &str,
    gateway: &str,
    ip: &str,
    state: &Arc<Mutex<State>>,
) -> bool {
    if lock_state(state).devices.iter().any(|d| d == ip) {
        return false; // already managed
    }

    let Some(session) = spoof::start_spoof(iface, gateway, ip, state) else {
        return false;
    };

    {
        let mut st = lock_state(state);
        st.arpspoof_sessions.insert(ip.to_string(), session);
        st.devices.push(ip.to_string());
    }
    true
}

/// Throttles several newly-discovered devices, rebuilding the shaping tree
/// once instead of once per device.
pub fn throttle_batch(
    iface: &str,
    gateway: &str,
    ips: &[String],
    state: &Arc<Mutex<State>>,
) -> usize {
    let newly: Vec<String> = ips
        .iter()
        .filter(|ip| start_throttling(iface, gateway, ip, state))
        .cloned()
        .collect();

    if !newly.is_empty() {
        apply_shaping(iface, state);
        for ip in &newly {
            let mac = get_mac(state, iface, ip);
            log_event(state, &format!("Throttled {ip} ({mac})"));
        }
    }
    newly.len()
}

/// The actual work of releasing devices: kill their spoofing, drop them from
/// the shaping plan, and restore their ARP entries. Shaping is rebuilt once
/// for the whole batch.
///
/// Deliberately silent — no spinner. The background monitor releases devices
/// on its own schedule, and an animation written from that thread would fight
/// the dashboard for the terminal.
fn release_inner(iface: &str, ips: &[String], state: &Arc<Mutex<State>>) {
    if ips.is_empty() {
        return;
    }

    let sessions: Vec<_> = {
        let mut st = lock_state(state);
        let sessions = ips
            .iter()
            .filter_map(|ip| st.arpspoof_sessions.remove(ip))
            .collect();
        st.devices.retain(|d| !ips.contains(d));
        st.exempt_online.retain(|d| !ips.contains(d));
        st.ipv6_bypass.retain(|d| !ips.contains(d));
        for ip in ips {
            st.missed.remove(ip);
        }
        sessions
    };
    for session in sessions {
        spoof::stop_spoof(session);
    }

    apply_shaping(iface, state);
    for ip in ips {
        spoof::restore_arp(iface, ip);
        // Stop attributing site activity to a device we no longer manage.
        crate::dnswatch::with_log(|log| log.forget(ip));
    }
}

/// Stops managing `ips` without any terminal output. For the background
/// monitor; interactive callers want [`unblock_device`].
pub fn release(iface: &str, ips: &[String], state: &Arc<Mutex<State>>) {
    release_inner(iface, ips, state);
}

/// Stops throttling a single device and restores its ARP entry, leaving every
/// other managed device untouched. Shows a spinner, so this is the version for
/// menu actions.
pub fn unblock_device(iface: &str, ip: &str, state: &Arc<Mutex<State>>) {
    let ips = vec![ip.to_string()];
    let iface_owned = iface.to_string();
    let state_for_spin = Arc::clone(state);
    spin_while("Giving full speed", move || {
        release_inner(&iface_owned, &ips, &state_for_spin);
    });
    log_event(state, &format!("Unblocked {ip}"));
}

/// Full shutdown: stops all ARP spoofing, tears down traffic shaping,
/// restores ARP for every affected device, restores the previous IP
/// forwarding setting, releases the lock, and exits.
///
/// Every step is best-effort and independent — a failure in one must not skip
/// the rest, because leaving ARP poisoned after Curfew exits is the worst
/// thing it can do to a network.
pub fn cleanup(state: &Arc<Mutex<State>>) {
    if CLEANUP_STARTED.swap(true, Ordering::SeqCst) {
        // A second Ctrl+C means "stop waiting". Still kill our arpspoof
        // processes first: an orphaned one keeps poisoning ARP forever, with
        // nothing left running to undo it.
        eprintln!("\n{YELLOW}Second interrupt — exiting now. Restoring ARP entries first.{RESET}");
        spoof::kill_all("");
        lock::release();
        std::process::exit(1);
    }

    println!("\nCleaning up, restoring normal internet for everyone...");
    crate::accesslog::record(
        crate::accesslog::Kind::Stopped,
        crate::accesslog::ACTOR_TERMINAL,
        "",
    );

    let state_owned = Arc::clone(state);
    spin_while("Restoring everyone's internet", move || {
        let (iface, devices, gateway, sessions) = {
            let mut st = lock_state(&state_owned);
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
        // Catches anything whose handle we lost (e.g. after a panic).
        spoof::kill_all(&iface);
        tc::teardown_all(&iface);
        // Reap the tcpdump helpers too, so they don't outlive us still
        // capturing, and remove any defense pins so the kernel table is left
        // exactly as we found it.
        crate::dnswatch::stop();
        crate::arpwatch::stop();
        crate::defense::disable();

        for ip in &devices {
            spoof::restore_arp(&iface, ip);
        }
        spoof::restore_arp(&iface, &gateway);

        crate::system::disable_ip_forward();
    });

    lock::release();
    println!("{GREEN}All devices restored to normal. Your previous settings are back. Exiting.{RESET}");
    std::process::exit(0);
}
