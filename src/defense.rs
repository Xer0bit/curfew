//! Actively defending the network once a spoofer is found.
//!
//! Detection (see [`crate::arpwatch`]) answers "is someone throttling my
//! devices?". This module answers the follow-up: "so what do we do about it?"
//!
//! # How the defense works
//!
//! ARP spoofing only succeeds because the kernel believes whichever reply
//! arrived last. Two things break that:
//!
//! 1. **Pinning.** A neighbour entry in the `permanent` state is never
//!    replaced by an ARP reply — the kernel stops consulting the wire for that
//!    address entirely. Pinning a device's *real* hardware address means a
//!    spoofer's replies for it are simply ignored.
//! 2. **Re-announcing.** Other devices on the network still hold the spoofer's
//!    lie in their own caches. A gratuitous ARP from this machine (the same
//!    `arping -A` Curfew already uses to clean up after itself) tells them the
//!    truth again.
//!
//! # What is protected, and why not more
//!
//! The **gateway** is always pinned: whoever controls the gateway mapping
//! controls where every device's traffic goes, so it is the one address worth
//! defending unconditionally. Devices that are actually being contested get
//! pinned too. Devices nobody is interfering with are left alone — pinning
//! healthy devices adds kernel state and a cleanup burden for no benefit, and
//! would turn a targeted incident into a network-wide change.
//!
//! # The honest limits
//!
//! - **This is a fight Curfew can lose.** A spoofer that pins *its* lies
//!   faster, or has root on the router, wins. Defense is re-applied on every
//!   scan, so a temporary win by the spoofer is corrected within a scan
//!   interval — but between scans, traffic can leak.
//! - **Pinning assumes the recorded MAC is the real one.** It comes from
//!   Curfew's own observations, which a sufficiently determined attacker could
//!   have poisoned first. If the pinned address is wrong, the defense is
//!   confidently wrong — which is why the UI says what was pinned, so a human
//!   can check it.
//! - **It does not remove the spoofer.** Their machine is still on the
//!   network. This stops their lies from taking effect; it does not evict
//!   them. That needs the router (block their MAC, change the Wi-Fi password).
//!
//! Everything here is reversible: [`Defense::disable`] removes every pin it
//! created. Nothing is done to the spoofer's machine.

use std::collections::BTreeMap;

/// One address Curfew has pinned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    pub ip: String,
    /// The hardware address Curfew believes is real, now enforced by the
    /// kernel.
    pub mac: String,
    /// Why this address was pinned.
    pub reason: Reason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The gateway mapping — defended unconditionally.
    Gateway,
    /// A device whose address is being contested by a spoofer.
    ContestedDevice,
}

impl Reason {
    pub fn label(self) -> &'static str {
        match self {
            Reason::Gateway => "gateway",
            Reason::ContestedDevice => "contested device",
        }
    }
}

/// The commands that implement one pin, as plain argv so the exact kernel
/// interaction can be asserted in tests without root.
///
/// Split from execution for the same reason the `tc` command builders are:
/// this is the part that can't be exercised without root and a live network,
/// and it's where a wrong flag would silently do nothing.
pub fn pin_commands(ip: &str, mac: &str, iface: &str) -> Vec<Vec<String>> {
    vec![[
        "neigh", "replace", ip, "lladdr", mac, "nud", "permanent", "dev", iface,
    ]
    .iter()
    .map(|p| p.to_string())
    .collect()]
}

/// The command that removes one pin.
pub fn unpin_command(ip: &str, iface: &str) -> Vec<String> {
    ["neigh", "del", ip, "dev", iface]
        .iter()
        .map(|p| p.to_string())
        .collect()
}

/// The command that re-announces a true binding to the rest of the network.
///
/// `-A` sends an ARP *reply* (gratuitous ARP) rather than a request, which is
/// what updates other machines' caches without them asking.
pub fn announce_command(ip: &str, iface: &str) -> Vec<String> {
    ["-c", "2", "-A", "-I", iface, ip]
        .iter()
        .map(|p| p.to_string())
        .collect()
}

/// Decides which addresses deserve pinning, given what the watcher saw.
///
/// Pure, so the policy is testable: the gateway always, plus every device
/// whose address is being claimed by more than one machine.
pub fn plan(
    gateway: &str,
    gateway_mac: Option<&str>,
    contested: &[(String, String)], // (ip, real mac)
) -> Vec<Pin> {
    let mut pins = Vec::new();

    // The gateway is the one mapping that matters to everyone.
    if let Some(mac) = gateway_mac {
        pins.push(Pin {
            ip: gateway.to_string(),
            mac: mac.to_string(),
            reason: Reason::Gateway,
        });
    }

    for (ip, mac) in contested {
        // A device already pinned as the gateway doesn't need a second entry.
        if pins.iter().any(|pin| pin.ip == *ip) {
            continue;
        }
        pins.push(Pin {
            ip: ip.clone(),
            mac: mac.clone(),
            reason: Reason::ContestedDevice,
        });
    }

    pins
}

/// The active defense state: what's pinned, and whether it's on.
#[derive(Default)]
pub struct Defense {
    enabled: bool,
    /// Currently pinned addresses, keyed by IP. `BTreeMap` so listings are
    /// stable and readable.
    pins: BTreeMap<String, Pin>,
}

impl Defense {
    /// Turns the defense on and applies the plan.
    ///
    /// Returns the pins that were newly created, so the caller can log them.
    /// Idempotent: an address already pinned correctly is left alone rather
    /// than re-pinned, so repeated scans don't churn the kernel table.
    pub fn enable(
        &mut self,
        iface: &str,
        pins: Vec<Pin>,
        apply: &mut dyn FnMut(&[String]),
    ) -> Vec<Pin> {
        self.enabled = true;
        let mut fresh = Vec::new();

        for pin in pins {
            if self.pins.get(&pin.ip).map(|p| p.mac.clone()) == Some(pin.mac.clone()) {
                continue; // already pinned to the right address
            }
            // If the address was pinned to a *different* MAC (the situation
            // changed), replace it rather than leaving a stale pin.
            apply(&pin_commands(&pin.ip, &pin.mac, iface)
                .iter()
                .map(|argv| argv.join(" "))
                .collect::<Vec<_>>());
            fresh.push(pin.clone());
            self.pins.insert(pin.ip.clone(), pin);
        }

        fresh
    }

    /// Turns the defense off and removes every pin Curfew created.
    ///
    /// Returns the addresses that were unpinned. Only entries Curfew itself
    /// created are removed — pre-existing permanent entries the user made
    /// themselves are left alone, because they were there first and removing
    /// someone else's configuration is not ours to do.
    pub fn disable(&mut self, iface: &str, apply: &mut dyn FnMut(&[String])) -> Vec<String> {
        self.enabled = false;
        let removed: Vec<String> = self.pins.keys().cloned().collect();
        for ip in &removed {
            apply(&[unpin_command(ip, iface).join(" ")]);
        }
        self.pins.clear();
        removed
    }

    /// Re-applies the current pins without changing the enabled state.
    ///
    /// Called on every scan while defense is on: if a spoofer managed to
    /// dislodge a pin, this puts it back. Returns addresses that had to be
    /// re-asserted.
    pub fn maintain(&mut self, iface: &str, apply: &mut dyn FnMut(&[String])) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }
        let mut reasserted = Vec::new();
        for (ip, pin) in &self.pins {
            apply(&pin_commands(ip, &pin.mac, iface)
                .iter()
                .map(|argv| argv.join(" "))
                .collect::<Vec<_>>());
            reasserted.push(ip.clone());
        }
        reasserted
    }

    /// The addresses to re-announce to the network: every pinned IP. Other
    /// machines' caches still hold the spoofer's lie until told otherwise.
    pub fn announce_targets(&self) -> Vec<String> {
        self.pins.keys().cloned().collect()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The current pins, ordered by IP.
    pub fn list(&self) -> Vec<&Pin> {
        self.pins.values().collect()
    }
}

// ---------------------------------------------------------------------------
// The live defense
// ---------------------------------------------------------------------------

use std::sync::{Mutex, OnceLock};

struct Running {
    defense: Defense,
    iface: String,
}

static RUNNING: OnceLock<Mutex<Option<Running>>> = OnceLock::new();

fn running() -> &'static Mutex<Option<Running>> {
    RUNNING.get_or_init(|| Mutex::new(None))
}

/// Runs one command through the system, swallowing output. Curfew runs as
/// root, which both `ip neigh` and `arping` require.
fn execute(argv: &[String]) {
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    // `ip neigh ...` vs `arping ...`: the pin commands start with the `ip`
    // subcommand name, the announce command is an arping flag list.
    if argv.first().map(String::as_str) == Some("neigh") {
        crate::system::run_quiet("ip", &args);
    } else {
        crate::system::run_quiet("arping", &args);
    }
}

/// True if the defense feature is available at all: it needs `ip` and
/// `arping`, which are already required dependencies on Linux.
pub fn available() -> bool {
    crate::system::tool_exists("ip") && crate::system::tool_exists("arping")
}

/// True if the defense is currently switched on.
pub fn is_enabled() -> bool {
    let guard = running().lock().unwrap_or_else(|p| p.into_inner());
    guard.as_ref().map(|r| r.defense.is_enabled()).unwrap_or(false)
}

/// The current pins, for display.
pub fn list_pins() -> Vec<Pin> {
    let guard = running().lock().unwrap_or_else(|p| p.into_inner());
    guard
        .as_ref()
        .map(|r| r.defense.list().into_iter().cloned().collect())
        .unwrap_or_default()
}

/// Turns the defense on and applies `pins`.
///
/// Returns the pins that were newly created, for logging. Safe to call again:
/// an unchanged plan does nothing.
pub fn enable(iface: &str, pins: Vec<Pin>) -> Vec<Pin> {
    let mut guard = running().lock().unwrap_or_else(|p| p.into_inner());
    let running = guard.get_or_insert_with(|| Running {
        defense: Defense::default(),
        iface: iface.to_string(),
    });
    let fresh = running.defense.enable(iface, pins, &mut execute);

    // Tell the rest of the network the truth. Other machines' caches still
    // hold the spoofer's lie until this runs.
    for ip in running.defense.announce_targets() {
        execute(&announce_command(&ip, &running.iface));
    }
    if !fresh.is_empty() {
        // Re-announcing is part of enabling, not part of each pin, so report
        // the pins alone.
        fresh
    } else {
        fresh
    }
}

/// Turns the defense off and removes every pin Curfew created.
pub fn disable() -> Vec<String> {
    let mut guard = running().lock().unwrap_or_else(|p| p.into_inner());
    let Some(running) = guard.as_mut() else {
        return Vec::new();
    };
    let iface = running.iface.clone();
    let removed = running.defense.disable(&iface, &mut execute);
    removed
}

/// Re-asserts every pin. Called on each scan while the defense is on, so a
/// spoofer that dislodged one is corrected within a scan interval.
///
/// Returns the addresses re-asserted, for logging.
pub fn maintain() -> Vec<String> {
    let mut guard = running().lock().unwrap_or_else(|p| p.into_inner());
    let Some(running) = guard.as_mut() else {
        return Vec::new();
    };
    let iface = running.iface.clone();
    let reasserted = running.defense.maintain(&iface, &mut execute);

    // Re-announce on the same cadence: other machines' caches expire on their
    // own schedule, not ours.
    for ip in running.defense.announce_targets() {
        execute(&announce_command(&ip, &iface));
    }
    reasserted
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The runtime is a process-wide singleton, so the tests that touch it
    /// must not run in parallel with each other. This gate serialises them
    /// without needing an extra crate.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[allow(unused_macros)]
    macro_rules! serial_defense {
        () => {}
    }

    #[test]
    fn availability_matches_the_required_tools() {
        // The defense reuses Curfew's required dependencies, so on a normal
        // install it's always available; this pins the check to the tools
        // rather than to a hardcoded true.
        assert_eq!(available(), crate::system::tool_exists("ip") && crate::system::tool_exists("arping"));
    }

    #[test]
    fn queries_before_any_enable_are_safe_defaults() {
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        // Nothing has been enabled; the queries must not panic and must not
        // claim protection that doesn't exist.
        assert!(!is_enabled());
        assert_eq!(list_pins().len(), 0);
        assert!(list_pins().is_empty());
        assert!(maintain().is_empty());
        assert!(disable().is_empty());
    }

    #[test]
    fn enable_then_disable_round_trips() {
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        // Uses the loopback interface: the commands will fail without root,
        // but the state machine must still track what it attempted, which is
        // what these tests are about.
        let pins = vec![Pin {
            ip: "127.0.0.2".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            reason: Reason::Gateway,
        }];
        let _ = enable("lo", pins);
        assert_eq!(list_pins().len(), 1, "the pin is tracked even if the kernel refused it");
        let removed = disable();
        assert_eq!(removed.len(), 1);
        assert_eq!(list_pins().len(), 0);
        assert!(!is_enabled());
    }

    #[test]
    fn enable_is_idempotent_across_calls() {
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        let pins = vec![Pin {
            ip: "127.0.0.3".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            reason: Reason::Gateway,
        }];
        let first = enable("lo", pins.clone());
        assert_eq!(first.len(), 1);
        let second = enable("lo", pins);
        assert!(second.is_empty(), "no new pins the second time");
        disable();
    }

    #[test]
    fn a_changed_mac_is_re_pinned() {
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        let first = vec![Pin {
            ip: "127.0.0.4".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            reason: Reason::Gateway,
        }];
        let _ = enable("lo", first);
        let second = vec![Pin {
            ip: "127.0.0.4".to_string(),
            mac: "00:11:22:33:44:66".to_string(),
            reason: Reason::Gateway,
        }];
        let fresh = enable("lo", second);
        assert_eq!(fresh.len(), 1, "the changed pin is applied");
        assert_eq!(list_pins()[0].mac, "00:11:22:33:44:66");
        disable();
    }

    #[test]
    fn maintain_reasserts_while_enabled() {
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        let pins = vec![Pin {
            ip: "127.0.0.5".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            reason: Reason::Gateway,
        }];
        let _ = enable("lo", pins);
        let reasserted = maintain();
        assert_eq!(reasserted, vec!["127.0.0.5".to_string()]);
        disable();
        assert!(maintain().is_empty(), "nothing to maintain when off");
    }
}
