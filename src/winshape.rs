//! Windows traffic shaping. There's no built-in equivalent of Linux `tc` or
//! macOS `dnctl`, so this intercepts every forwarded IPv4 packet via
//! WinDivert's forward layer and applies a per-device token bucket (see
//! [`crate::bucket`]) to packets belonging to a managed device. Blocked
//! devices' packets are simply not re-injected. Everything else is forwarded
//! immediately at full speed.
//!
//! Unverified against real hardware: no Windows build/test environment was
//! available, and the vendored WinDivert crate needs a mingw C toolchain to
//! cross-compile. `WinDivert::forward`/`recv`/`send` signatures and
//! `WinDivertFlags::new()` are confirmed against the crate's published docs,
//! and all the packet/rate logic lives in the unit-tested [`crate::bucket`]
//! module, but the end-to-end loop has not been run.

use crate::bucket::{ipv4_addrs, Buckets, Verdict};
use crate::colors::{RED, RESET};
use crate::rate;
use crate::tc::DeviceSpec;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use windivert::prelude::*;

struct Shared {
    buckets: Mutex<Buckets>,
    throttled_bytes: AtomicU64,
    fast_bytes: AtomicU64,
    stop: AtomicBool,
}

static SHARED: OnceLock<Arc<Shared>> = OnceLock::new();

fn shared() -> &'static Arc<Shared> {
    SHARED.get_or_init(|| {
        Arc::new(Shared {
            buckets: Mutex::new(Buckets::default()),
            throttled_bytes: AtomicU64::new(0),
            fast_bytes: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        })
    })
}

/// Converts a bit-rate string into bytes/sec. `1` is the floor so a plain
/// divide-by-eight can't round a very slow lane down to a stall.
fn bytes_per_sec(rate_str: &str) -> u64 {
    rate::parse_bps(rate_str)
        .map(|bps| (bps / 8).max(1))
        .unwrap_or(1)
}

/// Applies `targets` to the shaper and starts the interception thread on the
/// first call.
///
/// Every target carries its own rate, so there's no separate household
/// default to apply here — the caller has already resolved each device's
/// effective speed. `FullSpeed` devices are left out of the limits map
/// entirely, so their packets take the fast path — the same "explicit
/// throttle list, implicit fast lane" shape the other backends use.
pub fn configure(_default_rate: &str, targets: &[(String, DeviceSpec)]) {
    let mut limits: HashMap<Ipv4Addr, u64> = HashMap::new();
    for (ip, spec) in targets {
        let Ok(addr) = ip.parse::<Ipv4Addr>() else {
            continue;
        };
        let bps = match spec {
            // A zero limit is the shaper's "block" signal.
            DeviceSpec::Block => 0,
            DeviceSpec::ThrottleAt(rate) => bytes_per_sec(rate),
        };
        limits.insert(addr, bps);
    }

    let s = shared();
    s.buckets.lock().unwrap().set_limits(limits);
    s.stop.store(false, Ordering::Relaxed);

    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return; // worker already running
    }

    let s = Arc::clone(shared());
    thread::spawn(move || {
        let wd = match WinDivert::<ForwardLayer>::forward("true", 0, WinDivertFlags::new()) {
            Ok(wd) => wd,
            Err(e) => {
                eprintln!("{RED}WinDivert failed to open: {e:?}. Is the driver installed and is Curfew running as Administrator?{RESET}");
                return;
            }
        };

        let mut buf = vec![0u8; 65535];

        while !s.stop.load(Ordering::Relaxed) {
            let packet = match wd.recv(&mut buf) {
                Ok(p) => p,
                Err(_) => {
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };

            let len = packet.data.len();

            // Which managed device, if any, does this packet belong to?
            let peer = {
                let buckets = s.buckets.lock().unwrap();
                ipv4_addrs(&packet.data).and_then(|(src, dst)| {
                    if buckets.limit_for(&src).is_some() {
                        Some(src)
                    } else if buckets.limit_for(&dst).is_some() {
                        Some(dst)
                    } else {
                        None
                    }
                })
            };

            match peer {
                Some(ip) => {
                    let verdict = s.buckets.lock().unwrap().charge(ip, len, Instant::now());
                    s.throttled_bytes.fetch_add(len as u64, Ordering::Relaxed);
                    if verdict == Verdict::Drop {
                        // Not re-injecting is what "blocked" means at this
                        // layer.
                        continue;
                    }
                    if let Verdict::Delay(wait) = verdict {
                        if !wait.is_zero() {
                            thread::sleep(wait);
                        }
                    }
                }
                None => {
                    s.fast_bytes.fetch_add(len as u64, Ordering::Relaxed);
                }
            }

            let _ = wd.send(&packet);
        }
    });
}

pub fn stats() -> (u64, u64) {
    let s = shared();
    (
        s.throttled_bytes.load(Ordering::Relaxed),
        s.fast_bytes.load(Ordering::Relaxed),
    )
}

pub fn teardown_all() {
    let s = shared();
    s.stop.store(true, Ordering::Relaxed);
    s.buckets.lock().unwrap().set_limits(HashMap::new());
}
