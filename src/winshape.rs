//! Windows traffic shaping. There's no built-in equivalent of Linux `tc` or
//! macOS `dnctl`, so this intercepts every forwarded IPv4 packet via
//! WinDivert's forward layer, applies a token-bucket rate limit to packets
//! whose source or destination is a throttled IP, and re-injects everything
//! else immediately at full speed.
//!
//! Unverified against real hardware in this session — no Windows build/test
//! environment was available. `WinDivert::forward`/`recv`/`send` signatures
//! and `WinDivertFlags::new()` are confirmed against the crate's published
//! docs, but the end-to-end packet loop has not been run.

use crate::colors::{RED, RESET};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use windivert::prelude::*;

struct Shared {
    targets: Mutex<HashSet<Ipv4Addr>>,
    rate_bps: AtomicU64,
    throttled_bytes: AtomicU64,
    fast_bytes: AtomicU64,
    stop: AtomicBool,
}

static SHARED: OnceLock<std::sync::Arc<Shared>> = OnceLock::new();

fn shared() -> &'static std::sync::Arc<Shared> {
    SHARED.get_or_init(|| {
        std::sync::Arc::new(Shared {
            targets: Mutex::new(HashSet::new()),
            rate_bps: AtomicU64::new(10_000 / 8), // overwritten by start()
            throttled_bytes: AtomicU64::new(0),
            fast_bytes: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        })
    })
}

/// Parses a `tc`-style rate ("10kbit") into bytes/sec.
fn parse_rate_bps(rate: &str) -> u64 {
    let lower = rate.to_lowercase();
    let split_at = lower.find(|c: char| c.is_alphabetic()).unwrap_or(lower.len());
    let (num, unit) = lower.split_at(split_at);
    let n: f64 = num.parse().unwrap_or(10.0);
    let bits_per_sec = match unit {
        "kbit" | "kbps" => n * 1_000.0,
        "mbit" | "mbps" => n * 1_000_000.0,
        _ => n,
    };
    ((bits_per_sec / 8.0).max(1.0)) as u64
}

fn ipv4_addrs(bytes: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if bytes.len() < 20 || (bytes[0] >> 4) != 4 {
        return None;
    }
    let src = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    Some((src, dst))
}

/// Starts (once) the interception thread and (re)sets the throttle rate.
pub fn start(rate: &str) {
    let s = shared();
    s.rate_bps.store(parse_rate_bps(rate), Ordering::Relaxed);
    s.stop.store(false, Ordering::Relaxed);

    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return; // worker already running
    }

    let s = std::sync::Arc::clone(shared());
    thread::spawn(move || {
        let wd = match WinDivert::<ForwardLayer>::forward("true", 0, WinDivertFlags::new()) {
            Ok(wd) => wd,
            Err(e) => {
                eprintln!("{RED}WinDivert failed to open: {e:?}. Is the driver installed and is Curfew running as Administrator?{RESET}");
                return;
            }
        };

        let mut buf = vec![0u8; 65535];
        let mut tokens: f64 = 0.0;
        let mut last_refill = Instant::now();

        while !s.stop.load(Ordering::Relaxed) {
            let packet = match wd.recv(&mut buf) {
                Ok(p) => p,
                Err(_) => {
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };

            let len = packet.data.len();
            let is_target = ipv4_addrs(&packet.data)
                .map(|(src, dst)| {
                    let targets = s.targets.lock().unwrap();
                    targets.contains(&src) || targets.contains(&dst)
                })
                .unwrap_or(false);

            if is_target {
                let rate = s.rate_bps.load(Ordering::Relaxed) as f64;
                let now = Instant::now();
                tokens += now.duration_since(last_refill).as_secs_f64() * rate;
                tokens = tokens.min(rate); // cap burst to ~1s worth
                last_refill = now;

                tokens -= len as f64;
                if tokens < 0.0 {
                    let deficit_secs = -tokens / rate;
                    thread::sleep(Duration::from_secs_f64(deficit_secs.min(2.0)));
                    tokens = 0.0;
                }
                s.throttled_bytes.fetch_add(len as u64, Ordering::Relaxed);
            } else {
                s.fast_bytes.fetch_add(len as u64, Ordering::Relaxed);
            }

            let _ = wd.send(&packet);
        }
    });
}

/// Adds `ip` to the throttled set. `_iface` is unused — WinDivert's forward
/// layer sees all interfaces' forwarded traffic, not one at a time.
pub fn add_target(_iface: &str, ip: &str) {
    if let Ok(addr) = ip.parse::<Ipv4Addr>() {
        shared().targets.lock().unwrap().insert(addr);
    }
}

pub fn stats(_iface: &str) -> (u64, u64) {
    let s = shared();
    (
        s.throttled_bytes.load(Ordering::Relaxed),
        s.fast_bytes.load(Ordering::Relaxed),
    )
}

pub fn teardown_all(_iface: &str) {
    let s = shared();
    s.stop.store(true, Ordering::Relaxed);
    s.targets.lock().unwrap().clear();
}
