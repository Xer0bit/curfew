//! The platform-independent half of the Windows shaper: IPv4 header parsing
//! and the per-device token buckets.
//!
//! This lives outside [`crate::winshape`] on purpose. The Windows backend
//! can't be compiled or tested on Linux (the vendored WinDivert crate needs a
//! mingw C toolchain), so anything with real logic in it belongs somewhere it
//! can actually be exercised — leaving `winshape.rs` as a thin shell around
//! `WinDivert` calls.
//!
//! Compiled on Windows and under `cargo test`; skipped in a plain Linux build.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// How long a device may burst for, once idle, in seconds worth of credit.
/// Without a cap, a device that had been quiet would bank unlimited credit
/// and could then dump a huge burst at line rate.
const BURST_SECS: f64 = 1.0;

/// Upper bound on how long a single packet may stall the capture thread. The
/// thread is shared by every device, so an unbounded sleep for one slow lane
/// would delay everybody else's packets too.
const MAX_SLEEP_SECS: f64 = 2.0;

/// What the shaper should do with one packet.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Forward immediately.
    Pass,
    /// Drop the packet — the device is blocked.
    Drop,
    /// Forward, but wait this long first to hold the device to its rate.
    Delay(Duration),
}

/// Token buckets, one per managed device.
#[derive(Default)]
pub struct Buckets {
    /// Bytes per second allowed per device. `0` means block outright.
    limits: HashMap<Ipv4Addr, u64>,
    /// `ip -> (tokens, last_refill)`.
    state: HashMap<Ipv4Addr, (f64, Instant)>,
}

impl Buckets {
    /// Replaces the managed set. Bucket state is dropped, so a device starts
    /// its new rate with a clean burst allowance instead of inheriting credit
    /// earned under the old one.
    pub fn set_limits(&mut self, limits: HashMap<Ipv4Addr, u64>) {
        self.limits = limits;
        self.state.clear();
    }

    /// The byte/sec limit for `ip`, or `None` if it isn't managed.
    pub fn limit_for(&self, ip: &Ipv4Addr) -> Option<u64> {
        self.limits.get(ip).copied()
    }

    /// Accounts for a `len`-byte packet belonging to `ip`.
    pub fn charge(&mut self, ip: Ipv4Addr, len: usize, now: Instant) -> Verdict {
        let Some(&limit) = self.limits.get(&ip) else {
            return Verdict::Pass;
        };
        if limit == 0 {
            return Verdict::Drop;
        }

        let rate = limit as f64;
        let entry = self.state.entry(ip).or_insert((rate, now));
        let elapsed = now.saturating_duration_since(entry.1).as_secs_f64();
        entry.0 = (entry.0 + elapsed * rate).min(rate * BURST_SECS);
        entry.1 = now;

        entry.0 -= len as f64;
        if entry.0 < 0.0 {
            let deficit_secs = (-entry.0 / rate).min(MAX_SLEEP_SECS);
            entry.0 = 0.0;
            Verdict::Delay(Duration::from_secs_f64(deficit_secs))
        } else {
            Verdict::Pass
        }
    }
}

/// Source and destination address of an IPv4 packet, or `None` if the buffer
/// isn't one. Only the first 20 bytes (the fixed header) are read, so a
/// truncated or non-IPv4 frame is rejected rather than misparsed.
pub fn ipv4_addrs(bytes: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if bytes.len() < 20 || (bytes[0] >> 4) != 4 {
        return None;
    }
    let src = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    Some((src, dst))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn buckets_with(limits: &[(&str, u64)]) -> Buckets {
        let mut b = Buckets::default();
        b.set_limits(limits.iter().map(|(a, r)| (ip(a), *r)).collect());
        b
    }

    #[test]
    fn reports_the_configured_limit() {
        let b = buckets_with(&[("10.0.0.5", 4096), ("10.0.0.6", 0)]);
        assert_eq!(b.limit_for(&ip("10.0.0.5")), Some(4096));
        assert_eq!(b.limit_for(&ip("10.0.0.6")), Some(0), "0 means blocked");
        assert_eq!(b.limit_for(&ip("10.0.0.7")), None, "unmanaged");
    }

    #[test]
    fn unmanaged_devices_always_pass() {
        let mut b = buckets_with(&[("10.0.0.5", 100)]);
        let now = Instant::now();
        for _ in 0..1000 {
            assert_eq!(b.charge(ip("10.0.0.9"), 1500, now), Verdict::Pass);
        }
    }

    #[test]
    fn a_zero_limit_drops_everything() {
        let mut b = buckets_with(&[("10.0.0.5", 0)]);
        let now = Instant::now();
        assert_eq!(b.charge(ip("10.0.0.5"), 60, now), Verdict::Drop);
        assert_eq!(b.charge(ip("10.0.0.5"), 1400, now), Verdict::Drop);
    }

    #[test]
    fn a_burst_within_one_seconds_credit_passes() {
        let mut b = buckets_with(&[("10.0.0.5", 100)]);
        let now = Instant::now();
        assert_eq!(b.charge(ip("10.0.0.5"), 50, now), Verdict::Pass);
        assert_eq!(b.charge(ip("10.0.0.5"), 50, now), Verdict::Pass);
    }

    #[test]
    fn exceeding_the_credit_delays_proportionally() {
        let mut b = buckets_with(&[("10.0.0.5", 100)]);
        let now = Instant::now();
        assert_eq!(b.charge(ip("10.0.0.5"), 100, now), Verdict::Pass);
        // Next 50 bytes have no credit at 100 B/s => half a second.
        match b.charge(ip("10.0.0.5"), 50, now) {
            Verdict::Delay(d) => {
                let secs = d.as_secs_f64();
                assert!((secs - 0.5).abs() < 0.01, "expected ~0.5s, got {secs}");
            }
            other => panic!("expected a delay, got {other:?}"),
        }
    }

    #[test]
    fn credit_refills_over_time() {
        let mut b = buckets_with(&[("10.0.0.5", 100)]);
        let now = Instant::now();
        assert_eq!(b.charge(ip("10.0.0.5"), 100, now), Verdict::Pass);
        // A full second later the bucket is back to its 1s burst cap.
        let later = now + Duration::from_secs(1);
        assert_eq!(b.charge(ip("10.0.0.5"), 50, later), Verdict::Pass);
    }

    #[test]
    fn burst_credit_is_capped_so_idle_devices_cannot_bank_unlimited() {
        let mut b = buckets_with(&[("10.0.0.5", 100)]);
        let now = Instant::now();
        // Idle for an hour: credit is still only one second's worth.
        let later = now + Duration::from_secs(3600);
        assert_eq!(b.charge(ip("10.0.0.5"), 100, later), Verdict::Pass);
        match b.charge(ip("10.0.0.5"), 100, later) {
            Verdict::Delay(_) => {}
            other => panic!("expected the burst cap to bite, got {other:?}"),
        }
    }

    #[test]
    fn a_single_packet_never_stalls_the_thread_for_too_long() {
        // A 1 byte/sec lane and a 1500 byte packet would otherwise compute a
        // 25-minute sleep, freezing every other device's traffic.
        let mut b = buckets_with(&[("10.0.0.5", 1)]);
        let now = Instant::now();
        b.charge(ip("10.0.0.5"), 1, now);
        match b.charge(ip("10.0.0.5"), 1500, now) {
            Verdict::Delay(d) => assert!(d.as_secs_f64() <= MAX_SLEEP_SECS),
            other => panic!("expected a capped delay, got {other:?}"),
        }
    }

    #[test]
    fn reconfigure_drops_stale_credit() {
        let mut b = buckets_with(&[("10.0.0.5", 100)]);
        let now = Instant::now();
        b.charge(ip("10.0.0.5"), 100, now);
        b.set_limits([(ip("10.0.0.5"), 10_000)].into_iter().collect());
        // Fresh bucket at the new rate: a small packet passes immediately.
        assert_eq!(b.charge(ip("10.0.0.5"), 100, now), Verdict::Pass);
    }

    #[test]
    fn parses_ipv4_addresses() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45; // IPv4, 5-word header
        pkt[12..16].copy_from_slice(&[192, 168, 1, 42]);
        pkt[16..20].copy_from_slice(&[192, 168, 1, 1]);
        assert_eq!(
            ipv4_addrs(&pkt),
            Some((ip("192.168.1.42"), ip("192.168.1.1")))
        );
    }

    #[test]
    fn rejects_short_or_non_ipv4_frames() {
        assert_eq!(ipv4_addrs(&[]), None);
        assert_eq!(ipv4_addrs(&[0u8; 19]), None);
        // IPv6: version nibble 6.
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        assert_eq!(ipv4_addrs(&v6), None);
        // ARP has no IP header at the fixed offset.
        let mut arp = vec![0u8; 42];
        arp[0] = 0x08;
        assert_eq!(ipv4_addrs(&arp), None);
    }
}
