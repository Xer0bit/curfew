//! Running `tcpdump` and feeding its output to a parser.
//!
//! Both the DNS watcher and the ARP watcher need the same thing: spawn a
//! filtered capture, hand each output line to a parser, and be able to stop it
//! cleanly. That machinery lives here once.
//!
//! Each capture uses a kernel BPF filter, so only the packets it asked for are
//! ever copied up to userspace — running two filtered captures costs
//! roughly the same as one unfiltered one.

use crate::colors::{DIM, RESET};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// True if `tcpdump` is on `PATH`. Without it, nothing can be observed and the
/// UI says so rather than showing an empty list.
pub fn available() -> bool {
    crate::system::tool_exists("tcpdump")
}

/// A running capture. Dropping it does *not* stop the process — call [`stop`],
/// so a forgotten capture can't be leaked silently.
///
/// [`stop`]: LineCapture::stop
pub struct LineCapture {
    child: Child,
    stop_flag: Arc<AtomicBool>,
}

impl LineCapture {
    /// Starts `tcpdump -n -l -q -i <iface> -s 512 <filter...>` and calls
    /// `on_line` for every line it prints.
    ///
    /// `label` only names the capture in the error if it can't start.
    /// Returns `None` if `tcpdump` is missing or fails to spawn.
    pub fn start(
        iface: &str,
        filter: &[&str],
        label: &str,
        on_line: impl Fn(&str) + Send + 'static,
    ) -> Option<LineCapture> {
        if !available() {
            return None;
        }

        let mut args = vec!["-n", "-l", "-q", "-i", iface, "-s", "512"];
        args.extend_from_slice(filter);

        let mut child = match Command::new("tcpdump")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                eprintln!("{DIM}{label} unavailable: could not start tcpdump ({e}){RESET}");
                return None;
            }
        };

        // Moving the pipe into the reader thread leaves the `Child` here, so
        // shutdown can still kill the process.
        let stdout = child.stdout.take()?;
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop_flag);

        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if stop_for_thread.load(Ordering::Relaxed) {
                    break;
                }
                match line {
                    Ok(line) => on_line(&line),
                    // A read error means the pipe is gone; nothing left to do.
                    Err(_) => break,
                }
            }
        });

        Some(LineCapture { child, stop_flag })
    }

    /// Stops capturing and reaps the process.
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_matches_whether_the_tool_exists() {
        // Both must agree; a mismatch would make the UI claim a feature works
        // when it can't start, or hide one that can.
        assert_eq!(available(), crate::system::tool_exists("tcpdump"));
    }

    #[test]
    fn starting_without_tcpdump_returns_none_rather_than_panicking() {
        // On a machine with tcpdump present this asserts the opposite, so it
        // stays meaningful either way: the point is that it never panics and
        // never returns a capture it can't back with a real process.
        let started = LineCapture::start("lo", &["arp"], "test", |_| {});
        if available() {
            assert!(started.is_some(), "tcpdump is present, so a capture should start");
        } else {
            assert!(started.is_none());
        }
        drop(started);
    }

    #[test]
    fn a_capture_can_be_stopped_without_hanging() {
        let Some(mut capture) = LineCapture::start("lo", &["arp"], "test", |_| {}) else {
            return; // no tcpdump here
        };
        // Must not block: the reader thread and the child both have to go.
        capture.stop();
        // Stopping twice must also be safe.
        capture.stop();
    }
}
