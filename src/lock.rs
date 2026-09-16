//! Single-instance guard.
//!
//! Two copies of Curfew running at once is genuinely destructive: each would
//! rebuild the same `tc` qdisc, overwrite the other's filters, and send
//! conflicting forged ARP replies — and whichever one exits first would
//! "restore" the network out from under the other. So we refuse to start a
//! second copy.
//!
//! The lock is a PID file. A stale file (process no longer alive) is detected
//! and reclaimed, so a crash or `kill -9` doesn't lock the user out forever.

use crate::paths::CONFIG_DIR;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

static LOCK_PATH: OnceLock<PathBuf> = OnceLock::new();

fn lock_file() -> PathBuf {
    std::path::Path::new(CONFIG_DIR).join("curfew.pid")
}

/// True if `pid` is a live process. Used only to decide whether an existing
/// PID file is stale.
#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    // `/proc` is the reliable answer on Linux; `kill -0` covers macOS (and
    // works on Linux too, if /proc is not mounted). Note a PID we can't
    // signal may still exist under another uid — running as root, that
    // can't happen here.
    if std::path::Path::new(&format!("/proc/{pid}")).exists() {
        return true;
    }
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn process_alive(pid: u32) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
        .unwrap_or(false)
}

fn own_pid() -> u32 {
    std::process::id()
}

/// Claims the single-instance lock, or returns a message explaining who
/// already holds it. Retries once if it finds a stale lock file.
pub fn acquire() -> Result<(), String> {
    crate::paths::ensure_dir();
    let path = lock_file();
    let me = own_pid();

    for _ in 0..2 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                let _ = writeln!(file, "{me}");
                crate::paths::restrict(&path.to_string_lossy());
                let _ = LOCK_PATH.set(path);
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok());
                match existing {
                    Some(pid) if pid != me && process_alive(pid) => {
                        // Worth recording: the owner asked to be told when
                        // someone else tries to start Curfew on this machine.
                        crate::accesslog::record(
                            crate::accesslog::Kind::LockContention,
                            crate::accesslog::ACTOR_TERMINAL,
                            &format!("another copy is already running (process {pid})"),
                        );
                        return Err(format!(
                            "Curfew is already running (process {pid}).\n\
                             Stop it first (choose option 0 in its window), or:\n  \
                             sudo kill {pid}"
                        ));
                    }
                    // Stale lock from a crash: reclaim it and retry.
                    _ => {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
            Err(e) => {
                return Err(format!(
                    "Could not create lock file {}: {e}",
                    path.display()
                ))
            }
        }
    }
    Err("Could not acquire the Curfew lock file.".to_string())
}

/// Releases the lock. Called explicitly from cleanup, because the shutdown
/// path ends in `process::exit`, which does not run destructors.
pub fn release() {
    if let Some(path) = LOCK_PATH.get() {
        let _ = std::fs::remove_file(path);
    }
}

/// The PID of a currently-running Curfew, if there is one. Used by
/// `--status` and as a sanity check, and deliberately independent of
/// [`acquire`] so it can be called without taking the lock.
pub fn running_pid() -> Option<u32> {
    let pid = std::fs::read_to_string(lock_file())
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()?;
    if process_alive(pid) {
        Some(pid)
    } else {
        None
    }
}
