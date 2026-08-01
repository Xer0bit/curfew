//! Thin wrappers around shelling out to system tools, and basic terminal I/O.

use crate::colors::{CYAN, RED, RESET};
use std::io::{self, Write};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Runs a command and returns its trimmed stdout. Panics if the command can't
/// even be spawned (e.g. the tool isn't installed) — this is only used for
/// tools we require up front (`id`, `ip`, `iw`, `nmap`).
pub fn run(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {cmd}: {e}"));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Runs a command, letting its stdout/stderr show, ignoring the exit status.
pub fn run_status(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).status();
}

/// Like [`run`], but returns `Err` instead of panicking if the command can't
/// be spawned. Used inside the long-running monitor loop, where a transient
/// or missing-tool failure should be reported once and retried, not silently
/// kill the background thread forever.
pub fn try_run(cmd: &str, args: &[&str]) -> Result<String, String> {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .map_err(|e| format!("failed to run {cmd}: {e}"))
}

/// Checks that every required external tool is on `PATH`. Returns the names
/// of any that are missing.
pub fn missing_dependencies() -> Vec<&'static str> {
    const REQUIRED: &[&str] = &[
        "iw",
        "ip",
        "tc",
        "nmap",
        "arpspoof",
        "arping",
        "pkill",
        "sha256sum",
        "stty",
    ];
    REQUIRED
        .iter()
        .filter(|cmd| {
            Command::new("sh")
                .arg("-c")
                .arg(format!("command -v {cmd}"))
                .output()
                .map(|o| !o.status.success())
                .unwrap_or(true)
        })
        .copied()
        .collect()
}

/// Like [`run_status`] but swallows stdout/stderr. Used for cleanup/teardown
/// commands where "nothing to clean up" is an expected, harmless outcome that
/// would otherwise print scary-looking tool errors to a non-technical user.
pub fn run_quiet(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Clears the terminal and moves the cursor home, so each menu redraw looks
/// like a fresh screen instead of an endless scroll of past output.
pub fn clear_screen() {
    print!("\x1b[2J\x1b[H");
    io::stdout().flush().unwrap();
}

/// Prints without a trailing newline and flushes, but doesn't read anything —
/// for callers doing their own (e.g. timeout-based) read afterward.
pub fn print_flush(msg: &str) {
    print!("{msg}");
    io::stdout().flush().unwrap();
}

/// Runs `work` on a background thread while animating a spinner next to
/// `label` in place, blocking until it finishes. Only used around genuinely
/// slow operations (arping, rebuilding tc rules) — the animation reflects
/// real work happening, not an artificial delay, and never runs while
/// waiting on keyboard input.
pub fn spin_while<T: Send + 'static>(label: &str, work: impl FnOnce() -> T + Send + 'static) -> T {
    const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let result = work();
        let _ = tx.send(());
        result
    });

    let mut i = 0;
    while rx.recv_timeout(Duration::from_millis(80)).is_err() {
        print!("\r{CYAN}{}{RESET} {label}...  ", FRAMES[i % FRAMES.len()]);
        io::stdout().flush().unwrap();
        i += 1;
    }
    print!("\r{}\r", " ".repeat(label.chars().count() + 8));
    io::stdout().flush().unwrap();

    handle.join().unwrap()
}

pub fn require_root() {
    let uid = run("id", &["-u"]);
    if uid != "0" {
        eprintln!("{RED}Must run as root (sudo). Exiting.{RESET}");
        std::process::exit(1);
    }
}

/// Prompts for a line of visible input.
pub fn prompt(msg: &str) -> String {
    print_flush(msg);
    crate::stdin::read_line()
}

/// Prompts for a line of input with terminal echo turned off, for passwords.
pub fn prompt_hidden(msg: &str) -> String {
    print_flush(msg);
    run_status("stty", &["-echo"]);
    let input = crate::stdin::read_line();
    run_status("stty", &["echo"]);
    println!();
    input
}
