//! A single background thread owns reading stdin; everything else (prompts,
//! the auto-refreshing menu) asks this module for the next line instead of
//! reading the file descriptor directly. That's what lets the dashboard poll
//! with a timeout ("has the user typed anything yet?") without racing the
//! blocking reads used by ordinary prompts.

use std::io;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

static LINES: OnceLock<Mutex<Receiver<String>>> = OnceLock::new();

/// Starts the background stdin reader. Call once, before any prompt.
pub fn init() {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || loop {
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                if tx.send(line.trim_end().to_string()).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    });
    let _ = LINES.set(Mutex::new(rx));
}

/// Blocks until a full line is available.
pub fn read_line() -> String {
    LINES
        .get()
        .expect("stdin::init() must run first")
        .lock()
        .unwrap()
        .recv()
        .unwrap_or_default()
}

/// Waits up to `timeout` for a line; `None` means nothing was typed yet.
pub fn read_line_timeout(timeout: Duration) -> Option<String> {
    LINES
        .get()
        .expect("stdin::init() must run first")
        .lock()
        .unwrap()
        .recv_timeout(timeout)
        .ok()
}
