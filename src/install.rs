//! Self-installation: copies the running binary onto `PATH` so future runs
//! anywhere on the system can just be `sudo curfew`, no manual install step.

use crate::colors::{DIM, RESET};

const INSTALL_PATH: &str = "/usr/local/bin/curfew";

/// No-ops if already running from `INSTALL_PATH`. Otherwise copies the
/// current executable there (overwriting an older copy, so this also
/// self-updates when you rebuild and re-run from a fresh checkout).
pub fn ensure_installed() {
    let current = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    if current == std::path::Path::new(INSTALL_PATH) {
        return;
    }

    if std::fs::copy(&current, INSTALL_PATH).is_ok() {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(INSTALL_PATH, std::fs::Permissions::from_mode(0o755));
        println!("{DIM}Installed to {INSTALL_PATH} — next time, just run: sudo curfew{RESET}");
    }
}
