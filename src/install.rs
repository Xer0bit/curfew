//! Self-installation: copies the running binary onto `PATH` (or a fixed,
//! well-known location) so future runs anywhere on the system can just be
//! `curfew`/`sudo curfew`, no manual install step.

use crate::colors::{DIM, RESET};

#[cfg(target_os = "linux")]
const INSTALL_PATH: &str = "/usr/local/bin/curfew";

#[cfg(target_os = "macos")]
const INSTALL_PATH: &str = "/usr/local/bin/curfew";

#[cfg(target_os = "windows")]
const INSTALL_PATH: &str = r"C:\ProgramData\Curfew\curfew.exe";

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

    if let Some(parent) = std::path::Path::new(INSTALL_PATH).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if std::fs::copy(&current, INSTALL_PATH).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(INSTALL_PATH, std::fs::Permissions::from_mode(0o755));
        }
        #[cfg(unix)]
        println!("{DIM}Installed to {INSTALL_PATH} — next time, just run: sudo curfew{RESET}");
        #[cfg(windows)]
        println!(
            "{DIM}Installed to {INSTALL_PATH} — next time, run it as Administrator from there.{RESET}"
        );
    }
}
