//! Where Curfew stores its persistent config: password file, exempt list,
//! nicknames, schedule. One directory, OS-appropriate location.

#[cfg(unix)]
pub const CONFIG_DIR: &str = "/etc/curfew";

#[cfg(windows)]
pub const CONFIG_DIR: &str = r"C:\ProgramData\Curfew";

pub fn ensure_dir() {
    let _ = std::fs::create_dir_all(CONFIG_DIR);
}

/// Reads a small saved setting (the chosen Wi-Fi, the speed level) so it
/// survives restarts. Returns `None` if unset or empty.
pub fn load_setting(name: &str) -> Option<String> {
    std::fs::read_to_string(std::path::Path::new(CONFIG_DIR).join(name))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn save_setting(name: &str, value: &str) {
    ensure_dir();
    let _ = std::fs::write(std::path::Path::new(CONFIG_DIR).join(name), value);
}

/// Locks a file down to owner-only access. On Windows this is a no-op —
/// `ProgramData` is admin-writable by default and Curfew always runs
/// elevated there, an acceptable tradeoff for a single-household tool.
pub fn restrict(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(windows)]
    {
        let _ = path;
    }
}
