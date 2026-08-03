//! Where Curfew stores its persistent config: password file, exempt list,
//! nicknames, schedule. One directory, OS-appropriate location.

#[cfg(unix)]
pub const CONFIG_DIR: &str = "/etc/curfew";

#[cfg(windows)]
pub const CONFIG_DIR: &str = r"C:\ProgramData\Curfew";

pub fn ensure_dir() {
    let _ = std::fs::create_dir_all(CONFIG_DIR);
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
