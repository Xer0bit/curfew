//! Password gate: only someone who knows a saved password can start or stop
//! Curfew. Passwords are stored as SHA-256 hashes (via the system
//! `sha256sum`, no crypto crate needed) in a root-only file, one per
//! authorized person.

use crate::colors::{RED, RESET};
use crate::system::prompt_hidden;
use std::io::Write;
use std::process::{Command, Stdio};

const PASSWD_FILE: &str = "/etc/curfew/passwd";

fn sha256_hex(input: &str) -> String {
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("sha256sum is required (coreutils)");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

fn read_new_password(who: &str) -> String {
    loop {
        let p1 = prompt_hidden(&format!("Set a password for {who}: "));
        let p2 = prompt_hidden("Type it again to confirm: ");
        if p1.is_empty() {
            println!("{RED}Password can't be empty.{RESET}");
        } else if p1 != p2 {
            println!("{RED}Those didn't match, try again.{RESET}");
        } else {
            return p1;
        }
    }
}

fn append_password_hash(hash: &str) {
    use std::fs::OpenOptions;
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all("/etc/curfew").unwrap();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(PASSWD_FILE)
        .expect("cannot write password file");
    writeln!(file, "{hash}").unwrap();
    std::fs::set_permissions(PASSWD_FILE, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Prompts to authenticate against any known password. Returns once a correct
/// password is entered; on the very first run (no password file yet) it walks
/// the owner through creating one instead.
pub fn authenticate() {
    if !std::path::Path::new(PASSWD_FILE).exists() {
        println!("No password set up yet, first-time setup.");
        let pass = read_new_password("yourself");
        append_password_hash(&sha256_hex(&pass));
        println!("Password saved. You'll need it each time you run this.");
        println!();
        return;
    }

    let known = std::fs::read_to_string(PASSWD_FILE).unwrap_or_default();
    let known: Vec<&str> = known.lines().filter(|l| !l.is_empty()).collect();

    for _ in 0..3 {
        let pass = prompt_hidden("Password: ");
        if known.contains(&sha256_hex(&pass).as_str()) {
            return;
        }
        println!("{RED}Wrong password.{RESET}");
    }
    eprintln!("{RED}Too many failed attempts. Exiting.{RESET}");
    std::process::exit(1);
}

/// `--add-user`: after the owner authenticates, adds a second valid password
/// (e.g. for a spouse) without replacing the existing one.
pub fn add_user() {
    authenticate();
    let pass = read_new_password("the new person");
    append_password_hash(&sha256_hex(&pass));
    println!("Done. They can now run this program with their own password.");
}
