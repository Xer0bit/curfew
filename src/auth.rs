//! Password gate: only someone who knows a saved password can start or stop
//! Curfew. Passwords are stored as SHA-256 hashes (computed in-process, see
//! [`crate::sha256`]) in an owner-only file, one per authorized person.

use crate::colors::{RED, RESET};
use crate::sha256;
use crate::system::prompt_hidden;
use std::io::Write;

fn sha256_hex(input: &str) -> String {
    sha256::hex(input.as_bytes())
}

fn passwd_file() -> std::path::PathBuf {
    std::path::Path::new(crate::paths::CONFIG_DIR).join("passwd")
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

    crate::paths::ensure_dir();
    let path = passwd_file();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("cannot write password file");
    writeln!(file, "{hash}").unwrap();
    crate::paths::restrict(&path.to_string_lossy());
}

/// Prompts to authenticate against any known password. Returns once a correct
/// password is entered; on the very first run (no password file yet) it walks
/// the owner through creating one instead.
pub fn authenticate() {
    let path = passwd_file();
    if !path.exists() {
        println!("No password set up yet, first-time setup.");
        let pass = read_new_password("yourself");
        append_password_hash(&sha256_hex(&pass));
        println!("Password saved. You'll need it each time you run this.");
        println!();
        return;
    }

    let known = std::fs::read_to_string(&path).unwrap_or_default();
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
