//! Password gate: only someone who knows a saved password can start or stop
//! Curfew, or perform an action through the web UI.
//!
//! Passwords are stored as **PBKDF2-HMAC-SHA256** with a per-password random
//! salt, in an owner-only file, one line per authorized person:
//!
//! ```text
//! pbkdf2$600000$<salt-hex>$<hash-hex>
//! ```
//!
//! Older versions stored a single unsalted SHA-256 hash. Those lines are still
//! accepted — and quietly upgraded to PBKDF2 the first time they're used
//! successfully — so an existing install keeps working.
//!
//! The upgrade matters now that authentication is reachable over the network:
//! one unsalted SHA-256 round is cheap enough to brute-force at billions of
//! guesses per second if the password file is ever read.

use crate::colors::{DIM, RED, RESET};
use crate::random;
use crate::sha256;
use crate::system::prompt_hidden;
use std::io::Write;

/// PBKDF2 work factor. OWASP's recommended figure for PBKDF2-HMAC-SHA256;
/// roughly a third of a second on a modern CPU, which is unnoticeable when
/// logging in but ruinous for an offline guessing attack.
///
/// Tests use a token count: the algorithm is identical, and hashing at the
/// production factor costs over a second per call, which would make the suite
/// unusably slow without testing anything extra.
#[cfg(not(test))]
const ITERATIONS: u32 = 600_000;
#[cfg(test)]
const ITERATIONS: u32 = 1_000;

/// Salt length in bytes. 16 is the usual choice and far beyond the point
/// where collisions between two salts matter.
const SALT_BYTES: usize = 16;

const PREFIX: &str = "pbkdf2";

/// Shortest password accepted. Enforced because this password protects a
/// network-reachable control panel, where a guessable password is the single
/// most likely way in.
pub const MIN_PASSWORD_LEN: usize = 8;

/// A stored password: either this version's PBKDF2 record or a bare SHA-256
/// hash left by an older version of Curfew.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredHash {
    Pbkdf2 {
        iterations: u32,
        salt: Vec<u8>,
        hash: Vec<u8>,
    },
    /// Legacy: unsalted single-round SHA-256, hex encoded.
    LegacySha256(String),
}

impl StoredHash {
    /// Parses one line of the password file. Returns `None` for anything
    /// unrecognisable, so a corrupt line is skipped rather than locking the
    /// owner out of every other entry.
    pub fn parse(line: &str) -> Option<StoredHash> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        if let Some(rest) = line.strip_prefix(&format!("{PREFIX}$")) {
            let mut parts = rest.split('$');
            let iterations: u32 = parts.next()?.parse().ok()?;
            let salt = sha256::from_hex(parts.next()?)?;
            let hash = sha256::from_hex(parts.next()?)?;
            if parts.next().is_some() || salt.is_empty() || hash.is_empty() {
                return None;
            }
            return Some(StoredHash::Pbkdf2 {
                iterations,
                salt,
                hash,
            });
        }
        // Legacy lines are a bare 64-character hex digest.
        if line.len() == 64 && sha256::from_hex(line).is_some() {
            return Some(StoredHash::LegacySha256(line.to_lowercase()));
        }
        None
    }

    /// True if `password` matches.
    pub fn verify(&self, password: &str) -> bool {
        match self {
            StoredHash::Pbkdf2 {
                iterations,
                salt,
                hash,
            } => {
                let derived = sha256::pbkdf2_sha256(
                    password.as_bytes(),
                    salt,
                    *iterations,
                    hash.len().max(32),
                );
                sha256::eq_constant_time(&derived, hash)
            }
            StoredHash::LegacySha256(expected) => sha256::eq_constant_time(
                sha256::hex(password.as_bytes()).as_bytes(),
                expected.as_bytes(),
            ),
        }
    }

    /// True for records written by an older version of Curfew.
    pub fn is_legacy(&self) -> bool {
        matches!(self, StoredHash::LegacySha256(_))
    }

    /// This record re-encoded in the current format.
    pub fn to_line(&self) -> String {
        match self {
            StoredHash::Pbkdf2 {
                iterations,
                salt,
                hash,
            } => format!(
                "{PREFIX}${iterations}${}${}",
                sha256::to_hex(salt),
                sha256::to_hex(hash)
            ),
            StoredHash::LegacySha256(value) => value.clone(),
        }
    }
}

/// Hashes `password` with a fresh random salt, in the current format.
pub fn hash_password(password: &str) -> Option<String> {
    let salt = random::bytes(SALT_BYTES)?;
    let derived = sha256::pbkdf2_sha256(password.as_bytes(), &salt, ITERATIONS, 32);
    Some(
        StoredHash::Pbkdf2 {
            iterations: ITERATIONS,
            salt,
            hash: derived,
        }
        .to_line(),
    )
}

fn passwd_file() -> std::path::PathBuf {
    std::path::Path::new(crate::paths::CONFIG_DIR).join("passwd")
}

/// Every stored password line.
fn stored_hashes() -> Vec<StoredHash> {
    std::fs::read_to_string(passwd_file())
        .unwrap_or_default()
        .lines()
        .filter_map(StoredHash::parse)
        .collect()
}

/// True if any password has been set up.
pub fn is_configured() -> bool {
    !stored_hashes().is_empty()
}

/// Checks `password` against every stored password.
///
/// Always checks all entries rather than stopping at the first match, so the
/// time taken doesn't leak which entry matched.
pub fn verify_password(password: &str) -> bool {
    let mut matched = false;
    for stored in stored_hashes() {
        if stored.verify(password) {
            matched = true;
        }
    }
    matched
}

/// Rewrites any legacy SHA-256 entries in the current PBKDF2 format, once the
/// password has been confirmed. Called after a successful login so an upgrade
/// happens without the user ever being asked to change anything.
fn upgrade_legacy_hashes(password: &str) {
    let hashes = stored_hashes();
    if !hashes.iter().any(StoredHash::is_legacy) {
        return;
    }
    let Some(replacement) = hash_password(password) else {
        return; // no secure random source; leave it as-is rather than weaken it
    };

    let lines: Vec<String> = hashes
        .into_iter()
        .map(|stored| {
            if stored.is_legacy() && stored.verify(password) {
                replacement.clone()
            } else {
                stored.to_line()
            }
        })
        .collect();

    if write_password_file(&lines).is_ok() {
        println!("{DIM}(Upgraded your saved password to a stronger format.){RESET}");
    }
}

fn write_password_file(lines: &[String]) -> std::io::Result<()> {
    crate::paths::ensure_dir();
    let path = passwd_file();
    let mut content = lines.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    std::fs::write(&path, content)?;
    crate::paths::restrict(&path.to_string_lossy());
    Ok(())
}

fn append_password_hash(line: &str) {
    crate::paths::ensure_dir();
    let path = passwd_file();
    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(e) => {
            eprintln!(
                "{RED}Cannot write the password file {}: {e}{RESET}",
                path.display()
            );
            return;
        }
    };
    if writeln!(file, "{line}").is_ok() {
        crate::paths::restrict(&path.to_string_lossy());
    }
}

fn read_new_password(who: &str) -> String {
    loop {
        let first = prompt_hidden(&format!("Set a password for {who}: "));
        let second = prompt_hidden("Type it again to confirm: ");
        if first.is_empty() {
            println!("{RED}Password can't be empty.{RESET}");
        } else if first.len() < MIN_PASSWORD_LEN {
            println!("{RED}Use at least {MIN_PASSWORD_LEN} characters.{RESET}");
        } else if first != second {
            println!("{RED}Those didn't match, try again.{RESET}");
        } else {
            return first;
        }
    }
}

/// Prompts to authenticate against any known password. Returns once a correct
/// password is entered; on the very first run (no password file yet) it walks
/// the owner through creating one instead.
pub fn authenticate() {
    if !is_configured() {
        println!("No password set up yet, first-time setup.");
        let password = read_new_password("yourself");
        match hash_password(&password) {
            Some(line) => {
                append_password_hash(&line);
                println!("Password saved. You'll need it each time you run this.");
            }
            None => {
                eprintln!(
                    "{RED}Could not get secure random bytes, so no password was saved.{RESET}"
                );
                eprintln!("{RED}Refusing to store a password that could be guessed.{RESET}");
                std::process::exit(1);
            }
        }
        println!();
        return;
    }

    for attempt in 0..3 {
        let password = prompt_hidden("Password: ");
        if verify_password(&password) {
            upgrade_legacy_hashes(&password);
            return;
        }
        let remaining = 2 - attempt;
        if remaining > 0 {
            println!("{RED}Wrong password. {remaining} more attempt(s).{RESET}");
        }
    }
    eprintln!("{RED}Too many failed attempts. Exiting.{RESET}");
    std::process::exit(1);
}

/// `--add-user`: after the owner authenticates, adds a second valid password
/// (e.g. for a spouse) without replacing the existing one.
pub fn add_user() {
    authenticate();
    let password = read_new_password("the new person");
    match hash_password(&password) {
        Some(line) => {
            append_password_hash(&line);
            println!("Done. They can now run this program with their own password.");
        }
        None => eprintln!("{RED}Could not get secure random bytes. Nothing was saved.{RESET}"),
    }
}

/// `--passwd`: replaces every stored password with a new one. Used to recover
/// access, and to rotate the password if it might have leaked — which matters
/// more than usual here, since the password protects remote control of the
/// network.
pub fn reset_passwords() {
    println!("This replaces every saved password with a new one.");
    println!("Anyone who could log in before will no longer be able to.");
    let password = read_new_password("yourself");
    match hash_password(&password) {
        Some(line) => match write_password_file(&[line]) {
            Ok(()) => println!("Done. Your new password is in effect."),
            Err(e) => eprintln!("{RED}Could not save the new password: {e}{RESET}"),
        },
        None => eprintln!("{RED}Could not get secure random bytes. Nothing was changed.{RESET}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_pbkdf2_line() {
        let line = format!(
            "pbkdf2$1000${}${}",
            sha256::to_hex(&[0xab; 16]),
            sha256::to_hex(&[0xcd; 32])
        );
        match StoredHash::parse(&line) {
            Some(StoredHash::Pbkdf2 {
                iterations,
                salt,
                hash,
            }) => {
                assert_eq!(iterations, 1000);
                assert_eq!(salt, vec![0xab; 16]);
                assert_eq!(hash, vec![0xcd; 32]);
            }
            other => panic!("expected a pbkdf2 record, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_legacy_line_so_existing_installs_still_work() {
        let legacy = sha256::hex(b"hunter2");
        assert_eq!(
            StoredHash::parse(&legacy),
            Some(StoredHash::LegacySha256(legacy.clone()))
        );
        let parsed = StoredHash::parse(&legacy).unwrap();
        assert!(parsed.is_legacy());
        assert!(parsed.verify("hunter2"));
        assert!(!parsed.verify("hunter3"));
    }

    #[test]
    fn rejects_malformed_lines_without_panicking() {
        let not_hex = "z".repeat(64);
        for bad in [
            "",
            "   ",
            "pbkdf2$",
            "pbkdf2$abc$ff$ff",
            "pbkdf2$1000$ff",
            "pbkdf2$1000$$ff",
            "pbkdf2$1000$ff$ff$extra",
            "not-a-hash",
            not_hex.as_str(),
        ] {
            assert!(
                StoredHash::parse(bad).is_none(),
                "should have rejected {bad:?}"
            );
        }
    }

    #[test]
    fn a_pbkdf2_hash_round_trips_and_verifies() {
        let line = hash_password("correct horse battery staple").expect("random source");
        let parsed = StoredHash::parse(&line).expect("should parse back");
        assert!(!parsed.is_legacy());
        assert!(parsed.verify("correct horse battery staple"));
        assert!(!parsed.verify("correct horse battery stapl"));
        assert!(!parsed.verify(""));
    }

    #[test]
    fn the_same_password_hashes_differently_each_time() {
        // A fixed salt would make identical passwords produce identical
        // hashes, revealing which users share a password.
        let a = hash_password("same-password").unwrap();
        let b = hash_password("same-password").unwrap();
        assert_ne!(a, b, "salts must be random per password");
        assert!(StoredHash::parse(&a).unwrap().verify("same-password"));
        assert!(StoredHash::parse(&b).unwrap().verify("same-password"));
    }

    #[test]
    fn iteration_count_comes_from_the_record() {
        // The work factor must be read from each record, not from a constant,
        // or raising it later would invalidate every existing password.
        let salt = [7u8; SALT_BYTES];
        let derived = sha256::pbkdf2_sha256(b"pw", &salt, 100, 32);
        let record = StoredHash::Pbkdf2 {
            iterations: 100,
            salt: salt.to_vec(),
            hash: derived,
        };
        assert!(record.verify("pw"));
        assert!(!record.verify("nope"));
    }

    #[test]
    fn line_encoding_round_trips() {
        let line = hash_password("another-password").unwrap();
        assert_eq!(StoredHash::parse(&line).unwrap().to_line(), line);
    }

    #[test]
    fn the_stored_record_is_the_documented_format() {
        let line = hash_password("format-check").unwrap();
        let parts: Vec<&str> = line.split('$').collect();
        assert_eq!(parts.len(), 4, "line was {line}");
        assert_eq!(parts[0], "pbkdf2");
        assert_eq!(parts[1].parse::<u32>().unwrap(), ITERATIONS);
        assert_eq!(parts[2].len(), SALT_BYTES * 2, "salt is hex of SALT_BYTES");
        assert_eq!(parts[3].len(), 64, "32-byte hash as hex");
    }
}
