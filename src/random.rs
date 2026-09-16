//! Cryptographically secure random bytes, without pulling in a crate.
//!
//! Needed for password salts and web session tokens. Both are security
//! critical: a predictable salt lets an attacker precompute hashes, and a
//! predictable session token lets anyone impersonate the owner.
//!
//! Returns `None` rather than falling back to a weak source. A caller that
//! needs unpredictability must fail loudly instead of silently shipping
//! guessable tokens — which is why callers of [`bytes`] treat `None` as fatal
//! rather than degrading.

/// Reads `n` cryptographically secure random bytes, or `None` if the
/// platform's generator is unavailable.
#[cfg(unix)]
pub fn bytes(n: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    // /dev/urandom never blocks once the kernel pool is seeded, which it is
    // long before any userspace process runs.
    let mut file = std::fs::File::open("/dev/urandom").ok()?;
    let mut buffer = vec![0u8; n];
    file.read_exact(&mut buffer).ok()?;
    Some(buffer)
}

/// Windows: `BCryptGenRandom` from bcrypt.dll, the documented OS generator.
/// Linked directly so no crate is needed.
///
/// Unverified on real hardware — this repo has no Windows build environment,
/// and the vendored WinDivert dependency blocks cross-compilation. The
/// signature and flag value are taken from the published Win32 API.
#[cfg(all(windows, not(test)))]
pub fn bytes(n: usize) -> Option<Vec<u8>> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut u8,
            buffer: *mut u8,
            len: u32,
            flags: u32,
        ) -> i32;
    }
    /// `BCRYPT_USE_SYSTEM_PREFERRED_RNG`
    const USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    let mut buffer = vec![0u8; n];
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            USE_SYSTEM_PREFERRED_RNG,
        )
    };
    // 0 == STATUS_SUCCESS
    if status == 0 {
        Some(buffer)
    } else {
        None
    }
}

/// A lowercase hex token of `bytes` random bytes, or `None` if no secure
/// source is available.
pub fn hex_token(byte_count: usize) -> Option<String> {
    bytes(byte_count).map(|b| crate::sha256::to_hex(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_the_requested_length() {
        let value = bytes(32).expect("a secure random source should exist");
        assert_eq!(value.len(), 32);
        assert_eq!(hex_token(16).unwrap().len(), 32, "hex doubles the length");
    }

    #[test]
    fn output_is_not_constant() {
        // A stub that returned zeros would pass a length check but fail here.
        let a = bytes(32).unwrap();
        let b = bytes(32).unwrap();
        assert_ne!(a, b, "two draws must differ");
        assert!(a.iter().any(|b| *b != 0), "output shouldn't be all zeroes");
    }

    #[test]
    fn hex_token_is_valid_hex() {
        let token = hex_token(8).unwrap();
        assert!(crate::sha256::from_hex(&token).is_some());
    }
}
