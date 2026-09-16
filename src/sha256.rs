//! Minimal, dependency-free SHA-256 (FIPS 180-4). Used for password hashing
//! instead of shelling out to `sha256sum`/`shasum`/`certutil` — those differ
//! per OS (and Windows has none of them by default), while this is ~60 lines
//! that works identically everywhere.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Returns the lowercase hex-encoded SHA-256 digest of `input`.
pub fn hex(input: &[u8]) -> String {
    let mut h = H0;
    let bit_len = (input.len() as u64) * 8;

    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for (i, &ki) in K.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(ki)
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    h.iter().map(|x| format!("{x:08x}")).collect()
}

/// The raw 32-byte SHA-256 digest of `input`.
pub fn digest(input: &[u8]) -> [u8; 32] {
    let mut h = H0;
    let bit_len = (input.len() as u64) * 8;

    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for (i, &ki) in K.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(ki)
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// SHA-256's block size, in bytes. HMAC pads its key to this.
const BLOCK: usize = 64;

/// An HMAC key, with its inner and outer pads precomputed.
///
/// PBKDF2 applies HMAC to the same key hundreds of thousands of times, so the
/// padding work (and, in the naive version, two heap allocations per call) is
/// pure overhead. Hoisting it out turns the inner loop into stack-only work.
struct HmacKey {
    inner_pad: [u8; BLOCK],
    outer_pad: [u8; BLOCK],
}

impl HmacKey {
    fn new(key: &[u8]) -> Self {
        let mut padded = [0u8; BLOCK];
        if key.len() > BLOCK {
            // A key longer than a block is replaced by its hash, never
            // truncated — truncating would silently weaken every hash.
            padded[..32].copy_from_slice(&digest(key));
        } else {
            padded[..key.len()].copy_from_slice(key);
        }

        let mut inner_pad = [0u8; BLOCK];
        let mut outer_pad = [0u8; BLOCK];
        for i in 0..BLOCK {
            inner_pad[i] = padded[i] ^ 0x36;
            outer_pad[i] = padded[i] ^ 0x5c;
        }
        HmacKey {
            inner_pad,
            outer_pad,
        }
    }

    /// HMAC over a 32-byte message on a fixed-size stack buffer.
    fn mac_32(&self, message: &[u8; 32]) -> [u8; 32] {
        let mut inner_input = [0u8; BLOCK + 32];
        inner_input[..BLOCK].copy_from_slice(&self.inner_pad);
        inner_input[BLOCK..].copy_from_slice(message);
        let inner = digest(&inner_input);

        let mut outer_input = [0u8; BLOCK + 32];
        outer_input[..BLOCK].copy_from_slice(&self.outer_pad);
        outer_input[BLOCK..].copy_from_slice(&inner);
        digest(&outer_input)
    }

    /// HMAC over an arbitrary message.
    fn mac(&self, message: &[u8]) -> [u8; 32] {
        let mut inner_input = Vec::with_capacity(BLOCK + message.len());
        inner_input.extend_from_slice(&self.inner_pad);
        inner_input.extend_from_slice(message);
        let inner = digest(&inner_input);

        let mut outer_input = Vec::with_capacity(BLOCK + 32);
        outer_input.extend_from_slice(&self.outer_pad);
        outer_input.extend_from_slice(&inner);
        digest(&outer_input)
    }
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    HmacKey::new(key).mac(message)
}

/// PBKDF2-HMAC-SHA256 (RFC 2898).
///
/// Replaces a single unsalted SHA-256 round, which is far too cheap to protect
/// a password that is now reachable over the network: one round means an
/// attacker with the password file can test billions of guesses per second.
/// Iterating makes each guess cost real time.
///
/// Note the iteration count is what sets the attacker's cost — an attacker
/// uses a fast, optimised implementation, not this one. So this function is
/// deliberately *not* made cheaper when it feels slow; the work factor is
/// chosen for the attacker's hardware and the implementation is optimised
/// instead.
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    // An iteration count of zero would produce an all-zero key; refuse rather
    // than silently emit something unusable.
    let iterations = iterations.max(1);
    let key = HmacKey::new(password);
    let mut first_input = Vec::with_capacity(salt.len() + 4);
    first_input.extend_from_slice(salt);
    let salt_len = first_input.len();

    let mut out = Vec::with_capacity(dk_len);
    for block_index in 1..=(dk_len.div_ceil(32) as u32) {
        first_input.truncate(salt_len);
        first_input.extend_from_slice(&block_index.to_be_bytes());

        let mut u = hmac_sha256(password, &first_input);
        let mut accumulator = u;

        // The chain step always hashes exactly 32 bytes, so it takes the
        // allocation-free path.
        for _ in 1..iterations {
            u = key.mac_32(&u);
            for (acc, byte) in accumulator.iter_mut().zip(u.iter()) {
                *acc ^= byte;
            }
        }

        out.extend_from_slice(&accumulator);
    }

    out.truncate(dk_len);
    out
}

/// Compares two digests without leaking, through timing, how many leading
/// bytes matched. `==` on slices short-circuits at the first difference,
/// which is measurable over a network.
pub fn eq_constant_time(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        difference |= x ^ y;
    }
    difference == 0
}

/// Hex-encodes bytes.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decodes a hex string, returning `None` on odd length or non-hex input.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-checked against Python's `hashlib.sha256`, including the
    /// block-padding boundaries (55/56/63/64/65 bytes) that the original
    /// two-vector test never exercised.
    #[test]
    fn sha256_matches_a_reference_implementation() {
        let cases: &[(usize, &str)] = &[
            (0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (1, "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
            (55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"),
            (56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"),
            (63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"),
            (64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"),
            (65, "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"),
            (119, "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb"),
            (120, "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c"),
            (1000, "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"),
        ];
        for (len, expected) in cases {
            let input = vec![b'a'; *len];
            assert_eq!(&hex(&input), expected, "sha256 of {len} bytes");
        }
    }

    #[test]
    fn digest_and_hex_agree() {
        assert_eq!(to_hex(&digest(b"abc")), hex(b"abc"));
    }

    /// RFC 4231 test cases 1 and 2.
    #[test]
    fn hmac_matches_rfc4231_vectors() {
        assert_eq!(
            to_hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            to_hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_handles_a_key_longer_than_the_block_size() {
        // A key over 64 bytes must be hashed first, not truncated; getting
        // this wrong silently weakens every password hash.
        let key = vec![0xaa; 131];
        let expected = {
            let hashed = digest(&key);
            hmac_sha256(&hashed, b"Test Using Larger Than Block-Size Key")
        };
        assert_eq!(
            hmac_sha256(&key, b"Test Using Larger Than Block-Size Key"),
            expected
        );
    }

    /// Cross-checked against Python's `hashlib.pbkdf2_hmac`.
    #[test]
    fn pbkdf2_matches_a_reference_implementation() {
        let cases: &[(&str, &str, u32, &str)] = &[
            ("password", "salt", 1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
            ("password", "salt", 2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
            ("password", "salt", 4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
            ("letmein", "abcdefgh", 10000, "faa1152c25019eda1fe135623b68746d013ddd4ee44360fa6f4a560c38b83b80"),
        ];
        for (password, salt, iterations, expected) in cases {
            let derived =
                pbkdf2_sha256(password.as_bytes(), salt.as_bytes(), *iterations, 32);
            assert_eq!(to_hex(&derived), *expected, "{password}/{iterations}");
        }
    }

    #[test]
    fn pbkdf2_supports_output_longer_than_one_block() {
        // Multi-block output exercises the block-index counter; getting it
        // wrong would make bytes 33+ repeat block 1.
        let derived = pbkdf2_sha256(b"password", b"salt", 4096, 64);
        assert_eq!(derived.len(), 64);
        assert_ne!(&derived[0..32], &derived[32..64]);
        // The first block must still match the single-block result.
        assert_eq!(derived[0..32], pbkdf2_sha256(b"password", b"salt", 4096, 32)[..]);
    }

    #[test]
    fn pbkdf2_is_deterministic_and_salt_sensitive() {
        let a = pbkdf2_sha256(b"pw", b"salt-a", 100, 32);
        let b = pbkdf2_sha256(b"pw", b"salt-a", 100, 32);
        let c = pbkdf2_sha256(b"pw", b"salt-b", 100, 32);
        assert_eq!(a, b, "same input must give the same hash");
        assert_ne!(a, c, "a different salt must give a different hash");
    }

    #[test]
    fn pbkdf2_treats_zero_iterations_as_one() {
        // Better a weak-but-valid hash than a silent all-zero key.
        assert_eq!(
            pbkdf2_sha256(b"pw", b"salt", 0, 32),
            pbkdf2_sha256(b"pw", b"salt", 1, 32)
        );
    }

    #[test]
    fn constant_time_comparison_is_correct() {
        assert!(eq_constant_time(b"abc", b"abc"));
        assert!(!eq_constant_time(b"abc", b"abd"));
        assert!(!eq_constant_time(b"abc", b"ab"));
        assert!(!eq_constant_time(b"", b"a"));
        assert!(eq_constant_time(b"", b""));
    }

    /// Reports how long the production work factor actually takes, so the
    /// security parameter can be re-checked rather than guessed. Ignored by
    /// default because it deliberately burns a couple of seconds.
    ///
    /// `cargo test --release -- --ignored --nocapture pbkdf2_cost`
    #[test]
    #[ignore = "measurement, not a check"]
    fn pbkdf2_cost_at_the_production_work_factor() {
        let start = std::time::Instant::now();
        let derived = pbkdf2_sha256(b"password", b"0123456789abcdef", 600_000, 32);
        let elapsed = start.elapsed();
        println!("600,000 iterations took {elapsed:?}");
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn hex_round_trips() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(from_hex(&to_hex(&bytes)), Some(bytes));
    }

    #[test]
    fn from_hex_rejects_bad_input() {
        assert_eq!(from_hex("abc"), None, "odd length");
        assert_eq!(from_hex("zz"), None, "not hex");
        assert_eq!(from_hex(""), Some(vec![]));
    }
}
