//! MAC-tagged self-authenticating fakes.
//!
//! Free-form random fakes (those that don't live in a reserved range —
//! detected-but-unregistered high-entropy secrets and formatless vault
//! values with a long enough body) carry their identity in their own
//! bytes: the last K characters of the fake are a truncated HMAC-SHA-256
//! of everything that precedes them, encoded in the fake's alphabet. A
//! later re-scrub can recognise the fake **statelessly** by recomputing
//! the MAC and checking, with no session state required. This is
//! idempotence check (c).
//!
//! Two costs of the design are documented in the threat model:
//!
//! 1. **MAC false-positive cost.** A real secret whose tail bytes
//!    coincidentally match `HMAC(body)` would be left unscrubbed; the
//!    odds are ~2^-32 per pattern-matched candidate. Registered secrets
//!    are immune via exact-match precedence (idempotence check that
//!    runs ahead of this one).
//! 2. **Short-fake carve-out.** A fake whose total body is shorter than
//!    K characters cannot carry a MAC tail. `verify` returns `false`
//!    for short candidates so idempotence falls through to whichever
//!    other check (live session map, reserved-range membership) covers
//!    them. In two-command terminal mode short fakes are simply not
//!    re-scrubbed-idempotent — that limit is documented to the user.
//!
//! Per-alphabet `K` is chosen as the smallest count of symbols whose
//! information content reaches the 32-bit floor: `K = ceil(32 / log2(R))`.
//! Examples: K=6 at base62 (≈35.7 bits), K=8 at hex (32 bits), K=10 at
//! digits (≈33.2 bits), K=7 at base32 / base36 (≈35.0 / ≈36.2 bits).
//!
//! All alphabets defined here are ASCII-only. `verify` returns `false`
//! on any candidate that contains non-ASCII bytes — Invisibool never
//! emits non-ASCII fakes, so a non-ASCII candidate cannot be ours.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::alphabet::Alphabet;

type HmacSha256 = Hmac<Sha256>;

/// Compute the K-character MAC tail for `body` under `key`. The tail
/// consists of symbols from `alphabet`; its length is
/// `alphabet.mac_tail_len()`.
///
/// `key` is treated as opaque keying material — its length is not
/// constrained (HMAC accepts any-length keys). The caller is expected to
/// pass a session-scoped MAC key derived from the vault key, not the
/// vault key directly.
pub fn mac_tail(key: &[u8], body: &[u8], alphabet: &Alphabet) -> String {
    let mac_bytes = hmac_sha256(key, body);
    encode_to_alphabet(&mac_bytes, alphabet)
}

/// Verify that `candidate` is a MAC-tagged fake under `key` for the
/// given alphabet. Returns `true` only if `candidate` is ASCII, at
/// least K characters long, ends with K alphabet symbols, and those
/// symbols equal `HMAC(candidate[..len-K])` (constant-time compare).
///
/// Short-fake carve-out: candidates shorter than K characters return
/// `false`. Such fakes cannot carry a MAC tail, so they cannot be
/// recognised statelessly here; downstream idempotence falls through to
/// the live session map (when present) or to the unrestorable-fake
/// disclosure in two-command terminal mode.
pub fn verify(key: &[u8], candidate: &str, alphabet: &Alphabet) -> bool {
    // Non-ASCII candidates cannot be ours: Invisibool never emits
    // non-ASCII fakes. Reject early so we never byte-slice through a
    // multi-byte boundary below.
    if !candidate.is_ascii() {
        return false;
    }

    let k = alphabet.mac_tail_len();
    if candidate.len() < k {
        return false;
    }

    let split = candidate.len() - k;
    let body = &candidate[..split];
    let claimed_tail = &candidate[split..];

    // The claimed tail must consist of valid alphabet characters — a
    // candidate with junk in the tail position cannot be one of ours
    // and we skip the HMAC computation in that case.
    if !claimed_tail.chars().all(|c| alphabet.contains(c)) {
        return false;
    }

    let expected_tail = mac_tail(key, body.as_bytes(), alphabet);
    expected_tail
        .as_bytes()
        .ct_eq(claimed_tail.as_bytes())
        .into()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Produce a length-matched MAC-tagged fake for `real_value`.
///
/// Layout of the output: `body || tail`, where the body is `N - K`
/// alphabet symbols deterministically derived from
/// `HKDF-SHA256(salt = empty, ikm = key, info = real_value.as_bytes())`
/// and the tail is `K` symbols equal to `mac_tail(key, body, alphabet)`.
/// `N` is `real_value.len()` and `K` is `alphabet.mac_tail_len()`.
///
/// The deterministic body derivation makes the same `(key, real_value)`
/// produce the same fake every call, so a session map keyed on `real`
/// can short-circuit re-scrubs without re-running this generator. It
/// also makes the fake reproducible by tests and by an M1 daemon that
/// rebuilds its session map after an idle-lock wake.
///
/// Returns `None` when `real_value.len() <= K`: the short-fake carve-out
/// documented at the module level. With no room for at least one body
/// character before the K-character MAC tail, the fake would be either
/// the empty body's MAC (degenerate, not meaningful as a fake) or simply
/// too short to verify back through `verify`. The engine routes these
/// values to its fail-closed redaction path instead.
pub fn make_macfake(key: &[u8], real_value: &str, alphabet: &Alphabet) -> Option<String> {
    let k = alphabet.mac_tail_len();
    let n = real_value.len();
    if n <= k {
        return None;
    }
    let body_len = n - k;
    let body = derive_body(key, real_value, body_len, alphabet);
    let tail = mac_tail(key, body.as_bytes(), alphabet);
    Some(format!("{body}{tail}"))
}

/// Derive `body_len` alphabet symbols pseudorandomly from `(key, real_value)`.
///
/// Uses HKDF-SHA256 to produce `body_len` bytes (HKDF's 255 * HashLen
/// ceiling is 8160 bytes for SHA-256, far above any realistic Formatless
/// value length). Each byte is mapped into the alphabet by modulus.
///
/// Modulo bias note: a single byte mapped `b % radix` is slightly
/// non-uniform when the radix does not divide 256. The bias is at most
/// `radix / 256` and is acceptable here — the body is plausibility
/// padding around an authoritative MAC tail, not cryptographic output.
/// FF1 uses a separate, properly bias-free numeral path.
fn derive_body(key: &[u8], real_value: &str, body_len: usize, alphabet: &Alphabet) -> String {
    let hkdf = Hkdf::<Sha256>::new(None, key);
    let mut out = vec![0u8; body_len];
    hkdf.expand(real_value.as_bytes(), &mut out)
        .expect("body_len fits in HKDF-SHA256's 255*32 byte ceiling for any realistic value");
    let radix = alphabet.radix();
    out.into_iter()
        .map(|b| alphabet.symbol_at(u32::from(b) % radix))
        .collect()
}

fn encode_to_alphabet(mac_bytes: &[u8], alphabet: &Alphabet) -> String {
    let k = alphabet.mac_tail_len();
    let radix = u64::from(alphabet.radix());
    let k_u32 = u32::try_from(k).expect("k fits in u32 for all defined alphabets");
    let modulus = radix
        .checked_pow(k_u32)
        .expect("radix^k fits in u64 for all defined alphabets");

    // Treat the first up-to-8 bytes of the HMAC as a big-endian u64.
    // For all our alphabets, 32 bits of entropy (modulo radix^K) suffice;
    // taking 8 bytes (64 bits) before the mod gives the modulo bias the
    // best uniform distribution we can get without an integer >u64.
    let mut value: u64 = 0;
    for &b in mac_bytes.iter().take(8) {
        value = (value << 8) | u64::from(b);
    }
    let mut v = value % modulus;

    // Emit K symbols, least-significant first, then reverse for the
    // canonical most-significant-first representation.
    let mut symbols = Vec::with_capacity(k);
    for _ in 0..k {
        let idx = u32::try_from(v % radix).expect("v % radix < radix < u32::MAX");
        symbols.push(alphabet.symbol_at(idx));
        v /= radix;
    }
    symbols.reverse();
    symbols.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &[u8] = b"a-test-session-mac-key-not-secret";

    // ----- Alphabet -----

    #[test]
    fn alphabet_radices_match_expected() {
        assert_eq!(Alphabet::BASE62.radix(), 62);
        assert_eq!(Alphabet::BASE32.radix(), 32);
        assert_eq!(Alphabet::HEX_LOWER.radix(), 16);
        assert_eq!(Alphabet::HEX_UPPER.radix(), 16);
        assert_eq!(Alphabet::DIGITS.radix(), 10);
        assert_eq!(Alphabet::ALPHA_LOWER.radix(), 26);
        assert_eq!(Alphabet::ALPHA_UPPER.radix(), 26);
        assert_eq!(Alphabet::BASE36_LOWER.radix(), 36);
    }

    #[test]
    fn mac_tail_lengths_meet_32_bit_floor() {
        // K = ceil(32 / log2(radix)) for each.
        assert_eq!(Alphabet::BASE62.mac_tail_len(), 6);
        assert_eq!(Alphabet::BASE32.mac_tail_len(), 7);
        assert_eq!(Alphabet::HEX_LOWER.mac_tail_len(), 8);
        assert_eq!(Alphabet::HEX_UPPER.mac_tail_len(), 8);
        assert_eq!(Alphabet::DIGITS.mac_tail_len(), 10);
        assert_eq!(Alphabet::ALPHA_LOWER.mac_tail_len(), 7);
        assert_eq!(Alphabet::ALPHA_UPPER.mac_tail_len(), 7);
        assert_eq!(Alphabet::BASE36_LOWER.mac_tail_len(), 7);

        // Sanity: every entry actually reaches >= 32 bits.
        for ab in [
            Alphabet::BASE62,
            Alphabet::BASE32,
            Alphabet::HEX_LOWER,
            Alphabet::HEX_UPPER,
            Alphabet::DIGITS,
            Alphabet::ALPHA_LOWER,
            Alphabet::ALPHA_UPPER,
            Alphabet::BASE36_LOWER,
        ] {
            let bits = ab.mac_tail_len() as f64 * f64::from(ab.radix()).log2();
            assert!(bits >= 32.0, "alphabet radix {} below floor", ab.radix());
        }
    }

    #[test]
    fn contains_recognises_alphabet_chars() {
        assert!(Alphabet::HEX_LOWER.contains('a'));
        assert!(Alphabet::HEX_LOWER.contains('0'));
        assert!(!Alphabet::HEX_LOWER.contains('g'));
        assert!(!Alphabet::HEX_LOWER.contains('A'));
        assert!(Alphabet::HEX_UPPER.contains('A'));
        assert!(!Alphabet::HEX_UPPER.contains('a'));
    }

    // ----- mac_tail -----

    #[test]
    fn tail_is_correct_length() {
        for ab in [
            Alphabet::BASE62,
            Alphabet::HEX_LOWER,
            Alphabet::DIGITS,
            Alphabet::BASE32,
        ] {
            let tail = mac_tail(TEST_KEY, b"some body bytes", &ab);
            assert_eq!(tail.len(), ab.mac_tail_len());
        }
    }

    #[test]
    fn tail_consists_only_of_alphabet_chars() {
        for ab in [
            Alphabet::BASE62,
            Alphabet::HEX_LOWER,
            Alphabet::HEX_UPPER,
            Alphabet::DIGITS,
            Alphabet::BASE32,
            Alphabet::ALPHA_LOWER,
            Alphabet::ALPHA_UPPER,
            Alphabet::BASE36_LOWER,
        ] {
            let tail = mac_tail(TEST_KEY, b"body", &ab);
            assert!(
                tail.chars().all(|c| ab.contains(c)),
                "tail {tail} contains non-alphabet chars for radix {}",
                ab.radix()
            );
        }
    }

    #[test]
    fn tail_is_deterministic_in_key_and_body() {
        let a = mac_tail(TEST_KEY, b"hello", &Alphabet::BASE62);
        let b = mac_tail(TEST_KEY, b"hello", &Alphabet::BASE62);
        assert_eq!(a, b);
    }

    #[test]
    fn different_keys_yield_different_tails() {
        let a = mac_tail(b"key-A", b"same body", &Alphabet::BASE62);
        let b = mac_tail(b"key-B", b"same body", &Alphabet::BASE62);
        assert_ne!(a, b);
    }

    #[test]
    fn different_bodies_yield_different_tails() {
        let a = mac_tail(TEST_KEY, b"body-A", &Alphabet::BASE62);
        let b = mac_tail(TEST_KEY, b"body-B", &Alphabet::BASE62);
        assert_ne!(a, b);
    }

    // ----- verify -----

    #[test]
    fn verify_accepts_a_freshly_computed_fake() {
        let body = "sk-ant-randombodyhere";
        let tail = mac_tail(TEST_KEY, body.as_bytes(), &Alphabet::BASE62);
        let fake = format!("{body}{tail}");
        assert!(verify(TEST_KEY, &fake, &Alphabet::BASE62));
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let body = "AKIA0123456789012345"; // 20 chars; we'll MAC and append
        let tail = mac_tail(TEST_KEY, body.as_bytes(), &Alphabet::HEX_LOWER);
        // Pretend an attacker flipped a body char and submitted same tail.
        let mut tampered = String::from("AKIA1123456789012345");
        tampered.push_str(&tail);
        assert!(!verify(TEST_KEY, &tampered, &Alphabet::HEX_LOWER));
    }

    #[test]
    fn verify_rejects_tampered_tail() {
        let body = "real-body";
        let tail = mac_tail(TEST_KEY, body.as_bytes(), &Alphabet::BASE62);
        // Flip the first tail character to a different valid alphabet symbol.
        let first = tail.chars().next().unwrap();
        let replacement = if first == 'a' { 'b' } else { 'a' };
        let mut bad_tail: String = std::iter::once(replacement).collect();
        bad_tail.push_str(&tail[1..]);
        let bad_fake = format!("{body}{bad_tail}");
        assert!(!verify(TEST_KEY, &bad_fake, &Alphabet::BASE62));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let body = "real-body";
        let tail = mac_tail(b"signing-key", body.as_bytes(), &Alphabet::BASE62);
        let fake = format!("{body}{tail}");
        assert!(!verify(b"different-key", &fake, &Alphabet::BASE62));
    }

    #[test]
    fn verify_returns_false_for_short_candidate_carveout() {
        // Candidate too short to carry a 6-char base62 MAC tail.
        assert!(!verify(TEST_KEY, "abc", &Alphabet::BASE62));
        // Exactly K chars: there is no body to MAC, so the tail (the
        // whole string) cannot match HMAC of an empty body in general.
        // Still must not panic.
        let _ = verify(TEST_KEY, "abcdef", &Alphabet::BASE62);
    }

    #[test]
    fn verify_returns_false_for_non_ascii_candidate() {
        assert!(!verify(
            TEST_KEY,
            "héllo-with-base62-tailABCDEF",
            &Alphabet::BASE62
        ));
    }

    #[test]
    fn verify_returns_false_when_tail_contains_non_alphabet_chars() {
        // Tail position contains chars outside hex.
        assert!(!verify(TEST_KEY, "bodybytes_gxyz!?", &Alphabet::HEX_LOWER));
    }

    #[test]
    fn verify_round_trip_across_multiple_alphabets() {
        for ab in [
            Alphabet::BASE62,
            Alphabet::HEX_LOWER,
            Alphabet::HEX_UPPER,
            Alphabet::DIGITS,
            Alphabet::BASE32,
            Alphabet::ALPHA_LOWER,
            Alphabet::ALPHA_UPPER,
            Alphabet::BASE36_LOWER,
        ] {
            let body = "body";
            let tail = mac_tail(TEST_KEY, body.as_bytes(), &ab);
            let fake = format!("{body}{tail}");
            assert!(
                verify(TEST_KEY, &fake, &ab),
                "round-trip failed for radix {}",
                ab.radix()
            );
        }
    }

    // ----- make_macfake -----

    #[test]
    fn make_macfake_matches_real_value_length() {
        let real = "p@$$w0rd!-with-22-chars";
        let fake = make_macfake(TEST_KEY, real, &Alphabet::BASE62).expect("long enough");
        assert_eq!(fake.len(), real.len());
    }

    #[test]
    fn make_macfake_output_verifies_under_same_key() {
        // Round-trip: a freshly-generated fake recognises itself via
        // the same verify path the idempotence layer uses.
        let real = "ABCDEFGHIJ";
        let fake = make_macfake(TEST_KEY, real, &Alphabet::BASE62).expect("long enough");
        assert!(verify(TEST_KEY, &fake, &Alphabet::BASE62));
    }

    #[test]
    fn make_macfake_does_not_contain_the_real_value() {
        // Defence in depth: the fake's body is derived from HKDF over
        // the real value, but the output bytes must not contain the
        // real value as a substring. This pins the "no plaintext
        // smuggling" invariant.
        let real = "exfiltrate-this-string";
        let fake = make_macfake(TEST_KEY, real, &Alphabet::BASE62).expect("long enough");
        assert!(
            !fake.contains(real),
            "MAC-fake contained the real value: fake={fake} real={real}"
        );
    }

    #[test]
    fn make_macfake_is_deterministic_in_key_and_real() {
        let real = "deterministic-input";
        let a = make_macfake(TEST_KEY, real, &Alphabet::BASE62).unwrap();
        let b = make_macfake(TEST_KEY, real, &Alphabet::BASE62).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn make_macfake_distinct_reals_yield_distinct_fakes() {
        let a = make_macfake(TEST_KEY, "real-value-AAAA", &Alphabet::BASE62).unwrap();
        let b = make_macfake(TEST_KEY, "real-value-BBBB", &Alphabet::BASE62).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn make_macfake_distinct_keys_yield_distinct_fakes() {
        let real = "same-input-string";
        let a = make_macfake(b"key-A", real, &Alphabet::BASE62).unwrap();
        let b = make_macfake(b"key-B", real, &Alphabet::BASE62).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn make_macfake_short_carve_out_returns_none() {
        // BASE62 K = 6. Any real value of length <= 6 has no room for a
        // body before the tail; the carve-out fires.
        assert!(make_macfake(TEST_KEY, "", &Alphabet::BASE62).is_none());
        assert!(make_macfake(TEST_KEY, "abc", &Alphabet::BASE62).is_none());
        assert!(make_macfake(TEST_KEY, "abcdef", &Alphabet::BASE62).is_none());
        // K + 1 = 7: the smallest length that fits one body char + tail.
        assert!(make_macfake(TEST_KEY, "abcdefg", &Alphabet::BASE62).is_some());
    }

    #[test]
    fn make_macfake_body_is_in_alphabet() {
        // Every output character must be an alphabet symbol, so a
        // subsequent verify round-trip cannot be defeated by stray
        // non-alphabet bytes in the body.
        let real = "longer-real-value-here";
        for ab in [
            Alphabet::BASE62,
            Alphabet::HEX_LOWER,
            Alphabet::DIGITS,
            Alphabet::BASE32,
        ] {
            let fake = make_macfake(TEST_KEY, real, &ab).unwrap();
            assert!(
                fake.chars().all(|c| ab.contains(c)),
                "MAC-fake {fake} contains a char outside the alphabet (radix {})",
                ab.radix()
            );
            assert!(verify(TEST_KEY, &fake, &ab));
        }
    }
}
