//! Format-preserving encryption for FF1-eligible registered values.
//!
//! Stateless format-preserving reversal via deterministic FF1 - uses
//! the `fpe` crate's NIST SP 800-38G FF1-AES256 implementation. Restore
//! decrypts a candidate's body with each profile-matching
//! registration's tweak and accepts the match whose plaintext equals
//! the registered value (constant-time compare).
//!
//! **The "stateless" claim, precisely.** FF1 restore needs only persistent
//! vault state, not per-submission ephemeral state. The shared state
//! across CLI processes is exactly the vault file (registered values +
//! their tweaks) and the vault key (from the OS keychain, hashed through
//! HKDF for the FF1 subkey). There is no path that restores a registered
//! value without the vault loaded.
//!
//! Process 1 - `invisibool scrub` - loads the vault, FF1-encrypts each
//! match's body under `(FF1_KEY, registered.tweak)`, exits without
//! writing any session artifact. Process 2 - `invisibool restore`, minutes
//! later - reloads the vault (same values, same tweaks), re-derives the
//! same FF1 subkey via HKDF from the same vault key, trial-decrypts each
//! profile-matching candidate.
//!
//! **Crypto choices.**
//!
//! - Block cipher: AES-256.
//! - FF1 subkey derivation: HKDF-SHA256 with `salt = empty`,
//!   `ikm = vault_key`, `info = "invisibool-ff1-key-v1"`. The version
//!   suffix lets us rotate the derivation independently of the vault key.
//! - Tweak: per-registered-value, 16 random bytes generated at
//!   registration and stored alongside the value. Stable across rename
//!   (rename touches metadata, not the tweak). Destroyed only by
//!   `forget --purge`, which makes old fakes unrestorable - matching the
//!   documented `forget --purge` semantics.
//! - Restore acceptance: `subtle::ConstantTimeEq` on the decrypted body
//!   vs. the registered body, so timing does not reveal which registered
//!   value matched.
//! - Eligibility: enforced at registration (M4a) AND at scrub (here, as
//!   the engine's safety net). Failures route to the session-map path
//!   with explicit consequence disclosure - never silent.

use aes::Aes256;
use fpe::ff1::{FlexibleNumeralString, FF1};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::alphabet::Alphabet;

/// HKDF `info` string for the FF1 subkey derivation. Bumping the `-v1`
/// suffix is how we rotate the derivation without rotating the vault key.
const FF1_KEY_INFO: &[u8] = b"invisibool-ff1-key-v1";
/// AES-256 needs 32 bytes of key material.
const FF1_KEY_LEN: usize = 32;
/// Tweak length in bytes - fixed at 16 (128 bits) for all registered
/// values, well within NIST SP 800-38G's 0–65535-byte range.
pub const TWEAK_LEN: usize = 16;
/// FF1 minimum domain size: `radix^length ≥ 10^6`. Below this floor
/// the fake's possibility space is too small to give meaningful
/// indistinguishability - a 5-digit fake of a 5-digit value lives in a
/// 100k-element space, trivially brute-forceable.
const MIN_DOMAIN: u64 = 1_000_000;

/// Source of the vault key. M0b ships an in-memory test impl; M1 swaps
/// in a keychain-backed implementation without engine changes.
pub trait KeyProvider {
    /// Bytes of the vault key. HKDF turns this into the FF1 subkey.
    fn vault_key(&self) -> &[u8];
}

/// In-memory `KeyProvider` for tests. The key is held `Zeroizing`-wrapped
/// so it is wiped from memory when the provider drops.
pub struct InMemoryKeyProvider {
    key: Zeroizing<Vec<u8>>,
}

impl InMemoryKeyProvider {
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }
}

impl KeyProvider for InMemoryKeyProvider {
    fn vault_key(&self) -> &[u8] {
        &self.key
    }
}

/// A registered vault value, classified by how its fake is produced.
///
/// `Fpe` entries take the FF1 path (this module). They are restorable
/// across two-command CLI invocations because the vault holds everything
/// the engine needs (value, tweak, profile) and the FF1 subkey is
/// reproducible by HKDF.
///
/// `SessionMapped` entries - formatless values, cards, structured PII -
/// take the session-map path. They are not restorable across two-
/// command CLI invocations without an explicit `--session` file; the
/// end-of-scrub notice discloses this.
#[derive(Debug)]
pub enum RegisteredValue {
    Fpe(FpeRegistration),
    SessionMapped(SessionRegistration),
}

/// A registered value that takes the FF1 path. Construct only via
/// `register` after passing the eligibility check.
///
/// `Debug` is implemented manually so the registered plaintext never
/// appears in `{:?}` output - the derived impl would delegate to
/// `Zeroizing<String>::fmt`, which prints the inner string verbatim. A
/// stray `dbg!(&registration)` or a future log line that formats the
/// struct must not leak the secret.
pub struct FpeRegistration {
    pub label: String,
    pub value: Zeroizing<String>,
    /// Per-value 16-byte tweak generated at registration; stable across
    /// rename.
    pub tweak: [u8; TWEAK_LEN],
    /// Character set of the value's body (after stripping `prefix`).
    pub alphabet: Alphabet,
    /// Literal prefix preserved through FF1 (e.g. `sk-ant-`).
    pub prefix: String,
}

impl std::fmt::Debug for FpeRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FpeRegistration")
            .field("label", &self.label)
            .field("value", &"<redacted>")
            .field("tweak", &self.tweak)
            .field("alphabet", &self.alphabet)
            .field("prefix", &self.prefix)
            .finish()
    }
}

/// A registered value that takes the session-map path. `kind` chooses
/// the fake generator: test-BIN for cards, reserved range for PII,
/// random + MAC for formatless.
///
/// `Debug` is implemented manually for the same reason as
/// `FpeRegistration` above.
pub struct SessionRegistration {
    pub label: String,
    pub value: Zeroizing<String>,
    pub kind: SessionFakeKind,
}

impl std::fmt::Debug for SessionRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRegistration")
            .field("label", &self.label)
            .field("value", &"<redacted>")
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionFakeKind {
    /// Cards (registered or detected) always take the test-BIN path,
    /// never FF1 - the PAN domain is too small for FF1's bijection
    /// guarantee to be collision-safe against real cards.
    Card,
    /// Structured PII - emails, IPv4 addresses, phone numbers - uses
    /// reserved-range generators (`example.com`, 192.0.2.0/24,
    /// +1-555-0100..0199 etc.) so the fake collides with no real entity.
    Pii(PiiKind),
    /// Values that fail FF1 eligibility (domain too small, whitespace,
    /// non-ASCII alphabet). Routed here at registration with explicit
    /// consequence disclosure.
    Formatless,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PiiKind {
    Email,
    Ipv4,
    Phone,
}

/// FF1 tokenizer. Built once per process by deriving the FF1 subkey from
/// the vault key.
pub struct FpeTokenizer {
    ff1_key: Zeroizing<Vec<u8>>,
}

impl FpeTokenizer {
    /// Derive the FF1 subkey from the vault key:
    /// `FF1_KEY = HKDF-SHA256(salt: empty, ikm: vault_key, info: "invisibool-ff1-key-v1")`.
    pub fn new<K: KeyProvider>(key_provider: &K) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, key_provider.vault_key());
        let mut ff1_key = vec![0u8; FF1_KEY_LEN];
        hkdf.expand(FF1_KEY_INFO, &mut ff1_key)
            .expect("32-byte expansion always succeeds with HKDF-SHA256");
        Self {
            ff1_key: Zeroizing::new(ff1_key),
        }
    }

    /// Scrub `reg`'s value: rechecks eligibility (defense in depth),
    /// strips the literal prefix, FF1-encrypts the body, and reassembles
    /// `prefix || ciphertext_body`.
    pub fn scrub(&self, reg: &FpeRegistration) -> Result<String, FpeError> {
        check_eligibility(&reg.value, &reg.prefix, &reg.alphabet)?;

        // `strip_prefix` is infallible here because eligibility verified
        // the prefix matches.
        let body = reg
            .value
            .strip_prefix(reg.prefix.as_str())
            .expect("eligibility check verified prefix");

        let numerals = body_to_numerals(body, &reg.alphabet);
        let ff1 =
            FF1::<Aes256>::new(&self.ff1_key, reg.alphabet.radix()).map_err(|_| FpeError::Ff1)?;
        let ct = ff1
            .encrypt(&reg.tweak, &FlexibleNumeralString::from(numerals))
            .map_err(|_| FpeError::Ff1)?;
        let ct_numerals: Vec<u16> = ct.into();
        let cipher_body = numerals_to_body(&ct_numerals, &reg.alphabet);
        Ok(format!("{}{}", reg.prefix, cipher_body))
    }

    /// Try to restore `candidate` by trial-decrypting against each
    /// profile-matching registration. Returns the registered value on the
    /// first registration whose decryption equals it (constant-time
    /// compare). Returns `None` if no registration matches.
    pub fn try_restore(
        &self,
        candidate: &str,
        registered_set: &[FpeRegistration],
    ) -> Option<Zeroizing<String>> {
        for reg in registered_set {
            // Profile filter: prefix matches, body length matches,
            // every body char is in the alphabet. None of these is
            // secret information about the registration, so the early
            // continues are not a timing concern.
            let Some(body) = candidate.strip_prefix(reg.prefix.as_str()) else {
                continue;
            };
            let registered_body_len = reg.value.len().saturating_sub(reg.prefix.len());
            if body.len() != registered_body_len {
                continue;
            }
            if !body.chars().all(|c| reg.alphabet.contains(c)) {
                continue;
            }

            let numerals = body_to_numerals(body, &reg.alphabet);
            let Ok(ff1) = FF1::<Aes256>::new(&self.ff1_key, reg.alphabet.radix()) else {
                continue;
            };
            let Ok(pt) = ff1.decrypt(&reg.tweak, &FlexibleNumeralString::from(numerals)) else {
                continue;
            };
            let pt_numerals: Vec<u16> = pt.into();
            let pt_body = numerals_to_body(&pt_numerals, &reg.alphabet);
            let pt_value = format!("{}{}", reg.prefix, pt_body);

            // Constant-time equality on the decrypted-vs-registered bytes
            // so timing does not reveal which registered value matched.
            let eq: bool = pt_value.as_bytes().ct_eq(reg.value.as_bytes()).into();
            if eq {
                return Some(Zeroizing::new(reg.value.to_string()));
            }
        }
        None
    }
}

/// Check FF1 eligibility for a (value, prefix, alphabet) triple. Called
/// at registration (M4a `register`) AND at scrub time (the engine's
/// safety net). Errors are non-fatal at registration time - the M4a
/// command surfaces the consequence and offers the session-map path.
pub fn check_eligibility(
    value: &str,
    prefix: &str,
    alphabet: &Alphabet,
) -> Result<(), EligibilityError> {
    let body = value
        .strip_prefix(prefix)
        .ok_or(EligibilityError::PrefixMissing)?;
    if !body.is_ascii() {
        return Err(EligibilityError::ValueNotAscii);
    }
    if body.chars().any(char::is_whitespace) {
        return Err(EligibilityError::ValueContainsWhitespace);
    }
    for c in body.chars() {
        if !alphabet.contains(c) {
            return Err(EligibilityError::CharNotInAlphabet { ch: c });
        }
    }
    let radix = u64::from(alphabet.radix());
    let length = u32::try_from(body.chars().count()).map_err(|_| EligibilityError::BodyTooLong)?;
    let domain = radix.checked_pow(length).unwrap_or(u64::MAX);
    if domain < MIN_DOMAIN {
        return Err(EligibilityError::DomainTooSmall { radix, length });
    }
    Ok(())
}

/// Errors returned by `FpeTokenizer::scrub` and friends.
#[derive(Debug)]
pub enum FpeError {
    /// Value failed the FF1 eligibility check. Caller should route to
    /// the session-map path or report to the user.
    Eligibility(EligibilityError),
    /// The underlying FF1 crate returned an error. Treated as an internal
    /// failure - the caller has supplied something `fpe` rejected, which
    /// shouldn't happen after eligibility passes.
    Ff1,
}

impl From<EligibilityError> for FpeError {
    fn from(e: EligibilityError) -> Self {
        FpeError::Eligibility(e)
    }
}

/// Detailed reason a value failed FF1 eligibility.
#[derive(Debug, PartialEq, Eq)]
pub enum EligibilityError {
    /// `value` does not start with `prefix`.
    PrefixMissing,
    /// `value` body contains non-ASCII characters.
    ValueNotAscii,
    /// `value` body contains whitespace.
    ValueContainsWhitespace,
    /// `value` body contains a character outside the chosen alphabet.
    CharNotInAlphabet { ch: char },
    /// `radix^length` is below the FF1 minimum domain (10^6).
    DomainTooSmall { radix: u64, length: u32 },
    /// `value` body length does not fit in a `u32`.
    BodyTooLong,
}

impl std::fmt::Display for EligibilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrefixMissing => write!(f, "value does not start with the configured prefix"),
            Self::ValueNotAscii => write!(f, "value body contains non-ASCII characters"),
            Self::ValueContainsWhitespace => write!(f, "value body contains whitespace"),
            Self::CharNotInAlphabet { ch } => {
                write!(f, "value body contains {ch:?}, outside the alphabet")
            }
            Self::DomainTooSmall { radix, length } => write!(
                f,
                "radix^length = {radix}^{length} below FF1 minimum domain 10^6"
            ),
            Self::BodyTooLong => write!(f, "value body too long for FF1"),
        }
    }
}

impl std::error::Error for EligibilityError {}

fn body_to_numerals(body: &str, alphabet: &Alphabet) -> Vec<u16> {
    body.chars()
        .map(|c| {
            let i = alphabet
                .index_of(c)
                .expect("body chars in alphabet (eligibility-checked or profile-filtered)");
            u16::try_from(i).expect("alphabet radix ≤ 65535, so indices fit in u16")
        })
        .collect()
}

fn numerals_to_body(numerals: &[u16], alphabet: &Alphabet) -> String {
    numerals
        .iter()
        .map(|&n| alphabet.symbol_at(u32::from(n)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> InMemoryKeyProvider {
        InMemoryKeyProvider::new(vec![0xa5u8; 32])
    }

    fn tokenizer() -> FpeTokenizer {
        FpeTokenizer::new(&provider())
    }

    fn reg(value: &str, prefix: &str, alphabet: Alphabet, tweak: [u8; 16]) -> FpeRegistration {
        FpeRegistration {
            label: "test".to_string(),
            value: Zeroizing::new(value.to_string()),
            tweak,
            alphabet,
            prefix: prefix.to_string(),
        }
    }

    // ----- Eligibility -----

    #[test]
    fn eligibility_accepts_typical_anthropic_shape() {
        // 20 chars body in base62: 62^20 way over 10^6.
        assert!(
            check_eligibility("sk-ant-abcdefghijklmnopqrst", "sk-ant-", &Alphabet::BASE62).is_ok()
        );
    }

    #[test]
    fn eligibility_rejects_too_short_body() {
        // 3-char body in base62: 62^3 = 238_328 < 10^6.
        let err = check_eligibility("p-abc", "p-", &Alphabet::BASE62).unwrap_err();
        assert!(matches!(err, EligibilityError::DomainTooSmall { .. }));
    }

    #[test]
    fn eligibility_rejects_missing_prefix() {
        let err = check_eligibility("noprefix-here", "wrong-", &Alphabet::BASE62).unwrap_err();
        assert_eq!(err, EligibilityError::PrefixMissing);
    }

    #[test]
    fn eligibility_rejects_whitespace_in_body() {
        let err = check_eligibility("p-abc def ghi jkl", "p-", &Alphabet::BASE62).unwrap_err();
        assert_eq!(err, EligibilityError::ValueContainsWhitespace);
    }

    #[test]
    fn eligibility_rejects_char_outside_alphabet() {
        // Hex lower; body contains uppercase 'A'.
        let err = check_eligibility("p-Aabcdef0123", "p-", &Alphabet::HEX_LOWER).unwrap_err();
        assert_eq!(err, EligibilityError::CharNotInAlphabet { ch: 'A' });
    }

    // ----- Round-trip -----

    #[test]
    fn ff1_round_trips_through_scrub_and_restore() {
        let t = tokenizer();
        let r = reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [0u8; 16],
        );
        let scrubbed = t.scrub(&r).unwrap();
        assert!(scrubbed.starts_with("sk-ant-"));
        assert_eq!(scrubbed.len(), r.value.len());
        let restored = t.try_restore(&scrubbed, std::slice::from_ref(&r)).unwrap();
        assert_eq!(restored.as_str(), r.value.as_str());
    }

    #[test]
    fn ff1_preserves_alphabet() {
        let t = tokenizer();
        // 16-char body, all in HEX_LOWER. 16^16 way over the 10^6 floor.
        let r = reg("p-0123456789abcdef", "p-", Alphabet::HEX_LOWER, [0u8; 16]);
        let scrubbed = t.scrub(&r).unwrap();
        let body = scrubbed.strip_prefix("p-").unwrap();
        assert!(
            body.chars().all(|c| Alphabet::HEX_LOWER.contains(c)),
            "ciphertext body {body} not entirely hex"
        );
    }

    // ----- Tweak separation -----

    #[test]
    fn different_tweaks_yield_different_ciphertexts() {
        let t = tokenizer();
        let r1 = reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [1u8; 16],
        );
        let r2 = reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [2u8; 16],
        );
        let s1 = t.scrub(&r1).unwrap();
        let s2 = t.scrub(&r2).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn restore_picks_the_right_registration_by_tweak() {
        // Two registrations with identical plaintext but different tweaks
        // must each restore to themselves - restore picks the one whose
        // tweak decrypts the candidate correctly.
        let t = tokenizer();
        let r1 = reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [1u8; 16],
        );
        let r2 = reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [2u8; 16],
        );
        let set = [r1.clone_for_test(), r2.clone_for_test()];
        let s1 = t.scrub(&r1).unwrap();
        let s2 = t.scrub(&r2).unwrap();
        // Both candidates decode to the same plaintext via their own
        // tweak, so restore returns the registered value either way.
        assert_eq!(
            t.try_restore(&s1, &set).unwrap().as_str(),
            r1.value.as_str()
        );
        assert_eq!(
            t.try_restore(&s2, &set).unwrap().as_str(),
            r2.value.as_str()
        );
    }

    // Helper for the test above only - FpeRegistration is intentionally
    // not Clone in the public API (callers should not casually duplicate
    // secret material).
    impl FpeRegistration {
        fn clone_for_test(&self) -> Self {
            Self {
                label: self.label.clone(),
                value: Zeroizing::new(self.value.to_string()),
                tweak: self.tweak,
                alphabet: self.alphabet.clone(),
                prefix: self.prefix.clone(),
            }
        }
    }

    // ----- Key separation -----

    #[test]
    fn different_vault_keys_yield_different_ciphertexts() {
        let t1 = FpeTokenizer::new(&InMemoryKeyProvider::new(vec![0xa5u8; 32]));
        let t2 = FpeTokenizer::new(&InMemoryKeyProvider::new(vec![0x5au8; 32]));
        let r = reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [0u8; 16],
        );
        let s1 = t1.scrub(&r).unwrap();
        let s2 = t2.scrub(&r).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn hkdf_subkey_is_deterministic_across_tokenizers() {
        // Building two tokenizers from the same vault key must produce
        // the same FF1 subkey (HKDF determinism) - required for the
        // "scrub in process 1, restore in process 2" workflow.
        let t1 = tokenizer();
        let t2 = tokenizer();
        let r = reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [7u8; 16],
        );
        let s1 = t1.scrub(&r).unwrap();
        let s2 = t2.scrub(&r).unwrap();
        assert_eq!(s1, s2);
    }

    // ----- Restore failure modes -----

    #[test]
    fn restore_returns_none_for_candidate_outside_registered_set() {
        let t = tokenizer();
        let r = reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [0u8; 16],
        );
        // A different-prefix candidate cannot match the only registration.
        assert!(t
            .try_restore("AKIA0123456789012345", std::slice::from_ref(&r))
            .is_none());
    }

    #[test]
    fn restore_returns_none_when_no_registrations() {
        let t = tokenizer();
        assert!(t.try_restore("sk-ant-anything", &[]).is_none());
    }

    #[test]
    fn restore_returns_none_when_tweak_does_not_decrypt_to_registered() {
        // Scrub with one tweak; restore with a registration that has a
        // different tweak. The decryption succeeds (FF1 always decrypts),
        // but the plaintext does not equal the registered value, so
        // restore correctly returns None.
        let t = tokenizer();
        let scrubber_reg = reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [0xAAu8; 16],
        );
        let scrubbed = t.scrub(&scrubber_reg).unwrap();
        // Restorer-side registration: same value, different tweak.
        let restorer_reg = reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [0xBBu8; 16],
        );
        assert!(t
            .try_restore(&scrubbed, std::slice::from_ref(&restorer_reg))
            .is_none());
    }

    // ----- Debug-format redaction -----

    #[test]
    fn fpe_registration_debug_redacts_value() {
        let secret = "sk-test-supersecretbodyxyz12";
        let r = reg(secret, "sk-test-", Alphabet::BASE62, [0u8; 16]);
        let s = format!("{r:?}");
        assert!(
            !s.contains(secret),
            "FpeRegistration Debug leaked the registered value: {s}"
        );
        assert!(
            s.contains("<redacted>"),
            "FpeRegistration Debug missing the redaction marker: {s}"
        );
        // The non-secret fields stay visible so debug output is still useful.
        assert!(s.contains("sk-test-"));
        assert!(s.contains("label"));
    }

    #[test]
    fn session_registration_debug_redacts_value() {
        let secret = "alice@example.com";
        let r = SessionRegistration {
            label: "test".to_string(),
            value: Zeroizing::new(secret.to_string()),
            kind: SessionFakeKind::Pii(PiiKind::Email),
        };
        let s = format!("{r:?}");
        assert!(
            !s.contains(secret),
            "SessionRegistration Debug leaked the registered value: {s}"
        );
        assert!(
            s.contains("<redacted>"),
            "SessionRegistration Debug missing the redaction marker: {s}"
        );
        assert!(s.contains("Email"));
    }

    #[test]
    fn registered_value_enum_debug_redacts_value() {
        // The enum derives Debug - its variants must rely on each
        // inner type's redacted Debug, not on a separate code path.
        let secret = "sk-test-anothersecretbody1234";
        let r = RegisteredValue::Fpe(reg(secret, "sk-test-", Alphabet::BASE62, [0u8; 16]));
        let s = format!("{r:?}");
        assert!(
            !s.contains(secret),
            "RegisteredValue::Fpe Debug leaked the registered value: {s}"
        );
    }
}
