//! Three-check idempotence with exact-match precedence.
//!
//! Format-preserving fakes deliberately match the same shape as their
//! originals, so they re-trigger the very detectors that produced them.
//! Re-scrubbing already-scrubbed text - for example a user re-copying
//! their own scrubbed prompt out of the LLM input box - would
//! double-encrypt FF1 fakes and silently break restore. The mechanism
//! to prevent that is checked before tokenising ANY pattern-matched
//! candidate.
//!
//! ## The rule
//!
//! **Precedence.** A candidate that exactly equals a registered real
//! vault value is **always scrubbed**, regardless of any no-op check
//! below. (The astronomically unlikely "someone's fake equals another
//! registered real secret" collision is documented in the threat model,
//! not handled in code.)
//!
//! Otherwise, the candidate is left unchanged (no-op) if any of these
//! three recognition checks fires:
//!
//! - **(a) FF1 trial-decrypt** - try decrypting the candidate against
//!   each registered value's FF1 tweak (and then against the retired
//!   set). If any decryption equals the registered/retired plaintext,
//!   the candidate is already one of our FF1 fakes.
//! - **(b) Reserved-range membership** - if the candidate lies inside a
//!   reserved/test range we generate fakes into (RFC 2606 example
//!   domains, RFC 5737 TEST-NET-1/2/3, the 555-01XX phone exchange,
//!   or the 4242-test-BIN card space), it is already one of our
//!   session-map fakes.
//! - **(c) MAC verification** - if the candidate's tail verifies as a
//!   truncated keyed MAC over the preceding bytes, it is one of our
//!   MAC-tagged self-authenticating fakes.
//!
//! All three checks are cheap. (a) and (c) run only on pattern-matched
//! candidates already pre-filtered by prefix/length/character-class
//! profiles; (b) is constant-time string membership.
//!
//! ## Documented carve-out
//!
//! Fakes whose body is too short to embed a K-character MAC tail
//! (the short-fake carve-out on the MAC scheme) fail check (c) and
//! reach the Scrub branch. In live `watch` mode they are still
//! recognised by the session map; in two-command terminal mode they
//! are not idempotent and the user is told so at scrub time.

use crate::tokenizer::alphabet::Alphabet;
use crate::tokenizer::fpe::{FpeRegistration, FpeTokenizer};
use crate::tokenizer::mac;

/// What the idempotence layer says to do with a candidate.
#[derive(Debug, PartialEq, Eq)]
pub enum IdempotenceDecision {
    /// Tokenize this candidate into a fake. Either it exactly matched a
    /// registered real value (precedence) or no recognition check fired.
    Scrub,
    /// Leave this candidate unchanged - it's already one of our fakes.
    NoOp(NoOpReason),
}

/// Which recognition check fired.
#[derive(Debug, PartialEq, Eq)]
pub enum NoOpReason {
    /// FF1 trial-decrypt matched a registered vault value.
    Ff1DecryptedToRegistered,
    /// FF1 trial-decrypt matched a retired vault value (`forget`'d but
    /// kept in the recognition-only retired set). `restore` will say
    /// "forgotten - not restored" rather than restore.
    Ff1DecryptedToRetired,
    /// Candidate lies inside a reserved/test range the engine emits into.
    ReservedRange,
    /// Candidate's tail verifies as a truncated keyed MAC over its body.
    MacVerified,
}

/// Inputs the idempotence layer needs to make a decision. Built once
/// per scrub/restore invocation by the engine top level.
pub struct IdempotenceContext<'a> {
    /// Active vault entries that take the FF1 path.
    pub registered: &'a [FpeRegistration],
    /// Retired (forgot, non-purged) entries. Trial-decryption still runs
    /// against these so old fakes keep being recognised; the engine
    /// won't actually restore them.
    pub retired: &'a [FpeRegistration],
    /// FF1 tokenizer for trial-decryption (check a).
    pub fpe_tokenizer: &'a FpeTokenizer,
    /// HMAC key for MAC verification (check c). Derived per session
    /// from the vault key (M1 wiring).
    pub session_mac_key: &'a [u8],
}

impl IdempotenceContext<'_> {
    /// Decide whether `candidate` should be scrubbed or left unchanged.
    ///
    /// `mac_alphabet` is the candidate's expected alphabet - taken from
    /// the matched detector profile by the engine - used only by check
    /// (c) to know how many tail characters to verify.
    pub fn classify(&self, candidate: &str, mac_alphabet: &Alphabet) -> IdempotenceDecision {
        // PRECEDENCE: exact-match to a registered real value always scrubs.
        // (Comparison is straightforward `==`; the registered value's
        // presence in input is the same information the detection layer's
        // Aho-Corasick already discloses, so timing here adds no new leak.)
        for r in self.registered {
            if candidate == r.value.as_str() {
                return IdempotenceDecision::Scrub;
            }
        }

        // (a) FF1 trial-decrypt against registered then retired.
        if self
            .fpe_tokenizer
            .try_restore(candidate, self.registered)
            .is_some()
        {
            return IdempotenceDecision::NoOp(NoOpReason::Ff1DecryptedToRegistered);
        }
        if self
            .fpe_tokenizer
            .try_restore(candidate, self.retired)
            .is_some()
        {
            return IdempotenceDecision::NoOp(NoOpReason::Ff1DecryptedToRetired);
        }

        // (b) Reserved-range membership.
        if is_in_reserved_range(candidate) {
            return IdempotenceDecision::NoOp(NoOpReason::ReservedRange);
        }

        // (c) MAC tail verification.
        if mac::verify(self.session_mac_key, candidate, mac_alphabet) {
            return IdempotenceDecision::NoOp(NoOpReason::MacVerified);
        }

        IdempotenceDecision::Scrub
    }
}

/// True iff `candidate` lies in any reserved/test range the engine emits
/// fakes into. Liberal - accepts the wider RFC 2606 / RFC 5737 ranges
/// even though current generators emit only one subset of each, so a
/// future generator change doesn't break idempotence for old emissions.
fn is_in_reserved_range(candidate: &str) -> bool {
    is_email_example_domain(candidate)
        || is_ipv4_rfc5737(candidate)
        || is_phone_555_01(candidate)
        || is_card_test_bin_4242(candidate)
}

fn is_email_example_domain(candidate: &str) -> bool {
    // RFC 2606 reserved: example.com / .org / .net. The check is on the
    // suffix because the local part is the seed-derived random portion.
    [".com", ".org", ".net"]
        .iter()
        .any(|tld| candidate.ends_with(&format!("@example{tld}")))
}

fn is_ipv4_rfc5737(candidate: &str) -> bool {
    // TEST-NET-1, TEST-NET-2, TEST-NET-3. Last-octet validity is checked
    // because "192.0.2.999" lies in the reserved /24 by prefix but isn't
    // a valid IPv4 address - still, accepting prefix-only is the right
    // call here: we'd rather treat a malformed near-fake as already-fake
    // than risk double-encryption.
    ["192.0.2.", "198.51.100.", "203.0.113."]
        .iter()
        .any(|p| candidate.starts_with(p))
}

fn is_phone_555_01(candidate: &str) -> bool {
    // The current generator emits an 8-char "555-01XX" form. The check
    // is tight to that shape; broader phone layouts (with area codes)
    // can be added when the generator does.
    candidate.len() == 8
        && candidate.starts_with("555-01")
        && candidate.as_bytes()[6..8]
            .iter()
            .all(|b| b.is_ascii_digit())
}

fn is_card_test_bin_4242(candidate: &str) -> bool {
    // 16 digits, all ASCII, starting with 4242, with optional separators
    // (spaces or hyphens) preserved from the original. The Luhn check
    // is not strictly required here - by 4242-BIN membership the
    // candidate is already known to be in the test space; we accept
    // any 16-digit-with-prefix candidate to be liberal about future
    // separator layouts.
    let digits: Vec<char> = candidate.chars().filter(|c| c.is_ascii_digit()).collect();
    digits.len() == 16 && digits.starts_with(&['4', '2', '4', '2'])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokenizer::fpe::InMemoryKeyProvider;
    use zeroize::Zeroizing;

    fn provider() -> InMemoryKeyProvider {
        InMemoryKeyProvider::new(vec![0xa5u8; 32])
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

    fn ctx<'a>(
        registered: &'a [FpeRegistration],
        retired: &'a [FpeRegistration],
        tokenizer: &'a FpeTokenizer,
    ) -> IdempotenceContext<'a> {
        IdempotenceContext {
            registered,
            retired,
            fpe_tokenizer: tokenizer,
            session_mac_key: b"test-session-mac-key-not-secret",
        }
    }

    // ----- Precedence -----

    #[test]
    fn exact_match_to_registered_real_value_scrubs() {
        let t = FpeTokenizer::new(&provider());
        let registered = [reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [0u8; 16],
        )];
        let c = ctx(&registered, &[], &t);
        assert_eq!(
            c.classify("sk-ant-abcdefghijklmnopqrst", &Alphabet::BASE62),
            IdempotenceDecision::Scrub
        );
    }

    #[test]
    fn exact_match_overrides_reserved_range_check() {
        // A registered real value that happens to also look like a
        // reserved-range fake (ends in @example.com). Exact-match
        // precedence still scrubs.
        let t = FpeTokenizer::new(&provider());
        let registered = [reg(
            "alice-long-name@example.com",
            "alice-long-name",
            Alphabet::BASE62, // unused for this test
            [0u8; 16],
        )];
        let c = ctx(&registered, &[], &t);
        let candidate = "alice-long-name@example.com";
        // Sanity: candidate would otherwise match the reserved-range check.
        assert!(is_in_reserved_range(candidate));
        // But exact-match wins.
        assert_eq!(
            c.classify(candidate, &Alphabet::BASE62),
            IdempotenceDecision::Scrub
        );
    }

    // ----- (a) FF1 trial-decrypt -----

    #[test]
    fn ff1_fake_of_registered_value_classifies_as_noop_registered() {
        let t = FpeTokenizer::new(&provider());
        let r = reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [0x11u8; 16],
        );
        let registered = [reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [0x11u8; 16],
        )];
        let c = ctx(&registered, &[], &t);
        let fake = t.scrub(&r).unwrap();
        assert_eq!(
            c.classify(&fake, &Alphabet::BASE62),
            IdempotenceDecision::NoOp(NoOpReason::Ff1DecryptedToRegistered)
        );
    }

    #[test]
    fn ff1_fake_of_retired_value_classifies_as_noop_retired() {
        let t = FpeTokenizer::new(&provider());
        let r = reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [0x22u8; 16],
        );
        let retired = [reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [0x22u8; 16],
        )];
        let c = ctx(&[], &retired, &t);
        let fake = t.scrub(&r).unwrap();
        assert_eq!(
            c.classify(&fake, &Alphabet::BASE62),
            IdempotenceDecision::NoOp(NoOpReason::Ff1DecryptedToRetired)
        );
    }

    // ----- (b) Reserved-range membership -----

    #[test]
    fn email_in_example_com_classifies_as_noop_reserved_range() {
        let t = FpeTokenizer::new(&provider());
        let c = ctx(&[], &[], &t);
        assert_eq!(
            c.classify("abcdefghij@example.com", &Alphabet::ALPHA_LOWER),
            IdempotenceDecision::NoOp(NoOpReason::ReservedRange)
        );
    }

    #[test]
    fn email_in_example_org_or_net_also_recognised() {
        let t = FpeTokenizer::new(&provider());
        let c = ctx(&[], &[], &t);
        assert_eq!(
            c.classify("xyz@example.org", &Alphabet::ALPHA_LOWER),
            IdempotenceDecision::NoOp(NoOpReason::ReservedRange)
        );
        assert_eq!(
            c.classify("xyz@example.net", &Alphabet::ALPHA_LOWER),
            IdempotenceDecision::NoOp(NoOpReason::ReservedRange)
        );
    }

    #[test]
    fn ipv4_in_testnet_classifies_as_noop_reserved_range() {
        let t = FpeTokenizer::new(&provider());
        let c = ctx(&[], &[], &t);
        for addr in ["192.0.2.42", "198.51.100.7", "203.0.113.255"] {
            assert_eq!(
                c.classify(addr, &Alphabet::DIGITS),
                IdempotenceDecision::NoOp(NoOpReason::ReservedRange),
                "addr {addr}"
            );
        }
    }

    #[test]
    fn phone_555_01_classifies_as_noop_reserved_range() {
        let t = FpeTokenizer::new(&provider());
        let c = ctx(&[], &[], &t);
        assert_eq!(
            c.classify("555-0123", &Alphabet::DIGITS),
            IdempotenceDecision::NoOp(NoOpReason::ReservedRange)
        );
        assert_eq!(
            c.classify("555-0199", &Alphabet::DIGITS),
            IdempotenceDecision::NoOp(NoOpReason::ReservedRange)
        );
    }

    #[test]
    fn card_test_bin_4242_classifies_as_noop_reserved_range() {
        let t = FpeTokenizer::new(&provider());
        let c = ctx(&[], &[], &t);
        for card in [
            "4242424242424242",
            "4242 4242 4242 4242",
            "4242-4242-4242-4242",
        ] {
            assert_eq!(
                c.classify(card, &Alphabet::DIGITS),
                IdempotenceDecision::NoOp(NoOpReason::ReservedRange),
                "card {card}"
            );
        }
    }

    // ----- (c) MAC verification -----

    #[test]
    fn mac_tagged_fake_classifies_as_noop_mac_verified() {
        let t = FpeTokenizer::new(&provider());
        let c = ctx(&[], &[], &t);
        let body = "some-pattern-detected-body";
        let tail = mac::mac_tail(c.session_mac_key, body.as_bytes(), &Alphabet::BASE62);
        let fake = format!("{body}{tail}");
        assert_eq!(
            c.classify(&fake, &Alphabet::BASE62),
            IdempotenceDecision::NoOp(NoOpReason::MacVerified)
        );
    }

    // ----- Default Scrub path -----

    #[test]
    fn random_candidate_with_no_match_classifies_as_scrub() {
        let t = FpeTokenizer::new(&provider());
        let c = ctx(&[], &[], &t);
        assert_eq!(
            c.classify("totally-random-non-matching-12345", &Alphabet::BASE62),
            IdempotenceDecision::Scrub
        );
    }

    #[test]
    fn short_fake_carve_out_falls_through_to_scrub() {
        // Documented carve-out: a candidate too short to carry a MAC tail
        // cannot self-authenticate. In two-command terminal mode it
        // therefore re-scrubs, which is the intended behaviour the
        // user is warned about at scrub time.
        let t = FpeTokenizer::new(&provider());
        let c = ctx(&[], &[], &t);
        // BASE62 K = 6. A 3-char string is too short to carry a tail.
        assert_eq!(
            c.classify("abc", &Alphabet::BASE62),
            IdempotenceDecision::Scrub
        );
    }

    // ----- Property: scrub(scrub(x)) == scrub(x) for the FF1 class -----

    #[test]
    fn scrub_then_scrub_is_idempotent_for_ff1_fakes() {
        // The classical idempotence property at the per-candidate level:
        // once we've produced a fake, a second pass leaves it alone.
        let t = FpeTokenizer::new(&provider());
        let inputs = [
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-zzzzzzzzzzzzzzzzzzzz",
            "sk-ant-0123456789abcdefghij",
        ];
        for input in inputs {
            let r = reg(input, "sk-ant-", Alphabet::BASE62, [0x33u8; 16]);
            let registered = [reg(input, "sk-ant-", Alphabet::BASE62, [0x33u8; 16])];
            let c = ctx(&registered, &[], &t);
            let fake = t.scrub(&r).unwrap();
            let decision = c.classify(&fake, &Alphabet::BASE62);
            assert_eq!(
                decision,
                IdempotenceDecision::NoOp(NoOpReason::Ff1DecryptedToRegistered),
                "scrub(scrub({input})) was not idempotent, got {decision:?}"
            );
        }
    }
}
