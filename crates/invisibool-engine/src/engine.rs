//! Top-level engine API: detection + idempotence + tokenizers wired
//! into `Engine::scrub` and `Engine::restore`.
//!
//! ## Scope
//!
//! Scrub is end-to-end for every registered-value variant:
//!
//! - **FF1-eligible** registered values go through `FpeTokenizer` —
//!   round-trip restore works in any process that loads the same vault.
//! - **PII** (Email / IPv4 / Phone) goes through the reserved-range
//!   generators (`example.com`, RFC 5737, the 555-01XX phone exchange)
//!   — output is restorable in long-lived processes via the session
//!   map, but *not* in two-command terminal mode.
//! - **Cards** go through `fake_card_visa16` — same restorability story.
//! - **Formatless** values get a MAC-tagged fake of matching length —
//!   `mac::make_macfake` derives a deterministic body from
//!   `HKDF(session_mac_key, real)` and appends a `K`-character MAC
//!   tail so the idempotence layer can recognise the fake on re-scrub.
//!   Short-fake carve-out: if the registered value is too short to
//!   carry a MAC tail (`len <= K`), the engine FAILS CLOSED — the
//!   original is removed and replaced with `REDACTION_PLACEHOLDER`
//!   and a `RedactedFormatless` notice is recorded.
//!
//! ## Fail-closed contract
//!
//! Every code path that cannot produce a valid fake replaces the
//! original with `REDACTION_PLACEHOLDER` and emits a `Redacted*` notice
//! — no path ever leaves a real, unscrubbed secret in the returned
//! output. The three branches that fail closed today are:
//!
//! 1. FF1 scrub returns an error (a vault inconsistency between
//!    registration-time eligibility and scrub-time eligibility).
//! 2. `fake_card_visa16` returns None (a registered card whose layout
//!    isn't the 16-digit Visa shape the M0b generator understands).
//! 3. `Formatless` variant — covered above.
//!
//! Restore is **FF1-only at this layer**. Reserved-range and MAC-tagged
//! fakes ship through restore unchanged — the idempotence checks
//! recognise them as "already fake" so they pass through cleanly, and
//! the M1 CLI's `--session` path will add the session-map restore on
//! top.
//!
//! ## Modes
//!
//! M0b ships the stateless-FF1 mode. A long-lived "session" mode that
//! holds a `SessionMap` for restorability of non-FF1 types is the next
//! integration layer — the session-map type is implemented inside the
//! engine already; M1's `watch` daemon and the CLI's `--session` flag
//! wire it into a live restore path.

use std::time::Instant;

use crate::detection::{ExactMatcher, MatchKind};
use crate::idempotence::{IdempotenceContext, IdempotenceDecision};
use crate::tokenizer::alphabet::Alphabet;
use crate::tokenizer::fpe::{
    FpeRegistration, FpeTokenizer, KeyProvider, PiiKind, RegisteredValue, SessionFakeKind,
    SessionRegistration,
};
use crate::tokenizer::mac;
use crate::tokenizer::reserved::{fake_card_visa16, fake_email, fake_ipv4, fake_phone};
use crate::tokenizer::session::SessionMap;

/// The engine. Owns the registered vault snapshot, the FF1 tokenizer,
/// and a precompiled exact-match automaton.
pub struct Engine {
    fpe: FpeTokenizer,
    fpe_registered: Vec<FpeRegistration>,
    session_registered: Vec<SessionRegistration>,
    retired: Vec<FpeRegistration>,
    exact_matcher: ExactMatcher,
    session_mac_key: Vec<u8>,
    /// For each value_id reported by the exact-matcher, where to look
    /// up the corresponding registration.
    value_id_to_ref: Vec<RegistrationRef>,
}

/// Engine-internal mapping from exact-matcher `value_id` to the
/// registration in one of the two homogeneous vecs.
enum RegistrationRef {
    Fpe(usize),
    Session(usize),
}

/// Internal scrub-mode switch: either keep the engine stateless (default,
/// the `Engine::scrub` entry point) or thread a caller-owned session map
/// through so each generated session-mapped fake is stored for in-process
/// restore (the `Engine::scrub_with_session` entry point).
enum SessionStore<'a> {
    None,
    Map {
        session: &'a mut SessionMap,
        now: Instant,
    },
}

impl SessionStore<'_> {
    /// Persist a `(real, fake)` pair if a session map is attached.
    /// Returns true iff the pair was stored.
    fn store(&mut self, real: &str, fake: &str) -> bool {
        match self {
            SessionStore::None => false,
            SessionStore::Map { session, now } => {
                // `get_or_insert` is the simplest stable API on the
                // session map — for a fresh real value it inserts the
                // pair via the closure; for a repeat it returns the
                // existing fake (which equals the one we just generated
                // because all our session-fake generators are
                // deterministic in `real`).
                let fake_owned = fake.to_string();
                let _ = session.get_or_insert(real, *now, || fake_owned);
                true
            }
        }
    }
}

/// Errors building an `Engine`.
#[derive(Debug)]
pub enum BuildError {
    /// The Aho-Corasick automaton could not be built over the registered
    /// values. This effectively means an internal `aho-corasick` failure;
    /// the input itself is validated at registration.
    ExactMatcher(aho_corasick::BuildError),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExactMatcher(e) => write!(f, "could not build exact-match automaton: {e}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Placeholder the engine emits in place of a value it cannot produce
/// a valid fake for. The marker is distinctive (won't collide with
/// real text), ASCII-only (survives every transport), and carries no
/// label content (so the LLM doesn't get even that hint).
///
/// The leak harness MUST treat this marker as a known sentinel — if a
/// future change moves it, the matching assertion must move too.
pub const REDACTION_PLACEHOLDER: &str = "[INVISIBOOL_UNRESTORABLE]";

/// Outcome of `Engine::scrub`. `notices` carries the end-of-scrub
/// disclosure list — the M1 CLI formats this for the user.
///
/// `#[must_use]` so dropping the result without consulting `notices`
/// becomes a compile warning. Callers may still explicitly discard the
/// result with `let _ = engine.scrub(...);`, but that's a deliberate
/// acknowledgement rather than an oversight.
#[must_use]
#[derive(Debug)]
pub struct EngineScrubResult {
    pub output: String,
    pub scrubbed_count: usize,
    pub notices: Vec<ScrubNotice>,
}

/// Outcome of `Engine::restore`. `#[must_use]` for the same reason as
/// `EngineScrubResult`.
#[must_use]
#[derive(Debug)]
pub struct EngineRestoreResult {
    pub output: String,
    pub restored_count: usize,
}

/// Reasons the engine has something to tell the user after a scrub.
///
/// The engine fails CLOSED on every branch where it cannot produce a
/// valid fake: the original value is removed from the output and the
/// `REDACTION_PLACEHOLDER` is inserted in its place. The `Redacted*`
/// variants below tell the M1 CLI which path was taken so the end-of-
/// scrub disclosure can distinguish "this won't restore stateless"
/// from "this was removed but cannot be put back at all".
#[derive(Debug)]
pub enum ScrubNotice {
    /// A SessionMapped registration was scrubbed into a fake (not
    /// redacted) but its fake cannot be restored in stateless-FF1 mode.
    /// The user gets this in the end-of-scrub notice so they know the
    /// consequence of pasting and running `restore` without a
    /// `--session` file.
    SessionMappedUnrestorable {
        label: String,
        kind: SessionFakeKind,
    },
    /// A Formatless variant arrived at the engine. M0b does not yet
    /// have the random+MAC body generator wired here, so the value was
    /// removed and replaced with `REDACTION_PLACEHOLDER`. The M1 CLI
    /// integration will produce a real fake; this variant will then
    /// disappear or its meaning will tighten.
    RedactedFormatless { label: String },
    /// The engine attempted to produce a fake and the underlying
    /// generator returned an error (FF1 eligibility re-check failed at
    /// scrub time, a session-mapped generator returned None on a
    /// non-Formatless kind, etc.). The value was removed and replaced
    /// with `REDACTION_PLACEHOLDER`. This is an internal-consistency
    /// failure that the user or admin should investigate (a corrupt
    /// vault entry, a registered card with non-16-digit layout, ...).
    RedactedInternalFailure { label: String, reason: &'static str },
}

impl Engine {
    /// Build the engine over a snapshot of the vault. Ownership of the
    /// registration lists moves into the engine.
    ///
    /// `session_mac_key` is the HMAC key the idempotence layer hands to
    /// the MAC primitives when verifying whether a candidate is one of
    /// our own self-authenticating session fakes. M1 will derive it
    /// from the vault key per session.
    pub fn new<K: KeyProvider>(
        key_provider: &K,
        registered: Vec<RegisteredValue>,
        retired: Vec<FpeRegistration>,
        session_mac_key: Vec<u8>,
    ) -> Result<Self, BuildError> {
        let mut fpe_registered: Vec<FpeRegistration> = Vec::new();
        let mut session_registered: Vec<SessionRegistration> = Vec::new();
        let mut value_id_to_ref: Vec<RegistrationRef> = Vec::new();
        let mut values_for_matcher: Vec<String> = Vec::new();

        for r in registered {
            match r {
                RegisteredValue::Fpe(f) => {
                    values_for_matcher.push((*f.value).clone());
                    value_id_to_ref.push(RegistrationRef::Fpe(fpe_registered.len()));
                    fpe_registered.push(f);
                }
                RegisteredValue::SessionMapped(s) => {
                    values_for_matcher.push((*s.value).clone());
                    value_id_to_ref.push(RegistrationRef::Session(session_registered.len()));
                    session_registered.push(s);
                }
            }
        }

        let exact_matcher =
            ExactMatcher::build(values_for_matcher).map_err(BuildError::ExactMatcher)?;

        Ok(Self {
            fpe: FpeTokenizer::new(key_provider),
            fpe_registered,
            session_registered,
            retired,
            exact_matcher,
            session_mac_key,
            value_id_to_ref,
        })
    }

    /// Scrub the input. Walks the exact-match hits left to right,
    /// runs idempotence on each, and dispatches by registration kind.
    ///
    /// Stateless mode: session-mapped fakes (PII, Card, Formatless) are
    /// emitted with a `SessionMappedUnrestorable` notice — the user is
    /// told the fake cannot be restored without a long-lived session.
    /// For an in-process session-mapped round-trip, use
    /// [`Engine::scrub_with_session`] instead.
    pub fn scrub(&self, input: &str) -> EngineScrubResult {
        self.scrub_impl(input, SessionStore::None)
    }

    /// Scrub the input AND store each session-mapped `(real, fake)`
    /// pair in `session` so a later [`Engine::restore_with_session`]
    /// call can recover the original. In this mode the
    /// `SessionMappedUnrestorable` notice is suppressed — the fake IS
    /// restorable in-process through `session`.
    ///
    /// `now` is the timestamp handed to the session map's LRU/TTL
    /// bookkeeping. Production callers pass `Instant::now()`; tests
    /// construct successive `Instant`s by adding `Duration`s to a base.
    pub fn scrub_with_session(
        &self,
        input: &str,
        session: &mut SessionMap,
        now: Instant,
    ) -> EngineScrubResult {
        self.scrub_impl(input, SessionStore::Map { session, now })
    }

    fn scrub_impl(&self, input: &str, mut store: SessionStore<'_>) -> EngineScrubResult {
        let mut output = String::with_capacity(input.len());
        let mut notices: Vec<ScrubNotice> = Vec::new();
        let mut scrubbed_count = 0;

        let idem_ctx = IdempotenceContext {
            registered: &self.fpe_registered,
            retired: &self.retired,
            fpe_tokenizer: &self.fpe,
            session_mac_key: &self.session_mac_key,
        };

        let matches = self.exact_matcher.scan(input);
        let mut cursor = 0;
        for m in matches {
            // Emit untouched bytes before this match.
            output.push_str(&input[cursor..m.start]);
            cursor = m.end;
            let candidate = &input[m.start..m.end];

            // The exact-matcher only emits Exact variants.
            let MatchKind::Exact { value_id } = m.kind else {
                output.push_str(candidate);
                continue;
            };

            match &self.value_id_to_ref[value_id] {
                RegistrationRef::Fpe(idx) => {
                    let fpe_reg = &self.fpe_registered[*idx];
                    let decision = idem_ctx.classify(candidate, &fpe_reg.alphabet);
                    if matches!(decision, IdempotenceDecision::NoOp(_)) {
                        // Already a fake; leave it alone.
                        output.push_str(candidate);
                        continue;
                    }
                    match self.fpe.scrub(fpe_reg) {
                        Ok(fake) => {
                            output.push_str(&fake);
                            scrubbed_count += 1;
                        }
                        Err(_) => {
                            // Fail CLOSED: never leak the real value.
                            // Reaching this branch means eligibility
                            // passed at registration but failed at scrub
                            // — a vault inconsistency that must not be
                            // papered over by passing the secret through.
                            output.push_str(REDACTION_PLACEHOLDER);
                            scrubbed_count += 1;
                            notices.push(ScrubNotice::RedactedInternalFailure {
                                label: fpe_reg.label.clone(),
                                reason: "FF1 scrub failed at runtime; \
                                         eligibility was supposed to be \
                                         validated at registration",
                            });
                        }
                    }
                }
                RegistrationRef::Session(idx) => {
                    let session_reg = &self.session_registered[*idx];
                    let fake = match session_reg.kind {
                        SessionFakeKind::Pii(PiiKind::Email) => {
                            Some(fake_email(session_reg.value.as_bytes()))
                        }
                        SessionFakeKind::Pii(PiiKind::Ipv4) => {
                            Some(fake_ipv4(session_reg.value.as_bytes()))
                        }
                        SessionFakeKind::Pii(PiiKind::Phone) => {
                            Some(fake_phone(session_reg.value.as_bytes()))
                        }
                        SessionFakeKind::Card => fake_card_visa16(
                            session_reg.value.as_bytes(),
                            session_reg.value.as_str(),
                        ),
                        SessionFakeKind::Formatless => mac::make_macfake(
                            &self.session_mac_key,
                            session_reg.value.as_str(),
                            &Alphabet::BASE62,
                        ),
                    };
                    match (fake, session_reg.kind) {
                        (Some(fake), _) => {
                            output.push_str(&fake);
                            scrubbed_count += 1;
                            let stored = store.store(session_reg.value.as_str(), &fake);
                            if !stored {
                                // Stateless mode: the user must know
                                // this fake will not restore without a
                                // session.
                                notices.push(ScrubNotice::SessionMappedUnrestorable {
                                    label: session_reg.label.clone(),
                                    kind: session_reg.kind,
                                });
                            }
                        }
                        (None, SessionFakeKind::Formatless) => {
                            // Fail CLOSED on the short-fake carve-out:
                            // a Formatless value of length <= K cannot
                            // carry a MAC tail, so `make_macfake` returned
                            // None. Redact rather than emit a fake the
                            // idempotence layer cannot recognise.
                            output.push_str(REDACTION_PLACEHOLDER);
                            scrubbed_count += 1;
                            notices.push(ScrubNotice::RedactedFormatless {
                                label: session_reg.label.clone(),
                            });
                        }
                        (None, _) => {
                            // Fail CLOSED: a non-Formatless generator
                            // returned None — e.g. a registered card
                            // whose layout isn't the 16-digit Visa shape
                            // `fake_card_visa16` currently understands.
                            output.push_str(REDACTION_PLACEHOLDER);
                            scrubbed_count += 1;
                            notices.push(ScrubNotice::RedactedInternalFailure {
                                label: session_reg.label.clone(),
                                reason: "session-mapped fake generator \
                                         returned None (likely a format \
                                         mismatch in the registered value)",
                            });
                        }
                    }
                }
            }
        }
        output.push_str(&input[cursor..]);
        EngineScrubResult {
            output,
            scrubbed_count,
            notices,
        }
    }

    /// Restore FF1 fakes in `input` back to their registered plaintexts.
    /// Non-FF1 fakes (reserved-range, MAC-tagged) pass through
    /// unchanged — that's the stateless-mode behaviour, and idempotence
    /// confirms they're recognisable as fakes (not real secrets) so
    /// they're safe to leave in.
    pub fn restore(&self, input: &str) -> EngineRestoreResult {
        // Collect candidate spans matching each FpeRegistration's
        // profile (prefix + body_length + alphabet). Then walk them
        // left-to-right and call try_restore on each.
        let mut candidates: Vec<(usize, usize)> = Vec::new();

        for reg in &self.fpe_registered {
            // All FF1 values are ASCII-only after eligibility, so byte
            // lengths equal char counts.
            let total_len = reg.value.len();
            if total_len <= reg.prefix.len() {
                continue;
            }
            let body_len = total_len - reg.prefix.len();

            let mut search_start = 0;
            while let Some(pos) = input[search_start..].find(reg.prefix.as_str()) {
                let start = search_start + pos;
                let end = start + total_len;
                if end > input.len() {
                    break;
                }
                let body = &input[start + reg.prefix.len()..end];
                if body.len() == body_len && body.chars().all(|c| reg.alphabet.contains(c)) {
                    candidates.push((start, end));
                }
                search_start = start + 1;
            }
        }

        // Resolve overlaps: leftmost wins, then deduplicate.
        candidates.sort_unstable();
        candidates.dedup();

        let mut output = String::with_capacity(input.len());
        let mut cursor = 0;
        let mut restored_count = 0;
        for (start, end) in candidates {
            if start < cursor {
                // overlaps a span we already emitted; skip
                continue;
            }
            output.push_str(&input[cursor..start]);
            let candidate = &input[start..end];
            match self.fpe.try_restore(candidate, &self.fpe_registered) {
                Some(restored) => {
                    output.push_str(restored.as_str());
                    restored_count += 1;
                }
                None => output.push_str(candidate),
            }
            cursor = end;
        }
        output.push_str(&input[cursor..]);

        EngineRestoreResult {
            output,
            restored_count,
        }
    }

    /// Restore in session-mapped mode: first replace every session-stored
    /// fake with its registered real value, then run the stateless FF1
    /// restore pass over the result. Each session lookup touches the
    /// entry's `last_touched` timestamp so frequently-restored pairs
    /// keep their LRU/TTL standing.
    ///
    /// `now` is the timestamp handed to the session map's LRU/TTL
    /// bookkeeping (see `scrub_with_session`'s contract).
    ///
    /// The two passes compose cleanly because the FF1 fake space and the
    /// session-stored fake space do not overlap: an FF1 fake matches a
    /// known prefix + alphabet + length profile, and session-stored
    /// fakes never sit inside an FF1 registration's profile by
    /// construction.
    pub fn restore_with_session(
        &self,
        input: &str,
        session: &mut SessionMap,
        now: Instant,
    ) -> EngineRestoreResult {
        // First pass: session-map restoration. Collect candidates that
        // appear in the input before mutating the map so we don't hold
        // an iterator borrow while calling `restore`.
        let candidate_fakes: Vec<String> = session
            .entries()
            .filter_map(|(fake, _real)| {
                if input.contains(fake) {
                    Some(fake.to_string())
                } else {
                    None
                }
            })
            .collect();

        let mut working = input.to_string();
        let mut session_restored: usize = 0;
        for fake in candidate_fakes {
            if let Some(real) = session.restore(&fake, now) {
                let count = working.matches(&fake).count();
                if count > 0 {
                    working = working.replace(&fake, &real);
                    session_restored += count;
                }
            }
        }

        // Second pass: FF1 restoration over the working text.
        let ff1 = self.restore(&working);
        EngineRestoreResult {
            output: ff1.output,
            restored_count: session_restored + ff1.restored_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokenizer::alphabet::Alphabet;
    use crate::tokenizer::fpe::InMemoryKeyProvider;
    use zeroize::Zeroizing;

    fn provider() -> InMemoryKeyProvider {
        InMemoryKeyProvider::new(vec![0xa5u8; 32])
    }

    fn fpe_reg(value: &str, prefix: &str, alphabet: Alphabet, tweak: [u8; 16]) -> FpeRegistration {
        FpeRegistration {
            label: "test".to_string(),
            value: Zeroizing::new(value.to_string()),
            tweak,
            alphabet,
            prefix: prefix.to_string(),
        }
    }

    fn pii_reg(value: &str, kind: PiiKind) -> SessionRegistration {
        SessionRegistration {
            label: "pii".to_string(),
            value: Zeroizing::new(value.to_string()),
            kind: SessionFakeKind::Pii(kind),
        }
    }

    fn card_reg(value: &str) -> SessionRegistration {
        SessionRegistration {
            label: "card".to_string(),
            value: Zeroizing::new(value.to_string()),
            kind: SessionFakeKind::Card,
        }
    }

    // ----- FF1 round-trip -----

    #[test]
    fn ff1_round_trips_in_a_sentence() {
        let r = fpe_reg(
            "sk-ant-abcdefghijklmnopqrst",
            "sk-ant-",
            Alphabet::BASE62,
            [0x11u8; 16],
        );
        let engine = Engine::new(
            &provider(),
            vec![RegisteredValue::Fpe(fpe_reg(
                "sk-ant-abcdefghijklmnopqrst",
                "sk-ant-",
                Alphabet::BASE62,
                [0x11u8; 16],
            ))],
            vec![],
            b"test-mac-key".to_vec(),
        )
        .unwrap();
        let input = "the secret is sk-ant-abcdefghijklmnopqrst, please scrub it";
        let scrubbed = engine.scrub(input);
        assert_eq!(scrubbed.scrubbed_count, 1);
        assert!(!scrubbed.output.contains(r.value.as_str()));
        assert!(scrubbed.output.contains("the secret is "));
        let restored = engine.restore(&scrubbed.output);
        assert_eq!(restored.restored_count, 1);
        assert_eq!(restored.output, input);
    }

    // CAVEAT — also tracked in the threat model:
    //
    // This test asserts the equality scrub(scrub(x)) == scrub(x) at the
    // engine level. In M0b the engine uses ONLY exact-match detection
    // (pattern detection is built but waits for M2's rule corpus). The
    // first scrub replaces the registered real value with an FF1 fake;
    // the second scrub's Aho-Corasick automaton therefore finds nothing
    // in the input and the equality holds trivially — the engine's
    // call to `IdempotenceContext::classify` does not run.
    //
    // The per-candidate idempotence proof — that
    // `classify(fake_of(real)) == NoOp(Ff1DecryptedToRegistered)` —
    // lives in `idempotence.rs::scrub_then_scrub_is_idempotent_for_ff1_fakes`.
    // That is the load-bearing test today.
    //
    // M2 (when pattern detection wires the rule corpus into the engine)
    // MUST add a real engine-level idempotence test that fails if the
    // engine's classify-then-tokenize order is reversed or skipped.
    #[test]
    fn scrub_then_scrub_is_idempotent_on_ff1() {
        let engine = Engine::new(
            &provider(),
            vec![RegisteredValue::Fpe(fpe_reg(
                "sk-ant-abcdefghijklmnopqrst",
                "sk-ant-",
                Alphabet::BASE62,
                [0x22u8; 16],
            ))],
            vec![],
            b"test-mac-key".to_vec(),
        )
        .unwrap();
        let input = "scrub me: sk-ant-abcdefghijklmnopqrst end";
        let s1 = engine.scrub(input);
        let s2 = engine.scrub(&s1.output);
        // Second scrub leaves the FF1 fake alone — idempotence check (a) fires.
        assert_eq!(s1.output, s2.output);
        // And the second scrub reports zero new tokenisations.
        assert_eq!(s2.scrubbed_count, 0);
    }

    #[test]
    fn restore_leaves_non_fpe_input_untouched() {
        let engine = Engine::new(
            &provider(),
            vec![RegisteredValue::Fpe(fpe_reg(
                "sk-ant-abcdefghijklmnopqrst",
                "sk-ant-",
                Alphabet::BASE62,
                [0u8; 16],
            ))],
            vec![],
            b"test-mac-key".to_vec(),
        )
        .unwrap();
        let untouched = "no fakes here, just prose about the weather.";
        let restored = engine.restore(untouched);
        assert_eq!(restored.output, untouched);
        assert_eq!(restored.restored_count, 0);
    }

    // ----- Multiple FF1 registrations -----

    #[test]
    fn multiple_ff1_registrations_each_round_trip() {
        let engine = Engine::new(
            &provider(),
            vec![
                RegisteredValue::Fpe(fpe_reg(
                    "sk-ant-aaaaaaaaaaaaaaaaaaaa",
                    "sk-ant-",
                    Alphabet::BASE62,
                    [1u8; 16],
                )),
                RegisteredValue::Fpe(fpe_reg(
                    "sk-ant-bbbbbbbbbbbbbbbbbbbb",
                    "sk-ant-",
                    Alphabet::BASE62,
                    [2u8; 16],
                )),
            ],
            vec![],
            b"test-mac-key".to_vec(),
        )
        .unwrap();
        let input = "two keys: sk-ant-aaaaaaaaaaaaaaaaaaaa and sk-ant-bbbbbbbbbbbbbbbbbbbb here";
        let scrubbed = engine.scrub(input);
        assert_eq!(scrubbed.scrubbed_count, 2);
        let restored = engine.restore(&scrubbed.output);
        assert_eq!(restored.restored_count, 2);
        assert_eq!(restored.output, input);
    }

    // ----- Session-mapped paths -----

    #[test]
    fn scrubbing_a_registered_email_uses_reserved_range_generator() {
        let engine = Engine::new(
            &provider(),
            vec![RegisteredValue::SessionMapped(pii_reg(
                "alice@example.com",
                PiiKind::Email,
            ))],
            vec![],
            b"test-mac-key".to_vec(),
        )
        .unwrap();
        let input = "contact alice@example.com please";
        let result = engine.scrub(input);
        assert_eq!(result.scrubbed_count, 1);
        // Original is gone.
        assert!(!result.output.contains("alice@example.com"));
        // Fake lands in the reserved domain.
        assert!(result.output.contains("@example.com"));
        // And the user is told this won't restore stateless.
        assert!(result
            .notices
            .iter()
            .any(|n| matches!(n, ScrubNotice::SessionMappedUnrestorable { .. })));
    }

    #[test]
    fn scrubbing_a_registered_card_uses_test_bin_generator() {
        let engine = Engine::new(
            &provider(),
            vec![RegisteredValue::SessionMapped(card_reg(
                "4111 1111 1111 1111",
            ))],
            vec![],
            b"test-mac-key".to_vec(),
        )
        .unwrap();
        let input = "card is 4111 1111 1111 1111 for the order";
        let result = engine.scrub(input);
        assert_eq!(result.scrubbed_count, 1);
        // Original is gone.
        assert!(!result.output.contains("4111 1111 1111 1111"));
        // Fake starts with 4242 (test BIN) and preserves separators.
        assert!(result.output.contains("4242 "));
    }

    #[test]
    fn formatless_short_body_carveout_redacts() {
        // Short-fake carve-out: a Formatless value of length <= K
        // (K = 6 for BASE62) cannot carry a MAC tail, so `make_macfake`
        // returns None and the engine fails closed with the redaction
        // placeholder + RedactedFormatless notice.
        let engine = Engine::new(
            &provider(),
            vec![RegisteredValue::SessionMapped(SessionRegistration {
                label: "pin".to_string(),
                value: Zeroizing::new("ABCD".to_string()),
                kind: SessionFakeKind::Formatless,
            })],
            vec![],
            b"test-mac-key".to_vec(),
        )
        .unwrap();
        let input = "my pin is ABCD";
        let result = engine.scrub(input);
        // Original is REMOVED from the output — not papered over by a
        // notice that the user might miss.
        assert!(
            !result.output.contains("ABCD"),
            "real value leaked into output: {}",
            result.output
        );
        // Placeholder is in its place.
        assert!(result.output.contains(REDACTION_PLACEHOLDER));
        assert_eq!(result.scrubbed_count, 1);
        assert!(
            result
                .notices
                .iter()
                .any(|n| matches!(n, ScrubNotice::RedactedFormatless { .. })),
            "expected RedactedFormatless notice, got {:?}",
            result.notices
        );
    }

    #[test]
    fn formatless_long_body_emits_mac_fake() {
        // Long-body Formatless: the engine produces a MAC-tagged fake
        // of matching length, the original is gone, and the fake
        // round-trips through `mac::verify` so the idempotence layer
        // would recognise it on re-scrub. The user is told this fake
        // is unrestorable in stateless mode via SessionMappedUnrestorable.
        let real = "thisIsALongerFormatlessValue1234567890";
        let mac_key = b"test-mac-key".to_vec();
        let engine = Engine::new(
            &provider(),
            vec![RegisteredValue::SessionMapped(SessionRegistration {
                label: "passphrase".to_string(),
                value: Zeroizing::new(real.to_string()),
                kind: SessionFakeKind::Formatless,
            })],
            vec![],
            mac_key.clone(),
        )
        .unwrap();
        let input = format!("the passphrase is {real} please scrub");
        let result = engine.scrub(&input);
        assert_eq!(result.scrubbed_count, 1);
        assert!(
            !result.output.contains(real),
            "Formatless real value leaked into output: {}",
            result.output
        );
        assert!(
            !result.output.contains(REDACTION_PLACEHOLDER),
            "long Formatless emitted the placeholder instead of a MAC-fake",
        );
        // The emitted fake must verify under the same MAC key, proving
        // the idempotence layer will recognise it on re-scrub.
        let prefix = "the passphrase is ";
        let after_prefix = result
            .output
            .strip_prefix(prefix)
            .expect("scrub output keeps the surrounding prose");
        let fake = &after_prefix[..real.len()];
        assert_eq!(fake.len(), real.len(), "fake length must match real length");
        assert!(
            crate::tokenizer::mac::verify(&mac_key, fake, &Alphabet::BASE62),
            "emitted Formatless fake does not verify under the session MAC key",
        );
        // The stateless-mode notice fires so the user knows this fake
        // won't restore without a session map.
        assert!(
            result.notices.iter().any(|n| matches!(
                n,
                ScrubNotice::SessionMappedUnrestorable {
                    kind: SessionFakeKind::Formatless,
                    ..
                }
            )),
            "expected SessionMappedUnrestorable(Formatless) notice, got {:?}",
            result.notices,
        );
    }

    #[test]
    fn ff1_scrub_error_redacts_rather_than_leaks() {
        // Construct a registration that passes exact-matcher build
        // (it's a valid string) but fails FF1 eligibility at scrub
        // time: prefix == value means the body is empty, so radix^0 = 1
        // falls below the 10^6 domain floor.
        //
        // This shouldn't happen in practice — M4a `register` would
        // refuse — but the engine must fail CLOSED if a corrupt or
        // mis-migrated vault entry slips through.
        let bad = FpeRegistration {
            label: "broken".to_string(),
            value: Zeroizing::new("ab".to_string()),
            tweak: [0u8; 16],
            alphabet: Alphabet::BASE62,
            prefix: "ab".to_string(),
        };
        let engine = Engine::new(
            &provider(),
            vec![RegisteredValue::Fpe(bad)],
            vec![],
            b"test-mac-key".to_vec(),
        )
        .unwrap();
        let input = "the token is ab here";
        let result = engine.scrub(input);
        // The literal "ab" must not survive in the output.
        assert!(
            !result.output.contains(" ab "),
            "real value leaked into output: {}",
            result.output
        );
        assert!(result.output.contains(REDACTION_PLACEHOLDER));
        assert!(
            result
                .notices
                .iter()
                .any(|n| matches!(n, ScrubNotice::RedactedInternalFailure { .. })),
            "expected RedactedInternalFailure notice, got {:?}",
            result.notices
        );
    }

    #[test]
    fn card_layout_mismatch_redacts_rather_than_leaks() {
        // Register an Amex-shaped 15-digit card. The engine's
        // `fake_card_visa16` recognises only the 16-digit Visa shape
        // and returns None on this input. Fail CLOSED.
        let amex = "3782 822463 10005";
        let engine = Engine::new(
            &provider(),
            vec![RegisteredValue::SessionMapped(card_reg(amex))],
            vec![],
            b"test-mac-key".to_vec(),
        )
        .unwrap();
        let input = format!("my card is {amex} please charge it");
        let result = engine.scrub(&input);
        assert!(
            !result.output.contains(amex),
            "real card leaked into output: {}",
            result.output
        );
        assert!(result.output.contains(REDACTION_PLACEHOLDER));
        assert!(
            result
                .notices
                .iter()
                .any(|n| matches!(n, ScrubNotice::RedactedInternalFailure { .. })),
            "expected RedactedInternalFailure notice, got {:?}",
            result.notices
        );
    }

    #[test]
    fn redaction_placeholder_content_is_pinned() {
        // If this marker ever changes silently, downstream tooling that
        // recognises it — the leak-harness sentinel, the M1 CLI's
        // end-of-scrub renderer — would break in subtle ways. Any
        // change must be deliberate and walk every consumer through.
        assert_eq!(REDACTION_PLACEHOLDER, "[INVISIBOOL_UNRESTORABLE]");
    }

    // ----- session-mode round-trip -----

    #[test]
    fn scrub_with_session_then_restore_with_session_round_trips_formatless() {
        use crate::tokenizer::session::SessionMap;
        use std::time::Duration;

        let real = "ProductionPassphrase-not-FF1-eligible-because-contains-some-:special:-chars";
        let engine = Engine::new(
            &provider(),
            vec![RegisteredValue::SessionMapped(SessionRegistration {
                label: "passphrase".to_string(),
                value: Zeroizing::new(real.to_string()),
                kind: SessionFakeKind::Formatless,
            })],
            vec![],
            b"test-mac-key".to_vec(),
        )
        .unwrap();
        let input = format!("the passphrase is {real} please scrub it");

        let mut session = SessionMap::new(64, Duration::from_secs(600));
        let now = std::time::Instant::now();
        let scrubbed = engine.scrub_with_session(&input, &mut session, now);

        // Scrub side: original is gone, no SessionMappedUnrestorable
        // notice (the fake IS restorable in-process through `session`).
        assert_eq!(scrubbed.scrubbed_count, 1);
        assert!(
            !scrubbed.output.contains(real),
            "real value leaked into session-mode scrub output: {}",
            scrubbed.output,
        );
        assert!(
            scrubbed.notices.is_empty(),
            "session-mode scrub emitted notices for a restorable fake: {:?}",
            scrubbed.notices,
        );
        assert_eq!(session.len(), 1, "session map did not record the fake");

        // Restore side: the in-process round-trip recovers the original
        // verbatim from the same session map.
        let restored = engine.restore_with_session(
            &scrubbed.output,
            &mut session,
            now + Duration::from_secs(1),
        );
        assert_eq!(
            restored.output, input,
            "session-mode restore did not round-trip"
        );
        assert_eq!(restored.restored_count, 1);
    }

    #[test]
    fn scrub_with_session_short_formatless_still_redacts() {
        // Short-fake carve-out must survive into session mode: there's
        // no MAC-tagged fake to store, so the engine emits the
        // placeholder and a RedactedFormatless notice fires regardless
        // of whether a session map is attached.
        use crate::tokenizer::session::SessionMap;
        use std::time::Duration;

        let engine = Engine::new(
            &provider(),
            vec![RegisteredValue::SessionMapped(SessionRegistration {
                label: "pin".to_string(),
                value: Zeroizing::new("ABCD".to_string()),
                kind: SessionFakeKind::Formatless,
            })],
            vec![],
            b"test-mac-key".to_vec(),
        )
        .unwrap();
        let mut session = SessionMap::new(64, Duration::from_secs(600));
        let now = std::time::Instant::now();
        let scrubbed = engine.scrub_with_session("my pin is ABCD", &mut session, now);
        assert!(!scrubbed.output.contains("ABCD"));
        assert!(scrubbed.output.contains(REDACTION_PLACEHOLDER));
        assert!(scrubbed
            .notices
            .iter()
            .any(|n| matches!(n, ScrubNotice::RedactedFormatless { .. })));
        assert_eq!(
            session.len(),
            0,
            "carve-out path must not poison the session map"
        );
    }

    // ----- Mixed registrations + multiple occurrences -----

    #[test]
    fn mixed_ff1_and_pii_in_one_input_both_scrub() {
        let engine = Engine::new(
            &provider(),
            vec![
                RegisteredValue::Fpe(fpe_reg(
                    "sk-ant-abcdefghijklmnopqrst",
                    "sk-ant-",
                    Alphabet::BASE62,
                    [0x33u8; 16],
                )),
                RegisteredValue::SessionMapped(pii_reg("bob@example.com", PiiKind::Email)),
            ],
            vec![],
            b"test-mac-key".to_vec(),
        )
        .unwrap();
        let input = "ping bob@example.com about sk-ant-abcdefghijklmnopqrst soon";
        let result = engine.scrub(input);
        assert_eq!(result.scrubbed_count, 2);
        assert!(!result.output.contains("bob@example.com"));
        assert!(!result.output.contains("sk-ant-abcdefghijklmnopqrst"));
    }

    #[test]
    fn repeated_ff1_secret_in_one_input_scrubs_to_same_fake() {
        let engine = Engine::new(
            &provider(),
            vec![RegisteredValue::Fpe(fpe_reg(
                "sk-ant-abcdefghijklmnopqrst",
                "sk-ant-",
                Alphabet::BASE62,
                [0x44u8; 16],
            ))],
            vec![],
            b"test-mac-key".to_vec(),
        )
        .unwrap();
        let input =
            "two copies: sk-ant-abcdefghijklmnopqrst and again sk-ant-abcdefghijklmnopqrst end";
        let result = engine.scrub(input);
        assert_eq!(result.scrubbed_count, 2);
        // Same secret → same fake (FF1 is deterministic given (key, tweak)).
        let fake = engine.fpe.scrub(&engine.fpe_registered[0]).unwrap();
        assert_eq!(result.output.matches(fake.as_str()).count(), 2);
    }

    // ----- Restore over noisy input -----

    #[test]
    fn restore_round_trips_when_input_has_unrelated_words_around_the_fake() {
        let engine = Engine::new(
            &provider(),
            vec![RegisteredValue::Fpe(fpe_reg(
                "sk-ant-abcdefghijklmnopqrst",
                "sk-ant-",
                Alphabet::BASE62,
                [0x55u8; 16],
            ))],
            vec![],
            b"test-mac-key".to_vec(),
        )
        .unwrap();
        let real = "sk-ant-abcdefghijklmnopqrst";
        let input = format!("prefix bytes\nlorem ipsum {real} dolor sit amet\nfollowing bytes");
        let scrubbed = engine.scrub(&input);
        let restored = engine.restore(&scrubbed.output);
        assert_eq!(restored.output, input);
    }
}
