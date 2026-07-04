# Threat model

This document is the honest accounting of what Invisibool's engine
defends against, what it does not, and where the residual risk sits.
It covers the engine library shipped at M0b (detection + tokenization
+ scrub/restore API). Surfaces that don't exist yet - the CLI, the
clipboard `watch` daemon, the vault file, the OS-keychain backend,
the control channel, `forget`/`rotate-key` - are listed at the end as
**deferred rows** so this file grows additively as those milestones
land, rather than being rewritten.

The intended reader is the operator deciding whether to trust this
tool with real secrets. Read every row. If a residual is unacceptable
for your threat model, that is the place to stop using the tool, not
the place where we'll have closed it later.

## What this model does NOT prove

Every test and every CI gate in this repo verifies **behaviour**, not
**cryptographic correctness**. A wrong FF1 round, an AEAD nonce-reuse
bug, or a `zeroize` defeated by a compiler-inserted copy would pass
every demo, every leak-harness round, and every regression bench.
The leak harness catches an unexpected canary in an output channel;
it cannot catch a fake whose ciphertext is malleable in a way that
leaks the underlying plaintext under chosen-input attack.

If you intend to run this against high-value production secrets, get
an independent cryptographic review before doing so. That review has
not happened. The README repeats this statement so a first-time user
hits it before installing.

---

## Live rows (M0b and M1)

### 1. Warm exact-match automaton holds every registered value in process memory

**Threat.** The exact-match detector is one Aho-Corasick automaton built
once at engine construction over the entire registered-value set. While
the engine process is running, every registered plaintext is resident in
the automaton's internal tables. A memory dump of the process - by an
attacker with code execution as the same user, by a crash-dump uploader,
by a debugger attaching to the live process - recovers every registered
secret in clear bytes.

**Mitigation.** The engine itself carries `#![forbid(unsafe_code)]`
and has zero network dependencies, so the plaintext cannot exit
through the engine's own code paths. We do not claim the secrets are
loaded individually or kept encrypted in memory - the warm automaton
makes that impossible by design. M1 will bound the in-memory window:
the automaton will be built only when the vault is loaded and dropped
on idle-lock (planned to AEAD-encrypt the session map and drop the
automaton + key on inactivity). At M0b the engine has no daemon or
idle path, so the automaton lives for the lifetime of whatever
process holds the `Engine` value.

**Residual.** Same-user code execution is fatal to this protection.
For users who prefer not to keep registered values pre-compiled into
memory at all, an opt-out `--no-exact-vault` mode is planned (M4a):
exact-match would fall back to per-input matching at a latency cost,
and the warm vault would never assemble. Until that lands, treat
the engine process as a single piece of secret-holding state.

---

### 2. `HashMap` resize moves leave secret-byte residue

**Threat.** `std::collections::HashMap` grows by copying keys and
values into a new allocation and freeing the old one. The freed slot
is not zeroized - its bytes linger until the allocator overwrites
them. The session map holds real values in two places (the
`Zeroizing<String>` inside each Entry, and a plaintext `String` key
in `by_real`). Both copies are wiped on the eviction paths we
control. A resize-time move bypasses those paths.

**Mitigation.** Construction sizes the maps generously so an
in-process resize is rare under normal operating volume. All explicit
eviction paths (LRU, TTL prune, explicit `clear`, collision
overwrite, `Drop`) wipe both copies of each evicted real value.

**Residual.** The resize-move case is invisible to the SessionMap
layer and cannot be closed without a custom zeroizing hash table.
The OS-keychain holding the vault key at rest and the daemon's
process-isolation boundary will be the real defences against the
threat this residue creates - both arrive at M1. At M0b the engine
holds its MAC key as plain bytes passed in at construction, so the
residue is fully exposed to anyone who can read the engine
process's memory. In-memory wipe is a hardening measure, not a
guarantee, in either case.

---

### 3. `SessionMap::restore()` returns a plaintext clone

**Threat.** The session map's canonical copy of each real value is
`Zeroizing`-wrapped, so it is wiped on eviction. `restore()` hands
the caller a freshly-allocated `String`. Once that clone crosses the
function boundary, the map cannot track its lifetime - if the caller
holds it in a non-wiping container, the plaintext lingers until the
allocator reuses the memory.

**Mitigation.** The original copy inside the map stays wiped on
eviction/drop. The engine-level `restore_with_session` consumes the
clone immediately and emits its bytes into the output string the
caller asked for; it does not retain its own copy.

**Residual.** Caller-side lifetime is on the caller. The M1 CLI's
restore-to-stdout path will be the natural short-lifetime case
(bytes flushed to the terminal, buffer dropped) - that path does not
exist yet at M0b. A future engine API revision may push
`Zeroizing<String>` (or `SecretBox<String>`) one level out so callers
inherit auto-wipe; this is a known follow-up.

---

### 4. FF1 is deterministic - same `(key, tweak, value)` always produces the same fake

**Threat.** Two scrubs of the same registered value, in the same
process or in two different processes loading the same vault, produce
the same fake. An attacker who sees both scrubbed outputs can cluster
"these two prompts referenced the same underlying secret" without
ever recovering the secret itself. Format leakage on top - the fake
preserves length, alphabet, and any literal prefix - narrows the
guess about what kind of secret it was even if the bytes are
unreadable.

**Mitigation.** Determinism is the design: an FF1 fake that varied
each call would not be restorable from a separate process. The
per-value 16-byte tweak prevents cross-value linkability (each
registered secret encrypts under its own pseudorandom permutation
even when alphabets match). Cards never go through FF1 because the
card-number domain is too small for FF1's bijection to be safe
against a guess-and-check attacker - they take the test-BIN path
instead.

**Residual.** Within a single registered value, fake-equality reveals
that two prompts touched the same secret. We accept this as the cost
of stateless cross-process restorability. Format leakage is documented
plainly: the fake exposes the secret's length, alphabet, and prefix,
which can already narrow an attacker's hypothesis about provider /
service.

---

### 5. FF1 fakes are key-recoverable ciphertext, not one-way derivatives

**Threat.** Every FF1 fake is the AES-256-FF1 encryption of the real
value under a subkey derived from the vault key via HKDF-SHA-256
with a versioned info label (`invisibool-ff1-key-v1`) and the
per-value tweak. An attacker who steals the vault key - by
extracting it from the OS
keychain after compromising the user account, by reading it from a
crashed process's memory, by social-engineering the user into running
a malicious binary - can decrypt every FF1 fake the user has ever
emitted. That includes fakes sitting in third-party LLM logs the
user no longer controls.

**Mitigation.** At M1 the vault key will sit behind the OS-keychain
boundary - the same boundary the operating system uses to protect
every other application's stored credentials. At M4a a `rotate-key`
command will generate a fresh vault key, re-encrypt the registered
values under it, and (by default) destroy the old key, after which
every fake produced under the old key becomes unrestorable to
anyone; a `--keep-old-for-restore` flag will retain the old key for
decryption only at a documented exposure cost. The M4c README will
surface this property in plain words so a first-time user reads it
before installing. **None of these surfaces ship at M0b.** The engine
today accepts a vault key as raw bytes from its caller and holds it
in process memory; the caller is responsible for where that key
came from and what wipes it.

**Residual.** Key theft is fatal to past confidentiality of scrubbed
prompts. Realistically, an attacker who can read the OS keychain has
usually already compromised the machine, so the incremental risk is
modest - but it is real, it is retroactive, and it is documented
honestly here rather than hidden behind "we encrypt your secrets"
language that overclaims.

---

### 6. MAC-tagged self-authenticating fakes carry a false-positive cost

**Threat.** The idempotence layer's third check verifies a candidate
by re-computing its keyed MAC. A real secret whose tail bytes
coincidentally equal `HMAC(session_mac_key, body)` would be classified
as "already a fake" and left unscrubbed. Engine paths that also
generate MAC-tagged fakes (the Formatless branch) pay the same
false-positive rate on a re-scrub round.

**Mitigation.** The MAC tail length per alphabet is chosen to meet a
32-bit floor - `K = ceil(32 / log2(radix))`. The actual rate depends
on the alphabet: BASE62 reaches ~2^-35.7, hex sits at exactly 2^-32,
digits at ~2^-33.2. The 32-bit floor is the conservative number to
quote. Registered values bypass this risk entirely via the exact-
match precedence rule in idempotence: an exact match always wins
before any MAC computation runs, so a registered secret cannot be
silently passed through by a MAC coincidence.

**Residual.** A detected-but-unregistered high-entropy secret remains
exposed at the 32-bit-floor false-positive rate. At typical prompt
volumes this is an acceptable rare-event cost. If you registered the
value first, the risk is zero - registration is the recommended way
to protect a value you specifically care about.

---

### 7. Fail-closed redaction is a deliberate property of the engine

**Threat.** Three engine paths cannot produce a valid fake: a
Formatless registration whose value is too short to carry a MAC tail,
an FF1 registration whose eligibility re-check fails at scrub time
(corrupt or migrated vault entry), and a session-mapped card whose
layout the test-BIN generator does not recognise (e.g. a 15-digit
Amex shape). In each, the obvious "easy" fallback would be to leave
the original value in the output and emit a warning notice - which
is exactly the leak class that gets the tool uninstalled the first
time a user pastes their fallback-notice'd prompt into an LLM
unaware.

**Mitigation.** All three paths fail CLOSED: the value is removed
from the output and replaced with `REDACTION_PLACEHOLDER`
(`[INVISIBOOL_UNRESTORABLE]`), and a typed `ScrubNotice` is emitted
so the end-of-scrub disclosure lists exactly which value was lost.
The leak harness specifically exercises each branch with a fresh
runtime canary and asserts the canary is absent from every escape
channel (scrub output, the `Debug` impl of the scrub result, each
notice's `Debug`, the debug-format of the registered set, and the
placeholder bytes themselves). A CI green light on the leak harness
is the property's automated enforcement.

**Residual.** Fail-closed is a hard cost: legitimate Formatless
values too short to carry a MAC tail produce no fake at all. The
user must register a longer value (e.g. a passphrase rather than a
PIN), pre-pad the value to clear `K + 1` characters, or accept that
the value is unscrubbable at this engine version.

---

### 8. Registration prefixes are intentionally NOT redacted in `Debug`

**Threat.** The redacting `Debug` impls on `FpeRegistration` and
`SessionRegistration` print `value: <redacted>` but leave the `prefix`
field visible (e.g. `prefix: "sk-ant-"`, `prefix: "AKIA"`). A reader
of a debug-formatted registration learns which provider the secret
belongs to, even though they cannot recover the secret itself.

**Mitigation.** Prefixes are treated as **format metadata**, not as
secrets. They appear unredacted in the registered value itself
(the prefix is the literal beginning of the value) and in the FF1
restore profile-matching logic (which needs them to identify
candidates). The future M4a `list` command will print masked
previews of the form `sk-ant-…AB12` for the same reason - prefix
visible, body redacted - so this assumption holds across the whole
surface, not only the engine internals. Redacting the prefix in
`Debug` would either render the debug output useless or require a
parallel non-redacted path. The leak harness's debug-format checks
deliberately use a canary whose `prefix` is not the canary itself,
so a prefix-equal-to-canary collision does not mask a real leak.

**Residual.** A debug-format leak that drops `prefix` into a log
file tells a log reader which provider the registered value belongs
to. We accept this on the explicit assumption that registration
prefixes are not secret. If your threat model treats the existence
of a credential of a given type as a secret in its own right
(e.g. "the fact that this user has an Anthropic API key at all is
sensitive"), that assumption fails and the engine is not the right
tool.

---

### 9. Formatless restorability is in-process only at M0b

**Threat.** A registered Formatless value (long enough to carry a
MAC tail) is scrubbed into a MAC-tagged fake, but the mapping from
fake back to real lives only in the in-memory session map. A user
running two-command CLI flow at M0b - `invisibool scrub < input >
scrubbed`, then later `invisibool restore < reply > output` - gets
no restoration of Formatless values across the two process
boundaries. The fake passes through restore untouched, and the
original is gone.

**Mitigation.** The engine emits `ScrubNotice::SessionMappedUnrestorable`
on the stateless scrub path so the user is told plainly at the end
of scrub which values cannot be restored without a session. The
in-process round-trip works today via `scrub_with_session` +
`restore_with_session`, which is the path M1's `watch` daemon will
hold open. M1 will also add an explicit `--session` flag for
two-command terminal users who want the AEAD-encrypted on-disk
session file - that flag does not yet exist.

**Residual.** Until M1 lands, Formatless registrations are useful
only inside long-lived processes (or as a fail-closed scrub-only
path where the user does not care about restoring the original).
The CLI is not yet built and so this row is technically not yet
user-visible, but the constraint is real and load-bearing for M1's
design.

---

### 10. PII fakes are linkable across a session

**Threat.** A registered email/IPv4/phone is scrubbed into a fake
from a reserved range (`@example.com`, the RFC 5737 test-net,
the 555-01XX exchange). Within a single long-lived process the
session map returns the same fake for the same input every call,
so an attacker who sees several scrubbed prompts can cluster which
ones referenced the same original even though they cannot recover
the original. The reserved-range fakes are also distinguishable as
fake to a literate attacker - anyone who knows `@example.com` is
the documentation domain reads a reserved-range fake as "this used
to be a real email".

**Mitigation.** Reserved-range fakes are required because a fake
PII value that collides with a real PII value would silently route
LLM follow-up to the wrong human. The reserved ranges are the
standardised way to emit "obviously not a real entity" PII. The
session map bounds linkability to the live session: LRU eviction at
the configured `max_entries` and TTL pruning at the configured
duration both drop the mapping, after which a re-registration
produces a fresh fake (deterministic in `(key, real)` for our
generators, but the previous fake-real pair is gone).

**Residual.** A long-lived session has no upper bound on observed
linkability for values that stay alive. The reserved-range fake
also makes downstream consumers (security teams reviewing LLM
logs) able to tell "this prompt was Invisibool-scrubbed", which is
either useful transparency or unwanted attribution depending on the
operator.

---

### 11. Format-preserving fakes trip third-party secret scanners

**Threat.** Invisibool's fakes are deliberately indistinguishable in
shape from real secrets - that is the entire point of FPE. A scrubbed
prompt forwarded to an LLM provider, logged in a corporate proxy,
copied into a ticketing system, or pushed to a code repository by a
contributor pasting it as "what I sent the model" will be flagged
by gitleaks, TruffleHog, GitHub secret scanning, and corporate DLP
exactly as if it carried a real secret. Provider-side validators
(e.g. Anthropic's key-format checks) will attempt to verify the fake
and predictably fail, but the alert has already fired.

**Mitigation.** This is inherent to format-preserving substitution
and cannot be closed without either degrading the fake (which
defeats the purpose) or coordinating per-scanner signalling. We
accept it and document it plainly. The user-side mitigation is to
keep Invisibool output inside the LLM-prompt boundary - do not
paste scrubbed text into systems that will be unhappy to see
secret-shaped strings. If you have a security team that reviews
exfiltration alerts, tell them Invisibool is in use so a flagged
prompt does not start an incident response cycle.

**Residual.** Reputation noise toward the user's own security
operations. This is a known cost; the alternative (fakes that
don't trip scanners but also don't preserve format) is a worse
design.

---

### 12. The engine-level idempotence test passes trivially at M0b

**Threat.** A future refactor could reverse the engine's order of
operations from "detect → idempotence-classify → tokenize" to
"detect → tokenize → idempotence-classify", which would silently
double-encrypt an already-faked input on every re-scrub. The engine
test that claims to prove `scrub(scrub(x)) == scrub(x)` at the
engine level is the natural place to catch such a reordering - but
at M0b the engine uses only exact-match detection. After the first
scrub the registered value is replaced by a fake the Aho-Corasick
automaton cannot find, so the second scrub's input contains no
matches; the `IdempotenceContext::classify` call never runs, and
the test passes trivially.

**Mitigation.** The per-candidate idempotence proof - that
`classify(fake_of(real)) == NoOp(Ff1DecryptedToRegistered)` - does
exist and is load-bearing today: it lives in `idempotence.rs`'s
unit tests and runs on every PR. The engine-level test's source
also carries an explicit `// CAVEAT` block flagging this limitation
to the next reader.

**Residual.** When the pattern-rule corpus wires into the engine
(planned for M2), the engine-level test must add an input containing
only FF1 fakes (which a pattern rule will still match) and assert
the output is identical and `scrubbed_count == 0`. Without that
follow-up, a detect→tokenize→classify reordering would silently
break idempotence and cause repeated double-encryption - exactly
the bug the three-check idempotence mechanism was built to prevent.

---

### 13. FF1 trial-decrypt cost is paid in both restore and idempotence

**Threat.** Restore and the FF1-arm of idempotence both work by
trial-decryption: for each candidate matching an `FpeRegistration`'s
profile (prefix + body length + alphabet), the engine FF1-decrypts
the body under each profile-matching registration's tweak and
constant-time-compares the result against the registered value. At
N profile-matching registrations the cost per candidate is N FF1
decryptions plus N constant-time comparisons. Two surfaces pay this
cost: restore (once per restore candidate) and idempotence (once per
scrub candidate to check "already a fake?"). The user is not charged
twice for the same candidate, but the per-call cost is real.

**Mitigation.** The trial-decrypt loop runs only over registrations
matching the candidate's profile, which is in practice a small
subset of the total vault. The constant-time comparison via
`subtle::ConstantTimeEq` ensures the loop does not leak which
registration matched via timing. The Criterion benches measure the
combined scrub cost over a committed corpus on every PR. The
per-call latency **target** (p50 < 1 ms, p99 < 5 ms on a consistent
machine) is the design budget this trial-decrypt loop is built to
fit inside; the published two-number README pair will land at M4c.
At M0b the CI regression tripwire is in bootstrap state - the
committed `bench-baseline.json` carries `pending_first_ci_baseline:
true` and the first real baseline has not been captured on the
pinned runner class yet, so the target above is the design intent,
not a measured-and-validated result.

**Residual.** A vault with thousands of registered values sharing a
single profile would push the trial-decrypt cost outside the
target budget. We accept this - vaults that large are not the
target use case, and a future optimisation (e.g. indexing by
profile fingerprint) is a known follow-up if the use case
materialises.

---

### 14. The vault file: real secrets at rest on the user's disk (M1)

**Threat.** Until M1 the engine held no secrets at rest; the caller
fed it a vault key as raw bytes. At M1 the vault module persists
the registered values on disk under an AEAD encryption scheme.
Three concrete failure modes the design has to defend against:
the file could be tampered with (rolled back, downgraded, or
ciphertext-flipped); a vault written under one key could be
silently decrypted under another (compromising key separation);
and a crash mid-write could leave a corrupted file that locks the
user out of every secret they've ever registered.

**Mitigation.**

- **AEAD: XChaCha20-Poly1305** from the `chacha20poly1305` crate,
  with a fresh 24-byte random nonce per encrypt drawn from the OS
  CSPRNG. Collision probability for `q` writes is `q² / 2¹⁹²`,
  which is negligible at any realistic vault write count; no
  persistent nonce counter is needed, eliminating that whole
  failure mode.
- **AEAD key derivation: HKDF-SHA-256** with `salt = empty`,
  `ikm = vault_key` (the 32-byte secret fetched from the
  keychain), `info = "invisibool-vault-aead-v1"`. The versioned
  info string lets a future `rotate-key` change the derivation
  independently of the vault key. The same `vault_key` is the HKDF
  ikm for the FF1 subkey (separate info string, so the two
  derived keys are independent given the same input).
- **AAD = magic + version + reserved (first 20 bytes).**
  Tampering with any of those bytes makes Poly1305 verification
  fail. **Version-in-AAD specifically defeats downgrade attacks:**
  a future v2 reader cannot accept a v1 file even under the same
  vault key, because the AAD it authenticates against (containing
  version=2) does not match the file's bytes (containing
  version=1).
- **Atomic write: write-temp + fsync + rename + fsync-parent.**
  At any crash point the on-disk state is one of two stable
  states: the OLD vault still intact (the rename hasn't happened)
  or the NEW vault fully durable (the rename and parent-fsync
  succeeded). A half-written file is unreachable by construction.
  The orphan-scan path at `Vault::open` cleans up any leftover
  `<basename>.tmp.*` siblings from a previous crashed write. Test
  16 (`failed_rename_leaves_old_vault_bytes_intact`) pins this
  by sha256-comparing the on-disk bytes before and after a
  fault-injected rename failure.
- **File permissions: `0o600` set at create time on Unix** via
  `OpenOptions::mode`, so no other user on a shared system can
  read the ciphertext (already AEAD-encrypted, but
  defense-in-depth on the filesystem boundary too). On Windows
  the file inherits the parent dir's DACL from the per-user
  `%LOCALAPPDATA%` hierarchy.
- **Vault key acquisition: only via
  `keychain::fetch_or_create`,** never raw fetch-then-store. The
  contract enforced at the keychain trait (a real backend failure
  returns Err, NOT Ok(None) that would trigger a generate-and-
  overwrite) is the trust anchor for the vault key: a locked
  keychain produces a vault-open failure, never a fresh key that
  would orphan the existing vault contents.
- **No hand-rolled crypto.** Every primitive is from RustCrypto:
  `chacha20poly1305` for the AEAD, `hkdf` for the AEAD-key
  derivation, `sha2` for the underlying hash. The vault module
  only composes them.

**Residual.**

- **The plaintext is decrypted in process memory** during the
  open-and-build-engine path. While the engine is running, the
  registered values are heap-resident (covered by row 1 above for
  the Aho-Corasick automaton, and by the engine's own
  `Zeroizing<String>` wrap for each registered value). The
  vault's encryption-at-rest does not change the in-memory
  posture; it adds the at-rest layer.
- **The AEAD key is also plaintext in memory** during the brief
  window between HKDF derivation and the encrypt or decrypt call.
  Wrapped in `Zeroizing<[u8; 32]>` so it wipes on drop, but
  visible to a memory-dumping attacker within that window.
- **Vault file size leaks the approximate number of registered
  values.** The ciphertext length is the plaintext length plus
  16 bytes (Poly1305 tag); an observer who watches the vault
  file's size can estimate how many entries it has. Acceptable;
  documented.
- **`serde_json` intermediate-allocation residual.** During
  decrypt, the JSON parser allocates intermediate `String`
  values as it walks the plaintext bytes. Those allocations are
  not Zeroizing-wrapped; the bytes linger in the allocator until
  reuse. The decrypted plaintext `Vec<u8>` IS wrapped (it wipes
  on drop), and each value is moved into a `Zeroizing<String>`
  inside the engine's `RegisteredValue` types after parsing - so
  the long-lived in-engine copy is wiped on eviction, but the
  short-lived deserialization-time intermediate is not. A custom
  Zeroizing-direct deserializer would close this; deferred to
  M4a's vault hardening rather than landing in M1 because the
  bytes are already heap-resident either way (row 1's residual
  covers the broader case).
- **Register-time `VaultEntry.value` heap copy (write-path
  instance of the same residual class as the `serde_json`
  intermediate above).** The M1 chunk-19 CLI `register` command
  reads the user's secret as a `Zeroizing<String>` (wipes on
  drop) and copies it into `VaultEntry.value: String` (chunk
  18's deliberate plain-`String` choice for the on-disk schema)
  via `.to_string()`; the copy persists in
  `Vault.contents.entries[i].value` through `save()` and drops
  unzeroed at end of the command. The on-disk artifact is
  AEAD-encrypted, so this is a local heap residual only - same
  class as the read-path `serde_json` intermediate above. Full
  closure (typing `VaultEntry.value` as `Zeroizing<String>` for
  the write path AND a Zeroizing-direct deserializer for the
  read path) is deferred to M4a's vault hardening so both halves
  close together; closing only the write path in M1 would change
  chunk-18 code while leaving the read-path intermediate open
  for no user-facing benefit.
- **`EngineScrubResult.output` and `EngineRestoreResult.output`
  String allocations (chunk-20 scrub / restore engine return
  values).** The M1 chunk-20 CLI scrub / restore handlers call
  `Engine::scrub` / `Engine::restore` and receive an
  `EngineScrubResult` / `EngineRestoreResult` whose `output`
  field is a plain `String` holding, respectively, the scrubbed
  text (no real secrets after substitution, but registered values
  may co-exist briefly during the in-engine pass) and the
  restored text (REAL recovered secrets - the most sensitive
  transient in the tool). The CLI handlers re-wrap each output
  in a `Zeroizing<String>` at the chunk-20 boundary, so the
  user-visible copy on the CLI side IS wiped after `write_all`
  returns. The engine-internal `String` that the handler `move`s
  out of the result struct is the residual: the allocation
  pre-dates the `Zeroizing::new` wrap and the inner bytes are
  the same heap region, so wrapping at the CLI boundary does not
  retroactively zeroize the engine's allocation - only the CLI's
  re-wrapped view. Same residual class as the `serde_json`
  intermediate and the `VaultEntry.value` write-path heap copy
  above. Full closure (returning `Zeroizing<String>` directly
  from the engine's `EngineScrubResult.output` /
  `EngineRestoreResult.output`) is deferred to M4a's vault
  hardening together with the chunk-18 / chunk-19 sibling
  residuals - landing the engine-side type change in M1 would
  reshape chunk-9 / chunk-10 engine code with no user-facing
  benefit while half the sibling class (the read-path
  `serde_json` intermediate) stays open. The restore output is
  the more sensitive of the two (it holds reconstructed real
  secrets); chunk 20's leak-harness boundary tests confirm those
  bytes appear only on the user's chosen stdout channel and
  nowhere else, which is the M1-grade defence pending M4a's
  engine-side closure.
- **macOS `F_FULLFSYNC` is not used.** Standard `fsync` on macOS
  does not guarantee durability against unexpected power loss.
  A power-loss within ~milliseconds of a vault write on macOS
  may not survive. Acceptable for M1; M4a vault hardening can
  switch to `F_FULLFSYNC` if desired.
- **Concurrent vault writers are unsupported.** Two Invisibool
  processes writing the same vault simultaneously could produce
  interleaved temp files with the rename winner clobbering the
  loser. Documented as "run one Invisibool process per user".
  M1 watch daemon takes the single-writer position; M4a can add
  file locking if needed.

---

### 15. The `--session` file: fake -> real pairs at rest on the user's disk (M1)

**Threat.** The chunk-21 `scrub --session PATH` and
`restore --session PATH` commands persist a `{fake -> real}` map on
disk between the two commands so PII / Card / Formatless
registered values are restorable across two separate CLI
invocations. The map holds real secret bytes; the file itself is a
new at-rest artifact under the user's control, sitting alongside
the vault file with the same overall class of risk. Concrete
failure modes: (a) an attacker who acquires the file but not the
OS keychain reads structured metadata (schema version, timestamps,
approximate entry count via ciphertext length) and MUST NOT be
able to recover any pair; (b) an attacker with BOTH the file and
the keychain recovers every pair - the same trust boundary as the
vault; (c) a same-user attacker on a shared system reads the file
via filesystem access if permissions are lax; (d) accidental
type-confusion with the vault file under a shared vault key would
let one artifact class silently succeed at the AEAD layer when
handed to the other's code path.

**Mitigation.**

- **AEAD: XChaCha20-Poly1305,** identical primitive and nonce
  discipline as the vault (row 14). Fresh 24-byte random nonce
  per encrypt via the OS CSPRNG under the same panic contract.
- **AEAD key derivation: HKDF-SHA-256** with a **distinct**
  `info` label `"invisibool-session-aead-v1"` (vault uses
  `"invisibool-vault-aead-v1"`). Same vault key sources both
  derivations, but the derived subkeys are independent under
  HKDF's domain-separation guarantee - a compromise or rotation
  of one does not follow the other.
- **AAD = MAGIC + version + reserved (first 20 bytes)** with the
  **distinct** MAGIC `b"INVISIBOOL_SESSN"` (vault uses
  `b"INVISIBOOL_VAULT"`). Distinct MAGIC is checked BEFORE the
  AEAD attempt, so pointing `--session` at a vault file (or a
  vault file at `--session`) returns a typed
  `SessionFileError::NotASessionFile` rather than a subtle AEAD
  or JSON-schema failure. Under a shared vault key that check is
  load-bearing: without it, a vault file passed to
  `restore --session` would decrypt cleanly at the AEAD layer
  and only fail at JSON-schema parse, an ambiguous surface where
  the behavior mistake would be silent.
- **Atomic write: write-temp + fsync + rename + fsync-parent,**
  reusing `VaultIo::write_atomic` verbatim. At any crash point
  the on-disk state is one of two stable states; a half-written
  session file is unreachable by construction.
- **File permissions: `0o600` set at create time on Unix,**
  matching the vault-file discipline exactly. On Windows the
  file inherits the parent dir's DACL; chunk 25 / 26 / 27 will
  refine the platform-specific privacy hooks together with the
  vault-side counterparts.
- **Mandatory short TTL, enforced at load with NO silent reset.**
  Every session file carries `created_at` and `expires_at =
  created_at + 30 min`. Loading a file with `expires_at <=
  now_epoch` returns `SessionFileError::Expired { expired_at }`;
  the CLI refuses the operation rather than silently regenerating
  the file. A REPEAT `scrub --session PATH` merges new entries
  into the existing file while **preserving the original
  `expires_at`** - repeated scrubbing cannot extend the session's
  lifetime past its first-write deadline.
- **Wipe on restore: `remove_file` (unlink), not shred.** After
  a successful `restore --session PATH`, the CLI unlinks the file
  per spec A6 design 2 ("restore --session consumes the file and
  wipes it"). Overwrite-based shredding is deliberately **not**
  attempted - modern filesystem journaling and SSD wear-levelling
  make it largely ineffective, and claiming shred we cannot
  deliver would be theater. The real confidentiality mitigation
  is AEAD ciphertext under a keychain-custody key; unlink alone
  is honest about that.
- **Visible destruction on wipe.** If entries in the file were
  NOT present in the restore input (the reply text the user is
  processing), those mappings are destroyed by the wipe. The
  CLI's stderr summary reports the count explicitly ("N session
  entries not present in this input, discarded with the session
  file.") so the destruction is never silent - matches the
  spec's "unrestorability is never silent" discipline for the
  scrub-side notices.
- **No hand-rolled crypto.** Same RustCrypto crates as row 14
  (`chacha20poly1305`, `hkdf`, `sha2`); the session-file module
  only composes them with a distinct AAD and HKDF info label.

**Residual.**

- **Attacker class 1 (file only, no keychain):** sees the file's
  size (bounds the entry count), the plaintext header
  (`INVISIBOOL_SESSN` + version + reserved), and the AAD's
  authenticated identifier. Cannot recover any `{fake, real}`
  pair. Same shape as the vault-file attacker in row 14.
- **Attacker class 2 (file AND keychain):** full plaintext. Every
  `{fake, real}` pair falls to a single vault-key derivation.
  Trust boundary is identical to the vault file's; the session
  file adds no new exposure class beyond what the vault already
  has for the same registered values. `rotate-key` (M4a) rotates
  BOTH the vault and any live session file's decryptability at
  once - a session file written under the old key cannot be read
  under the new one.
- **Attacker class 3 (same-user on the machine):** `0o600` blocks
  cross-user read; the trust boundary is the OS user account, the
  same boundary the OS keychain already sits behind. Same-user
  is not a threat we can close at the filesystem layer.
- **Post-unlink ciphertext blocks may survive on the physical
  medium.** Journaling filesystems, SSD wear-levelling, and copy-
  on-write layouts routinely retain freed blocks until the
  filesystem reuses them. `remove_file` releases the inode; the
  underlying block content is not overwritten by us. The
  confidentiality guarantee for those surviving blocks is the
  AEAD ciphertext they hold, not physical erasure. Any user
  concerned about medium-level residuals should encrypt the
  filesystem itself (LUKS / FileVault / BitLocker); we cannot
  offer a stronger guarantee at the application layer without
  claiming shred we cannot deliver.
- **`serde_json` read-path intermediate + `SessionContents.entries[i].real`
  heap copies.** The session file's decrypt path parses the
  plaintext into a `SessionContents { entries: Vec<SessionPair
  { fake: String, real: String }> }`. Both `String`s land in
  serde_json intermediate allocations that are not
  Zeroizing-wrapped, then get imported into the `SessionMap`
  which does wipe its own copies on eviction. Sibling residual to
  the chunk-18 vault read path (row 14's `serde_json`
  intermediate bullet), the chunk-19 write-path
  `VaultEntry.value`, and the chunk-20 engine output buffers.
  Full closure (a Zeroizing-direct deserializer plus
  `SessionPair.real: Zeroizing<String>`) is deferred to M4a
  vault hardening together with the other siblings so the whole
  class closes at once rather than half-closing across three
  milestones. Phrased as "deferred to M4a" (a plan), not "will
  be fixed" (a promise).
- **Fake -> real linkability within one session file's lifetime.**
  The engine's session-mapped fakes are deterministic in the real
  value under one session (per-submission stability). An attacker
  who has BOTH the session file AND the LLM prompt / reply text
  can correlate scrubbed messages by fake reuse. Same shape as
  the PII-fake-linkability row 10 for the live `watch` daemon;
  the session file exposes the same property at rest for its
  30-minute lifetime.

---

## Deferred rows (introduced at later milestones)

These items are part of the documented threat model but the code
they describe does not exist at M0b. They are listed here so a
reader who consults this file at M0b knows what's coming, and so
the file grows by filling these stubs in rather than by being
rewritten when each milestone lands.

| Row | Introduced at | Summary |
|---|---|---|
| Idle lock | M1 | When the `watch` daemon idles past its threshold, AEAD-encrypts the in-memory session map under the vault key and drops the plaintext map + key + automaton. Restorability survives idle (one keychain fetch on wake re-derives, decrypts, rebuilds). Ciphertext-at-rest in memory while idle. |
| Clipboard history / cloud sync | M1 | Windows clipboard history, macOS Universal Clipboard, and cross-device cloud clipboards may capture the *pre-scrub original* before `watch` writes the scrubbed text - Invisibool cannot retract it. Mitigations: platform clipboard-privacy hints (`ExcludeClipboardContentFromMonitorProcessing` etc.), content-checked 60 s auto-clear of the restore slot, a first-run platform-specific warning. Hint-ignoring clipboard managers defeat the privacy-hint mitigation; this is admitted in the M1 docs. |
| Polling race | M1 | On platforms without clipboard event APIs, `watch` polls; a clipboard write between polls can be observed by the next reader before scrub runs. The worst-case polling window is published in the M1 README. |
| Silent corruption from non-verbatim echo | M1 | `watch` must never write a partially-restored value - the daemon refuses to write back a value it could not restore completely, surfacing the failure instead. |
| Control-channel same-user attack | M1 | The daemon control socket (Unix domain socket / Windows named pipe) is peer-UID/DACL-checked and never TCP. Same-user code execution already has every privilege the daemon does, so the control channel is not a new exposure class. |
| `forget` orphans old fakes | M4a | Default `forget` moves to an encrypted retired set (idempotence still recognises the old fake; `restore` reports "forgotten - not restored"). `forget --purge` deletes fully and warns that old fakes become unrecognisable, so re-scrubbing old text may double-fake them. |

---

## How to read this file

A row is **live** when the code path it describes is present in the
shipped engine - the threat and residual apply to anything you do
with the engine today. A row is **deferred** when the code lands in
a later milestone; the threat is documented now so the introduction
of the code is not the first time a reader sees the trade-off, but
the residual does not apply until the milestone ships.

If you discover a threat that is not on this list, that is a bug in
this document. Open an issue or send a PR - the goal is to surface
risk, not to defend a clean-looking page.
