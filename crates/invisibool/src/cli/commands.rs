//! Command handlers: `register`, `list`, `forget`, `scrub`, `restore`.
//!
//! Each command is a pure function over (vault path, keychain, I/O
//! sinks, command args). The production binary's `main` constructs
//! the real [`OsKeychain`] + [`StdVaultIo`] and calls these; tests
//! construct [`InMemoryKeychain`] + a temp-dir vault path and call
//! the same functions, so the dispatch logic, exit codes, and
//! Formatless disclosure are exercised in unit tests without
//! running the binary as a subprocess.
//!
//! ## Exit codes (chunk 19)
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | Success |
//! | 2    | Usage error (clap's own; not produced here) |
//! | 3    | Vault I/O, keychain, or path-resolution error |
//! | 4    | `forget` on a label that does not exist |
//! | 5    | `register` on a label that is already registered |
//!
//! ## M1 chunk-19 dispatch policy (the kind a freshly-registered entry gets)
//!
//! For each registered value the CLI calls
//! [`tokenizer::fpe::check_eligibility`] with `prefix=""` and
//! `alphabet=Alphabet::BASE62`. If it passes, the entry is stored
//! as [`VaultEntryKind::Fpe`] with an empty prefix, the BASE62
//! alphabet, and a fresh 16-byte tweak from
//! [`vault::random_ff1_tweak`] (which inherits the os_random PANIC
//! CONTRACT - a CSPRNG failure terminates the process; a non-random
//! tweak weakens FF1). If it fails, the entry is stored as
//! [`VaultEntryKind::SessionMapped`] with kind
//! [`SessionFakeKind::Formatless`] AND the CLI prints the
//! A15-row-2 non-restorability disclosure to stderr.
//!
//! This is a deliberate M1 simplification - alphabet detection
//! (Base32 / Hex / etc.) and prefix inference (`sk-`, `ghp_`,
//! `xoxb-`, ...) land in M3 per the spec's M3 line. M4a adds
//! minimum-strength guards and the URL/connection-string component
//! split. The base62/empty-prefix default is the cheapest
//! spec-correct minimum: it dispatches eligible values to FF1
//! (per the M1 "reversal uses stateless FF1 by default for
//! eligible vault secrets" requirement) without making any
//! alphabet-pattern claims chunk-19 is not equipped to back up.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use invisibool_engine::engine::ScrubNotice;
use invisibool_engine::keychain::KeychainBackend;
use invisibool_engine::tokenizer::alphabet::Alphabet;
use invisibool_engine::tokenizer::fpe::{check_eligibility, SessionFakeKind};
use invisibool_engine::vault::{
    self, default_vault_path, EntryKindSummary, StdVaultIo, Vault, VaultEntry, VaultEntryKind,
    VaultIo,
};

/// The chunk-19 register dispatch policy uses BASE62 with an empty
/// prefix. See module doc for the rationale and the M3/M4a follow-on
/// list. Centralised here so both the production code and the
/// branch-tests reference the same alphabet (drift would weaken
/// the test's value).
///
/// MUST match one of the names accepted by
/// `vault::format::resolve_alphabet`. Mismatched casing produces a
/// `VaultError::UnknownAlphabet` at `Vault::build_engine()` time -
/// invisible to the chunk-19 register/list/forget tests which never
/// build the engine, surfaced immediately by chunk 20's scrub/restore
/// tests. Keep the constant aligned with `resolve_alphabet`'s match
/// arms (uppercase `BASE62`); the engine has an explicit test that
/// lowercase does NOT resolve.
const DEFAULT_FPE_ALPHABET_NAME: &str = "BASE62";

/// Resolve the vault path: `--vault` if set, otherwise the
/// platform default. Returns a typed error (with exit code 3 in
/// `main`) if no path can be resolved, rather than panicking - a
/// user on a Windows machine with both `%LOCALAPPDATA%` and
/// `%USERPROFILE%` unset gets a clear actionable message.
pub fn resolve_vault_path(override_path: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = override_path {
        return Ok(p);
    }
    default_vault_path().ok_or_else(|| {
        "could not determine the default vault location (no $HOME on Unix, \
         or no %LOCALAPPDATA% / %USERPROFILE% on Windows); \
         pass --vault <PATH> to choose one explicitly"
            .to_string()
    })
}

/// `invisibool register <LABEL>`. Returns the process exit code.
///
/// - Exits 5 if `label` already exists in the vault.
/// - Otherwise inserts a new entry (Fpe or SessionMapped) and saves.
/// - Prints the Formatless disclosure to `err` when the value is
///   FF1-ineligible.
pub fn register<K: KeychainBackend, W: Write, E: Write>(
    vault_path: &std::path::Path,
    keychain: &K,
    io: &dyn VaultIo,
    label: &str,
    value: Zeroizing<String>,
    out: &mut W,
    err: &mut E,
) -> Result<i32, CommandError> {
    let mut v = Vault::open(io, vault_path, keychain).map_err(CommandError::Vault)?;
    if v.labels().any(|l| l == label) {
        writeln!(
            err,
            "error: a secret is already registered under label '{label}'. \
             Run `invisibool forget {label}` first if you want to replace it."
        )
        .ok();
        return Ok(5);
    }

    let alphabet = Alphabet::BASE62;
    let entry_kind = match check_eligibility(value.as_str(), "", &alphabet) {
        Ok(()) => VaultEntryKind::Fpe {
            tweak: vault::random_ff1_tweak(),
            prefix: String::new(),
            alphabet: DEFAULT_FPE_ALPHABET_NAME.to_string(),
        },
        Err(reason) => {
            writeln!(
                err,
                "notice: '{label}' was registered as a session-mapped \
                 (Formatless) value because it failed FF1 eligibility ({reason}). \
                 Consequence: scrub will replace it with a MAC-tagged random \
                 fake. The original value is NOT restorable in terminal mode \
                 without --session; the running `invisibool watch` daemon \
                 keeps it in its session map until restart. This is the \
                 chunk-19 / A15-row-2 disclosure; the registration is still \
                 recorded."
            )
            .ok();
            VaultEntryKind::SessionMapped {
                kind: SessionFakeKind::Formatless,
            }
        }
    };

    v.register(VaultEntry {
        label: label.to_string(),
        value: value.as_str().to_string(),
        entry_kind,
    });
    v.save(io, vault_path).map_err(CommandError::Vault)?;
    writeln!(out, "registered '{label}'").ok();
    Ok(0)
}

/// `invisibool list`. Prints `label    KIND` per entry, alphabetical
/// by label. Returns 0 on success.
pub fn list<K: KeychainBackend, W: Write>(
    vault_path: &std::path::Path,
    keychain: &K,
    io: &dyn VaultIo,
    out: &mut W,
) -> Result<i32, CommandError> {
    let v = Vault::open(io, vault_path, keychain).map_err(CommandError::Vault)?;
    let mut metadata = v.list_metadata();
    metadata.sort_by(|a, b| a.label.cmp(&b.label));
    if metadata.is_empty() {
        writeln!(out, "(no registered entries)").ok();
        return Ok(0);
    }
    for m in &metadata {
        writeln!(out, "{}\t{}", m.label, format_kind(&m.kind)).ok();
    }
    Ok(0)
}

/// Read the scrub/restore input from a file or stdin into a
/// [`Zeroizing<String>`]. The wrapper is the CLI-boundary closure
/// for THREAT_MODEL row 14's chunk-20 sub-residual: this allocation
/// IS zeroed on drop. The engine-internal `EngineScrubResult.output`
/// / `EngineRestoreResult.output` allocations stay plain `String`
/// for now and are deferred to M4a together with the chunk-18 /
/// chunk-19 vault sibling residuals.
fn read_input(source: Option<&Path>) -> io::Result<Zeroizing<String>> {
    let mut buf = String::new();
    match source {
        Some(path) => {
            std::fs::File::open(path)?.read_to_string(&mut buf)?;
        }
        None => {
            io::stdin().lock().read_to_string(&mut buf)?;
        }
    }
    Ok(Zeroizing::new(buf))
}

/// Render a single `ScrubNotice` into a one-line stderr message. The
/// SessionMappedUnrestorable line is the spec line 39 / A15-row-2
/// disclosure ("scrub ends by printing exactly which values will not
/// be restorable"). The two `Redacted*` lines surface engine-side
/// fail-closed events that the user needs to know about (the value
/// was removed, not faked).
fn format_notice(n: &ScrubNotice) -> String {
    match n {
        ScrubNotice::SessionMappedUnrestorable { label, kind } => {
            format!(
                "notice: '{label}' ({kind:?}) was scrubbed into a session-mapped fake; \
                 it will NOT restore in terminal mode without --session. The chunk-19 \
                 register-time disclosure said this would happen."
            )
        }
        ScrubNotice::RedactedFormatless { label } => {
            format!(
                "warning: '{label}' was redacted (placeholder substituted, original removed); \
                 chunk-20 cannot restore it. Engine-side Formatless fake generator is the \
                 chunk-19+ follow-on."
            )
        }
        ScrubNotice::RedactedInternalFailure { label, reason } => {
            format!(
                "error (internal): '{label}' was redacted because the engine could not \
                 produce a valid fake ({reason}). Please investigate the registration; \
                 a corrupt vault entry can cause this."
            )
        }
    }
}

/// `invisibool [--vault PATH] scrub [FILE]`. Returns 0 on success.
///
/// - Reads input from `input` (already a `Zeroizing<String>` so the
///   caller controls the I/O - tests inject buffers directly, the
///   binary's `run()` glue calls [`read_input`] for stdin/file).
/// - Calls [`Engine::scrub`] over the input.
/// - Writes the scrubbed text to `out` (stdout in production).
///   Output is wrapped in a `Zeroizing<String>` at the CLI boundary
///   so the buffer is wiped on drop after `write_all` returns; see
///   THREAT_MODEL row 14 chunk-20 sub-residual for the engine-side
///   `EngineScrubResult.output` deferral.
/// - Writes one notice line per [`ScrubNotice`] to `err`, then a
///   one-line "scrubbed N value(s)" summary - the chunk-20
///   "every scrub event surfaces a visible indication" + "unrestorability
///   is always disclosed" non-negotiable.
pub fn scrub<K: KeychainBackend, W: Write, E: Write>(
    vault_path: &Path,
    keychain: &K,
    io: &dyn VaultIo,
    input: Zeroizing<String>,
    out: &mut W,
    err: &mut E,
) -> Result<i32, CommandError> {
    let v = Vault::open(io, vault_path, keychain).map_err(CommandError::Vault)?;
    let engine = v.build_engine().map_err(CommandError::Vault)?;
    let result = engine.scrub(input.as_str());
    let scrubbed_out: Zeroizing<String> = Zeroizing::new(result.output);
    out.write_all(scrubbed_out.as_bytes())
        .map_err(CommandError::Io)?;
    for notice in &result.notices {
        writeln!(err, "{}", format_notice(notice)).ok();
    }
    writeln!(err, "scrubbed {} value(s)", result.scrubbed_count).ok();
    Ok(0)
}

/// `invisibool [--vault PATH] restore [FILE]`. Returns 0 on success.
///
/// Same shape as `scrub`. Restore operates ONLY on the bytes passed
/// in `input`: it does not read the clipboard, does not poll, does
/// not infer from "scrubbed-looking" text. Recognition is purely
/// mechanical (FF1 trial-decrypt against registered values); bytes
/// that aren't engine-produced FF1 fakes pass through unchanged.
/// Output wrapped in `Zeroizing<String>` at the CLI boundary - the
/// restore output buffer carries real recovered secrets and is the
/// most sensitive transient in the tool.
pub fn restore<K: KeychainBackend, W: Write, E: Write>(
    vault_path: &Path,
    keychain: &K,
    io: &dyn VaultIo,
    input: Zeroizing<String>,
    out: &mut W,
    err: &mut E,
) -> Result<i32, CommandError> {
    let v = Vault::open(io, vault_path, keychain).map_err(CommandError::Vault)?;
    let engine = v.build_engine().map_err(CommandError::Vault)?;
    let result = engine.restore(input.as_str());
    let restored_out: Zeroizing<String> = Zeroizing::new(result.output);
    out.write_all(restored_out.as_bytes())
        .map_err(CommandError::Io)?;
    writeln!(err, "restored {} value(s)", result.restored_count).ok();
    Ok(0)
}

/// `invisibool forget <LABEL>`. Returns 0 if removed, 4 if missing.
pub fn forget<K: KeychainBackend, W: Write, E: Write>(
    vault_path: &std::path::Path,
    keychain: &K,
    io: &dyn VaultIo,
    label: &str,
    out: &mut W,
    err: &mut E,
) -> Result<i32, CommandError> {
    let mut v = Vault::open(io, vault_path, keychain).map_err(CommandError::Vault)?;
    let removed = v.forget(label);
    if !removed {
        writeln!(err, "error: no entry with label '{label}'").ok();
        return Ok(4);
    }
    v.save(io, vault_path).map_err(CommandError::Vault)?;
    writeln!(out, "forgot '{label}'").ok();
    Ok(0)
}

/// Render an [`EntryKindSummary`] as the text the `list` output
/// shows. Never includes the value (the type already guarantees
/// this) and never includes the FF1 tweak bytes (the summary type
/// already dropped them).
fn format_kind(k: &EntryKindSummary) -> String {
    match k {
        EntryKindSummary::Fpe { alphabet, prefix } => {
            if prefix.is_empty() {
                format!("FPE {alphabet}")
            } else {
                format!("FPE {alphabet} prefix={prefix:?}")
            }
        }
        EntryKindSummary::SessionMapped { kind } => match kind {
            SessionFakeKind::Card => "SessionMapped Card".to_string(),
            SessionFakeKind::Formatless => "SessionMapped Formatless".to_string(),
            SessionFakeKind::Pii(p) => format!("SessionMapped Pii({p:?})"),
        },
    }
}

/// Errors a command function may return. `main` maps these to exit
/// codes (typically 3 for any variant; the per-variant breakout
/// lets future surfaces - `watch`, `scrub` - distinguish them).
#[derive(Debug)]
pub enum CommandError {
    Vault(invisibool_engine::vault::VaultError),
    #[allow(dead_code)]
    Io(io::Error),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vault(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "I/O: {e}"),
        }
    }
}

impl std::error::Error for CommandError {}

/// Production entry point glue. Resolves the vault path, dispatches
/// to the matching command handler, and translates a
/// [`CommandError`] (any variant) into exit code 3. Tests call
/// `register`/`list`/`forget` directly; this is the function
/// `main` invokes.
pub fn run(
    cli: crate::cli::args::Cli,
    keychain: &impl KeychainBackend,
    io: &dyn VaultIo,
    secret_reader: impl FnOnce() -> io::Result<Zeroizing<String>>,
) -> i32 {
    let vault_path = match resolve_vault_path(cli.vault) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("error: {msg}");
            return 3;
        }
    };
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let result = match cli.command {
        crate::cli::args::Command::Register { label } => {
            let value = match secret_reader() {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(stderr, "error: failed to read secret from stdin: {e}");
                    return 3;
                }
            };
            register(
                &vault_path,
                keychain,
                io,
                &label,
                value,
                &mut stdout,
                &mut stderr,
            )
        }
        crate::cli::args::Command::List => list(&vault_path, keychain, io, &mut stdout),
        crate::cli::args::Command::Forget { label } => {
            forget(&vault_path, keychain, io, &label, &mut stdout, &mut stderr)
        }
        crate::cli::args::Command::Scrub { file } => {
            let input = match read_input(file.as_deref()) {
                Ok(b) => b,
                Err(e) => {
                    let _ = writeln!(stderr, "error: failed to read scrub input: {e}");
                    return 3;
                }
            };
            scrub(&vault_path, keychain, io, input, &mut stdout, &mut stderr)
        }
        crate::cli::args::Command::Restore { file } => {
            let input = match read_input(file.as_deref()) {
                Ok(b) => b,
                Err(e) => {
                    let _ = writeln!(stderr, "error: failed to read restore input: {e}");
                    return 3;
                }
            };
            restore(&vault_path, keychain, io, input, &mut stdout, &mut stderr)
        }
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            let _ = writeln!(stderr, "error: {e}");
            3
        }
    }
}

// ---------- the production glue that main() actually calls ----------

/// Convenience for `main`: build the real keychain + I/O traits and
/// run. Lives here (not in main.rs) so it is reachable from
/// integration tests under `tests/`.
pub fn run_with_defaults(cli: crate::cli::args::Cli) -> i32 {
    let keychain = invisibool_engine::keychain::OsKeychain::new();
    let io = StdVaultIo;
    run(cli, &keychain, &io, crate::cli::secret_input::read_secret)
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use invisibool_engine::keychain::InMemoryKeychain;
    use std::path::PathBuf;

    /// Per-test temp directory with cleanup on drop. Avoids pulling
    /// in `tempfile` (one less dep); the directory is created under
    /// the system temp dir with a process-unique name derived from
    /// PID + a per-call counter.
    struct TempVaultDir {
        path: PathBuf,
    }

    impl TempVaultDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let path = std::env::temp_dir().join(format!("invisibool-test-{tag}-{pid}-{n}"));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
        fn vault_path(&self) -> PathBuf {
            self.path.join("vault.bin")
        }
    }

    impl Drop for TempVaultDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn zeroizing(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    // ----- register: FPE branch -----
    //
    // A value that passes check_eligibility(prefix="", alphabet=BASE62)
    // must store as VaultEntry::Fpe with empty prefix + base62 + a
    // 16-byte tweak. The tweak must NOT be all zeros (the os_random
    // PANIC CONTRACT means real CSPRNG bytes; a zero tweak would
    // indicate someone replaced random_ff1_tweak with a stub).
    #[test]
    fn register_eligible_value_stores_as_fpe_with_base62_and_random_tweak() {
        let dir = TempVaultDir::new("register-fpe");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        let mut err = Vec::new();

        let value = zeroizing("HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs");
        let exit = register(
            &dir.vault_path(),
            &kc,
            &io,
            "my-api-key",
            value,
            &mut out,
            &mut err,
        )
        .expect("register on empty vault should succeed");
        assert_eq!(exit, 0);
        assert!(err.is_empty(), "Fpe branch must NOT emit the disclosure");
        let stdout = String::from_utf8(out).unwrap();
        assert!(stdout.contains("registered 'my-api-key'"));

        // Re-open the vault and inspect the stored entry kind.
        let reopened = Vault::open(&io, &dir.vault_path(), &kc).expect("reopen");
        let meta = reopened.list_metadata();
        assert_eq!(meta.len(), 1);
        match &meta[0].kind {
            EntryKindSummary::Fpe { alphabet, prefix } => {
                assert_eq!(
                    alphabet, "BASE62",
                    "chunk-19 dispatch writes the engine-canonical UPPERCASE name; \
                     mismatched casing would fail Vault::build_engine at scrub/restore \
                     time (chunk 20 surfaced this)"
                );
                assert!(prefix.is_empty());
            }
            other => panic!("expected Fpe, got {other:?}"),
        }
    }

    // ----- register: Formatless branch + disclosure pinned -----
    //
    // A value that contains a non-base62 character (a hyphen here)
    // fails check_eligibility and must store as SessionMapped
    // Formatless. The disclosure MUST land on stderr and contain
    // the load-bearing phrases so a user grepping output sees them.
    #[test]
    fn register_ineligible_value_stores_as_formatless_and_prints_disclosure() {
        let dir = TempVaultDir::new("register-formatless");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        let mut err = Vec::new();

        // Hyphen is outside base62; check_eligibility errors with
        // CharNotInAlphabet { ch: '-' }. This routes to Formatless.
        let value = zeroizing("not-base62-because-hyphen");
        let exit = register(
            &dir.vault_path(),
            &kc,
            &io,
            "hyphenated-token",
            value,
            &mut out,
            &mut err,
        )
        .expect("register should not error on Formatless dispatch");
        assert_eq!(exit, 0);

        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("Formatless"),
            "disclosure must name the Formatless routing: {stderr}"
        );
        assert!(
            stderr.contains("NOT restorable"),
            "disclosure must say the value is not restorable in terminal mode: {stderr}"
        );
        assert!(
            stderr.contains("--session"),
            "disclosure must mention the --session escape hatch: {stderr}"
        );

        let reopened = Vault::open(&io, &dir.vault_path(), &kc).expect("reopen");
        let meta = reopened.list_metadata();
        assert_eq!(meta.len(), 1);
        match &meta[0].kind {
            EntryKindSummary::SessionMapped { kind } => {
                assert_eq!(*kind, SessionFakeKind::Formatless);
            }
            other => panic!("expected SessionMapped Formatless, got {other:?}"),
        }
    }

    // ----- register: existing label = exit 5 -----
    #[test]
    fn register_on_existing_label_exits_5_with_clear_message() {
        let dir = TempVaultDir::new("register-existing");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        let mut err = Vec::new();

        let first = register(
            &dir.vault_path(),
            &kc,
            &io,
            "duplicate",
            zeroizing("HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs"),
            &mut out,
            &mut err,
        )
        .unwrap();
        assert_eq!(first, 0);
        out.clear();
        err.clear();

        let second = register(
            &dir.vault_path(),
            &kc,
            &io,
            "duplicate",
            zeroizing("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &mut out,
            &mut err,
        )
        .unwrap();
        assert_eq!(second, 5);
        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("already registered"));
        assert!(stderr.contains("forget duplicate"));
    }

    // ----- LOAD-BEARING: register --> Vault::build_engine seam -----
    //
    // The chunk-19/chunk-20 seam regression test. The chunk-19
    // register dispatch wrote `alphabet="base62"` (lowercase) while
    // the engine's `vault::format::resolve_alphabet` requires the
    // uppercase canonical `"BASE62"`. That mismatch slept through
    // chunk 19 because no chunk-19 test crossed the register -->
    // build_engine seam; chunk-20's first scrub call hit
    // `Vault::build_engine()` and failed with
    // `VaultError::UnknownAlphabet("base62")`. This test closes the
    // CLASS: any future register dispatch change that writes data
    // `build_engine` cannot consume (bad alphabet name, bad prefix,
    // bad kind, ...) fails THIS test immediately rather than
    // sleeping until something downstream incidentally hits it.
    //
    // Coverage: both dispatch branches (Fpe and SessionMapped
    // Formatless) registered into the same vault, vault closed and
    // re-opened (full save/load round-trip), build_engine asserted
    // Ok. The Vault::registered_values() inspection confirms each
    // entry-kind survived the round-trip with its alphabet name
    // resolvable to the engine's typed Alphabet.
    #[test]
    fn register_then_build_engine_round_trips_for_both_dispatch_branches() {
        use invisibool_engine::tokenizer::fpe::RegisteredValue;

        let dir = TempVaultDir::new("register-build-engine-seam");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;

        // Register one Fpe-branch value and one Formatless-branch
        // value into the same vault, so both kinds are exercised by
        // the same build_engine call.
        let mut out = Vec::new();
        let mut err = Vec::new();
        register(
            &dir.vault_path(),
            &kc,
            &io,
            "fpe-entry",
            zeroizing("HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs"),
            &mut out,
            &mut err,
        )
        .expect("Fpe register should succeed");
        register(
            &dir.vault_path(),
            &kc,
            &io,
            "formatless-entry",
            zeroizing("not-base62-because-hyphen"),
            &mut out,
            &mut err,
        )
        .expect("Formatless register should succeed");

        // Re-open the vault from disk (full save/load round-trip)
        // and call build_engine. Either branch writing data the
        // engine cannot consume would fail here. Engine does not
        // implement Debug (intentionally - it would leak registered
        // values via formatting), so only the error arm is formatted.
        let v = Vault::open(&io, &dir.vault_path(), &kc).expect("vault reopen");
        if let Err(e) = v.build_engine() {
            panic!(
                "Vault::build_engine MUST succeed for a chunk-19-registered vault. \
                 A failure here means the register dispatch wrote data the engine \
                 cannot consume - the casing-bug class. Got: {e:?}"
            );
        }

        // Inspect the engine-side typed surface: both kinds present,
        // alphabet name resolved to a real Alphabet. registered_values
        // is the same fallible path build_engine takes internally,
        // re-exposed for this kind of test.
        let registered = v
            .registered_values()
            .expect("registered_values must also succeed (same path)");
        assert_eq!(registered.len(), 2, "both entries should be present");
        let mut saw_fpe = false;
        let mut saw_formatless = false;
        for rv in &registered {
            match rv {
                RegisteredValue::Fpe(reg) => {
                    saw_fpe = true;
                    assert_eq!(reg.label, "fpe-entry");
                    // Spot-check the resolved alphabet is functional
                    // (radix > 1). If chunk-19 ever wrote a name that
                    // resolved to a bogus Alphabet, this catches it.
                    assert!(
                        reg.alphabet.radix() >= 2,
                        "Fpe alphabet must have a real radix"
                    );
                }
                RegisteredValue::SessionMapped(reg) => {
                    saw_formatless = true;
                    assert_eq!(reg.label, "formatless-entry");
                    assert_eq!(reg.kind, SessionFakeKind::Formatless);
                }
            }
        }
        assert!(
            saw_fpe,
            "Fpe entry must round-trip into a RegisteredValue::Fpe"
        );
        assert!(
            saw_formatless,
            "Formatless entry must round-trip into a RegisteredValue::SessionMapped"
        );
    }

    // ----- forget: missing label = exit 4 -----
    #[test]
    fn forget_on_missing_label_exits_4() {
        let dir = TempVaultDir::new("forget-missing");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        let mut err = Vec::new();

        let exit = forget(&dir.vault_path(), &kc, &io, "nope", &mut out, &mut err).unwrap();
        assert_eq!(exit, 4);
        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("no entry with label 'nope'"));
    }

    // ----- forget: present label = 0, gone afterwards -----
    #[test]
    fn forget_present_label_removes_entry_and_returns_zero() {
        let dir = TempVaultDir::new("forget-present");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        let mut err = Vec::new();

        register(
            &dir.vault_path(),
            &kc,
            &io,
            "to-remove",
            zeroizing("HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs"),
            &mut out,
            &mut err,
        )
        .unwrap();
        out.clear();

        let exit = forget(&dir.vault_path(), &kc, &io, "to-remove", &mut out, &mut err).unwrap();
        assert_eq!(exit, 0);
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("forgot 'to-remove'"));

        // Re-open and confirm the entry is gone.
        let reopened = Vault::open(&io, &dir.vault_path(), &kc).unwrap();
        assert!(reopened.is_empty());
    }

    // ----- list: value-isolation canary (load-bearing) -----
    //
    // Register a value containing a distinctive marker; run `list`;
    // assert the marker is absent from list's stdout. This pins
    // the type-level guarantee at run time: the projection cannot
    // accidentally print the value because no field of
    // EntryMetadata or EntryKindSummary holds the value bytes.
    #[test]
    fn list_output_does_not_contain_the_registered_value() {
        let dir = TempVaultDir::new("list-isolation");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        let mut err = Vec::new();

        const CANARY: &str = "skLISTCANARY9f3a2b1cZZZZZZZZZZZZ";
        register(
            &dir.vault_path(),
            &kc,
            &io,
            "labelled",
            zeroizing(CANARY),
            &mut out,
            &mut err,
        )
        .unwrap();
        out.clear();

        list(&dir.vault_path(), &kc, &io, &mut out).unwrap();
        let stdout = String::from_utf8(out).unwrap();
        assert!(
            !stdout.contains(CANARY),
            "list output MUST NOT contain the registered value; \
             a regression here means EntryMetadata gained a value-bearing \
             field. Output was:\n{stdout}"
        );
        assert!(
            stdout.contains("labelled"),
            "list should still show the label: {stdout}"
        );
    }

    // ----- list: empty-vault message -----
    #[test]
    fn list_on_empty_vault_prints_empty_marker() {
        let dir = TempVaultDir::new("list-empty");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        list(&dir.vault_path(), &kc, &io, &mut out).unwrap();
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("no registered entries"));
    }

    // ----- --vault override routes through Vault::open (format check) -----
    //
    // Pointing --vault at a non-vault file must trip ONE of chunk
    // 18's format checks (TruncatedFile if the file is shorter than
    // the 60-byte minimum, BadMagic if it is longer but the first
    // 16 bytes are not the magic), NOT silently overwrite or
    // corrupt the file. We assert two cases: a short junk file
    // (TruncatedFile) and a long junk file (BadMagic). Both prove
    // --vault routes through Vault::open with chunk 18's format
    // discipline; failing either of the two would mean the override
    // bypassed format checks.
    #[test]
    fn vault_override_routes_through_open_and_rejects_junk_files() {
        use invisibool_engine::vault::VaultError;

        let dir = TempVaultDir::new("vault-override-junk");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;

        // Case 1: short junk file (< 60 bytes) trips TruncatedFile.
        let short_junk = dir.path.join("short-junk.bin");
        let short_bytes = b"short, definitely not a vault";
        std::fs::write(&short_junk, short_bytes).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = register(
            &short_junk,
            &kc,
            &io,
            "anything",
            zeroizing("HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs"),
            &mut out,
            &mut err,
        );
        assert!(
            matches!(result, Err(CommandError::Vault(VaultError::TruncatedFile))),
            "short junk file must be rejected with TruncatedFile from chunk 18's \
             minimum-size check; got {result:?}. If this passes or returns a \
             different variant, --vault may have bypassed Vault::open."
        );
        assert_eq!(
            std::fs::read(&short_junk).unwrap(),
            short_bytes,
            "the short rejected file must NOT have been touched"
        );

        // Case 2: long junk file (>= 60 bytes, wrong first 16 bytes)
        // trips BadMagic.
        let long_junk = dir.path.join("long-junk.bin");
        let long_bytes = vec![0xAAu8; 128];
        std::fs::write(&long_junk, &long_bytes).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = register(
            &long_junk,
            &kc,
            &io,
            "anything",
            zeroizing("HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs"),
            &mut out,
            &mut err,
        );
        assert!(
            matches!(result, Err(CommandError::Vault(VaultError::BadMagic))),
            "long junk file must be rejected with BadMagic from chunk 18's \
             magic-bytes check; got {result:?}. If this passes or returns a \
             different variant, --vault may have bypassed Vault::open."
        );
        assert_eq!(
            std::fs::read(&long_junk).unwrap(),
            long_bytes,
            "the long rejected file must NOT have been touched"
        );
    }

    // ----- resolve_vault_path -----
    #[test]
    fn resolve_vault_path_returns_override_when_set() {
        let p = PathBuf::from("/tmp/explicit-vault.bin");
        assert_eq!(resolve_vault_path(Some(p.clone())).unwrap(), p);
    }

    // ============================================================
    // chunk 20: scrub / restore tests
    // ============================================================

    /// Helper: build a fresh vault in a temp dir and register one
    /// FF1-eligible value under `label`. Returns the temp dir (drop
    /// = cleanup) and the keychain so the same keys are reused on
    /// subsequent opens.
    fn fpe_vault_with(label: &str, value: &str, tag: &str) -> (TempVaultDir, InMemoryKeychain) {
        let dir = TempVaultDir::new(tag);
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let exit = register(
            &dir.vault_path(),
            &kc,
            &io,
            label,
            zeroizing(value),
            &mut out,
            &mut err,
        )
        .expect("register on empty vault should succeed");
        assert_eq!(exit, 0);
        (dir, kc)
    }

    // ----- INVARIANT 1: explicit-only restore -----
    //
    // No-inference proof #1: with NOTHING registered, restore over
    // arbitrary text (including FF1-shape, MAC-tail-shape, real-
    // looking-secret strings) MUST be a byte-identical no-op. If
    // any "guess what this might be" logic ever sneaks in, the
    // engine would have nothing to guess TO with zero registrations,
    // so this test would catch a partial regression too.
    #[test]
    fn restore_on_arbitrary_text_with_empty_vault_is_byte_identical_no_op() {
        let dir = TempVaultDir::new("restore-empty-noop");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;

        // Force vault creation by opening + saving an empty vault
        // (a register/forget pair would also work but this is fewer
        // moving parts).
        let v = Vault::open(&io, &dir.vault_path(), &kc).unwrap();
        v.save(&io, &dir.vault_path()).unwrap();

        let lookalikes = [
            "",
            "ordinary prose with no secrets at all",
            "sk-ant-fakelooking1234567890abcdef", // Anthropic-key shaped
            "AKIAIOSFODNN7EXAMPLE",               // AWS-key shaped
            "ghp_aBcDeF1234567890abcdefghij1234ABCD", // GitHub PAT shaped
            "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs",   // 32-char base62 (FF1-fake shape)
        ];

        for input in lookalikes {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let exit = restore(
                &dir.vault_path(),
                &kc,
                &io,
                zeroizing(input),
                &mut out,
                &mut err,
            )
            .expect("restore should not error on a clean vault");
            assert_eq!(exit, 0);
            assert_eq!(
                String::from_utf8(out).unwrap(),
                input,
                "with no registrations, restore MUST be a byte-identical no-op. \
                 Failed input: {input:?}. A regression here would mean restore \
                 fabricated swaps without any registered values - the inference \
                 hazard the spec retired."
            );
            let stderr = String::from_utf8(err).unwrap();
            assert!(
                stderr.contains("restored 0 value(s)"),
                "summary line should report zero restores: {stderr:?}"
            );
        }
    }

    // No-inference proof #2: even WITH a registration present whose
    // FF1 profile (alphabet + length) the candidate string matches,
    // trial-decrypt must reject any candidate whose decryption is
    // not the registered real value. The lookalike below is 32-char
    // base62 (same profile as the registered FF1 entry) but is not
    // the registered entry's FF1 fake under this vault's key, so
    // try_restore must return None and leave the span untouched.
    #[test]
    fn restore_on_ff1_shape_lookalike_that_is_not_our_fake_does_not_swap() {
        let (dir, kc) = fpe_vault_with(
            "real-token",
            "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs",
            "restore-lookalike",
        );
        let io = StdVaultIo;

        // 32-char base62, deliberately constructed to NOT be the
        // FF1 fake of "real-token" under this vault's key. Trial-
        // decrypt will yield SOME 32-char base62 plaintext; the
        // odds of that being exactly "real-token" are ~62^32 to one.
        let lookalike = "XqJp3WnTbZyR4mFcDvLkAhEsGqYjK2Bo";
        let mut out = Vec::new();
        let mut err = Vec::new();
        let exit = restore(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing(lookalike),
            &mut out,
            &mut err,
        )
        .expect("restore should not error");
        assert_eq!(exit, 0);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            lookalike,
            "FF1-shape lookalike (not our fake) MUST pass through unchanged. \
             A regression would mean trial-decrypt false-positives a span as \
             a real fake, which would silently corrupt user data."
        );
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("restored 0 value(s)"),
            "summary line should report zero restores: {stderr:?}"
        );
    }

    // ----- INVARIANT 2: byte-exact round-trip for FF1 -----
    //
    // FF1 is a bijection over (key, tweak, alphabet, length); the
    // CLI is a thin pass-through. For every input shape, scrub then
    // restore must produce a byte-identical copy of the original.
    #[test]
    fn scrub_then_restore_is_byte_identical_for_ff1_registered_value() {
        const VALUE: &str = "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs";
        let (dir, kc) = fpe_vault_with("api-token", VALUE, "roundtrip");
        let io = StdVaultIo;

        let inputs = [
            "",
            "no secrets here at all",
            VALUE,                                              // bare value
            &format!("prefix {VALUE} suffix"),                  // surrounded
            &format!("{VALUE} {VALUE}"),                        // repeated
            &format!("multi\nline\nwith {VALUE} embedded\nyo"), // multi-line
        ];

        for original in inputs {
            let mut scrub_out = Vec::new();
            let mut scrub_err = Vec::new();
            let exit = scrub(
                &dir.vault_path(),
                &kc,
                &io,
                zeroizing(original),
                &mut scrub_out,
                &mut scrub_err,
            )
            .expect("scrub should succeed");
            assert_eq!(exit, 0);
            let scrubbed = String::from_utf8(scrub_out).unwrap();

            let mut restore_out = Vec::new();
            let mut restore_err = Vec::new();
            let exit = restore(
                &dir.vault_path(),
                &kc,
                &io,
                zeroizing(&scrubbed),
                &mut restore_out,
                &mut restore_err,
            )
            .expect("restore should succeed");
            assert_eq!(exit, 0);
            let restored = String::from_utf8(restore_out).unwrap();

            assert_eq!(
                restored, original,
                "round-trip MUST be byte-identical. Original: {original:?}; \
                 scrubbed: {scrubbed:?}; restored: {restored:?}."
            );
        }
    }

    // ----- Formatless gap honesty -----
    //
    // Per chunk 19 dispatch, an FF1-ineligible value (hyphen here)
    // is registered as SessionMapped Formatless. Engine-side, that
    // currently lands in RedactedFormatless (M0b placeholder). At
    // either way, the round-trip leaves the engine's output in
    // place (the fake/placeholder survives restore) and the scrub
    // notice surfaces the gap. This test pins BOTH: the user is
    // told (notice fires) and the gap is honest (restore does not
    // magically recover the value).
    #[test]
    fn formatless_scrub_emits_notice_and_round_trip_leaves_engine_output_in_place() {
        let dir = TempVaultDir::new("formatless-roundtrip");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;

        // Register a hyphen-bearing value as Formatless.
        const VALUE: &str = "not-base62-because-hyphen";
        let mut out = Vec::new();
        let mut err = Vec::new();
        register(
            &dir.vault_path(),
            &kc,
            &io,
            "hyphenated",
            zeroizing(VALUE),
            &mut out,
            &mut err,
        )
        .unwrap();

        // Scrub a paragraph containing the value.
        let input = format!("the value is {VALUE} and that is all");
        let mut scrub_out = Vec::new();
        let mut scrub_err = Vec::new();
        scrub(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing(&input),
            &mut scrub_out,
            &mut scrub_err,
        )
        .unwrap();
        let scrubbed = String::from_utf8(scrub_out).unwrap();
        let scrub_stderr = String::from_utf8(scrub_err).unwrap();

        // The original Formatless value must be gone from the
        // scrubbed output. (Either replaced with REDACTION or with
        // a Formatless fake; either way the user's secret left
        // memory via that channel.)
        assert!(
            !scrubbed.contains(VALUE),
            "scrubbed output MUST NOT contain the Formatless value: {scrubbed:?}"
        );

        // One of the two Formatless-class notices MUST appear in
        // stderr - the user is told "this is unrestorable" or
        // "this was redacted", never silent.
        let mentioned_formatless = scrub_stderr.contains("hyphenated")
            && (scrub_stderr.contains("session-mapped") || scrub_stderr.contains("redacted"));
        assert!(
            mentioned_formatless,
            "scrub stderr MUST disclose the Formatless gap for 'hyphenated': {scrub_stderr:?}"
        );

        // Round-trip: restoring the scrubbed text without --session
        // must not magically recover the value.
        let mut restore_out = Vec::new();
        let mut restore_err = Vec::new();
        restore(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing(&scrubbed),
            &mut restore_out,
            &mut restore_err,
        )
        .unwrap();
        let restored = String::from_utf8(restore_out).unwrap();
        assert!(
            !restored.contains(VALUE),
            "stateless restore MUST NOT recover the Formatless value. The user was \
             told this at scrub time; magically recovering it would be a worse \
             surprise than the documented gap. Got: {restored:?}"
        );
    }

    // ----- CLI surface: stdout cleanliness + stderr indication -----
    //
    // Per non-negotiables: every scrub event surfaces a visible
    // indication, and stdout carries ONLY the scrubbed text so the
    // user can pipe it directly into the next tool without mixing
    // notices into the data stream.
    #[test]
    fn scrub_writes_only_scrubbed_text_to_stdout_and_indication_to_stderr() {
        const VALUE: &str = "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs";
        let (dir, kc) = fpe_vault_with("api-token", VALUE, "scrub-channels");
        let io = StdVaultIo;

        let input = format!("send me {VALUE} please");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        scrub(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing(&input),
            &mut stdout,
            &mut stderr,
        )
        .unwrap();

        let scrubbed = String::from_utf8(stdout).unwrap();
        let stderr_text = String::from_utf8(stderr).unwrap();

        // Stdout MUST be exactly the scrubbed text - no notice lines,
        // no summary line, no decoration. A user piping into an LLM
        // depends on this.
        assert!(
            scrubbed.starts_with("send me ") && scrubbed.ends_with(" please"),
            "stdout must be the scrubbed prose only: {scrubbed:?}"
        );
        assert!(
            !scrubbed.contains("scrubbed") && !scrubbed.contains("notice"),
            "stdout MUST NOT contain notice/summary contamination: {scrubbed:?}"
        );
        assert!(
            !scrubbed.contains(VALUE),
            "stdout MUST NOT contain the original value: {scrubbed:?}"
        );

        // Stderr MUST contain the visible-indication line.
        assert!(
            stderr_text.contains("scrubbed 1 value(s)"),
            "stderr must include the visible scrub-event count: {stderr_text:?}"
        );
    }

    #[test]
    fn restore_writes_only_restored_text_to_stdout_and_summary_to_stderr() {
        const VALUE: &str = "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs";
        let (dir, kc) = fpe_vault_with("api-token", VALUE, "restore-channels");
        let io = StdVaultIo;

        // Scrub first so we have a real engine fake to feed back in.
        let original = format!("token: {VALUE} ok");
        let mut s_out = Vec::new();
        let mut s_err = Vec::new();
        scrub(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing(&original),
            &mut s_out,
            &mut s_err,
        )
        .unwrap();
        let scrubbed = String::from_utf8(s_out).unwrap();

        // Restore the scrubbed text.
        let mut r_out = Vec::new();
        let mut r_err = Vec::new();
        restore(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing(&scrubbed),
            &mut r_out,
            &mut r_err,
        )
        .unwrap();
        let restored = String::from_utf8(r_out).unwrap();
        let restore_stderr = String::from_utf8(r_err).unwrap();

        assert_eq!(
            restored, original,
            "round-trip via the CLI handlers must be byte-identical"
        );
        // Stdout must be ONLY the restored bytes - no summary line,
        // so piping the output stays clean. The summary lives on
        // stderr.
        assert!(
            !restored.contains("restored "),
            "stdout MUST NOT contain the summary line: {restored:?}"
        );
        assert!(
            restore_stderr.contains("restored 1 value(s)"),
            "stderr must include the restore summary count: {restore_stderr:?}"
        );
    }

    // ----- --vault override routes scrub/restore through Vault::open -----
    //
    // Same chunk-18 format-check discipline as the chunk-19 register
    // override test, applied to scrub and restore. Pointing --vault
    // at a junk file must trip a typed VaultError, not silently
    // overwrite the file.
    #[test]
    fn vault_override_for_scrub_and_restore_routes_through_open() {
        use invisibool_engine::vault::VaultError;

        let dir = TempVaultDir::new("vault-override-scrub-restore");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;

        let junk = dir.path.join("junk.bin");
        let junk_bytes = vec![0xAAu8; 128]; // long enough to clear chunk-18's minimum
        std::fs::write(&junk, &junk_bytes).unwrap();

        // Scrub on a junk vault must fail with BadMagic, not silently
        // succeed.
        let mut out = Vec::new();
        let mut err = Vec::new();
        let res = scrub(&junk, &kc, &io, zeroizing("anything"), &mut out, &mut err);
        assert!(
            matches!(res, Err(CommandError::Vault(VaultError::BadMagic))),
            "scrub --vault must route through Vault::open and fail BadMagic on \
             a junk file; got {res:?}"
        );
        assert_eq!(
            std::fs::read(&junk).unwrap(),
            junk_bytes,
            "junk file MUST NOT be modified by a failed scrub"
        );

        // Same for restore.
        let mut out = Vec::new();
        let mut err = Vec::new();
        let res = restore(&junk, &kc, &io, zeroizing("anything"), &mut out, &mut err);
        assert!(
            matches!(res, Err(CommandError::Vault(VaultError::BadMagic))),
            "restore --vault must route through Vault::open and fail BadMagic on \
             a junk file; got {res:?}"
        );
    }
}
