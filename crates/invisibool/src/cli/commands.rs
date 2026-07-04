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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use invisibool_engine::engine::ScrubNotice;
use invisibool_engine::keychain::KeychainBackend;
use invisibool_engine::session_file::{
    wipe_session_file, SessionContents, SessionFileError, SessionPair, SESSION_TTL_SECS,
};
use invisibool_engine::tokenizer::alphabet::Alphabet;
use invisibool_engine::tokenizer::fpe::{check_eligibility, SessionFakeKind};
use invisibool_engine::tokenizer::session::SessionMap;
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

/// Bounded but generous entry-count cap for the per-CLI-call
/// [`SessionMap`]. A single scrub/restore invocation only ever passes
/// through the map once, so LRU eviction never fires in practice;
/// the cap exists so a pathologically-huge session file doesn't
/// silently overflow. If a user actually scrubs 4096 session-mapped
/// values in one prompt, later chunks (session ls|clear, watch)
/// raise it or reject at load.
const CLI_SESSION_MAP_CAPACITY: usize = 4096;

/// Wall-clock helper. Kept out of scrub/restore's signature so the
/// production glue can call it directly and tests inject a fixed
/// value via the `now_epoch: u64` argument the handlers actually
/// take.
pub fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `invisibool [--vault PATH] scrub [FILE] [--session PATH]`.
/// Returns 0 on success.
///
/// - Reads input from `input` (already a `Zeroizing<String>` so the
///   caller controls the I/O; tests inject buffers directly, the
///   binary's `run()` glue calls [`read_input`] for stdin/file).
/// - When `session_path` is `None`: calls [`Engine::scrub`]
///   (stateless-FF1 chunk-20 behavior). The `SessionMappedUnrestorable`
///   notices from the engine list every non-FF1 value that got faked
///   into an unrestorable fake - the spec's "unrestorability is
///   never silent" discipline.
/// - When `session_path` is `Some(path)`:
///   - Loads-or-creates a [`SessionContents`] at `path` via
///     [`Vault::load_session_file`]. Missing file: create fresh at
///     `now_epoch`. Existing valid file: merge, preserving the
///     ORIGINAL `expires_at` - a repeat scrub does NOT reset the
///     TTL, so repeated scrubbing cannot keep a session alive
///     forever.
///   - Calls [`Engine::scrub_with_session`], which suppresses the
///     `SessionMappedUnrestorable` notices (the value IS
///     restorable through the session file).
///   - Saves the updated session file back to `path`.
/// - Writes the scrubbed text to `out` wrapped in
///   [`Zeroizing<String>`] at the CLI boundary; engine-side
///   `EngineScrubResult.output` residual is deferred to M4a
///   (THREAT_MODEL row 14).
/// - Writes one notice line per [`ScrubNotice`] to `err`, then a
///   one-line "scrubbed N value(s)" summary.
///
/// `now_epoch` is Unix seconds. Production callers pass
/// [`now_epoch_secs()`]; tests inject known constants so the
/// expiry-refuses and merge-preserves-expiry cases are deterministic.
#[allow(clippy::too_many_arguments)]
pub fn scrub<K: KeychainBackend, W: Write, E: Write>(
    vault_path: &Path,
    keychain: &K,
    io: &dyn VaultIo,
    input: Zeroizing<String>,
    session_path: Option<&Path>,
    now_epoch: u64,
    out: &mut W,
    err: &mut E,
) -> Result<i32, CommandError> {
    let v = Vault::open(io, vault_path, keychain).map_err(CommandError::Vault)?;
    let engine = v.build_engine().map_err(CommandError::Vault)?;

    let result = match session_path {
        None => engine.scrub(input.as_str()),
        Some(path) => {
            // Load-or-create session contents. A missing file is a
            // signal (Ok(None)), not an error; any other failure -
            // NotASessionFile, Expired, AeadDecrypt - is fatal so
            // the user cannot accidentally overwrite an unrelated
            // file or silently reset a mandatory TTL.
            let existing = v
                .load_session_file(io, path, now_epoch)
                .map_err(CommandError::Session)?;
            let (mut contents, ttl_secs_remaining) = match existing {
                Some(c) => {
                    let remaining = c.expires_at.saturating_sub(now_epoch);
                    (c, remaining)
                }
                None => (SessionContents::new_at(now_epoch), SESSION_TTL_SECS),
            };

            // Seed a SessionMap with the existing pairs. TTL matches
            // the file's remaining life so an in-process TTL prune
            // cannot outlive the on-disk expiry.
            let mut map = SessionMap::new(
                CLI_SESSION_MAP_CAPACITY,
                Duration::from_secs(ttl_secs_remaining.max(1)),
            );
            let import_iter = contents
                .entries
                .iter()
                .map(|p| (p.fake.clone(), p.real.clone()));
            let now_instant = Instant::now();
            map.import(import_iter, now_instant);

            let r = engine.scrub_with_session(input.as_str(), &mut map, now_instant);

            // Rebuild the entries list from the (possibly-grown)
            // map. The original created_at / expires_at are
            // preserved verbatim - repeat scrubs do NOT push the
            // expiry forward.
            contents.entries = map
                .entries()
                .map(|(fake, real)| SessionPair {
                    fake: fake.to_string(),
                    real: real.to_string(),
                })
                .collect();
            v.save_session_file(io, path, &contents)
                .map_err(CommandError::Session)?;
            r
        }
    };

    let scrubbed_out: Zeroizing<String> = Zeroizing::new(result.output);
    out.write_all(scrubbed_out.as_bytes())
        .map_err(CommandError::Io)?;
    for notice in &result.notices {
        writeln!(err, "{}", format_notice(notice)).ok();
    }
    writeln!(err, "scrubbed {} value(s)", result.scrubbed_count).ok();
    Ok(0)
}

/// `invisibool [--vault PATH] restore [FILE] [--session PATH]`.
/// Returns 0 on success.
///
/// Same shape as [`scrub`]. Restore operates ONLY on the bytes
/// passed in `input`: it does not read the clipboard, does not
/// poll, does not infer from "scrubbed-looking" text. Recognition
/// is purely mechanical (FF1 trial-decrypt against registered
/// values, plus SessionMap lookup when `--session` is passed);
/// bytes that aren't engine-produced fakes pass through unchanged.
///
/// - When `session_path` is `None`: stateless [`Engine::restore`],
///   chunk-20 behavior unchanged.
/// - When `session_path` is `Some(path)`:
///   - Loads the session file. A MISSING file is fatal - the flag
///     never silently degrades to stateless restore.
///   - Counts how many session entries are `present` in the input
///     BEFORE the engine call (the difference between total and
///     present is the number of mappings destroyed by the wipe).
///   - Calls [`Engine::restore_with_session`].
///   - Unlinks the session file (spec A6 design 2:
///     "restore --session consumes the file and wipes it").
///     Unlink, not shred - the confidentiality mitigation is AEAD +
///     keychain custody per THREAT_MODEL row 15.
///   - Stderr summary reports both the restored count AND the count
///     of discarded-with-wipe entries so the destruction is
///     visible, per the never-silent discipline.
///
/// Output wrapped in `Zeroizing<String>` at the CLI boundary - the
/// restore output buffer carries real recovered secrets and is the
/// most sensitive transient in the tool.
#[allow(clippy::too_many_arguments)]
pub fn restore<K: KeychainBackend, W: Write, E: Write>(
    vault_path: &Path,
    keychain: &K,
    io: &dyn VaultIo,
    input: Zeroizing<String>,
    session_path: Option<&Path>,
    now_epoch: u64,
    out: &mut W,
    err: &mut E,
) -> Result<i32, CommandError> {
    let v = Vault::open(io, vault_path, keychain).map_err(CommandError::Vault)?;
    let engine = v.build_engine().map_err(CommandError::Vault)?;

    let (result, unused_entries) = match session_path {
        None => (engine.restore(input.as_str()), 0usize),
        Some(path) => {
            let contents = v
                .load_session_file(io, path, now_epoch)
                .map_err(CommandError::Session)?
                .ok_or_else(|| {
                    CommandError::Session(SessionFileError::Io(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "session file '{}' not found; `restore --session` \
                             never silently degrades to stateless restore",
                            path.display()
                        ),
                    )))
                })?;

            let total_entries = contents.entries.len();
            let present_entries = contents
                .entries
                .iter()
                .filter(|p| input.contains(&p.fake))
                .count();
            let unused = total_entries.saturating_sub(present_entries);

            let ttl_secs_remaining = contents.expires_at.saturating_sub(now_epoch).max(1);
            let mut map = SessionMap::new(
                CLI_SESSION_MAP_CAPACITY,
                Duration::from_secs(ttl_secs_remaining),
            );
            let import_iter = contents.entries.into_iter().map(|p| (p.fake, p.real));
            let now_instant = Instant::now();
            map.import(import_iter, now_instant);

            let r = engine.restore_with_session(input.as_str(), &mut map, now_instant);

            // Wipe (unlink). If the wipe itself fails, surface a
            // warning to stderr but keep the exit success - the
            // restore itself worked, and the file's `expires_at`
            // still bounds the residual regardless of whether we
            // could remove it now.
            if let Err(e) = wipe_session_file(path) {
                writeln!(
                    err,
                    "warning: could not remove session file '{}': {}. \
                     The file's `expires_at` still bounds its lifetime.",
                    path.display(),
                    e
                )
                .ok();
            }

            (r, unused)
        }
    };

    let restored_out: Zeroizing<String> = Zeroizing::new(result.output);
    out.write_all(restored_out.as_bytes())
        .map_err(CommandError::Io)?;
    writeln!(err, "restored {} value(s)", result.restored_count).ok();
    if unused_entries > 0 {
        // Visible destruction: the mappings the user might have
        // expected to use on the next reply are gone with the
        // wipe. Per spec's "unrestorability is never silent"
        // discipline (and the chunk-21 gate addition), we say so
        // explicitly.
        writeln!(
            err,
            "{} session entr{} not present in this input, discarded with the session file.",
            unused_entries,
            if unused_entries == 1 { "y" } else { "ies" }
        )
        .ok();
    }
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
    Session(SessionFileError),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vault(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::Session(e) => write!(f, "{e}"),
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
        crate::cli::args::Command::Scrub { file, session } => {
            let input = match read_input(file.as_deref()) {
                Ok(b) => b,
                Err(e) => {
                    let _ = writeln!(stderr, "error: failed to read scrub input: {e}");
                    return 3;
                }
            };
            scrub(
                &vault_path,
                keychain,
                io,
                input,
                session.as_deref(),
                now_epoch_secs(),
                &mut stdout,
                &mut stderr,
            )
        }
        crate::cli::args::Command::Restore { file, session } => {
            let input = match read_input(file.as_deref()) {
                Ok(b) => b,
                Err(e) => {
                    let _ = writeln!(stderr, "error: failed to read restore input: {e}");
                    return 3;
                }
            };
            restore(
                &vault_path,
                keychain,
                io,
                input,
                session.as_deref(),
                now_epoch_secs(),
                &mut stdout,
                &mut stderr,
            )
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
                None,
                0,
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
            None,
            0,
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
                None,
                0,
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
                None,
                0,
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
            None,
            0,
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
            None,
            0,
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
            None,
            0,
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
            None,
            0,
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
            None,
            0,
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
        let res = scrub(
            &junk,
            &kc,
            &io,
            zeroizing("anything"),
            None,
            0,
            &mut out,
            &mut err,
        );
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
        let res = restore(
            &junk,
            &kc,
            &io,
            zeroizing("anything"),
            None,
            0,
            &mut out,
            &mut err,
        );
        assert!(
            matches!(res, Err(CommandError::Vault(VaultError::BadMagic))),
            "restore --vault must route through Vault::open and fail BadMagic on \
             a junk file; got {res:?}"
        );
    }

    // ================================================================
    // Chunk 21: --session PATH tests
    // ================================================================
    //
    // These tests exercise the session-file wiring around chunk-20's
    // handlers. Design invariants (per the chunk-21 gate):
    //
    // 1. The engine's `scrub_with_session` and `restore_with_session`
    //    are ADDITIVE - passing `session_path = None` leaves chunk-20
    //    behavior byte-identical (test:
    //    `without_session_flag_scrub_still_emits_session_mapped_unrestorable_notice`).
    //
    // 2. The session file is AEAD-encrypted with a DISTINCT MAGIC so
    //    wrong-file-kind fails as `NotASessionFile`, not as an AEAD
    //    or JSON error (test:
    //    `session_file_wrong_magic_fails_typed_not_crypto`).
    //
    // 3. A repeat scrub MERGES entries and PRESERVES `expires_at` -
    //    never resets the TTL. Otherwise repeated scrubbing could
    //    keep a session alive indefinitely. (test:
    //    `scrub_with_session_second_time_merges_not_resets_expiry`).
    //
    // 4. `restore --session` DELETES the file after success. If
    //    entries in the file were NOT present in the input, they are
    //    destroyed by the wipe - the stderr summary must say so
    //    explicitly (test:
    //    `restore_with_session_reports_unused_entries_in_stderr_summary`).
    //
    // 5. Expired / missing / wrong-magic files FAIL CLOSED - never
    //    silently reset, never silently degrade to stateless
    //    (tests: `..._refuses_on_expired_file`,
    //    `..._refuses_on_missing_file`, wrong-magic above).

    use invisibool_engine::session_file::SESSION_TTL_SECS as ENGINE_SESSION_TTL_SECS;
    use invisibool_engine::tokenizer::fpe::PiiKind;
    use invisibool_engine::vault::VaultEntryKind as VEK;

    /// Build a vault with one PII-Email registration + one FF1
    /// registration under the same keychain. Used for scrub/restore
    /// tests that exercise session-mapped restorability.
    ///
    /// Chunk 19's `register` CLI only dispatches Fpe / Formatless, so
    /// building a PII-Email entry goes through the vault's direct
    /// `Vault::register(VaultEntry { ... })` API instead. That is
    /// deliberate: session-mapped kinds arrive via M3 detection at
    /// the CLI layer; the vault type itself already supports them.
    fn session_vault_with_pii_and_fpe(
        tag: &str,
        pii_label: &str,
        pii_value: &str,
        fpe_label: &str,
        fpe_value: &str,
    ) -> (TempVaultDir, InMemoryKeychain) {
        let dir = TempVaultDir::new(tag);
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        {
            let mut v = Vault::open(&io, &dir.vault_path(), &kc).expect("open empty");
            v.register(VaultEntry {
                label: pii_label.to_string(),
                value: pii_value.to_string(),
                entry_kind: VEK::SessionMapped {
                    kind: SessionFakeKind::Pii(PiiKind::Email),
                },
            });
            v.register(VaultEntry {
                label: fpe_label.to_string(),
                value: fpe_value.to_string(),
                entry_kind: VEK::Fpe {
                    tweak: [0x33u8; 16],
                    prefix: String::new(),
                    alphabet: DEFAULT_FPE_ALPHABET_NAME.to_string(),
                },
            });
            v.save(&io, &dir.vault_path()).expect("save");
        }
        (dir, kc)
    }

    fn session_path(dir: &TempVaultDir, name: &str) -> PathBuf {
        dir.path.join(name)
    }

    /// Load a session file directly (bypassing the CLI handler) so
    /// tests can inspect the on-disk contents. Uses the vault to
    /// borrow the AEAD key.
    fn load_session_via_vault(
        dir: &TempVaultDir,
        kc: &InMemoryKeychain,
        io: &dyn VaultIo,
        session_path: &Path,
        now: u64,
    ) -> Option<SessionContents> {
        let v = Vault::open(io, &dir.vault_path(), kc).expect("open vault");
        v.load_session_file(io, session_path, now).expect("load OK")
    }

    // ----- ADDITIVE: chunk-20 no-session behavior unchanged -----

    #[test]
    fn without_session_flag_scrub_still_emits_session_mapped_unrestorable_notice() {
        // Chunk-21 regression pin: the additive `session_path = None`
        // branch must leave the pre-chunk-21 notice behavior in
        // place. If a future refactor accidentally suppresses the
        // notice in the None case, this test catches it.
        let (dir, kc) = session_vault_with_pii_and_fpe(
            "chunk21-no-session",
            "email",
            "alice@example.com",
            "token",
            "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs",
        );
        let io = StdVaultIo;

        let input = "please send alice@example.com the info";
        let mut out = Vec::new();
        let mut err = Vec::new();
        let exit = scrub(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing(input),
            None, // no --session
            0,
            &mut out,
            &mut err,
        )
        .expect("scrub OK");
        assert_eq!(exit, 0);
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("session-mapped fake") && stderr.contains("email"),
            "no --session must still emit SessionMappedUnrestorable notice: {stderr:?}"
        );
    }

    // ----- Basic scrub-then-restore round trip with session file -----

    #[test]
    fn scrub_with_session_creates_aead_file_with_expected_mode_and_magic() {
        let (dir, kc) = session_vault_with_pii_and_fpe(
            "chunk21-file-mode",
            "email",
            "alice@example.com",
            "token",
            "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs",
        );
        let io = StdVaultIo;
        let sp = session_path(&dir, "s.bin");

        let input = "email is alice@example.com and token is HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs";
        let mut out = Vec::new();
        let mut err = Vec::new();
        let now = 1_000_000_u64;
        let exit = scrub(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing(input),
            Some(&sp),
            now,
            &mut out,
            &mut err,
        )
        .expect("scrub OK");
        assert_eq!(exit, 0);

        // File exists and is mode 0o600.
        assert!(sp.exists(), "session file must be created");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&sp).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "session file mode must be 0o600, got {mode:o}");
        }

        // First 16 bytes are the session MAGIC (distinct from vault).
        let bytes = std::fs::read(&sp).unwrap();
        assert!(bytes.len() >= 16);
        assert_eq!(
            &bytes[..16],
            b"INVISIBOOL_SESSN",
            "session file must start with the distinct session MAGIC"
        );
        assert_ne!(
            &bytes[..16],
            b"INVISIBOOL_VAULT",
            "session file must NOT share the vault MAGIC (type-confusion guard)"
        );

        // Loading it back yields our email pair, with a preserved TTL.
        let contents =
            load_session_via_vault(&dir, &kc, &io, &sp, now + 1).expect("Some(contents)");
        assert_eq!(contents.created_at, now);
        assert_eq!(contents.expires_at, now + ENGINE_SESSION_TTL_SECS);
        assert!(
            contents
                .entries
                .iter()
                .any(|p| p.real == "alice@example.com"),
            "session file must contain the alice@example.com pair"
        );
    }

    #[test]
    fn restore_with_session_recovers_pii_and_wipes_file() {
        let (dir, kc) = session_vault_with_pii_and_fpe(
            "chunk21-restore-wipe",
            "email",
            "alice@example.com",
            "token",
            "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs",
        );
        let io = StdVaultIo;
        let sp = session_path(&dir, "s.bin");
        let now = 2_000_000_u64;

        // Scrub with session.
        let original = "email alice@example.com and token HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs";
        let mut s_out = Vec::new();
        let mut s_err = Vec::new();
        scrub(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing(original),
            Some(&sp),
            now,
            &mut s_out,
            &mut s_err,
        )
        .expect("scrub OK");
        let scrubbed = String::from_utf8(s_out).unwrap();
        // The scrubbed text must not contain the real email (the fake
        // takes its place).
        assert!(
            !scrubbed.contains("alice@example.com"),
            "scrubbed text must not carry the real email: {scrubbed:?}"
        );
        // And no SessionMappedUnrestorable notice should appear when
        // --session is active - the value IS restorable via the file.
        let scrub_stderr = String::from_utf8(s_err).unwrap();
        assert!(
            !scrub_stderr.contains("session-mapped fake"),
            "SessionMappedUnrestorable notice must NOT fire with --session: \
             {scrub_stderr:?}"
        );
        assert!(sp.exists(), "file must exist after scrub");

        // Restore with session.
        let mut r_out = Vec::new();
        let mut r_err = Vec::new();
        let exit = restore(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing(&scrubbed),
            Some(&sp),
            now + 1,
            &mut r_out,
            &mut r_err,
        )
        .expect("restore OK");
        assert_eq!(exit, 0);
        let restored = String::from_utf8(r_out).unwrap();
        assert_eq!(
            restored, original,
            "session-mapped PII must round-trip byte-exact: {restored:?}"
        );

        // File is GONE.
        assert!(
            !sp.exists(),
            "session file must be unlinked by restore --session"
        );

        // No unused-entries line: everything in the file was present
        // in input (both the email and the FF1 fake).
        let restore_stderr = String::from_utf8(r_err).unwrap();
        assert!(
            !restore_stderr.contains("discarded with the session file"),
            "no discard line expected (all entries were used): {restore_stderr:?}"
        );
        assert!(
            restore_stderr.contains("restored 2 value(s)"),
            "restore summary must include the session-restored count \
             (1 PII email + 1 FF1 token = 2 total): {restore_stderr:?}"
        );
    }

    // ----- LOAD-BEARING: merge preserves expires_at -----

    #[test]
    fn scrub_with_session_second_time_merges_not_resets_expiry() {
        // Register TWO PII entries so we can prove the second scrub
        // adds one without moving the file's expires_at.
        let dir = TempVaultDir::new("chunk21-merge-preserves-expiry");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        {
            let mut v = Vault::open(&io, &dir.vault_path(), &kc).expect("open");
            v.register(VaultEntry {
                label: "email-a".to_string(),
                value: "alice@example.com".to_string(),
                entry_kind: VEK::SessionMapped {
                    kind: SessionFakeKind::Pii(PiiKind::Email),
                },
            });
            v.register(VaultEntry {
                label: "email-b".to_string(),
                value: "bob@example.com".to_string(),
                entry_kind: VEK::SessionMapped {
                    kind: SessionFakeKind::Pii(PiiKind::Email),
                },
            });
            v.save(&io, &dir.vault_path()).expect("save");
        }

        let sp = session_path(&dir, "s.bin");
        let t0 = 1_000_000_u64;
        // First scrub at t0 - only mentions Alice.
        let mut out = Vec::new();
        let mut err = Vec::new();
        scrub(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing("please email alice@example.com"),
            Some(&sp),
            t0,
            &mut out,
            &mut err,
        )
        .expect("scrub 1 OK");
        let after_first =
            load_session_via_vault(&dir, &kc, &io, &sp, t0 + 1).expect("Some after scrub 1");
        let expiry_after_first = after_first.expires_at;
        assert_eq!(after_first.created_at, t0);
        assert_eq!(expiry_after_first, t0 + ENGINE_SESSION_TTL_SECS);
        let entries_after_first = after_first.entries.len();
        assert_eq!(entries_after_first, 1, "one email pair after scrub 1");

        // Second scrub 5 minutes later, over an input that mentions
        // Bob. `expires_at` MUST NOT move; entries count MUST grow.
        let t1 = t0 + 5 * 60;
        let mut out2 = Vec::new();
        let mut err2 = Vec::new();
        scrub(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing("also email bob@example.com"),
            Some(&sp),
            t1,
            &mut out2,
            &mut err2,
        )
        .expect("scrub 2 OK");
        let after_second =
            load_session_via_vault(&dir, &kc, &io, &sp, t1 + 1).expect("Some after scrub 2");
        assert_eq!(
            after_second.created_at, t0,
            "created_at must remain the first-scrub timestamp, not move to t1. \
             Got: {} (want {t0})",
            after_second.created_at
        );
        assert_eq!(
            after_second.expires_at, expiry_after_first,
            "expires_at MUST NOT move when a second scrub merges into an existing \
             session file. Otherwise repeated scrubs could keep a session alive \
             indefinitely, defeating the spec's mandatory short TTL. Got \
             expires_at = {} (want {})",
            after_second.expires_at, expiry_after_first
        );
        assert!(
            after_second.entries.len() >= entries_after_first,
            "second scrub must not shrink the entry set: was {}, now {}",
            entries_after_first,
            after_second.entries.len()
        );
    }

    // ----- Refuse expired file -----

    #[test]
    fn scrub_with_session_refuses_on_expired_file() {
        let (dir, kc) = session_vault_with_pii_and_fpe(
            "chunk21-expired-scrub",
            "email",
            "alice@example.com",
            "token",
            "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs",
        );
        let io = StdVaultIo;
        let sp = session_path(&dir, "s.bin");
        let t_write = 1_000_000_u64;
        // Write with expires_at = t_write + TTL. Read at t_read past
        // expiry.
        {
            let mut out = Vec::new();
            let mut err = Vec::new();
            scrub(
                &dir.vault_path(),
                &kc,
                &io,
                zeroizing("mention alice@example.com"),
                Some(&sp),
                t_write,
                &mut out,
                &mut err,
            )
            .expect("scrub OK");
        }
        let t_read = t_write + ENGINE_SESSION_TTL_SECS + 1;

        // Second scrub past expiry MUST refuse.
        let mut out = Vec::new();
        let mut err = Vec::new();
        let res = scrub(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing("mention bob@example.com"),
            Some(&sp),
            t_read,
            &mut out,
            &mut err,
        );
        assert!(
            matches!(
                res,
                Err(CommandError::Session(SessionFileError::Expired { .. }))
            ),
            "expired session file must refuse with typed Expired, not silently \
             reset: got {res:?}"
        );
    }

    #[test]
    fn restore_with_session_refuses_on_expired_file() {
        let (dir, kc) = session_vault_with_pii_and_fpe(
            "chunk21-expired-restore",
            "email",
            "alice@example.com",
            "token",
            "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs",
        );
        let io = StdVaultIo;
        let sp = session_path(&dir, "s.bin");
        let t_write = 1_000_000_u64;
        {
            let mut out = Vec::new();
            let mut err = Vec::new();
            scrub(
                &dir.vault_path(),
                &kc,
                &io,
                zeroizing("mention alice@example.com"),
                Some(&sp),
                t_write,
                &mut out,
                &mut err,
            )
            .expect("scrub OK");
        }
        let t_read = t_write + ENGINE_SESSION_TTL_SECS + 1;

        let mut r_out = Vec::new();
        let mut r_err = Vec::new();
        let res = restore(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing("some fake text"),
            Some(&sp),
            t_read,
            &mut r_out,
            &mut r_err,
        );
        assert!(
            matches!(
                res,
                Err(CommandError::Session(SessionFileError::Expired { .. }))
            ),
            "expired file must refuse restore too: got {res:?}"
        );
        // File is UNTOUCHED - expired reads do not delete.
        assert!(
            sp.exists(),
            "an expired-refusal MUST NOT delete the file (the user might \
             want to inspect it or copy it before removing)"
        );
    }

    // ----- Refuse missing file (fail closed, never silent stateless) -----

    #[test]
    fn restore_with_session_refuses_on_missing_file() {
        let (dir, kc) = session_vault_with_pii_and_fpe(
            "chunk21-missing-restore",
            "email",
            "alice@example.com",
            "token",
            "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs",
        );
        let io = StdVaultIo;
        let sp = session_path(&dir, "never-created.bin");
        assert!(!sp.exists());

        let mut r_out = Vec::new();
        let mut r_err = Vec::new();
        let res = restore(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing("some text"),
            Some(&sp),
            1_000_000,
            &mut r_out,
            &mut r_err,
        );
        // Missing file must be a typed session error, NOT a silent
        // degrade-to-stateless. If the CLI ever "helpfully" ran
        // stateless restore when the file didn't exist, a user
        // running the same command twice would silently lose the
        // session-mapped restoration path on the second run.
        assert!(
            matches!(res, Err(CommandError::Session(_))),
            "missing session file must fail closed: got {res:?}"
        );
    }

    // ----- Wrong-magic typed error (not raw AEAD failure) -----

    #[test]
    fn session_file_wrong_magic_fails_typed_not_crypto() {
        let (dir, kc) = session_vault_with_pii_and_fpe(
            "chunk21-wrong-magic",
            "email",
            "alice@example.com",
            "token",
            "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs",
        );
        let io = StdVaultIo;
        // First save a real vault (already saved by
        // session_vault_with_pii_and_fpe). Try to use the vault file
        // AS a session file - MAGIC mismatches (INVISIBOOL_VAULT vs
        // INVISIBOOL_SESSN). Under a shared vault key this is exactly
        // where type confusion would silently succeed at the AEAD
        // layer if we hadn't chosen a distinct MAGIC; the typed
        // NotASessionFile error is our load-bearing guard.
        let vault_path_as_session = dir.vault_path();
        assert!(vault_path_as_session.exists());

        let mut out = Vec::new();
        let mut err = Vec::new();
        let res = scrub(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing("mention alice@example.com"),
            Some(&vault_path_as_session),
            1_000_000,
            &mut out,
            &mut err,
        );
        assert!(
            matches!(
                res,
                Err(CommandError::Session(SessionFileError::NotASessionFile))
            ),
            "pointing --session at a vault file must fail with NotASessionFile, \
             NOT with AeadDecrypt or Serde - distinct MAGIC is the type-tag. \
             Got: {res:?}"
        );
        // File is UNTOUCHED - refusal does not overwrite.
        let bytes_after = std::fs::read(&vault_path_as_session).unwrap();
        assert!(
            bytes_after.starts_with(b"INVISIBOOL_VAULT"),
            "vault file bytes must be untouched by the refusal"
        );
    }

    // ----- Stdout cleanliness with --session -----

    #[test]
    fn scrub_with_session_writes_only_scrubbed_text_to_stdout() {
        // Reuses chunk-20's channel-discipline shape: adding
        // --session must NOT leak the fake<->real pairs into stdout
        // or stderr. The session file is the ONE new output channel;
        // stdout continues to carry ONLY the scrubbed text.
        let (dir, kc) = session_vault_with_pii_and_fpe(
            "chunk21-stdout-clean",
            "email",
            "alice@example.com",
            "token",
            "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs",
        );
        let io = StdVaultIo;
        let sp = session_path(&dir, "s.bin");
        let input = "hey alice@example.com please respond";

        let mut out = Vec::new();
        let mut err = Vec::new();
        scrub(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing(input),
            Some(&sp),
            1_000_000,
            &mut out,
            &mut err,
        )
        .expect("scrub OK");
        let scrubbed = String::from_utf8(out).unwrap();
        let stderr_text = String::from_utf8(err).unwrap();

        assert!(
            !scrubbed.contains("alice@example.com"),
            "stdout MUST NOT carry the real email: {scrubbed:?}"
        );
        assert!(
            !scrubbed.contains("scrubbed") && !scrubbed.contains("notice"),
            "stdout MUST NOT contain summary/notice contamination: {scrubbed:?}"
        );
        assert!(
            !stderr_text.contains("alice@example.com"),
            "stderr MUST NOT carry the real email either (the file is the ONE \
             new output channel; stderr stays informational): {stderr_text:?}"
        );
        assert!(
            stderr_text.contains("scrubbed 1 value(s)"),
            "stderr must include the visible scrub-event count: {stderr_text:?}"
        );
    }

    // ----- Empty session file: predictable presence -----

    #[test]
    fn scrub_with_session_with_no_session_mapped_values_still_writes_empty_session_file() {
        // A vault with only FF1 entries (no PII/Card/Formatless)
        // still writes a session file when --session PATH is passed,
        // so the presence of the file is predictable and the leak
        // harness has a consistent artifact to check. The file
        // decrypts to zero entries; a subsequent restore no-ops the
        // session pass and wipes the file.
        let (dir, kc) = fpe_vault_with(
            "token",
            "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs",
            "chunk21-empty-session",
        );
        let io = StdVaultIo;
        let sp = session_path(&dir, "s.bin");
        let now = 1_000_000_u64;
        let input = "no session-mapped values here";

        let mut out = Vec::new();
        let mut err = Vec::new();
        scrub(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing(input),
            Some(&sp),
            now,
            &mut out,
            &mut err,
        )
        .expect("scrub OK");
        assert!(sp.exists(), "session file MUST be created even when empty");

        // File loads and has zero entries.
        let v = Vault::open(&io, &dir.vault_path(), &kc).expect("open");
        let contents = v
            .load_session_file(&io, &sp, now + 1)
            .expect("load OK")
            .expect("Some(contents)");
        assert_eq!(contents.entries.len(), 0);

        // Restore also no-ops and wipes.
        let mut r_out = Vec::new();
        let mut r_err = Vec::new();
        restore(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing("anything"),
            Some(&sp),
            now + 1,
            &mut r_out,
            &mut r_err,
        )
        .expect("restore OK");
        assert!(!sp.exists(), "session file must be unlinked by restore");
    }

    // ----- Discard visibility on wipe (chunk-21 gate addition) -----

    #[test]
    fn restore_with_session_reports_unused_entries_in_stderr_summary() {
        // The spec-mandated wipe on restore destroys the file
        // wholesale - including entries whose fake did NOT appear in
        // the input the user just handed to `restore --session`. That
        // is a silent-destruction hazard: the user might have expected
        // to use those mappings on the next reply.
        //
        // The chunk-21 gate: name the count in stderr. "M session
        // entries not present in this input, discarded with the
        // session file." Never silent.
        let dir = TempVaultDir::new("chunk21-unused-discard");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        {
            let mut v = Vault::open(&io, &dir.vault_path(), &kc).expect("open");
            v.register(VaultEntry {
                label: "email-a".to_string(),
                value: "alice@example.com".to_string(),
                entry_kind: VEK::SessionMapped {
                    kind: SessionFakeKind::Pii(PiiKind::Email),
                },
            });
            v.register(VaultEntry {
                label: "email-b".to_string(),
                value: "bob@example.com".to_string(),
                entry_kind: VEK::SessionMapped {
                    kind: SessionFakeKind::Pii(PiiKind::Email),
                },
            });
            v.save(&io, &dir.vault_path()).expect("save");
        }
        let sp = session_path(&dir, "s.bin");
        let t0 = 1_000_000_u64;

        // Scrub both emails so both pairs land in the session file.
        let mut out = Vec::new();
        let mut err = Vec::new();
        scrub(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing("hi alice@example.com and bob@example.com"),
            Some(&sp),
            t0,
            &mut out,
            &mut err,
        )
        .expect("scrub OK");
        let scrubbed = String::from_utf8(out).unwrap();

        // Read the file back to find alice's fake specifically.
        let contents = load_session_via_vault(&dir, &kc, &io, &sp, t0 + 1).expect("Some(contents)");
        assert_eq!(contents.entries.len(), 2);
        let alice_fake = contents
            .entries
            .iter()
            .find(|p| p.real == "alice@example.com")
            .map(|p| p.fake.clone())
            .expect("alice pair present");
        // Sanity: the scrubbed text contains alice's fake.
        assert!(scrubbed.contains(&alice_fake));

        // Now hand `restore --session` only the alice fake - bob's
        // fake is NOT in this input. Bob's pair is destroyed by the
        // wipe; the stderr summary must say so.
        let restore_input = format!("just this line with {alice_fake} in it");
        let mut r_out = Vec::new();
        let mut r_err = Vec::new();
        restore(
            &dir.vault_path(),
            &kc,
            &io,
            zeroizing(&restore_input),
            Some(&sp),
            t0 + 1,
            &mut r_out,
            &mut r_err,
        )
        .expect("restore OK");
        assert!(!sp.exists(), "wipe still happens");
        let restore_stderr = String::from_utf8(r_err).unwrap();
        assert!(
            restore_stderr.contains(
                "1 session entry not present in this input, discarded with the session file"
            ) || restore_stderr.contains(
                "1 session entries not present in this input, discarded with the session file"
            ),
            "stderr MUST report the count of destroyed-by-wipe entries; \
             silent destruction of mappings the user might have expected to \
             use on the next reply violates never-silent. Got: {restore_stderr:?}"
        );
    }

    // ----- Cross-vault refusal: wrong key → typed AeadDecrypt -----

    #[test]
    fn session_file_wrong_vault_key_fails_typed_aead_decrypt() {
        // A file written under vault A must not decrypt under vault
        // B. Prevents one vault's session bleeding real values
        // through another vault's process.
        let (dir_a, kc_a) = session_vault_with_pii_and_fpe(
            "chunk21-xvault-a",
            "email",
            "alice@example.com",
            "token",
            "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs",
        );
        let (dir_b, kc_b) = session_vault_with_pii_and_fpe(
            "chunk21-xvault-b",
            "email",
            "alice@example.com",
            "token",
            "HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs",
        );
        let io = StdVaultIo;
        let sp = session_path(&dir_a, "s.bin");
        let now = 1_000_000_u64;

        // Scrub under vault A.
        let mut out = Vec::new();
        let mut err = Vec::new();
        scrub(
            &dir_a.vault_path(),
            &kc_a,
            &io,
            zeroizing("hi alice@example.com"),
            Some(&sp),
            now,
            &mut out,
            &mut err,
        )
        .expect("scrub A OK");

        // Try to restore under vault B (different keychain → different
        // vault key → different session-AEAD subkey).
        let mut r_out = Vec::new();
        let mut r_err = Vec::new();
        let res = restore(
            &dir_b.vault_path(),
            &kc_b,
            &io,
            zeroizing("anything"),
            Some(&sp),
            now + 1,
            &mut r_out,
            &mut r_err,
        );
        assert!(
            matches!(
                res,
                Err(CommandError::Session(SessionFileError::AeadDecrypt))
            ),
            "cross-vault use must fail typed AeadDecrypt: got {res:?}"
        );
    }
}
