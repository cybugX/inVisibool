//! `clap` derive definitions for `invisibool`.
//!
//! Surface (M1 chunks 19-20):
//!
//! ```text
//! invisibool [--vault <PATH>] <SUBCOMMAND>
//!
//!   register <LABEL>     Add a new secret to the vault (value via TTY prompt or stdin pipe).
//!   list                 Print labels + kinds for every entry. Never prints the value.
//!   forget <LABEL>       Remove an entry. Exits 4 if the label does not exist.
//!   scrub  [FILE]        Read input from FILE or stdin, write scrubbed text to stdout.
//!   restore [FILE]       Read input from FILE or stdin, write restored text to stdout.
//! ```
//!
//! ## `scrub` / `restore` shape (chunks 20 and 21)
//!
//! Both take one optional positional (`FILE`) and one optional named
//! flag (`--session PATH`). Stdin is the default input source. There
//! is NO `--watch`, `--monitor`, `--clipboard`, or any flag that
//! would change the trigger from "the user typed the command" to a
//! background source. That invariant is the "restore is explicit-only,
//! never inferred" non-negotiable, and the scrub/restore-subcommand-
//! shape pins in this file fail if any such flag is added.
//!
//! `--session PATH` (chunk 21) threads a session-map file through
//! the engine's `scrub_with_session` / `restore_with_session` entry
//! points so PII / Card / Formatless registered values become
//! restorable across two separate CLI invocations. The file itself
//! is AEAD-encrypted under a subkey derived from the vault key, has
//! a mandatory 30-minute TTL that a repeat scrub does NOT extend,
//! and is unlinked by `restore --session PATH` after a successful
//! restore. Path-only in chunk 21 (matches `--vault PATH`); a
//! bare-name shorthand and the `$XDG_STATE_HOME` sessions-dir
//! default arrive with `invisibool session ls|clear` in M4a.
//!
//! ## Security-critical clap shape
//!
//! `register` has **exactly one argument**: the positional `LABEL`.
//! There is NO `--value`, `--secret`, `--password`, `--from-env`, or
//! `--from-file` flag, and the design forbids adding any. Reason: a
//! flag whose value is the secret would put the secret in `argv`,
//! visible to every other user via `/proc/<pid>/cmdline` (Linux),
//! `ps aux` (Unix), or Task Manager command-line columns (Windows),
//! and into shell history files (`.bash_history`, `.zsh_history`).
//! The register-subcommand-shape pin test in this file fails if
//! anyone ever adds such a flag.
//!
//! ## `--vault` placement
//!
//! `--vault` is a top-level flag, not redeclared per subcommand, so
//! it can appear before or after the subcommand:
//!
//! ```text
//! invisibool --vault /tmp/v.bin register my-token
//! invisibool register my-token --vault /tmp/v.bin   # SAME COMMAND
//! ```
//!
//! Path resolution: if `--vault` is set, the CLI uses that path
//! verbatim. Otherwise it calls
//! [`invisibool_engine::vault::default_vault_path`]. Either way the
//! path is opened through the same `Vault::open` entry point, which
//! enforces the AEAD magic-bytes check and the file-mode discipline
//! from chunk 18; `--vault` does not bypass those format checks.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "invisibool",
    about = "Local, privacy-first secrets and PII scrubber for LLM prompts.",
    version
)]
pub struct Cli {
    /// Override the default vault file location. If unset, the CLI
    /// uses the platform-default path (see
    /// `invisibool_engine::vault::default_vault_path`). The path is
    /// opened through `Vault::open` with the same magic-bytes /
    /// AEAD-format checks regardless of where it came from; pointing
    /// `--vault` at a non-vault file fails safely (BadMagic) rather
    /// than corrupting anything.
    #[arg(long, value_name = "PATH", global = true)]
    pub vault: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Add a new secret to the vault.
    ///
    /// The secret value is read from stdin: if stdin is a terminal,
    /// the CLI prompts with no echo (via rpassword); if stdin is
    /// piped from another process, the CLI reads until EOF and
    /// strips a single trailing newline. The value is NEVER taken
    /// from a command-line argument, environment variable, or file
    /// path - this is the chunk-19 secret-input contract and is
    /// pinned by a structural clap-shape test.
    Register {
        /// The label this secret is registered under (printed by
        /// `list`, referenced by `forget`). Not secret.
        #[arg(value_name = "LABEL")]
        label: String,
    },
    /// Print every registered entry's label and kind. Never prints
    /// the registered value (the underlying API has no value field
    /// at the projection layer).
    List,
    /// Remove the entry with the given label. Exits 4 if no entry
    /// matches the label (not silent: the user knows their `forget`
    /// did not change the vault).
    Forget {
        /// The label whose entry to remove.
        #[arg(value_name = "LABEL")]
        label: String,
    },
    /// Read input from FILE (or stdin if FILE is omitted), substitute
    /// format-preserving fakes for every registered or detected
    /// secret, and write the result to stdout. The scrubbed text is
    /// safe to paste into an LLM. Per-event indications and any
    /// unrestorability notices go to stderr; stdout carries ONLY the
    /// scrubbed text so it can be piped cleanly into the next tool.
    Scrub {
        /// Optional input file. If omitted, the CLI reads stdin to
        /// EOF. The path is the ONLY positional and the ONLY input
        /// source; there is no `--from-env`, `--clipboard`, or
        /// `--watch` flag (those would convert scrub from
        /// "operate on the bytes the user passed" to "trigger on
        /// other channels", which the non-negotiables forbid).
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        /// Optional AEAD-encrypted session file. When present, PII /
        /// Card / Formatless registered values become restorable via
        /// `restore --session <same-path>`. Absent (the default):
        /// stateless FF1 only, and the end-of-scrub notice lists
        /// which values will NOT be restorable. The file has a fixed
        /// 30-minute TTL that a repeat scrub does not extend; a
        /// scrub against an expired or wrong-magic file fails
        /// closed rather than silently resetting.
        #[arg(long, value_name = "PATH")]
        session: Option<PathBuf>,
    },
    /// Read input from FILE (or stdin if FILE is omitted), recover
    /// the registered real value behind every FF1 fake the engine
    /// recognises, and write the result to stdout. Restore operates
    /// ONLY on the bytes the user passes: never on the clipboard,
    /// never on a background source, never inferred from
    /// scrubbed-looking text outside the input scope. Bytes that
    /// are not the engine's fakes (random base62 strings,
    /// fake-shape-but-not-our-fake content) are left unchanged.
    Restore {
        /// Optional input file. If omitted, the CLI reads stdin to
        /// EOF. Same explicit-only rationale as `scrub`'s FILE.
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        /// Optional AEAD-encrypted session file (must match the one
        /// used by an earlier `scrub --session`). Recovers PII /
        /// Card / Formatless fakes in addition to FF1 fakes, and
        /// unlinks the file on success (spec A6 design 2:
        /// "restore --session consumes the file and wipes it").
        /// A missing session file is fatal - the flag never
        /// silently degrades to stateless restore.
        #[arg(long, value_name = "PATH")]
        session: Option<PathBuf>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    // ----- LOAD-BEARING: register has exactly one argument -----
    //
    // The register subcommand must take ONLY the LABEL positional.
    // If anyone ever adds `--value`, `--secret`, `--from-env`, or
    // any other value-carrying flag, the secret-input contract is
    // broken: the value would land in argv, visible via
    // /proc/<pid>/cmdline, `ps`, Task Manager, and shell history.
    // This test fails if any non-help argument appears on
    // `register` beyond the LABEL positional.
    #[test]
    fn register_subcommand_has_no_value_carrying_argument() {
        let cmd = Cli::command();
        let register = cmd
            .find_subcommand("register")
            .expect("the register subcommand must exist");
        // clap auto-adds --help on every subcommand; filter it out
        // so the test compares only OUR declarations. If clap ever
        // adds another auto-arg with a name other than "help",
        // this filter needs revisiting; the assertion message
        // surfaces the actual id list to make that easy to spot.
        let our_args: Vec<&clap::Arg> = register
            .get_arguments()
            .filter(|a| a.get_id() != "help")
            .collect();
        assert_eq!(
            our_args.len(),
            1,
            "register must declare exactly ONE argument (LABEL positional); \
             adding a value-carrying flag would expose the secret via argv. \
             Found args: {:?}",
            our_args
                .iter()
                .map(|a| a.get_id().as_str())
                .collect::<Vec<_>>()
        );
        let only = our_args[0];
        assert!(
            only.is_positional(),
            "register's only arg must be positional (LABEL); a named option \
             would accept a value on the command line. Got: {:?}",
            only.get_id().as_str()
        );
        assert_eq!(
            only.get_id().as_str(),
            "label",
            "register's positional must be named 'label'"
        );
    }

    // ----- forget shape: one positional (LABEL), no other args -----
    //
    // Mirror of the register pin so a similar drift on forget is
    // caught immediately. `forget` does not take a secret value, so
    // the argv-leak hazard is less acute, but keeping the surface
    // narrow keeps the parser predictable.
    #[test]
    fn forget_subcommand_has_exactly_one_positional() {
        let cmd = Cli::command();
        let forget = cmd
            .find_subcommand("forget")
            .expect("the forget subcommand must exist");
        let our_args: Vec<&clap::Arg> = forget
            .get_arguments()
            .filter(|a| a.get_id() != "help")
            .collect();
        assert_eq!(our_args.len(), 1);
        assert!(our_args[0].is_positional());
        assert_eq!(our_args[0].get_id().as_str(), "label");
    }

    // ----- list shape: no positional / option args -----
    #[test]
    fn list_subcommand_takes_no_arguments() {
        let cmd = Cli::command();
        let list = cmd
            .find_subcommand("list")
            .expect("the list subcommand must exist");
        let our_args: Vec<&clap::Arg> = list
            .get_arguments()
            .filter(|a| a.get_id() != "help" && a.get_id() != "vault")
            .collect();
        assert!(
            our_args.is_empty(),
            "list must take no arguments beyond the global --vault flag; \
             found: {:?}",
            our_args
                .iter()
                .map(|a| a.get_id().as_str())
                .collect::<Vec<_>>()
        );
    }

    // ----- LOAD-BEARING: scrub/restore accept only FILE, --vault, and --session -----
    //
    // These pins are the structural enforcement of invariant 1
    // ("restore is explicit-only, never inferred") at the parser
    // layer. Each subcommand must accept ONLY:
    //   - the optional FILE positional (the user's explicit input scope),
    //   - the global `--vault` flag (a path, not a secret value), and
    //   - the chunk-21 `--session` flag (a path to the AEAD session file).
    //
    // No `--watch`, `--monitor`, `--clipboard`, `--from-env`,
    // `--auto`, `--background`, etc. The test asserts the actual
    // arg SET so a drift fails CI with a clear list of the new args
    // (rather than just a count mismatch that would be ambiguous when
    // chunk 21 legitimately added the `session` arg).
    #[test]
    fn scrub_subcommand_has_only_optional_file_and_session_flag() {
        let cmd = Cli::command();
        let scrub = cmd
            .find_subcommand("scrub")
            .expect("the scrub subcommand must exist");
        // Exclude clap-auto `--help` and the global `--vault` from
        // the assertion - we are pinning OUR scrub-specific surface.
        let mut ids: Vec<&str> = scrub
            .get_arguments()
            .filter(|a| a.get_id() != "help" && a.get_id() != "vault")
            .map(|a| a.get_id().as_str())
            .collect();
        ids.sort();
        assert_eq!(
            ids,
            vec!["file", "session"],
            "scrub must accept exactly {{FILE positional, --session PATH flag}} \
             beyond --help/--vault. Any new named flag risks becoming a \
             non-explicit input trigger (--watch / --clipboard / --from-env) \
             and must land through this pin's ledger."
        );

        // FILE is positional; --session is a named flag.
        let file = scrub
            .get_arguments()
            .find(|a| a.get_id() == "file")
            .expect("file arg present");
        assert!(file.is_positional(), "FILE must be positional");
        let session = scrub
            .get_arguments()
            .find(|a| a.get_id() == "session")
            .expect("session arg present");
        assert!(
            !session.is_positional(),
            "--session must be a named flag, not a positional"
        );
        assert_eq!(session.get_long(), Some("session"));
    }

    #[test]
    fn restore_subcommand_has_only_optional_file_and_session_flag() {
        let cmd = Cli::command();
        let restore = cmd
            .find_subcommand("restore")
            .expect("the restore subcommand must exist");
        let mut ids: Vec<&str> = restore
            .get_arguments()
            .filter(|a| a.get_id() != "help" && a.get_id() != "vault")
            .map(|a| a.get_id().as_str())
            .collect();
        ids.sort();
        assert_eq!(
            ids,
            vec!["file", "session"],
            "restore must accept exactly {{FILE positional, --session PATH flag}} \
             beyond --help/--vault. A `--clipboard`, `--watch`, or `--auto` flag \
             here would break the explicit-only invariant - restore must only \
             ever operate on bytes the user explicitly passed in."
        );

        let file = restore
            .get_arguments()
            .find(|a| a.get_id() == "file")
            .expect("file arg present");
        assert!(file.is_positional(), "FILE must be positional");
        let session = restore
            .get_arguments()
            .find(|a| a.get_id() == "session")
            .expect("session arg present");
        assert!(
            !session.is_positional(),
            "--session must be a named flag, not a positional"
        );
        assert_eq!(session.get_long(), Some("session"));
    }

    // ----- clap self-test: the derived parser is internally consistent -----
    #[test]
    fn clap_command_passes_internal_assertions() {
        Cli::command().debug_assert();
    }
}
