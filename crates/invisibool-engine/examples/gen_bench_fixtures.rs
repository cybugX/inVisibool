//! Deterministic generator for the committed bench corpus.
//!
//! Produces the three fixture files exercised by `benches/scrub.rs`:
//!
//!   tests/fixtures/prose_2kb.txt    - ~2 KB English prose with 3 secrets
//!   tests/fixtures/source_64kb.rs   - ~64 KB synthetic Rust source (no secrets)
//!   tests/fixtures/log_1mb.log      - ~1 MB synthetic access log (no secrets)
//!
//! All three are written by a fixed-output procedure with no randomness, so
//! re-running this example after any source change reproduces the exact
//! bytes that should be committed. CI's regression tripwire pins on these
//! fixtures, so the committed bytes must match what this generator emits -
//! a regen drift would silently move the baseline.
//!
//! Every secret-shaped token in the prose fixture uses an `inv-EXAMPLE-`
//! prefix and a body whose first characters spell `EXAMPLE`. The prefix
//! is project-namespaced (no third-party scanner has a rule for it), and
//! the `EXAMPLE` marker is the project's convention for fixture-only
//! secret-shaped data - it tells both human readers and third-party
//! secret scanners that the value is bench input, not a real credential.
//!
//! Run from the workspace root:
//!     cargo run --example gen_bench_fixtures -p invisibool-engine

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

fn fixtures_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/invisibool-engine/ when run via
    // `cargo run --example` against this crate. The corpus lives under
    // `tests/fixtures/` so the repo-wide secret-scanner allowlist can
    // be narrowly path-scoped to exactly one directory.
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("cargo sets CARGO_MANIFEST_DIR for example binaries");
    Path::new(&manifest).join("tests").join("fixtures")
}

fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create fixtures dir");
    }
    let mut f = fs::File::create(path).expect("open fixture for write");
    f.write_all(bytes).expect("write fixture bytes");
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
}

fn main() {
    let dir = fixtures_dir();
    write_file(&dir.join("prose_2kb.txt"), prose_2kb().as_bytes());
    write_file(&dir.join("source_64kb.rs"), source_64kb().as_bytes());
    write_file(&dir.join("log_1mb.log"), log_1mb().as_bytes());
}

// ---------- prose, ~2 KB, three secrets ----------

/// Three registered-style tokens. Each has the `inv-EXAMPLE-` prefix and
/// a 20-char BASE62 body whose first seven characters spell "EXAMPLE".
/// The bench's engine registers these exact strings so the Aho-Corasick
/// automaton fires on each occurrence.
pub const PROSE_SECRETS: [&str; 3] = [
    "inv-EXAMPLE-EXAMPLEa1b2c3d4e5f6g7",
    "inv-EXAMPLE-EXAMPLEh8i9j0k1l2m3n4",
    "inv-EXAMPLE-EXAMPLEo5p6q7r8s9t0u1",
];

fn prose_2kb() -> String {
    // ~2 KB of prose written as a fake handoff doc that drops three
    // registered-style tokens at distinct positions. Hand-written rather
    // than templated so the matcher sees realistic English byte
    // distributions, not a repeating pattern.
    let mut s = String::with_capacity(2200);
    s.push_str(
        "Onboarding notes for the data-ingest service rewrite.\n\
         \n\
         The current ingestor reads from the upstream queue and forwards \
         events to the warehouse over the internal bus. There are three \
         credentials that the new service needs in order to come up, all \
         of which live in the team's secret manager today. The first is \
         the API token used to talk to the upstream queue's admin \
         endpoint, currently rotated weekly. For the purposes of these \
         notes the token is ",
    );
    s.push_str(PROSE_SECRETS[0]);
    s.push_str(
        " and the rotation is performed by the queue team on Mondays. \
         If the rotation runs while a deploy is in flight the deploy \
         will retry once and then page the on-call. None of that logic \
         is moving in this rewrite; the new service inherits it.\n\
         \n\
         The second credential is the warehouse loader's identity token, \
         used to assume the loader role and sign individual batches. \
         Today that token is ",
    );
    s.push_str(PROSE_SECRETS[1]);
    s.push_str(
        " and it is loaded from the secret manager once at process \
         start. The new service will load it the same way and refresh \
         on a five-minute interval rather than relying on the on-start \
         load; the loader role's tokens are valid for thirty minutes, \
         so the refresh window leaves plenty of headroom. The refresh \
         path has its own structured log line; do not let it leak the \
         value, just the prefix and the expiry stamp.\n\
         \n\
         The third credential is the metrics-bus push token, used by \
         the per-batch telemetry path. The current value is ",
    );
    s.push_str(PROSE_SECRETS[2]);
    s.push_str(
        " and unlike the first two this one is not rotated on a \
         schedule; the metrics team only rotates it when a leak is \
         suspected. The new service can keep this on a longer refresh \
         interval (twelve hours) since the value is so stable. Make \
         sure the refresh path uses the same exponential backoff that \
         the loader path uses; the metrics endpoint is the first thing \
         that goes flaky under load and we do not want the refresh to \
         pile on.\n\
         \n\
         None of the three credentials are committed to this repo. \
         The values above are placeholders for the benchmark corpus \
         and are recognisable as such from the EXAMPLE marker inside \
         each one. Real values live in the secret manager and only the \
         service-account identity that backs the deploy can read them.\n",
    );
    // Pad to a round ~2 KB so the bench input size is stable; padding
    // is plain prose so the matcher still sees realistic text.
    while s.len() < 2048 {
        s.push_str(
            " The remaining paragraphs of this handoff note describe \
             the deployment topology and the on-call rotation; both are \
             unchanged from the previous service and do not influence \
             the new code path.\n",
        );
    }
    s.truncate(2048);
    s
}

// ---------- source, ~64 KB, no secrets ----------

fn source_64kb() -> String {
    // Synthetic but Rust-shaped source: a module with N stub functions
    // and a docstring above each one. Token distribution is realistic
    // (identifiers, punctuation, whitespace) so the matcher's hot-path
    // scan sees a representative byte mix. No registered values appear,
    // so this bench measures the no-match scanning throughput.
    let header = "// Synthetic source fixture for the invisibool-engine scrub bench.\n\
                  // No secrets: exercises the matcher's no-match fast path on\n\
                  // moderate input. Generated by examples/gen_bench_fixtures.rs;\n\
                  // do not edit by hand.\n\
                  \n\
                  #![allow(dead_code, unused_variables, clippy::all)]\n\
                  \n";
    let mut s = String::with_capacity(70_000);
    s.push_str(header);
    let mut i: usize = 0;
    while s.len() < 65_536 {
        s.push_str(&format!(
            "/// Compute stage {i} of the synthetic pipeline.\n\
             ///\n\
             /// This function does no real work; it exists so the fixture has\n\
             /// realistic identifier and punctuation density without carrying\n\
             /// any meaningful logic that a future reader could misread.\n\
             pub fn stage_{i:05}(input: u64) -> u64 {{\n\
             \x20   let a = input.wrapping_add({i});\n\
             \x20   let b = a.wrapping_mul(2654435761);\n\
             \x20   let c = b ^ (b >> 13);\n\
             \x20   let d = c.wrapping_add(0x9E3779B97F4A7C15);\n\
             \x20   d ^ (d >> 17)\n\
             }}\n\
             \n"
        ));
        i += 1;
    }
    s.truncate(65_536);
    s
}

// ---------- log, ~1 MB, no secrets ----------

fn log_1mb() -> String {
    // Synthetic combined-log-format lines, deterministic. No secrets -
    // this is the large-input no-match throughput bench. Cycling through
    // a small set of paths and agents keeps the bytes realistic without
    // introducing per-line randomness.
    let paths = [
        "/api/v1/health",
        "/api/v1/items/list",
        "/api/v1/items/42",
        "/static/app.js",
        "/static/styles.css",
        "/favicon.ico",
        "/robots.txt",
        "/api/v1/search?q=widget",
    ];
    let agents = [
        "Mozilla/5.0 (compatible; benchcorpus/1.0)",
        "curl/8.0.1",
        "Go-http-client/1.1",
        "python-requests/2.32",
    ];
    let methods = ["GET", "POST", "GET", "GET", "HEAD"];
    let statuses = [200, 200, 200, 204, 304, 404];

    let mut s = String::with_capacity(1_100_000);
    let mut i: usize = 0;
    while s.len() < 1_048_576 {
        let ip_a = (i % 240) + 10;
        let ip_b = (i / 240) % 240;
        let method = methods[i % methods.len()];
        let path = paths[i % paths.len()];
        let status = statuses[i % statuses.len()];
        let bytes = 256 + (i % 8192);
        let agent = agents[i % agents.len()];
        // RFC-3339-ish synthetic timestamp; second counter just increments.
        let ts_sec = 1_700_000_000_u64 + i as u64;
        s.push_str(&format!(
            "10.{ip_a}.{ip_b}.1 - - [{ts_sec}] \"{method} {path} HTTP/1.1\" {status} {bytes} \"-\" \"{agent}\"\n"
        ));
        i += 1;
    }
    s.truncate(1_048_576);
    s
}
