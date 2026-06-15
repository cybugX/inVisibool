//! Criterion benches for `Engine::scrub` over the committed corpus.
//!
//! Three benches, each named so the CI regression tripwire can find them
//! deterministically in `target/criterion/*/new/estimates.json`:
//!
//!   * `engine_scrub/prose_2kb_three_secrets` — the primary latency
//!     target. ~2 KB of realistic prose with three registered values;
//!     the matcher fires three times. The project's per-call latency
//!     goal — p50 < 1 ms / p99 < 5 ms on a consistent machine — is
//!     measured here, with the published README numbers taken from runs
//!     on a developer box rather than from CI's shared runners.
//!   * `engine_scrub/source_64kb_no_secrets` — moderate input, zero
//!     hits. Measures Aho-Corasick scanning throughput on text the
//!     matcher decides nothing about.
//!   * `engine_scrub/log_1mb_no_secrets` — large input, zero hits. Same
//!     fast path, scaled, to surface any per-byte cost that the small
//!     fixture would hide.
//!
//! The CI gate is RELATIVE-ONLY (a >2× regression vs. the committed
//! baseline). Shared CI runners are too noisy for absolute wall-clock
//! pass/fail thresholds — a hard "fail if > 5 ms" rule on a shared box
//! produces flaky red builds that contributors learn to ignore, which is
//! worse than no gate at all. The absolute targets are the product
//! promise published in the README; the CI gate is a regression
//! tripwire only.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use invisibool_engine::tokenizer::alphabet::Alphabet;
use invisibool_engine::tokenizer::fpe::{
    FpeRegistration, InMemoryKeyProvider, RegisteredValue, TWEAK_LEN,
};
use invisibool_engine::Engine;
use std::hint::black_box;
use std::time::Duration;
use zeroize::Zeroizing;

/// The three secrets registered for the prose bench. MUST equal the
/// `PROSE_SECRETS` constants in `examples/gen_bench_fixtures.rs`; if they
/// drift the bench's startup assertion fails loudly rather than the
/// matcher silently finding zero hits and the bench timing the wrong
/// thing.
const PROSE_SECRETS: [&str; 3] = [
    "inv-EXAMPLE-EXAMPLEa1b2c3d4e5f6g7",
    "inv-EXAMPLE-EXAMPLEh8i9j0k1l2m3n4",
    "inv-EXAMPLE-EXAMPLEo5p6q7r8s9t0u1",
];
const PROSE_PREFIX: &str = "inv-EXAMPLE-";

const PROSE: &str = include_str!("../tests/fixtures/prose_2kb.txt");
const SOURCE: &str = include_str!("../tests/fixtures/source_64kb.rs");
const LOG: &str = include_str!("../tests/fixtures/log_1mb.log");

fn engine_with_prose_secrets() -> Engine {
    let key_provider = InMemoryKeyProvider::new(vec![0xa5; 32]);
    let registered: Vec<RegisteredValue> = PROSE_SECRETS
        .iter()
        .enumerate()
        .map(|(i, value)| {
            let mut tweak = [0u8; TWEAK_LEN];
            tweak[0] = i as u8;
            RegisteredValue::Fpe(FpeRegistration {
                label: format!("bench-{i}"),
                value: Zeroizing::new((*value).to_string()),
                tweak,
                alphabet: Alphabet::BASE62,
                prefix: PROSE_PREFIX.to_string(),
            })
        })
        .collect();
    Engine::new(
        &key_provider,
        registered,
        Vec::new(),
        b"bench-mac-key-fixed-for-determinism".to_vec(),
    )
    .expect("engine builds for bench")
}

/// Built once; reused by the no-secrets benches so the matcher carries
/// the same registered set as the prose bench (the fast path's cost
/// depends on the registered-value set, not just on the input).
fn assert_prose_contains_secrets() {
    for s in PROSE_SECRETS {
        assert!(
            PROSE.contains(s),
            "prose fixture does not contain {s}; regenerate via \
             `cargo run --example gen_bench_fixtures -p invisibool-engine` \
             and keep PROSE_SECRETS in scrub.rs and gen_bench_fixtures.rs in sync"
        );
    }
}

fn bench_scrub(c: &mut Criterion) {
    assert_prose_contains_secrets();
    let engine = engine_with_prose_secrets();

    let mut group = c.benchmark_group("engine_scrub");
    // The latency goal is per-call, not per-byte. Bytes-throughput is
    // still useful information so Criterion can print MB/s for the
    // bigger fixtures.
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    group.sample_size(50);

    // Prose: 2 KB, three hits. Primary latency target.
    group.throughput(Throughput::Bytes(PROSE.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("prose_2kb_three_secrets", PROSE.len()),
        &PROSE,
        |b, &input| {
            b.iter(|| {
                let r = engine.scrub(black_box(input));
                black_box(r)
            });
        },
    );

    // Source: 64 KB, no hits. Fast-path scan.
    group.throughput(Throughput::Bytes(SOURCE.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("source_64kb_no_secrets", SOURCE.len()),
        &SOURCE,
        |b, &input| {
            b.iter(|| {
                let r = engine.scrub(black_box(input));
                black_box(r)
            });
        },
    );

    // Log: 1 MB, no hits. Same fast path, scaled. Fewer samples to keep
    // the bench total bounded.
    group.sample_size(20);
    group.throughput(Throughput::Bytes(LOG.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("log_1mb_no_secrets", LOG.len()),
        &LOG,
        |b, &input| {
            b.iter(|| {
                let r = engine.scrub(black_box(input));
                black_box(r)
            });
        },
    );

    group.finish();
}

criterion_group!(benches, bench_scrub);
criterion_main!(benches);
