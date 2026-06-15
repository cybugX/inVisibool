# Bench corpus

The three files in this directory are the fixed inputs for the `scrub`
Criterion bench (`benches/scrub.rs`) and the CI regression tripwire
(`scripts/bench-regression.py`) that gates against slowdowns versus the
committed baseline.

| File             | Size        | Registered hits | What it measures                                       |
| ---------------- | ----------- | --------------- | ------------------------------------------------------ |
| `prose_2kb.txt`  |     2,048 B |               3 | Realistic short LLM prompt — the latency-critical case |
| `source_64kb.rs` |    65,536 B |               0 | Moderate no-match input — matcher scan throughput      |
| `log_1mb.log`    | 1,048,576 B |               0 | Large-input no-match — matcher throughput at scale     |

The corpus lives under `tests/fixtures/` (not next to the bench file)
so the repo-wide secret-scanner allowlist can be narrowly scoped to
exactly one directory.

## Hygiene

Every secret-shaped token in `prose_2kb.txt` is fixture-only synthetic
data. Each one starts with the project-namespaced `inv-EXAMPLE-` prefix
(no third-party secret scanner has a rule for it) and has a body whose
first seven characters spell `EXAMPLE`. The other two fixtures contain
no secret-shaped tokens at all, so they will never collide with a real
credential a contributor accidentally pastes near the bench files.

The repo-root `.gitleaks.toml` carries a narrowly path-scoped allowlist
covering exactly `crates/invisibool-engine/tests/fixtures/**` so the
fixture tokens don't trip the scanner; the rest of the tree stays
fully scanned.

## Regenerating

These files are produced by a deterministic generator. If you change the
generator, re-run it and commit the resulting bytes alongside the source
change in the same commit — otherwise the CI regression tripwire would
be comparing measurements against bytes that no longer match what the
bench actually scrubs.

```
cargo run --example gen_bench_fixtures -p invisibool-engine
```

After regenerating, run `git diff -- crates/invisibool-engine/tests/fixtures/`
to inspect. If either the prose hand-text or the procedural log/source
shape changed, follow `docs/RUNBOOK_baseline_refresh.md` to refresh the
committed `bench-baseline.json` from a CI run on the pinned runner class
— the latency numbers depend on the exact input bytes, so a fixture edit
and a baseline refresh always travel together.
