//! Invisibool engine: detection, tokenization, vault.
//!
//! Surface-agnostic — reused by the CLI binary today and by future surfaces
//! (browser extension, traffic proxy) as separate projects. This crate
//! carries `#![forbid(unsafe_code)]` and depends on no network primitives.
//!
//! M0a is a scaffold only; real implementations land in M0b and later.

#![forbid(unsafe_code)]
