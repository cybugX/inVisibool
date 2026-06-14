//! Invisibool engine: detection, tokenization, vault.
//!
//! Surface-agnostic — reused by the CLI binary today and by future surfaces
//! (browser extension, traffic proxy) as separate projects. This crate
//! carries `#![forbid(unsafe_code)]` and depends on no network primitives.

#![forbid(unsafe_code)]

pub mod detection;
pub mod idempotence;
pub mod tokenizer;
