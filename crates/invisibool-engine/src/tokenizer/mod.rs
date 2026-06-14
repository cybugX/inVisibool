//! Tokenizer layer: generate format-preserving fake values that substitute
//! for detected secrets.
//!
//! Reserved-range generators produce fakes from value spaces that
//! real-world identifiers cannot occupy — RFC 2606 emails, RFC 5737
//! IPv4 addresses, the 555-01XX reserved phone exchange, and card
//! numbers in non-issued test BINs. Collision safety follows from range
//! membership: a fake from `@example.com` cannot equal a real email
//! address; an IPv4 fake from 192.0.2.0/24 cannot equal a real public
//! address. The cost is that fakes are linkable to each other (a stable
//! fake reveals which detector path produced it), which the threat
//! model documents.
//!
//! Each generator is deterministic in its seed: identical seed bytes
//! produce identical output. The caller chooses what to use as the
//! seed — the raw secret (deterministic across sessions) or a value
//! salted with a session key (per-session stable only).

pub mod alphabet;
pub mod fpe;
pub mod mac;
pub mod reserved;
pub mod session;

pub use alphabet::{Alphabet, AlphabetError};
