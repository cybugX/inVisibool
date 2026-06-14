//! Character set used by the FPE and MAC tokenizers.
//!
//! An `Alphabet` defines: which characters can appear in a fake of this
//! type, their canonical order (used as the symbol-to-index mapping for
//! FF1), and the radix.
//!
//! The eight named constants (`BASE62`, `BASE32`, `HEX_LOWER`, etc.)
//! cover the common cases and bypass validation; they are hand-curated
//! and the unit tests verify each one still satisfies the rules below.
//!
//! Runtime construction goes through `Alphabet::try_custom()` and is
//! validated against:
//!
//! - **ASCII only** — multi-byte UTF-8 cannot be safely indexed by
//!   byte offset.
//! - **No whitespace** — whitespace characters make candidate boundaries
//!   undefinable in free text (project spec §A6).
//! - **All distinct** — every symbol must appear at most once; otherwise
//!   `index_of` would be ambiguous.
//! - **Radix in `[2, 65535]`** — NIST SP 800-38G's FF1 domain bounds.
//!
//! Construction validation closes the gap that a misconfigured detection
//! rule (M2) cannot smuggle a non-ASCII or zero-symbol alphabet into FF1
//! and produce malformed ciphertext.

use std::borrow::Cow;

/// Character set for an FPE or MAC fake.
#[derive(Clone, Debug)]
pub struct Alphabet {
    chars: Cow<'static, str>,
}

impl Alphabet {
    /// `0-9 A-Z a-z` — radix 62.
    pub const BASE62: Self =
        Self::unchecked("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
    /// RFC 4648 base32: `A-Z 2-7` — radix 32.
    pub const BASE32: Self = Self::unchecked("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
    /// `0-9 a-f` — radix 16.
    pub const HEX_LOWER: Self = Self::unchecked("0123456789abcdef");
    /// `0-9 A-F` — radix 16.
    pub const HEX_UPPER: Self = Self::unchecked("0123456789ABCDEF");
    /// `0-9` — radix 10.
    pub const DIGITS: Self = Self::unchecked("0123456789");
    /// `a-z` — radix 26.
    pub const ALPHA_LOWER: Self = Self::unchecked("abcdefghijklmnopqrstuvwxyz");
    /// `A-Z` — radix 26.
    pub const ALPHA_UPPER: Self = Self::unchecked("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    /// `0-9 a-z` — radix 36.
    pub const BASE36_LOWER: Self = Self::unchecked("0123456789abcdefghijklmnopqrstuvwxyz");

    /// Build without validation. Reserved for the hand-curated named
    /// constants above; verified once by `every_named_constant_passes_validation`.
    pub(crate) const fn unchecked(chars: &'static str) -> Self {
        Self {
            chars: Cow::Borrowed(chars),
        }
    }

    /// Build an alphabet from a runtime-supplied character set. Validates
    /// the four invariants listed in the module docs and returns
    /// `AlphabetError` on any violation.
    pub fn try_custom<S: Into<Cow<'static, str>>>(chars: S) -> Result<Self, AlphabetError> {
        let chars = chars.into();
        validate(&chars)?;
        Ok(Self { chars })
    }

    /// Number of symbols in this alphabet.
    pub fn radix(&self) -> u32 {
        // ASCII-only after validation, so byte length equals char count.
        u32::try_from(self.chars.len()).expect("alphabet size fits in u32 after validation")
    }

    /// MAC-tail length `K` for this alphabet: the smallest count of
    /// symbols whose information content reaches 32 bits.
    /// `K = ceil(32 / log2(radix))`.
    pub fn mac_tail_len(&self) -> usize {
        let bits_per_char = f64::from(self.radix()).log2();
        (32.0 / bits_per_char).ceil() as usize
    }

    /// True iff `c` is a symbol of this alphabet.
    pub fn contains(&self, c: char) -> bool {
        self.chars.contains(c)
    }

    /// Index of `c` within this alphabet, or `None` if it isn't a symbol.
    /// Used by FF1 to convert plaintext characters to numerals.
    pub fn index_of(&self, c: char) -> Option<u32> {
        // ASCII-only; `find` returns the byte offset, which equals the
        // character index under that constraint.
        self.chars
            .find(c)
            .map(|i| u32::try_from(i).expect("index < radix < u32::MAX"))
    }

    /// Symbol at `index`. Used by FF1 to convert numerals back to
    /// characters. Panics if `index >= radix`.
    pub(crate) fn symbol_at(&self, index: u32) -> char {
        self.chars
            .as_bytes()
            .get(index as usize)
            .map(|b| char::from(*b))
            .expect("index < radix by construction")
    }
}

/// Reasons a custom alphabet fails validation.
#[derive(Debug, PartialEq, Eq)]
pub enum AlphabetError {
    /// The character set contains non-ASCII characters.
    NonAscii,
    /// The character set contains whitespace (space, tab, newline, ...).
    ContainsWhitespace,
    /// The character set has fewer than 2 or more than 65535 symbols.
    RadixOutOfRange { radix: usize },
    /// The character set contains a repeated character.
    DuplicateChar { ch: char },
}

impl std::fmt::Display for AlphabetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonAscii => write!(f, "alphabet must be ASCII"),
            Self::ContainsWhitespace => write!(f, "alphabet must not contain whitespace"),
            Self::RadixOutOfRange { radix } => write!(
                f,
                "alphabet radix {radix} outside NIST FF1 bounds [2, 65535]"
            ),
            Self::DuplicateChar { ch } => {
                write!(f, "alphabet contains duplicate character {ch:?}")
            }
        }
    }
}

impl std::error::Error for AlphabetError {}

fn validate(chars: &str) -> Result<(), AlphabetError> {
    if !chars.is_ascii() {
        return Err(AlphabetError::NonAscii);
    }
    if chars.chars().any(char::is_whitespace) {
        return Err(AlphabetError::ContainsWhitespace);
    }
    let radix = chars.chars().count();
    if !(2..=65535).contains(&radix) {
        return Err(AlphabetError::RadixOutOfRange { radix });
    }
    // After the ASCII check above we know every char fits in a byte.
    let mut seen = [false; 128];
    for c in chars.chars() {
        let b = c as usize;
        if seen[b] {
            return Err(AlphabetError::DuplicateChar { ch: c });
        }
        seen[b] = true;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_named() -> [Alphabet; 8] {
        [
            Alphabet::BASE62,
            Alphabet::BASE32,
            Alphabet::HEX_LOWER,
            Alphabet::HEX_UPPER,
            Alphabet::DIGITS,
            Alphabet::ALPHA_LOWER,
            Alphabet::ALPHA_UPPER,
            Alphabet::BASE36_LOWER,
        ]
    }

    #[test]
    fn every_named_constant_passes_validation() {
        for ab in all_named() {
            validate(&ab.chars).unwrap_or_else(|e| {
                panic!(
                    "named constant with radix {} failed validation: {e}",
                    ab.radix()
                )
            });
        }
    }

    #[test]
    fn try_custom_accepts_valid_alphabet() {
        let a = Alphabet::try_custom("abc123").unwrap();
        assert_eq!(a.radix(), 6);
        assert!(a.contains('a'));
        assert!(a.contains('3'));
        assert!(!a.contains('z'));
    }

    #[test]
    fn try_custom_accepts_owned_string() {
        // Cow<'static, str> needs an owned String for runtime input.
        let dynamic = String::from("abc");
        let a = Alphabet::try_custom(dynamic).unwrap();
        assert_eq!(a.radix(), 3);
    }

    #[test]
    fn try_custom_rejects_non_ascii() {
        let err = Alphabet::try_custom("éabc").unwrap_err();
        assert_eq!(err, AlphabetError::NonAscii);
    }

    #[test]
    fn try_custom_rejects_whitespace() {
        for s in ["ab cd", "ab\tc", "ab\nc"] {
            let err = Alphabet::try_custom(s).unwrap_err();
            assert_eq!(err, AlphabetError::ContainsWhitespace, "input {s:?}");
        }
    }

    #[test]
    fn try_custom_rejects_duplicates() {
        let err = Alphabet::try_custom("abca").unwrap_err();
        assert_eq!(err, AlphabetError::DuplicateChar { ch: 'a' });
    }

    #[test]
    fn try_custom_rejects_radix_too_small() {
        assert_eq!(
            Alphabet::try_custom("a").unwrap_err(),
            AlphabetError::RadixOutOfRange { radix: 1 }
        );
        assert_eq!(
            Alphabet::try_custom("").unwrap_err(),
            AlphabetError::RadixOutOfRange { radix: 0 }
        );
    }

    #[test]
    fn radix_matches_chars_count() {
        for ab in all_named() {
            assert_eq!(ab.radix() as usize, ab.chars.chars().count());
        }
    }

    #[test]
    fn index_of_and_symbol_at_roundtrip() {
        let ab = Alphabet::BASE62;
        for c in ab.chars.chars() {
            let i = ab.index_of(c).unwrap();
            assert_eq!(ab.symbol_at(i), c);
        }
        assert!(ab.index_of('!').is_none());
    }

    #[test]
    fn mac_tail_lengths_meet_32_bit_floor() {
        for ab in all_named() {
            let bits = ab.mac_tail_len() as f64 * f64::from(ab.radix()).log2();
            assert!(
                bits >= 32.0,
                "alphabet radix {} fails 32-bit floor: {bits} bits",
                ab.radix()
            );
        }
    }
}
