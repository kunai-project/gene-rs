//! How gene writes raw bytes (e.g. Linux paths) as text.
//!
//! The output format is part of gene's rule language: a rule matching
//! `\xff` must match the same bytes in every program using gene. Any change
//! to the format is a breaking change of this crate.

use std::borrow::Cow;

#[inline]
fn low_nibble_to_hex(b: u8) -> char {
    let b = b & 0xf;
    match b {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        0xa => 'a',
        0xb => 'b',
        0xc => 'c',
        0xd => 'd',
        0xe => 'e',
        0xf => 'f',
        _ => unreachable!(),
    }
}

/// Converts untrusted bytes to text: valid UTF-8 is kept as is and every
/// invalid byte is written as `\xNN`. Backslashes are not escaped, so the
/// conversion cannot always be reversed.
pub fn escape_invalid_utf8(bytes: &[u8]) -> Cow<'_, str> {
    let mut out = String::new();
    for chunk in bytes.utf8_chunks() {
        if chunk.valid().len() == bytes.len() {
            return Cow::Borrowed(chunk.valid());
        }
        out.reserve(bytes.len());
        out.push_str(chunk.valid());
        for byte in chunk.invalid() {
            out.push_str("\\x");
            out.push(low_nibble_to_hex(byte >> 4));
            out.push(low_nibble_to_hex(*byte));
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_utf8_is_borrowed() {
        assert!(matches!(
            escape_invalid_utf8(b"/bin/ls"),
            Cow::Borrowed("/bin/ls")
        ));
    }

    #[test]
    fn test_empty() {
        assert_eq!(escape_invalid_utf8(b""), "");
    }

    #[test]
    fn test_valid_non_ascii_is_kept() {
        assert_eq!(escape_invalid_utf8("/tmp/é".as_bytes()), "/tmp/é");
    }

    #[test]
    fn test_invalid_byte_is_lowercase_hex() {
        assert_eq!(escape_invalid_utf8(b"/tmp/\xff"), "/tmp/\\xff");
        assert_eq!(escape_invalid_utf8(b"\xab"), "\\xab");
    }

    #[test]
    fn test_each_invalid_byte_is_escaped() {
        assert_eq!(escape_invalid_utf8(b"a\xff\xfeb"), "a\\xff\\xfeb");
        // truncated multi-byte sequence of `€` (e2 82 ac)
        assert_eq!(escape_invalid_utf8(b"a\xe2\x82b"), "a\\xe2\\x82b");
    }

    #[test]
    fn test_valid_utf8_around_invalid_bytes() {
        assert_eq!(escape_invalid_utf8(b"\xc3\xa9\xff\xc3\xa9"), "é\\xffé");
    }

    #[test]
    fn test_backslash_is_not_escaped() {
        assert_eq!(escape_invalid_utf8(b"C:\\dir"), "C:\\dir");
        // an escaped byte and its literal text look the same
        assert_eq!(escape_invalid_utf8(b"\\xff"), escape_invalid_utf8(b"\xff"));
    }
}
