//! How gene represents raw data (e.g. Linux paths) as text, and back.
//!
//! [`escape_invalid_utf8`] keeps valid UTF-8 as is and writes each invalid
//! byte as `\xNN`; [`unescape_invalid_utf8`] restores the exact bytes.
//! [`escape_invalid_utf8_or_byte`] also writes a chosen byte as `\xNN`,
//! valid or not.
//!
//! These formats are part of gene's rule language: a rule matching `\xff`
//! must match the same bytes in every program using gene. Any change to a
//! format is a breaking change of this crate, so only such formats belong
//! here.

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

fn lower_hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// Returns the byte written as `xNN` at the start of `text`, if any.
fn byte_escape_value(text: &str) -> Option<u8> {
    match text.as_bytes() {
        [b'x', high, low, ..] => Some(lower_hex_value(*high)? << 4 | lower_hex_value(*low)?),
        _ => None,
    }
}

fn has_byte_escape(text: &str) -> bool {
    text.match_indices('\\')
        .any(|(i, _)| byte_escape_value(&text[i + 1..]).is_some())
}

/// Pushes valid text, doubling each run of backslashes that comes before
/// `xNN` so the decoder does not read it as an escaped byte.
fn push_valid(out: &mut String, valid: &str, is_before_byte_escape: bool) {
    let mut rest = valid;
    while let Some(start) = rest.find('\\') {
        // push everything until \
        out.push_str(&rest[..start]);
        let run = &rest[start..];
        let after = run.trim_start_matches('\\');
        let backslashes = &run[..run.len() - after.len()];
        let must_double_escape = if after.is_empty() {
            is_before_byte_escape
        } else {
            byte_escape_value(after).is_some()
        };
        out.push_str(backslashes);
        if must_double_escape {
            out.push_str(backslashes);
        }
        rest = after;
    }
    out.push_str(rest);
}

/// Converts untrusted bytes to text: valid UTF-8 is kept as is and every
/// invalid byte is written as `\xNN`. A run of backslashes right before
/// `xNN` is doubled, so [`unescape_invalid_utf8`] gets the exact bytes back;
/// other backslashes (e.g. `C:\Windows`) are kept.
//pub fn escape_invalid_utf8(bytes: &[u8]) -> Cow<'_, str> {
pub fn escape_invalid_utf8(bytes: &[u8]) -> Cow<'_, str> {
    let mut out = String::new();
    for chunk in bytes.utf8_chunks() {
        let valid = chunk.valid();
        if valid.len() == bytes.len() && !has_byte_escape(valid) {
            return Cow::Borrowed(valid);
        }
        out.reserve(bytes.len());
        push_valid(&mut out, valid, !chunk.invalid().is_empty());
        for byte in chunk.invalid() {
            push_byte_escape(&mut out, *byte);
        }
    }
    Cow::Owned(out)
}

/// Converts bytes like [`escape_invalid_utf8`], but also writes every `byte`
/// as `\xNN`, even when it is valid UTF-8 (e.g. `.` as `\x2e`), so the text
/// never contains it and it can be used as a separator.
pub fn escape_invalid_utf8_or_byte(bytes: &[u8], byte: u8) -> Cow<'_, str> {
    let mut out = String::new();
    let mut rest = bytes;
    while let Some(position) = rest.iter().position(|&b| b == byte) {
        out.reserve(rest.len());
        push_escaped(&mut out, &rest[..position], true);
        push_byte_escape(&mut out, byte);
        rest = &rest[position + 1..];
    }
    if out.is_empty() {
        return escape_invalid_utf8(bytes);
    }
    push_escaped(&mut out, rest, false);
    Cow::Owned(out)
}

/// Pushes `bytes` as [`escape_invalid_utf8`] writes them;
/// `is_before_byte_escape` tells that the caller pushes `\xNN` right after.
fn push_escaped(out: &mut String, bytes: &[u8], is_before_byte_escape: bool) {
    for chunk in bytes.utf8_chunks() {
        let has_invalid = !chunk.invalid().is_empty();
        push_valid(out, chunk.valid(), has_invalid || is_before_byte_escape);
        for byte in chunk.invalid() {
            push_byte_escape(out, *byte);
        }
    }
}

fn push_byte_escape(out: &mut String, byte: u8) {
    out.push_str("\\x");
    out.push(low_nibble_to_hex(byte >> 4));
    out.push(low_nibble_to_hex(byte));
}

/// Converts text written by [`escape_invalid_utf8`] back to the original
/// bytes: a run of backslashes before `xNN` is halved, and an odd run ends
/// with the escaped byte `0xNN`. Other text, such as `\x41`, is decoded the
/// same way, so it does not always round trip.
pub fn unescape_invalid_utf8(text: &str) -> Cow<'_, [u8]> {
    if !has_byte_escape(text) {
        return Cow::Borrowed(text.as_bytes());
    }
    let mut out = Vec::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('\\') {
        out.extend_from_slice(&rest.as_bytes()[..start]);
        let run = &rest[start..];
        let after = run.trim_start_matches('\\');
        let run_len = run.len() - after.len();
        rest = after;
        let Some(byte) = byte_escape_value(after) else {
            out.extend_from_slice(&run.as_bytes()[..run_len]);
            continue;
        };
        out.extend(std::iter::repeat_n(b'\\', run_len / 2));
        if run_len % 2 == 1 {
            out.push(byte);
            rest = &after["xNN".len()..];
        }
    }
    out.extend_from_slice(rest.as_bytes());
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
    fn test_backslash_not_before_escape_is_kept() {
        assert!(matches!(
            escape_invalid_utf8(br"C:\Windows\System32"),
            Cow::Borrowed(r"C:\Windows\System32")
        ));
        // `m` is not a hex digit
        assert_eq!(escape_invalid_utf8(br"C:\xampp"), r"C:\xampp");
        // the encoder only writes lowercase hex
        assert_eq!(escape_invalid_utf8(br"\xFF"), r"\xFF");
        assert_eq!(escape_invalid_utf8(br"end\xf"), r"end\xf");
    }

    #[test]
    fn test_literal_escape_text_is_escaped() {
        assert_eq!(escape_invalid_utf8(br"/tmp/\xff"), r"/tmp/\\xff");
        assert_eq!(escape_invalid_utf8(br"\x41"), r"\\x41");
        assert_eq!(escape_invalid_utf8(br"\\xff"), r"\\\\xff");
    }

    #[test]
    fn test_backslashes_before_invalid_byte_are_doubled() {
        assert_eq!(escape_invalid_utf8(b"a\\\xff"), r"a\\\xff");
        assert_eq!(escape_invalid_utf8(b"a\\\\\xff"), r"a\\\\\xff");
    }

    #[test]
    fn test_escaped_byte_and_its_literal_text_differ() {
        assert_ne!(escape_invalid_utf8(br"\xff"), escape_invalid_utf8(b"\xff"));
    }

    #[test]
    fn test_escape_invalid_utf8_or_byte_without_byte_is_borrowed() {
        assert!(matches!(
            escape_invalid_utf8_or_byte(b"abc", b'.'),
            Cow::Borrowed("abc")
        ));
    }

    #[test]
    fn test_escape_invalid_utf8_or_byte_escapes_valid_byte() {
        assert_eq!(escape_invalid_utf8_or_byte(b"a.b.", b'.'), r"a\x2eb\x2e");
    }

    #[test]
    fn test_escape_invalid_utf8_or_byte_keeps_escaping_invalid_bytes() {
        assert_eq!(
            escape_invalid_utf8_or_byte(b"\xff.\xfe", b'.'),
            r"\xff\x2e\xfe"
        );
    }

    #[test]
    fn test_escape_invalid_utf8_or_byte_inside_valid_multi_byte_char() {
        // `é` is c3 a9, so a9 alone leaves c3 invalid
        assert_eq!(
            escape_invalid_utf8_or_byte("é".as_bytes(), 0xa9),
            r"\xc3\xa9"
        );
    }

    #[test]
    fn test_escape_invalid_utf8_or_byte_doubles_backslashes_before_it() {
        assert_eq!(escape_invalid_utf8_or_byte(b"a\\.", b'.'), r"a\\\x2e");
        assert_eq!(escape_invalid_utf8_or_byte(br"\x2e.", b'.'), r"\\x2e\x2e");
    }

    #[test]
    fn test_escape_invalid_utf8_or_byte_round_trip() {
        let inputs: &[&[u8]] = &[
            b"",
            b".",
            b"a.b",
            b"a\\.b",
            b"a\\\\.\\",
            br"\x2e.",
            b"\xff.\xff",
            "é.é".as_bytes(),
        ];
        for input in inputs {
            let text = escape_invalid_utf8_or_byte(input, b'.');
            assert_eq!(&*unescape_invalid_utf8(&text), *input, "input: {input:?}");
        }
    }

    #[test]
    fn test_unescape_text_without_escape_is_borrowed() {
        let bytes = unescape_invalid_utf8(r"C:\Windows\xampp");
        assert!(matches!(bytes, Cow::Borrowed(_)));
        assert_eq!(&*bytes, br"C:\Windows\xampp");
    }

    #[test]
    fn test_unescape_odd_backslashes_give_a_byte() {
        assert_eq!(&*unescape_invalid_utf8(r"/tmp/\xff"), b"/tmp/\xff");
        assert_eq!(&*unescape_invalid_utf8(r"a\\\xff"), b"a\\\xff");
    }

    #[test]
    fn test_unescape_even_backslashes_give_literal_text() {
        assert_eq!(&*unescape_invalid_utf8(r"/tmp/\\xff"), br"/tmp/\xff");
        assert_eq!(&*unescape_invalid_utf8(r"\\\\xff"), br"\\xff");
    }

    #[test]
    fn test_round_trip() {
        let inputs: &[&[u8]] = &[
            b"",
            b"/bin/ls",
            "/tmp/é".as_bytes(),
            br"C:\Windows\System32",
            br"C:\xampp",
            br"\xFF",
            br"end\",
            br"end\x",
            br"end\xf",
            br"\xff",
            br"\\xff",
            br"\\\xff",
            b"\xff",
            b"\\\xff",
            b"\\\\\xff",
            b"\xffxab",
            b"\\x4\xff",
            b"a\xe2\x82b",
        ];
        for input in inputs {
            let text = escape_invalid_utf8(input);
            assert_eq!(&*unescape_invalid_utf8(&text), *input, "input: {input:?}");
        }
    }
}
