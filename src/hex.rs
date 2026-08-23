//! Lowercase hex, written out here rather than pulled in.
//!
//! Every digest this crate prints -- record ids, blob addresses, epoch beacons,
//! settlement ranks -- is hex text that other implementations must reproduce
//! byte for byte, so the encoder is part of the wire format and belongs in the
//! repository that pins it. `sha2` 0.11 removed the `LowerHex` impl its output
//! type used to carry, which is what made the previous `format!("{:x}", ..)`
//! spelling stop compiling; that formatter was never the contract, this is.
//!
//! **Not constant time**: it branches per nibble. Every value it is applied to
//! is published. No secret in this crate has a hex or `Display` form, precisely
//! so that this function cannot be pointed at one.

/// Encode `bytes` as lowercase hex, two characters per byte, no prefix.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(digit(byte >> 4));
        out.push(digit(byte & 0x0f));
    }
    out
}

/// Decode lowercase hex. `None` for an odd length, an uppercase letter, or any
/// character outside `0-9a-f`.
///
/// Strict about case on purpose, and the reason is upstream of taste: every hex
/// string this crate reads is one some other implementation wrote, and two
/// spellings of the same bytes are two spellings a record id could disagree
/// about. [`encode`] emits lowercase and this accepts exactly what it emits.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    // `as_chunks` rather than `chunks_exact`: the odd byte is already refused
    // above, and this yields `[u8; 2]` so the pair's shape is a type rather
    // than a promise. `clippy::chunks_exact_to_as_chunks` asks for it too.
    for pair in bytes.as_chunks::<2>().0 {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + value - 10),
        // Unreachable: callers pass a nibble. Total anyway, because a panic in a
        // formatter is a worse outcome than an odd character.
        _ => '?',
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn encodes_lowercase_two_characters_per_byte() {
        assert_eq!(encode(&[]), "");
        assert_eq!(encode(&[0x00]), "00");
        assert_eq!(encode(&[0x0f, 0xf0]), "0ff0");
        assert_eq!(encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn decode_is_the_inverse_of_encode_and_refuses_everything_else() {
        for byte in 0u8..=255 {
            assert_eq!(decode(&encode(&[byte])), Some(vec![byte]));
        }
        assert_eq!(decode(""), Some(Vec::new()));
        assert_eq!(decode("0"), None, "odd length");
        assert_eq!(decode("DE"), None, "uppercase is a second spelling");
        assert_eq!(decode("0g"), None);
        assert_eq!(decode("  "), None);
    }

    #[test]
    fn every_byte_round_trips_through_the_table() {
        for byte in 0u8..=255 {
            let text = encode(&[byte]);
            assert_eq!(text.len(), 2);
            assert_eq!(u8::from_str_radix(&text, 16).unwrap(), byte);
            assert!(text
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        }
    }
}
