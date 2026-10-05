//! ChaCha20-Poly1305 (RFC 8439), opening only.
//!
//! Written out rather than pulled in, for the reason the rest of this crate
//! is: it is a second opinion, and a second opinion that shares the primary's
//! AEAD crate would agree with it about exactly the cases where that crate is
//! wrong. It exists for one check -- that a committee share's published key
//! opens the sealed share in its commitment's envelope to the point the share
//! publishes -- so it opens and never seals, and nothing it handles is secret:
//! by the time a share key is on the log, the share it opens is too. So no
//! constant-time claim is made beyond the tag comparison, which is one anyway.
//!
//! Pinned by the RFC's own vectors: the §2.3.2 block, the §2.5.2 tag, and the
//! §2.8.2 AEAD, which the primary pins too.

/// One ChaCha20 block: 64 bytes of keystream for `counter`.
fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let word = |bytes: &[u8]| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for i in 0..8 {
        state[4 + i] = word(&key[4 * i..]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = word(&nonce[4 * i..]);
    }
    let mut working = state;
    let quarter = |s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize| {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(7);
    };
    for _ in 0..10 {
        quarter(&mut working, 0, 4, 8, 12);
        quarter(&mut working, 1, 5, 9, 13);
        quarter(&mut working, 2, 6, 10, 14);
        quarter(&mut working, 3, 7, 11, 15);
        quarter(&mut working, 0, 5, 10, 15);
        quarter(&mut working, 1, 6, 11, 12);
        quarter(&mut working, 2, 7, 8, 13);
        quarter(&mut working, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&working[i].wrapping_add(state[i]).to_le_bytes());
    }
    out
}

/// Poly1305 over `message` with the one-time key `key` (RFC 8439 §2.5), in
/// 26-bit limbs so every product fits a `u64`.
fn poly1305(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    const MASK: u64 = 0x3ff_ffff;
    let le = |bytes: &[u8]| u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    let r0 = le(&key[0..]) & 0x3ff_ffff;
    let r1 = (le(&key[3..]) >> 2) & 0x3ff_ff03;
    let r2 = (le(&key[6..]) >> 4) & 0x3ff_c0ff;
    let r3 = (le(&key[9..]) >> 6) & 0x3f0_3fff;
    let r4 = (le(&key[12..]) >> 8) & 0x00f_ffff;
    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u64, 0u64, 0u64, 0u64, 0u64);

    for chunk in message.chunks(16) {
        let mut padded = [0u8; 17];
        padded[..chunk.len()].copy_from_slice(chunk);
        // The 2^128 bit: past a full block's end, or the 0x01 a short final
        // block is padded with.
        let high = if chunk.len() == 16 {
            1 << 24
        } else {
            padded[chunk.len()] = 1;
            0
        };
        h0 += le(&padded[0..]) & MASK;
        h1 += (le(&padded[3..]) >> 2) & MASK;
        h2 += (le(&padded[6..]) >> 4) & MASK;
        h3 += (le(&padded[9..]) >> 6) & MASK;
        h4 += (le(&padded[12..]) >> 8) | high;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
        h0 = d0 & MASK;
        d1 += d0 >> 26;
        h1 = d1 & MASK;
        d2 += d1 >> 26;
        h2 = d2 & MASK;
        d3 += d2 >> 26;
        h3 = d3 & MASK;
        d4 += d3 >> 26;
        h4 = d4 & MASK;
        h0 += (d4 >> 26) * 5;
        h1 += h0 >> 26;
        h0 &= MASK;
    }

    // Fully carry, then subtract p = 2^130 - 5 if h >= p.
    let mut carry;
    carry = h1 >> 26;
    h1 &= MASK;
    h2 += carry;
    carry = h2 >> 26;
    h2 &= MASK;
    h3 += carry;
    carry = h3 >> 26;
    h3 &= MASK;
    h4 += carry;
    carry = h4 >> 26;
    h4 &= MASK;
    h0 += carry * 5;
    carry = h0 >> 26;
    h0 &= MASK;
    h1 += carry;

    let mut g0 = h0 + 5;
    carry = g0 >> 26;
    g0 &= MASK;
    let mut g1 = h1 + carry;
    carry = g1 >> 26;
    g1 &= MASK;
    let mut g2 = h2 + carry;
    carry = g2 >> 26;
    g2 &= MASK;
    let mut g3 = h3 + carry;
    carry = g3 >> 26;
    g3 &= MASK;
    let g4 = h4 + carry;
    // h + 5 reaches 2^130 exactly when h >= p, and then h - p = g mod 2^130.
    let (h0, h1, h2, h3, h4) = if g4 >> 26 != 0 {
        (g0, g1, g2, g3, g4 & MASK)
    } else {
        (h0, h1, h2, h3, h4)
    };

    let value: u128 = u128::from(h0)
        | (u128::from(h1) << 26)
        | (u128::from(h2) << 52)
        | (u128::from(h3) << 78)
        | (u128::from(h4) << 104);
    let pad = u128::from_le_bytes(key[16..32].try_into().expect("16 bytes"));
    value.wrapping_add(pad).to_le_bytes()
}

/// Open a ChaCha20-Poly1305 `sealed` (ciphertext then 16-byte tag) under
/// `key` and `nonce` with associated data `aad`. `None` on any tag mismatch.
pub fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < 16 {
        return None;
    }
    let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
    let one_time: [u8; 32] = block(key, 0, nonce)[..32].try_into().expect("32 bytes");
    let pad16 = |length: usize| vec![0u8; (16 - length % 16) % 16];
    let mut mac = Vec::with_capacity(aad.len() + ciphertext.len() + 48);
    mac.extend_from_slice(aad);
    mac.extend(pad16(aad.len()));
    mac.extend_from_slice(ciphertext);
    mac.extend(pad16(ciphertext.len()));
    mac.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    let expected = poly1305(&one_time, &mac);
    let differs = expected
        .iter()
        .zip(tag)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if differs != 0 {
        return None;
    }
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for (i, chunk) in ciphertext.chunks(64).enumerate() {
        let counter = u32::try_from(i + 1).ok()?;
        let stream = block(key, counter, nonce);
        plaintext.extend(chunk.iter().zip(stream.iter()).map(|(c, k)| c ^ k));
    }
    Some(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn the_block_function_matches_rfc_8439_2_3_2() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = [0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let expected = unhex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        );
        assert_eq!(block(&key, 1, &nonce).to_vec(), expected);
    }

    #[test]
    fn poly1305_matches_rfc_8439_2_5_2() {
        let key: [u8; 32] =
            unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                .try_into()
                .unwrap();
        let tag = poly1305(&key, b"Cryptographic Forum Research Group");
        assert_eq!(tag.to_vec(), unhex("a8061dc1305136c6c22b8baf0c0127a9"));
    }

    #[test]
    fn open_matches_rfc_8439_2_8_2_and_refuses_any_change() {
        let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
        let nonce = [
            0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let sealed = unhex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116\
             1ae10b594f09e26a7e902ecbd0600691",
        );
        let plaintext = open(&key, &nonce, &aad, &sealed).expect("the vector opens");
        assert_eq!(
            plaintext,
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip \
              for the future, sunscreen would be it."
                .to_vec()
        );
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert!(open(&key, &nonce, &aad, &tampered).is_none());
        assert!(open(&key, &nonce, b"", &sealed).is_none());
        let mut other = key;
        other[0] ^= 1;
        assert!(open(&other, &nonce, &aad, &sealed).is_none());
        assert!(open(&key, &nonce, &aad, &sealed[..15]).is_none());
    }
}
