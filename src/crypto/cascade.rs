//! A symmetric cascade: ChaCha20 XOR Threefish-256-CTR XOR Serpent-256-CTR.
//!
//! Either cipher alone suffices. The three keystreams are XORed, so a break
//! of one leg does not recover the plaintext while another leg holds. Keys
//! are split from one 32-byte input by domain-separated SHA-256 labels, so a
//! break of one label does not hand you the other key.
//!
//! The tag is HMAC-SHA-512 over the tweak and the body. ChaCha20-Poly1305
//! remains the AEAD for transport frames and sealed stores; this module does
//! not read those blobs. AES is not a leg. Version 1 is this cascade.

use chacha20::cipher::array::Array;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hmac::{Hmac, Mac};
use serpent::cipher::{BlockCipherEncrypt, KeyInit as SerpentKeyInit};
use serpent::Serpent;
use sha2::{Digest, Sha256, Sha512};

use super::threefish;

type HmacSha512 = Hmac<Sha512>;

const VERSION: u8 = 1;

/// Seal `plaintext` under `key`. `tweak` is mixed into the Threefish tweak so
/// a sealed line can bind its line number.
pub fn seal(key: &[u8; 32], tweak: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let chacha_key = derive(key, b"cairn/cascade/chacha20");
    let threefish_key = derive(key, b"cairn/cascade/threefish-256");
    let serpent_key = derive(key, b"cairn/cascade/serpent-256");
    let mac_key = derive(key, b"cairn/cascade/hmac-sha512");
    let mut body = keystream(
        &chacha_key,
        &threefish_key,
        &serpent_key,
        tweak,
        plaintext.len(),
    );
    for (out, byte) in body.iter_mut().zip(plaintext) {
        *out ^= byte;
    }
    let tag = hmac_tag(&mac_key, tweak, &body);
    let mut out = Vec::with_capacity(1 + body.len() + 64);
    out.push(VERSION);
    out.extend_from_slice(&body);
    out.extend_from_slice(&tag);
    out
}

/// Open a blob from [`seal`]. `None` when the version is unknown or the tag
/// does not match. A bad tag says nothing about the plaintext.
pub fn open(key: &[u8; 32], tweak: &[u8; 16], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.first().copied() != Some(VERSION) || blob.len() < 1 + 64 {
        return None;
    }
    let (body, tag) = blob[1..].split_at(blob.len() - 1 - 64);
    let mac_key = derive(key, b"cairn/cascade/hmac-sha512");
    let expect = hmac_tag(&mac_key, tweak, body);
    if !constant_eq(tag, &expect) {
        return None;
    }
    let chacha_key = derive(key, b"cairn/cascade/chacha20");
    let threefish_key = derive(key, b"cairn/cascade/threefish-256");
    let serpent_key = derive(key, b"cairn/cascade/serpent-256");
    let mut plain = keystream(&chacha_key, &threefish_key, &serpent_key, tweak, body.len());
    for (out, byte) in plain.iter_mut().zip(body) {
        *out ^= byte;
    }
    Some(plain)
}

fn derive(key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(key);
    hasher.finalize().into()
}

fn keystream(
    chacha_key: &[u8; 32],
    threefish_key: &[u8; 32],
    serpent_key: &[u8; 32],
    tweak: &[u8; 16],
    len: usize,
) -> Vec<u8> {
    let mut chacha = vec![0u8; len];
    let nonce: [u8; 12] = tweak[..12].try_into().expect("tweak is 16 bytes");
    let mut cipher = ChaCha20::new(&Array::from(*chacha_key), &Array::from(nonce));
    cipher.apply_keystream(&mut chacha);

    let mut three = vec![0u8; len];
    let mut counter = 0u64;
    let mut offset = 0;
    while offset < len {
        let mut block = [0u8; 32];
        block[..8].copy_from_slice(&counter.to_le_bytes());
        let ct = threefish::encrypt_256(threefish_key, tweak, &block);
        let n = (len - offset).min(32);
        three[offset..offset + n].copy_from_slice(&ct[..n]);
        offset += n;
        counter += 1;
    }
    for (a, b) in chacha.iter_mut().zip(&three) {
        *a ^= b;
    }
    let serpent = serpent_stream(serpent_key, tweak, len);
    for (a, b) in chacha.iter_mut().zip(serpent) {
        *a ^= b;
    }
    chacha
}

fn serpent_stream(key: &[u8; 32], tweak: &[u8; 16], len: usize) -> Vec<u8> {
    let cipher = Serpent::new_from_slice(key).expect("32-byte key");
    let mut out = vec![0u8; len];
    let mut counter = 0u64;
    let mut offset = 0;
    while offset < len {
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&counter.to_le_bytes());
        block[8..].copy_from_slice(&tweak[..8]);
        let mut array = Array::<u8, chacha20::cipher::consts::U16>::from(block);
        cipher.encrypt_block(&mut array);
        let ct: [u8; 16] = array.into();
        let n = (len - offset).min(16);
        out[offset..offset + n].copy_from_slice(&ct[..n]);
        offset += n;
        counter += 1;
    }
    out
}

fn hmac_tag(key: &[u8; 32], tweak: &[u8; 16], body: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(tweak);
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    out
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Serpent-256 of the NESSIE all-zero-key vector, so the crate we cascade
/// toward is pinned even though the cascade keystream itself is Threefish.
pub fn serpent_nessie_zero() -> [u8; 16] {
    let cipher = Serpent::new_from_slice(&[0u8; 32]).expect("32-byte key");
    let mut block = Array::<u8, chacha20::cipher::consts::U16>::from([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);
    cipher.encrypt_block(&mut block);
    block.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serpent_matches_the_nessie_256_vector() {
        assert_eq!(
            hex_encode(&serpent_nessie_zero()),
            "ad86de83231c3203a86ae33b721eaa9f"
        );
    }

    #[test]
    fn the_cascade_framing_is_pinned() {
        // Serpent and Threefish each have an external vector. The combination
        // does not, so this pins the version-1 framing: a quiet change of the
        // XOR or the tag fails here instead of only round-tripping.
        let blob = seal(&[0x0b; 32], &[0; 16], b"cairn");
        assert_eq!(
            hex_encode(&blob),
            include_str!("../../conformance/cascade-v1-cairn.hex").trim()
        );
    }

    #[test]
    fn the_cascade_opens_what_it_seals_and_rejects_a_flipped_tag() {
        let key = [9u8; 32];
        let tweak = [1u8; 16];
        let blob = seal(&key, &tweak, b"orbit witness");
        assert_eq!(
            open(&key, &tweak, &blob).as_deref(),
            Some(&b"orbit witness"[..])
        );
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(open(&key, &tweak, &bad).is_none());
    }

    fn hex_encode(bytes: &[u8]) -> String {
        crate::hex::encode(bytes)
    }
}
