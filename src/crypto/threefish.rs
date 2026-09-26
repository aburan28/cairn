//! Threefish-256, the block cipher inside Skein.
//!
//! Used as one leg of the cascade in [`super::cascade`]. The known-answer
//! test is the all-zero key, tweak and plaintext from the Skein 1.3 golden
//! KATs (the same vector Bouncy Castle pins). A round trip would not catch a
//! construction that is merely self-consistent.

const C240: u64 = 0x1BD11BDAA9FC1A22;

/// Rotation constants for Threefish-256, eight rounds, two mixes each.
const ROT: [[u32; 2]; 8] = [
    [14, 16],
    [52, 57],
    [23, 40],
    [5, 37],
    [25, 33],
    [46, 12],
    [58, 22],
    [32, 32],
];

fn mix(x0: u64, x1: u64, rot: u32) -> (u64, u64) {
    let y0 = x0.wrapping_add(x1);
    let y1 = x1.rotate_left(rot) ^ y0;
    (y0, y1)
}

fn words(bytes: &[u8]) -> Vec<u64> {
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| u64::from_le_bytes(*chunk))
        .collect()
}

/// Encrypt one 32-byte block under a 32-byte key and a 16-byte tweak.
pub fn encrypt_256(key: &[u8; 32], tweak: &[u8; 16], block: &[u8; 32]) -> [u8; 32] {
    let kw = words(key);
    let mut k = [0u64; 5];
    k[..4].copy_from_slice(&kw);
    k[4] = C240 ^ k[0] ^ k[1] ^ k[2] ^ k[3];
    let tw = words(tweak);
    let t = [tw[0], tw[1], tw[0] ^ tw[1]];
    let mut v: [u64; 4] = words(block).try_into().expect("4 words");

    for d in 0..72 {
        if d % 4 == 0 {
            inject(&mut v, &k, &t, d / 4);
        }
        let r = ROT[d % 8];
        let (y0, y1) = mix(v[0], v[1], r[0]);
        let (y2, y3) = mix(v[2], v[3], r[1]);
        v = [y0, y3, y2, y1];
    }
    inject(&mut v, &k, &t, 18);

    let mut out = [0u8; 32];
    for (i, word) in v.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn inject(v: &mut [u64; 4], k: &[u64; 5], t: &[u64; 3], s: usize) {
    v[0] = v[0].wrapping_add(k[s % 5]);
    v[1] = v[1].wrapping_add(k[(s + 1) % 5].wrapping_add(t[s % 3]));
    v[2] = v[2].wrapping_add(k[(s + 2) % 5].wrapping_add(t[(s + 1) % 3]));
    v[3] = v[3].wrapping_add(k[(s + 3) % 5].wrapping_add(s as u64));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_skein_all_zero_vector() {
        let ct = encrypt_256(&[0; 32], &[0; 16], &[0; 32]);
        let expect = hex_to("84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8");
        assert_eq!(ct.as_slice(), expect.as_slice());
    }

    fn hex_to(text: &str) -> Vec<u8> {
        crate::hex::decode(text).expect("hex")
    }
}
