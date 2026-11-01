//! A minisign signer for tests: a ring Ed25519 key, the prehashed `ED` and legacy `Ed`
//! signature forms, and the BLAKE2b-512 the prehash needs.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    clippy::redundant_pub_crate,
    clippy::trivially_copy_pass_by_ref,
    reason = "test code asserts by panicking, and the reference blake2b is long"
)]

use ring::signature::{Ed25519KeyPair, KeyPair};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn b64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(B64[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

fn compress(h: &mut [u64; 8], block: &[u8], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, w) in m.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&block[i * 8..i * 8 + 8]);
        *w = u64::from_le_bytes(b);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    let g = |v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64| {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    };
    for r in 0..12 {
        let s = &SIGMA[r % 10];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

pub(crate) fn blake2b(data: &[u8]) -> Vec<u8> {
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ 64;
    let mut offset = 0usize;
    while data.len() - offset > 128 {
        compress(
            &mut h,
            &data[offset..offset + 128],
            (offset + 128) as u128,
            false,
        );
        offset += 128;
    }
    let mut block = [0u8; 128];
    let rest = &data[offset..];
    block[..rest.len()].copy_from_slice(rest);
    compress(&mut h, &block, data.len() as u128, true);
    h.iter().flat_map(|w| w.to_le_bytes()).collect()
}

pub(crate) struct Signer {
    pair: Ed25519KeyPair,
    key_id: [u8; 8],
}

impl Signer {
    pub(crate) fn new(seed: u8) -> Self {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        Self {
            pair,
            key_id: [seed; 8],
        }
    }

    pub(crate) fn public_text(&self) -> String {
        let mut raw = b"Ed".to_vec();
        raw.extend_from_slice(&self.key_id);
        raw.extend_from_slice(self.pair.public_key().as_ref());
        format!("untrusted comment: minisign public key\n{}\n", b64(&raw))
    }

    pub(crate) fn sign_with(&self, message: &[u8], algorithm: &[u8; 2]) -> Vec<u8> {
        let payload = if algorithm == b"ED" {
            blake2b(message)
        } else {
            message.to_vec()
        };
        let sig = self.pair.sign(&payload);
        let mut raw = algorithm.to_vec();
        raw.extend_from_slice(&self.key_id);
        raw.extend_from_slice(sig.as_ref());
        let comment = "t";
        let mut global = sig.as_ref().to_vec();
        global.extend_from_slice(comment.as_bytes());
        let gsig = self.pair.sign(&global);
        format!(
            "untrusted comment: signature\n{}\ntrusted comment: {comment}\n{}\n",
            b64(&raw),
            b64(gsig.as_ref())
        )
        .into_bytes()
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.sign_with(message, b"ED")
    }
}
