//! Pure-Rust NIST FIPS 204 ML-DSA-65 (`Dilithium3` finalized) and FIPS 202 SHAKE128/SHAKE256.
//!
//! Used by [`crate::signing`] to validate ML-DSA-65 SPKI public keys and RFC 9881 PKCS#8 private
//! keys, derive public keys, and sign/verify signatures with pure ML-DSA (empty context `ctx = []`,
//! matching Bouncy Castle's JCA `"ML-DSA-65"` provider used by Canton 3.7.2).

// [CANTON-NOTE: STYLE] The index loops and the tuple of `sig_decode` follow the FIPS 204 pseudocode line by line (`for r in 0..K`, `for s in 0..L`), so
// they stay readable against the standard; the lints that ask for iterators or a type alias are allowed for this module.
#![allow(
    clippy::needless_range_loop,
    clippy::type_complexity,
    reason = "FIPS 204 algorithm loops and decode tuple match the reference pseudocode line-for-line"
)]

use crate::ber;

pub const PUBLIC_KEY_LEN: usize = 1952;
pub const SECRET_KEY_LEN: usize = 4032;
pub const SIGNATURE_LEN: usize = 3309;

/// `id-ml-dsa-65` (`2.16.840.1.101.3.4.3.18`) DER OID value octets.
pub const OID_ML_DSA_65: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];

const Q: i32 = 8_380_417;
const N: usize = 256;
const D: u32 = 13;
const K: usize = 6;
const L: usize = 5;
const ETA: i32 = 4;
const TAU: usize = 49;
const BETA: i32 = (TAU as i32) * ETA; // 196
const GAMMA1: i32 = 1 << 19; // 524_288
const GAMMA2: i32 = (Q - 1) / 32; // 261_888
const OMEGA: usize = 55;
const C_TILDE_LEN: usize = 48;
const F_INV: i64 = 8_347_681; // 256^{-1} mod Q

/// Bit-reversed powers of primitive 512th root of unity `zeta = 1753` mod `Q = 8380417`.
const ZETAS: [i32; 256] = [
    1, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987, 7778734, 3542485, 2682288,
    2129892, 3764867, 7375178, 557458, 7159240, 5010068, 4317364, 2663378, 6705802, 4855975,
    7946292, 676590, 7044481, 5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639,
    2283733, 3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875, 394148,
    928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050, 3415069, 1759347, 7562881,
    4805951, 3756790, 6444618, 6663429, 4430364, 5483103, 3192354, 556856, 3870317, 2917338,
    1853806, 3345963, 1858416, 3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977,
    8106357, 2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088, 1528066,
    482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034, 4213992, 4892034, 1987814,
    5183169, 1736313, 235407, 5130263, 3258457, 5801164, 1787943, 5989328, 6125690, 3482206,
    4197502, 7080401, 6018354, 7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816,
    3374250, 1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254, 348812,
    8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507, 1753, 6444997, 5720892, 6924527,
    2660408, 6600190, 8321269, 2772600, 1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502,
    4663471, 8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952, 6695264,
    4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040, 4234153, 6607829, 2192938,
    6653329, 2387513, 4768667, 8111961, 5199961, 3747250, 2296099, 1239911, 4541938, 3195676,
    2642980, 1254190, 8368000, 2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156,
    6161950, 7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452, 6757063,
    2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006, 6903432, 1994046, 2491325,
    6987258, 507927, 7192532, 7655613, 6545891, 5346675, 8041997, 2647994, 3009748, 5767564,
    4148469, 749577, 4357667, 3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598,
    5011144, 3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976, 3105558,
    7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265, 6195333, 3123762, 2358373, 6187330,
    5365997, 6663603, 2926054, 7987710, 8077412, 3531229, 4405932, 4606686, 1900052, 7598542,
    1054478, 7648983,
];

// ---------------------------------------------------------------------------------------------------------------------
// FIPS 202 Keccak-f[1600] & SHAKE128 / SHAKE256

const KECCAK_RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const KECCAK_ROT: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const KECCAK_PI: [usize; 25] = [
    0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
];

fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in &KECCAK_RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }
        let mut b = [0u64; 25];
        for i in 0..25 {
            b[KECCAK_PI[i]] = state[i].rotate_left(KECCAK_ROT[i]);
        }
        for y in 0..5 {
            let row = 5 * y;
            let a0 = b[row];
            let a1 = b[row + 1];
            let a2 = b[row + 2];
            let a3 = b[row + 3];
            let a4 = b[row + 4];
            state[row] = a0 ^ (!a1 & a2);
            state[row + 1] = a1 ^ (!a2 & a3);
            state[row + 2] = a2 ^ (!a3 & a4);
            state[row + 3] = a3 ^ (!a4 & a0);
            state[row + 4] = a4 ^ (!a0 & a1);
        }
        state[0] ^= rc;
    }
}

#[derive(Clone)]
struct ShakeXof {
    state: [u64; 25],
    rate: usize,
    pos: usize,
    finalized: bool,
    out_block: [u8; 168],
}

impl ShakeXof {
    fn shake128() -> Self {
        Self::new(168)
    }

    fn shake256() -> Self {
        Self::new(136)
    }

    fn new(rate: usize) -> Self {
        Self {
            state: [0u64; 25],
            rate,
            pos: 0,
            finalized: false,
            out_block: [0u8; 168],
        }
    }

    fn absorb(&mut self, input: &[u8]) {
        for &byte in input {
            let word = self.pos / 8;
            let shift = (self.pos % 8) * 8;
            self.state[word] ^= u64::from(byte) << shift;
            self.pos += 1;
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    fn finalize(&mut self) {
        if self.finalized {
            return;
        }
        let word = self.pos / 8;
        let shift = (self.pos % 8) * 8;
        self.state[word] ^= 0x1f_u64 << shift;
        let last = self.rate - 1;
        let lword = last / 8;
        let lshift = (last % 8) * 8;
        self.state[lword] ^= 0x80_u64 << lshift;
        keccak_f1600(&mut self.state);
        self.dump_block();
        self.pos = 0;
        self.finalized = true;
    }

    fn dump_block(&mut self) {
        for i in 0..(self.rate / 8) {
            let bytes = self.state[i].to_le_bytes();
            self.out_block[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }
    }

    fn squeeze_byte(&mut self) -> u8 {
        if !self.finalized {
            self.finalize();
        }
        if self.pos == self.rate {
            keccak_f1600(&mut self.state);
            self.dump_block();
            self.pos = 0;
        }
        let b = self.out_block[self.pos];
        self.pos += 1;
        b
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        for dst in out {
            *dst = self.squeeze_byte();
        }
    }
}

fn shake256_once(parts: &[&[u8]], out: &mut [u8]) {
    let mut xof = ShakeXof::shake256();
    for p in parts {
        xof.absorb(p);
    }
    xof.squeeze(out);
}

// ---------------------------------------------------------------------------------------------------------------------
// Polynomial arithmetic over Z_Q[X] / (X^256 + 1)

type Poly = [i32; N];

#[inline]
fn mod_q(x: i64) -> i32 {
    x.rem_euclid(i64::from(Q)) as i32
}

#[inline]
fn center_mod_q(x: i32) -> i32 {
    let r = x.rem_euclid(Q);
    if r > (Q - 1) / 2 {
        r - Q
    } else {
        r
    }
}

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut c = [0i32; N];
    for i in 0..N {
        let s = a[i] + b[i];
        c[i] = if s >= Q { s - Q } else { s };
    }
    c
}

fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut c = [0i32; N];
    for i in 0..N {
        let d = a[i] - b[i];
        c[i] = if d < 0 { d + Q } else { d };
    }
    c
}

fn poly_inf_norm(a: &Poly) -> i32 {
    a.iter().map(|&c| center_mod_q(c).abs()).max().unwrap_or(0)
}

fn ntt(a: &Poly) -> Poly {
    let mut w = *a;
    for v in &mut w {
        *v = v.rem_euclid(Q);
    }
    let mut m = 0usize;
    let mut len = 128usize;
    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            m += 1;
            let z = i64::from(ZETAS[m]);
            for j in start..start + len {
                let t = (z * i64::from(w[j + len])) % i64::from(Q);
                w[j + len] = mod_q(i64::from(w[j]) - t);
                w[j] = mod_q(i64::from(w[j]) + t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
    w
}

fn inv_ntt(a: &Poly) -> Poly {
    let mut w = *a;
    for v in &mut w {
        *v = v.rem_euclid(Q);
    }
    let mut m = 256usize;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            m -= 1;
            let z = i64::from(Q - ZETAS[m]);
            for j in start..start + len {
                let t = w[j];
                let d = i64::from(t) - i64::from(w[j + len]);
                w[j] = (t + w[j + len]).rem_euclid(Q);
                w[j + len] = mod_q(z * d);
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for v in &mut w {
        *v = mod_q(F_INV * i64::from(*v));
    }
    w
}

fn poly_pointwise(a: &Poly, b: &Poly) -> Poly {
    let mut c = [0i32; N];
    for i in 0..N {
        c[i] = ((i64::from(a[i]) * i64::from(b[i])) % i64::from(Q)) as i32;
    }
    c
}

fn mat_vec_mul_ntt<const R: usize, const C: usize>(
    mat: &[[Poly; C]; R],
    vec: &[Poly; C],
) -> [Poly; R] {
    let mut out = [[0i32; N]; R];
    for i in 0..R {
        for j in 0..C {
            let p = poly_pointwise(&mat[i][j], &vec[j]);
            out[i] = poly_add(&out[i], &p);
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------------------------
// Rounding & hints (FIPS 204 Algorithms 35–40)

fn power2round(r: i32) -> (i32, i32) {
    let rp = r.rem_euclid(Q);
    let mask = (1 << D) - 1;
    let mut r0 = rp & mask;
    if r0 > (1 << (D - 1)) {
        r0 -= 1 << D;
    }
    ((rp - r0) >> D, r0)
}

fn decompose(r: i32) -> (i32, i32) {
    let rp = r.rem_euclid(Q);
    let two_gamma2 = 2 * GAMMA2;
    let mut r0 = rp % two_gamma2;
    if r0 > GAMMA2 {
        r0 -= two_gamma2;
    }
    if rp - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((rp - r0) / two_gamma2, r0)
    }
}

fn high_bits(r: i32) -> i32 {
    decompose(r).0
}

fn low_bits(r: i32) -> i32 {
    decompose(r).1
}

fn make_hint(z: i32, r: i32) -> u8 {
    let r1 = high_bits(r);
    let v1 = high_bits(mod_q(i64::from(r) + i64::from(z)));
    u8::from(r1 != v1)
}

fn use_hint(h: u8, r: i32) -> i32 {
    let m = (Q - 1) / (2 * GAMMA2);
    let (r1, r0) = decompose(r);
    if h == 1 {
        if r0 > 0 {
            (r1 + 1).rem_euclid(m)
        } else {
            (r1 - 1).rem_euclid(m)
        }
    } else {
        r1
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Expansion & sampling (FIPS 204 Algorithms 29–34)

fn rej_ntt_poly(rho: &[u8; 32], s: u8, r: u8) -> Poly {
    let mut xof = ShakeXof::shake128();
    xof.absorb(rho);
    xof.absorb(&[s, r]);
    let mut a = [0i32; N];
    let mut j = 0usize;
    while j < N {
        let mut b = [0u8; 3];
        xof.squeeze(&mut b);
        let cand = i32::from(b[0]) | (i32::from(b[1]) << 8) | (i32::from(b[2] & 0x7f) << 16);
        if cand < Q {
            a[j] = cand;
            j += 1;
        }
    }
    a
}

fn expand_a(rho: &[u8; 32]) -> [[Poly; L]; K] {
    let mut mat = [[[0i32; N]; L]; K];
    for r in 0..K {
        for s in 0..L {
            mat[r][s] = rej_ntt_poly(rho, s as u8, r as u8);
        }
    }
    mat
}

fn rej_bounded_poly(rho_prime: &[u8; 64], idx: u16) -> Poly {
    let mut xof = ShakeXof::shake256();
    xof.absorb(rho_prime);
    xof.absorb(&idx.to_le_bytes());
    let mut p = [0i32; N];
    let mut j = 0usize;
    while j < N {
        let z = xof.squeeze_byte();
        let z0 = i32::from(z & 0x0f);
        if z0 < 9 {
            p[j] = ETA - z0;
            j += 1;
        }
        if j < N {
            let z1 = i32::from(z >> 4);
            if z1 < 9 {
                p[j] = ETA - z1;
                j += 1;
            }
        }
    }
    p
}

fn expand_s(rho_prime: &[u8; 64]) -> ([Poly; L], [Poly; K]) {
    let mut s1 = [[0i32; N]; L];
    let mut s2 = [[0i32; N]; K];
    for (r, dst) in s1.iter_mut().enumerate() {
        *dst = rej_bounded_poly(rho_prime, r as u16);
    }
    for (r, dst) in s2.iter_mut().enumerate() {
        *dst = rej_bounded_poly(rho_prime, (r + L) as u16);
    }
    (s1, s2)
}

fn expand_mask(rho_double_prime: &[u8; 64], kappa: u16) -> [Poly; L] {
    let mut y = [[0i32; N]; L];
    for (r, dst) in y.iter_mut().enumerate() {
        let mut buf = [0u8; 640];
        let mut xof = ShakeXof::shake256();
        xof.absorb(rho_double_prime);
        xof.absorb(&(kappa + r as u16).to_le_bytes());
        xof.squeeze(&mut buf);
        *dst = bit_unpack_gamma1(&buf);
    }
    y
}

fn sample_in_ball(c_tilde: &[u8; C_TILDE_LEN]) -> Poly {
    let mut xof = ShakeXof::shake256();
    xof.absorb(c_tilde);
    let mut sign_bytes = [0u8; 8];
    xof.squeeze(&mut sign_bytes);
    let mut signs = u64::from_le_bytes(sign_bytes);
    let mut c = [0i32; N];
    for i in (N - TAU)..N {
        let j = loop {
            let b = xof.squeeze_byte() as usize;
            if b <= i {
                break b;
            }
        };
        c[i] = c[j];
        c[j] = if (signs & 1) == 1 { Q - 1 } else { 1 };
        signs >>= 1;
    }
    c
}

// ---------------------------------------------------------------------------------------------------------------------
// Packing / unpacking

fn simple_bit_pack_10(p: &Poly, out: &mut [u8; 320]) {
    for i in 0..(N / 4) {
        let c0 = p[4 * i] as u32;
        let c1 = p[4 * i + 1] as u32;
        let c2 = p[4 * i + 2] as u32;
        let c3 = p[4 * i + 3] as u32;
        let o = &mut out[5 * i..5 * i + 5];
        o[0] = c0 as u8;
        o[1] = ((c0 >> 8) | (c1 << 2)) as u8;
        o[2] = ((c1 >> 6) | (c2 << 4)) as u8;
        o[3] = ((c2 >> 4) | (c3 << 6)) as u8;
        o[4] = (c3 >> 2) as u8;
    }
}

fn simple_bit_unpack_10(inp: &[u8]) -> Poly {
    let mut p = [0i32; N];
    for i in 0..(N / 4) {
        let s = &inp[5 * i..5 * i + 5];
        let b0 = u32::from(s[0]);
        let b1 = u32::from(s[1]);
        let b2 = u32::from(s[2]);
        let b3 = u32::from(s[3]);
        let b4 = u32::from(s[4]);
        p[4 * i] = (b0 | ((b1 & 0x03) << 8)) as i32;
        p[4 * i + 1] = ((b1 >> 2) | ((b2 & 0x0f) << 6)) as i32;
        p[4 * i + 2] = ((b2 >> 4) | ((b3 & 0x3f) << 4)) as i32;
        p[4 * i + 3] = ((b3 >> 6) | (b4 << 2)) as i32;
    }
    p
}

fn bit_pack_eta(p: &Poly, out: &mut [u8; 128]) {
    for i in 0..(N / 2) {
        let w0 = (ETA - p[2 * i]) as u8;
        let w1 = (ETA - p[2 * i + 1]) as u8;
        out[i] = (w0 & 0x0f) | (w1 << 4);
    }
}

fn bit_unpack_eta(inp: &[u8]) -> Result<Poly, &'static str> {
    let mut p = [0i32; N];
    for (i, &b) in inp[..128].iter().enumerate() {
        let w0 = i32::from(b & 0x0f);
        let w1 = i32::from(b >> 4);
        if w0 > 2 * ETA || w1 > 2 * ETA {
            return Err("ML-DSA-65 private key eta coefficient out of range");
        }
        p[2 * i] = ETA - w0;
        p[2 * i + 1] = ETA - w1;
    }
    Ok(p)
}

fn bit_pack_t0(p: &Poly, out: &mut [u8; 416]) {
    const BASE: i32 = 1 << (D - 1);
    for i in 0..(N / 8) {
        let mut w = [0u32; 8];
        for k in 0..8 {
            w[k] = (BASE - p[8 * i + k]) as u32;
        }
        let o = &mut out[13 * i..13 * i + 13];
        o[0] = w[0] as u8;
        o[1] = ((w[0] >> 8) | (w[1] << 5)) as u8;
        o[2] = (w[1] >> 3) as u8;
        o[3] = ((w[1] >> 11) | (w[2] << 2)) as u8;
        o[4] = ((w[2] >> 6) | (w[3] << 7)) as u8;
        o[5] = (w[3] >> 1) as u8;
        o[6] = ((w[3] >> 9) | (w[4] << 4)) as u8;
        o[7] = (w[4] >> 4) as u8;
        o[8] = ((w[4] >> 12) | (w[5] << 1)) as u8;
        o[9] = ((w[5] >> 7) | (w[6] << 6)) as u8;
        o[10] = (w[6] >> 2) as u8;
        o[11] = ((w[6] >> 10) | (w[7] << 3)) as u8;
        o[12] = (w[7] >> 5) as u8;
    }
}

fn bit_unpack_t0(inp: &[u8]) -> Poly {
    const BASE: i32 = 1 << (D - 1);
    let mut p = [0i32; N];
    for i in 0..(N / 8) {
        let s = &inp[13 * i..13 * i + 13];
        let b = [
            u32::from(s[0]),
            u32::from(s[1]),
            u32::from(s[2]),
            u32::from(s[3]),
            u32::from(s[4]),
            u32::from(s[5]),
            u32::from(s[6]),
            u32::from(s[7]),
            u32::from(s[8]),
            u32::from(s[9]),
            u32::from(s[10]),
            u32::from(s[11]),
            u32::from(s[12]),
        ];
        let w = [
            b[0] | ((b[1] & 0x1f) << 8),
            (b[1] >> 5) | (b[2] << 3) | ((b[3] & 0x03) << 11),
            (b[3] >> 2) | ((b[4] & 0x7f) << 6),
            (b[4] >> 7) | (b[5] << 1) | ((b[6] & 0x0f) << 9),
            (b[6] >> 4) | (b[7] << 4) | ((b[8] & 0x01) << 12),
            (b[8] >> 1) | ((b[9] & 0x3f) << 7),
            (b[9] >> 6) | (b[10] << 2) | ((b[11] & 0x07) << 10),
            (b[11] >> 3) | (b[12] << 5),
        ];
        for k in 0..8 {
            p[8 * i + k] = BASE - (w[k] as i32);
        }
    }
    p
}

fn bit_pack_gamma1(p: &Poly, out: &mut [u8; 640]) {
    for i in 0..(N / 2) {
        let w0 = (GAMMA1 - center_mod_q(p[2 * i])) as u32;
        let w1 = (GAMMA1 - center_mod_q(p[2 * i + 1])) as u32;
        let o = &mut out[5 * i..5 * i + 5];
        o[0] = w0 as u8;
        o[1] = (w0 >> 8) as u8;
        o[2] = (((w0 >> 16) & 0x0f) | (w1 << 4)) as u8;
        o[3] = (w1 >> 4) as u8;
        o[4] = (w1 >> 12) as u8;
    }
}

fn bit_unpack_gamma1(inp: &[u8]) -> Poly {
    let mut p = [0i32; N];
    for i in 0..(N / 2) {
        let s = &inp[5 * i..5 * i + 5];
        let b0 = u32::from(s[0]);
        let b1 = u32::from(s[1]);
        let b2 = u32::from(s[2]);
        let b3 = u32::from(s[3]);
        let b4 = u32::from(s[4]);
        let w0 = (b0 | (b1 << 8) | ((b2 & 0x0f) << 16)) as i32;
        let w1 = ((b2 >> 4) | (b3 << 4) | (b4 << 12)) as i32;
        p[2 * i] = GAMMA1 - w0;
        p[2 * i + 1] = GAMMA1 - w1;
    }
    p
}

fn w1_encode(w1: &[Poly; K]) -> [u8; K * 128] {
    let mut out = [0u8; K * 128];
    for r in 0..K {
        let slice = &mut out[r * 128..(r + 1) * 128];
        for i in 0..(N / 2) {
            slice[i] = ((w1[r][2 * i] as u8) & 0x0f) | ((w1[r][2 * i + 1] as u8) << 4);
        }
    }
    out
}

fn hint_bit_pack(h: &[[u8; N]; K], out: &mut [u8; OMEGA + K]) {
    out.fill(0);
    let mut idx = 0usize;
    for i in 0..K {
        for j in 0..N {
            if h[i][j] != 0 {
                out[idx] = j as u8;
                idx += 1;
            }
        }
        out[OMEGA + i] = idx as u8;
    }
}

fn hint_bit_unpack(inp: &[u8]) -> Option<[[u8; N]; K]> {
    if inp.len() != OMEGA + K {
        return None;
    }
    let mut h = [[0u8; N]; K];
    let mut idx = 0usize;
    for i in 0..K {
        let limit = usize::from(inp[OMEGA + i]);
        if limit < idx || limit > OMEGA {
            return None;
        }
        let first = idx;
        while idx < limit {
            if idx > first && inp[idx - 1] >= inp[idx] {
                return None;
            }
            h[i][usize::from(inp[idx])] = 1;
            idx += 1;
        }
    }
    for &pad in &inp[idx..OMEGA] {
        if pad != 0 {
            return None;
        }
    }
    Some(h)
}

fn pk_encode(rho: &[u8; 32], t1: &[Poly; K]) -> [u8; PUBLIC_KEY_LEN] {
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    pk[..32].copy_from_slice(rho);
    for r in 0..K {
        let dst: &mut [u8; 320] = (&mut pk[32 + r * 320..32 + (r + 1) * 320])
            .try_into()
            .expect("fixed 320-byte slice");
        simple_bit_pack_10(&t1[r], dst);
    }
    pk
}

fn pk_decode(pk: &[u8]) -> Option<([u8; 32], [Poly; K])> {
    if pk.len() != PUBLIC_KEY_LEN {
        return None;
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[..32]);
    let mut t1 = [[0i32; N]; K];
    for r in 0..K {
        t1[r] = simple_bit_unpack_10(&pk[32 + r * 320..32 + (r + 1) * 320]);
    }
    Some((rho, t1))
}

fn sk_encode(
    rho: &[u8; 32],
    k_seed: &[u8; 32],
    tr: &[u8; 64],
    s1: &[Poly; L],
    s2: &[Poly; K],
    t0: &[Poly; K],
) -> [u8; SECRET_KEY_LEN] {
    let mut sk = [0u8; SECRET_KEY_LEN];
    let mut pos = 0usize;
    sk[pos..pos + 32].copy_from_slice(rho);
    pos += 32;
    sk[pos..pos + 32].copy_from_slice(k_seed);
    pos += 32;
    sk[pos..pos + 64].copy_from_slice(tr);
    pos += 64;
    for p in s1 {
        let dst: &mut [u8; 128] = (&mut sk[pos..pos + 128]).try_into().expect("128 bytes");
        bit_pack_eta(p, dst);
        pos += 128;
    }
    for p in s2 {
        let dst: &mut [u8; 128] = (&mut sk[pos..pos + 128]).try_into().expect("128 bytes");
        bit_pack_eta(p, dst);
        pos += 128;
    }
    for p in t0 {
        let dst: &mut [u8; 416] = (&mut sk[pos..pos + 416]).try_into().expect("416 bytes");
        bit_pack_t0(p, dst);
        pos += 416;
    }
    debug_assert_eq!(pos, SECRET_KEY_LEN);
    sk
}

struct DecodedSk {
    rho: [u8; 32],
    k_seed: [u8; 32],
    tr: [u8; 64],
    s1: [Poly; L],
    s2: [Poly; K],
    t0: [Poly; K],
}

fn sk_decode(sk: &[u8]) -> Result<DecodedSk, &'static str> {
    if sk.len() != SECRET_KEY_LEN {
        return Err("invalid ML-DSA-65 expanded private key length");
    }
    let mut pos = 0usize;
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&sk[pos..pos + 32]);
    pos += 32;
    let mut k_seed = [0u8; 32];
    k_seed.copy_from_slice(&sk[pos..pos + 32]);
    pos += 32;
    let mut tr = [0u8; 64];
    tr.copy_from_slice(&sk[pos..pos + 64]);
    pos += 64;
    let mut s1 = [[0i32; N]; L];
    for p in &mut s1 {
        *p = bit_unpack_eta(&sk[pos..pos + 128])?;
        pos += 128;
    }
    let mut s2 = [[0i32; N]; K];
    for p in &mut s2 {
        *p = bit_unpack_eta(&sk[pos..pos + 128])?;
        pos += 128;
    }
    let mut t0 = [[0i32; N]; K];
    for p in &mut t0 {
        *p = bit_unpack_t0(&sk[pos..pos + 416]);
        pos += 416;
    }
    Ok(DecodedSk {
        rho,
        k_seed,
        tr,
        s1,
        s2,
        t0,
    })
}

fn sig_encode(c_tilde: &[u8; C_TILDE_LEN], z: &[Poly; L], h: &[[u8; N]; K]) -> [u8; SIGNATURE_LEN] {
    let mut sig = [0u8; SIGNATURE_LEN];
    let mut pos = 0usize;
    sig[pos..pos + C_TILDE_LEN].copy_from_slice(c_tilde);
    pos += C_TILDE_LEN;
    for p in z {
        let dst: &mut [u8; 640] = (&mut sig[pos..pos + 640]).try_into().expect("640 bytes");
        bit_pack_gamma1(p, dst);
        pos += 640;
    }
    let h_dst: &mut [u8; OMEGA + K] = (&mut sig[pos..pos + OMEGA + K])
        .try_into()
        .expect("hint bytes");
    hint_bit_pack(h, h_dst);
    sig
}

fn sig_decode(sig: &[u8]) -> Option<([u8; C_TILDE_LEN], [Poly; L], [[u8; N]; K])> {
    if sig.len() != SIGNATURE_LEN {
        return None;
    }
    let mut c_tilde = [0u8; C_TILDE_LEN];
    c_tilde.copy_from_slice(&sig[..C_TILDE_LEN]);
    let mut z = [[0i32; N]; L];
    let mut pos = C_TILDE_LEN;
    for p in &mut z {
        *p = bit_unpack_gamma1(&sig[pos..pos + 640]);
        pos += 640;
    }
    let h = hint_bit_unpack(&sig[pos..])?;
    Some((c_tilde, z, h))
}

// ---------------------------------------------------------------------------------------------------------------------
// FIPS 204 Core Algorithms: KeyGen_internal, Sign, Verify

/// `ML-DSA.KeyGen_internal(xi)` for parameter set ML-DSA-65 (FIPS 204 Algorithm 6).
pub fn keygen_from_seed(seed: &[u8; 32]) -> ([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]) {
    let mut expanded = [0u8; 128];
    let kl = [K as u8, L as u8];
    shake256_once(&[seed, &kl], &mut expanded);
    let rho: [u8; 32] = expanded[..32].try_into().expect("32 bytes");
    let rho_prime: [u8; 64] = expanded[32..96].try_into().expect("64 bytes");
    let k_seed: [u8; 32] = expanded[96..128].try_into().expect("32 bytes");

    let hat_a = expand_a(&rho);
    let (s1, s2) = expand_s(&rho_prime);
    let mut hat_s1 = [[0i32; N]; L];
    for i in 0..L {
        hat_s1[i] = ntt(&s1[i]);
    }
    let a_s1_hat = mat_vec_mul_ntt(&hat_a, &hat_s1);
    let mut t1 = [[0i32; N]; K];
    let mut t0 = [[0i32; N]; K];
    for r in 0..K {
        let t_r = poly_add(&inv_ntt(&a_s1_hat[r]), &s2[r]);
        for j in 0..N {
            let (hi, lo) = power2round(t_r[j]);
            t1[r][j] = hi;
            t0[r][j] = lo;
        }
    }
    let pk = pk_encode(&rho, &t1);
    let mut tr = [0u8; 64];
    shake256_once(&[&pk], &mut tr);
    let sk = sk_encode(&rho, &k_seed, &tr, &s1, &s2, &t0);
    (pk, sk)
}

/// Deterministic `ML-DSA.Sign(sk, M, ctx)` (FIPS 204 Algorithm 2 + Algorithm 7, `rnd = 0`).
pub fn sign_deterministic(
    sk: &[u8; SECRET_KEY_LEN],
    message: &[u8],
    ctx: &[u8],
) -> Result<[u8; SIGNATURE_LEN], &'static str> {
    if ctx.len() > 255 {
        return Err("ML-DSA context exceeds 255 bytes");
    }
    let prefix = [0x00_u8, ctx.len() as u8];
    let mut m_prime = Vec::with_capacity(2 + ctx.len() + message.len());
    m_prime.extend_from_slice(&prefix);
    m_prime.extend_from_slice(ctx);
    m_prime.extend_from_slice(message);
    sign_internal(sk, &m_prime, &[0u8; 32])
}

/// `ML-DSA.Sign_internal(sk, M', rnd)` (FIPS 204 Algorithm 7).
pub fn sign_internal(
    sk_bytes: &[u8],
    m_prime: &[u8],
    rnd: &[u8; 32],
) -> Result<[u8; SIGNATURE_LEN], &'static str> {
    let sk = sk_decode(sk_bytes)?;
    let hat_a = expand_a(&sk.rho);
    let mut hat_s1 = [[0i32; N]; L];
    for i in 0..L {
        hat_s1[i] = ntt(&sk.s1[i]);
    }
    let mut hat_s2 = [[0i32; N]; K];
    let mut hat_t0 = [[0i32; N]; K];
    for i in 0..K {
        hat_s2[i] = ntt(&sk.s2[i]);
        hat_t0[i] = ntt(&sk.t0[i]);
    }
    let mut mu = [0u8; 64];
    shake256_once(&[&sk.tr, m_prime], &mut mu);
    let mut rho_double_prime = [0u8; 64];
    shake256_once(&[&sk.k_seed, rnd, &mu], &mut rho_double_prime);

    let mut kappa = 0u16;
    loop {
        let y = expand_mask(&rho_double_prime, kappa);
        let mut hat_y = [[0i32; N]; L];
        for i in 0..L {
            hat_y[i] = ntt(&y[i]);
        }
        let ay_hat = mat_vec_mul_ntt(&hat_a, &hat_y);
        let mut w = [[0i32; N]; K];
        let mut w1 = [[0i32; N]; K];
        for r in 0..K {
            w[r] = inv_ntt(&ay_hat[r]);
            for j in 0..N {
                w1[r][j] = high_bits(w[r][j]);
            }
        }
        let w1_bytes = w1_encode(&w1);
        let mut c_tilde = [0u8; C_TILDE_LEN];
        shake256_once(&[&mu, &w1_bytes], &mut c_tilde);
        let c = sample_in_ball(&c_tilde);
        let hat_c = ntt(&c);

        let mut c_s1 = [[0i32; N]; L];
        let mut z = [[0i32; N]; L];
        let mut norm_ok = true;
        for i in 0..L {
            c_s1[i] = inv_ntt(&poly_pointwise(&hat_c, &hat_s1[i]));
            z[i] = poly_add(&y[i], &c_s1[i]);
            if poly_inf_norm(&z[i]) >= GAMMA1 - BETA {
                norm_ok = false;
                break;
            }
        }
        if !norm_ok {
            kappa = kappa.wrapping_add(L as u16);
            continue;
        }

        let mut c_s2 = [[0i32; N]; K];
        let mut w_minus_cs2 = [[0i32; N]; K];
        for r in 0..K {
            c_s2[r] = inv_ntt(&poly_pointwise(&hat_c, &hat_s2[r]));
            w_minus_cs2[r] = poly_sub(&w[r], &c_s2[r]);
            let mut r0 = [0i32; N];
            for j in 0..N {
                r0[j] = low_bits(w_minus_cs2[r][j]);
            }
            if poly_inf_norm(&r0) >= GAMMA2 - BETA {
                norm_ok = false;
                break;
            }
        }
        if !norm_ok {
            kappa = kappa.wrapping_add(L as u16);
            continue;
        }

        let mut c_t0 = [[0i32; N]; K];
        let mut h = [[0u8; N]; K];
        let mut hint_ones = 0usize;
        for r in 0..K {
            c_t0[r] = inv_ntt(&poly_pointwise(&hat_c, &hat_t0[r]));
            if poly_inf_norm(&c_t0[r]) >= GAMMA2 {
                norm_ok = false;
                break;
            }
            for j in 0..N {
                let neg_ct0 = Q - c_t0[r][j].rem_euclid(Q);
                let w_adj = mod_q(i64::from(w_minus_cs2[r][j]) + i64::from(c_t0[r][j]));
                let bit = make_hint(neg_ct0, w_adj);
                h[r][j] = bit;
                hint_ones += usize::from(bit);
            }
        }
        if !norm_ok || hint_ones > OMEGA {
            kappa = kappa.wrapping_add(L as u16);
            continue;
        }

        return Ok(sig_encode(&c_tilde, &z, &h));
    }
}

/// Pure `ML-DSA.Verify(pk, M, ctx, sig)` (FIPS 204 Algorithm 3 + Algorithm 8).
pub fn verify(pk: &[u8], message: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    if ctx.len() > 255 {
        return false;
    }
    let mut m_prime = Vec::with_capacity(2 + ctx.len() + message.len());
    m_prime.push(0x00);
    m_prime.push(ctx.len() as u8);
    m_prime.extend_from_slice(ctx);
    m_prime.extend_from_slice(message);
    verify_internal(pk, &m_prime, sig)
}

/// `ML-DSA.Verify_internal(pk, M', sig)` (FIPS 204 Algorithm 8).
pub fn verify_internal(pk: &[u8], m_prime: &[u8], sig: &[u8]) -> bool {
    let Some((rho, t1)) = pk_decode(pk) else {
        return false;
    };
    let Some((c_tilde, z, h)) = sig_decode(sig) else {
        return false;
    };
    for p in &z {
        if poly_inf_norm(p) >= GAMMA1 - BETA {
            return false;
        }
    }
    let hat_a = expand_a(&rho);
    let mut tr = [0u8; 64];
    shake256_once(&[pk], &mut tr);
    let mut mu = [0u8; 64];
    shake256_once(&[&tr, m_prime], &mut mu);

    let c = sample_in_ball(&c_tilde);
    let hat_c = ntt(&c);
    let mut hat_z = [[0i32; N]; L];
    for i in 0..L {
        hat_z[i] = ntt(&z[i]);
    }
    let az_hat = mat_vec_mul_ntt(&hat_a, &hat_z);

    let mut w1_prime = [[0i32; N]; K];
    for r in 0..K {
        let mut t1_scaled = [0i32; N];
        for j in 0..N {
            t1_scaled[j] = mod_q(i64::from(t1[r][j]) << D);
        }
        let c_t1_hat = poly_pointwise(&hat_c, &ntt(&t1_scaled));
        let w_approx = inv_ntt(&poly_sub(&az_hat[r], &c_t1_hat));
        for j in 0..N {
            w1_prime[r][j] = use_hint(h[r][j], w_approx[j]);
        }
    }

    let w1_bytes = w1_encode(&w1_prime);
    let mut c_tilde_prime = [0u8; C_TILDE_LEN];
    shake256_once(&[&mu, &w1_bytes], &mut c_tilde_prime);
    c_tilde == c_tilde_prime
}

// ---------------------------------------------------------------------------------------------------------------------
// Key validation & ASN.1 SPKI / RFC 9881 PKCS#8 helpers

/// Validates a raw 1952-byte ML-DSA-65 public key.
pub fn validate_public_key(pk: &[u8]) -> Result<(), &'static str> {
    if pk.len() != PUBLIC_KEY_LEN {
        return Err("an ML-DSA-65 public key is 1952 bytes");
    }
    Ok(())
}

/// Recomputes and verifies an ML-DSA-65 public key from a 4032-byte expanded private key.
pub fn derive_public_key_from_expanded(
    sk_bytes: &[u8],
) -> Result<[u8; PUBLIC_KEY_LEN], &'static str> {
    let sk = sk_decode(sk_bytes)?;
    let hat_a = expand_a(&sk.rho);
    let mut hat_s1 = [[0i32; N]; L];
    for i in 0..L {
        hat_s1[i] = ntt(&sk.s1[i]);
    }
    let a_s1_hat = mat_vec_mul_ntt(&hat_a, &hat_s1);
    let mut t1 = [[0i32; N]; K];
    let mut t0_calc = [[0i32; N]; K];
    for r in 0..K {
        let t_r = poly_add(&inv_ntt(&a_s1_hat[r]), &sk.s2[r]);
        for j in 0..N {
            let (hi, lo) = power2round(t_r[j]);
            t1[r][j] = hi;
            t0_calc[r][j] = lo;
        }
    }
    if t0_calc != sk.t0 {
        return Err("ML-DSA-65 expanded private key t0 mismatch");
    }
    let pk = pk_encode(&sk.rho, &t1);
    let mut tr_calc = [0u8; 64];
    shake256_once(&[&pk], &mut tr_calc);
    if tr_calc != sk.tr {
        return Err("ML-DSA-65 expanded private key tr hash mismatch");
    }
    Ok(pk)
}

/// Parses RFC 9881 `ML-DSA-PrivateKey` (the `OCTET STRING` content inside PKCS#8 `PrivateKeyInfo`)
/// and returns `(public_key, expanded_secret_key)`.
///
/// Accepts all RFC 9881 / Bouncy Castle choices:
/// - `[0] IMPLICIT OCTET STRING (32)` (`seed`)
/// - `OCTET STRING (32)` (`seed`, pre-RFC draft)
/// - `OCTET STRING (4032)` (`expandedKey`)
/// - `SEQUENCE { OCTET STRING(32), OCTET STRING(4032) }` (`both`, verifying seed expands to key)
pub fn parse_pkcs8_inner(
    inner: &[u8],
) -> Result<([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]), &'static str> {
    let node = ber::read_only(inner).map_err(|_| "malformed ML-DSA private key ASN.1")?;
    match node.tag {
        0x80 => {
            let seed: &[u8; 32] = node
                .content
                .try_into()
                .map_err(|_| "ML-DSA-65 seed must be 32 bytes")?;
            Ok(keygen_from_seed(seed))
        }
        ber::OCTET_STRING => {
            if let Ok(seed) = <&[u8; 32]>::try_from(node.content) {
                return Ok(keygen_from_seed(seed));
            }
            if node.content.len() == SECRET_KEY_LEN {
                let pk = derive_public_key_from_expanded(node.content)?;
                let sk: [u8; SECRET_KEY_LEN] = node.content.try_into().expect("checked 4032 bytes");
                return Ok((pk, sk));
            }
            Err("unexpected ML-DSA-65 private key octet length")
        }
        ber::SEQUENCE => {
            let parts = ber::children(&node).map_err(|_| "malformed ML-DSA both sequence")?;
            if parts.len() != 2
                || parts[0].tag != ber::OCTET_STRING
                || parts[1].tag != ber::OCTET_STRING
            {
                return Err("ML-DSA-65 both sequence requires seed and expandedKey octet strings");
            }
            let seed: &[u8; 32] = parts[0]
                .content
                .try_into()
                .map_err(|_| "ML-DSA-65 seed must be 32 bytes")?;
            let expanded: &[u8; SECRET_KEY_LEN] = parts[1]
                .content
                .try_into()
                .map_err(|_| "ML-DSA-65 expandedKey must be 4032 bytes")?;
            let (pk, sk) = keygen_from_seed(seed);
            if &sk != expanded {
                return Err("ML-DSA-65 seed and expandedKey disagree");
            }
            Ok((pk, sk))
        }
        _ => Err("unexpected ML-DSA-65 private key ASN.1 tag"),
    }
}

/// Validates RFC 9881 `ML-DSA-PrivateKey` and returns the derived 1952-byte public key.
pub fn derive_public_key_from_pkcs8_inner(
    inner: &[u8],
) -> Result<[u8; PUBLIC_KEY_LEN], &'static str> {
    parse_pkcs8_inner(inner).map(|(pk, _)| pk)
}

fn push_der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
}

fn wrap_der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + content.len());
    out.push(tag);
    push_der_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// DER `SubjectPublicKeyInfo` for an ML-DSA-65 public key (RFC 9881, absent algorithm params).
pub fn encode_spki(pk: &[u8; PUBLIC_KEY_LEN]) -> Vec<u8> {
    let alg = wrap_der_tlv(ber::SEQUENCE, &wrap_der_tlv(ber::OID, OID_ML_DSA_65));
    let mut bits = Vec::with_capacity(1 + pk.len());
    bits.push(0x00);
    bits.extend_from_slice(pk);
    let bit_string = wrap_der_tlv(ber::BIT_STRING, &bits);
    let mut body = alg;
    body.extend_from_slice(&bit_string);
    wrap_der_tlv(ber::SEQUENCE, &body)
}

fn wrap_pkcs8(inner: &[u8]) -> Vec<u8> {
    let version = [0x02_u8, 0x01, 0x00];
    let alg = wrap_der_tlv(ber::SEQUENCE, &wrap_der_tlv(ber::OID, OID_ML_DSA_65));
    let priv_octets = wrap_der_tlv(ber::OCTET_STRING, inner);
    let mut body = Vec::with_capacity(version.len() + alg.len() + priv_octets.len());
    body.extend_from_slice(&version);
    body.extend_from_slice(&alg);
    body.extend_from_slice(&priv_octets);
    wrap_der_tlv(ber::SEQUENCE, &body)
}

/// DER `PrivateKeyInfo` using RFC 9881 `seed [0]` encoding.
pub fn encode_pkcs8_seed(seed: &[u8; 32]) -> Vec<u8> {
    let inner = wrap_der_tlv(0x80, seed);
    wrap_pkcs8(&inner)
}

/// DER `PrivateKeyInfo` using RFC 9881 `expandedKey OCTET STRING` encoding.
pub fn encode_pkcs8_expanded(sk: &[u8; SECRET_KEY_LEN]) -> Vec<u8> {
    let inner = wrap_der_tlv(ber::OCTET_STRING, sk);
    wrap_pkcs8(&inner)
}

/// DER `PrivateKeyInfo` using RFC 9881 `both SEQUENCE { seed, expandedKey }` encoding.
pub fn encode_pkcs8_both(seed: &[u8; 32], sk: &[u8; SECRET_KEY_LEN]) -> Vec<u8> {
    let mut seq_body = wrap_der_tlv(ber::OCTET_STRING, seed);
    seq_body.extend_from_slice(&wrap_der_tlv(ber::OCTET_STRING, sk));
    let inner = wrap_der_tlv(ber::SEQUENCE, &seq_body);
    wrap_pkcs8(&inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shake_matches_fips_202_abc_vectors() {
        let mut out128 = [0u8; 32];
        let mut x128 = ShakeXof::shake128();
        x128.absorb(b"abc");
        x128.squeeze(&mut out128);
        assert_eq!(
            hex::encode(out128),
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
        );

        let mut out256 = [0u8; 64];
        shake256_once(&[b"abc"], &mut out256);
        assert_eq!(
            hex::encode(out256),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        );
    }

    #[test]
    fn keygen_sign_verify_and_pkcs8_forms_roundtrip() {
        let seed = [0x42u8; 32];
        let (pk, sk) = keygen_from_seed(&seed);
        let msg = b"canton-mldsa65-domain-message";
        let sig = sign_deterministic(&sk, msg, b"").expect("sign");
        assert!(verify(&pk, msg, b"", &sig));

        let mut bad_msg = msg.to_vec();
        bad_msg[0] ^= 1;
        assert!(!verify(&pk, &bad_msg, b"", &sig));

        let mut bad_sig = sig;
        bad_sig[100] ^= 0x01;
        assert!(!verify(&pk, msg, b"", &bad_sig));

        let spki_der = encode_spki(&pk);
        let parsed_spki = ber::parse_spki(&spki_der).expect("parse spki");
        assert_eq!(parsed_spki.key_bits, pk);

        for der in [
            encode_pkcs8_seed(&seed),
            encode_pkcs8_expanded(&sk),
            encode_pkcs8_both(&seed, &sk),
        ] {
            let pki = ber::parse_pkcs8(&der).expect("parse pkcs8");
            let derived = derive_public_key_from_pkcs8_inner(&pki.private_key).expect("derive");
            assert_eq!(derived, pk);
        }
    }
}
