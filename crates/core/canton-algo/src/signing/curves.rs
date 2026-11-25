//! Elliptic curve parameters and point validation (P-256, P-384, secp256k1, Ed25519).

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::IsIdentity;

use crate::ber;
use crate::ber::Params;

use super::{crypto_err, ProtoError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Curve {
    P256,
    P384,
    K256,
}

pub(super) const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

const OID_K256: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x0a];

pub(super) const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

/// The prime of each curve's field, big endian.
const P256_P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

const K256_P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

const P384_P: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
];

/// The group orders, big endian.
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

const K256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

const P384_N: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
    0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
];

impl Curve {
    fn from_oid(oid: &[u8]) -> Option<Curve> {
        match oid {
            OID_P256 => Some(Curve::P256),
            OID_P384 => Some(Curve::P384),
            OID_K256 => Some(Curve::K256),
            _ => None,
        }
    }

    fn oid(self) -> &'static [u8] {
        match self {
            Curve::P256 => OID_P256,
            Curve::P384 => OID_P384,
            Curve::K256 => OID_K256,
        }
    }

    /// The byte length of a field element and of a scalar.
    pub(super) fn size(self) -> usize {
        match self {
            Curve::P384 => 48,
            _ => 32,
        }
    }

    pub(super) fn prime(self) -> &'static [u8] {
        match self {
            Curve::P256 => &P256_P,
            Curve::P384 => &P384_P,
            Curve::K256 => &K256_P,
        }
    }

    pub(super) fn order(self) -> &'static [u8] {
        match self {
            Curve::P256 => &P256_N,
            Curve::P384 => &P384_N,
            Curve::K256 => &K256_N,
        }
    }

    fn from_explicit_params(explicit: &ber::ExplicitEcParams) -> Option<Curve> {
        // P-256, P-384, and secp256k1 all have cofactor = 1.
        if let Some(cof) = &explicit.cofactor {
            if trim_zeros(cof) != [1] {
                return None;
            }
        }
        let curve = match trim_zeros(&explicit.prime) {
            p if p == P256_P => Curve::P256,
            p if p == P384_P => Curve::P384,
            p if p == K256_P => Curve::K256,
            _ => return None,
        };
        if trim_zeros(&explicit.order) != curve.order() {
            return None;
        }
        let (expected_a, expected_b, expected_gx, expected_gy): (&[u8], &[u8], &[u8], &[u8]) =
            match curve {
                Curve::P256 => (
                    &[
                        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xfc,
                    ],
                    &[
                        0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55,
                        0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
                        0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
                    ],
                    &[
                        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5,
                        0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
                        0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
                    ],
                    &[
                        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
                        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
                        0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
                    ],
                ),
                Curve::P384 => (
                    &[
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0,
                        0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xfc,
                    ],
                    &[
                        0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b,
                        0xe3, 0xf8, 0x2d, 0x19, 0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12,
                        0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a, 0xc6, 0x56, 0x39, 0x8d,
                        0x8a, 0x2e, 0xd1, 0x9d, 0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef,
                    ],
                    &[
                        0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e,
                        0xf3, 0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98,
                        0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d,
                        0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7,
                    ],
                    &[
                        0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf,
                        0x92, 0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
                        0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce,
                        0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
                    ],
                ),
                Curve::K256 => (
                    &[0; 32],
                    &[
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 7,
                    ],
                    &[
                        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95,
                        0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
                        0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
                    ],
                    &[
                        0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc,
                        0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
                        0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
                    ],
                ),
            };
        if trim_zeros(&explicit.a) != trim_zeros(expected_a)
            || trim_zeros(&explicit.b) != trim_zeros(expected_b)
        {
            return None;
        }
        let (gx, gy) = decode_point(curve, &explicit.base_point).ok()?;
        if gx != expected_gx || gy != expected_gy {
            return None;
        }
        Some(curve)
    }

    pub(super) fn from_algorithm_params(params: &Params) -> Result<Curve, ProtoError> {
        match params {
            Params::Oid(oid) => Curve::from_oid(oid).ok_or_else(|| crypto_err("unknown curve")),
            Params::Explicit(ep) => Curve::from_explicit_params(ep)
                .ok_or_else(|| crypto_err("unknown explicit EC parameters")),
            _ => Err(crypto_err("EC key without named-curve parameters")),
        }
    }
}

/// `a >= b` for big-endian unsigned integers of any length.
pub(super) fn be_ge(a: &[u8], b: &[u8]) -> bool {
    let a = trim_zeros(a);
    let b = trim_zeros(b);
    a.len() > b.len() || (a.len() == b.len() && a >= b)
}

pub(super) fn trim_zeros(a: &[u8]) -> &[u8] {
    let n = a.iter().take_while(|x| **x == 0).count();
    &a[n..]
}

pub(super) fn be_is_zero(a: &[u8]) -> bool {
    a.iter().all(|x| *x == 0)
}

/// Decodes an EC point of `curve` as Bouncy Castle's `ECCurve.decodePoint` does and returns its affine coordinates.
///
/// [CANTON-NOTE: SEMANTICS] Compressed (02, 03), uncompressed (04) and hybrid (06, 07) forms are accepted. A compressed
/// point with the "wrong" parity is simply the other point with that x. A hybrid point whose parity bit disagrees with y is
/// refused. The point at infinity (a single 00) and any coordinate not below the field prime are refused.
pub(super) fn decode_point(curve: Curve, bits: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let n = curve.size();
    let sec1: Vec<u8> = match (bits.first(), bits.len()) {
        (Some(0x02 | 0x03), l) if l == 1 + n => bits.to_vec(),
        (Some(0x04), l) if l == 1 + 2 * n => bits.to_vec(),
        (Some(p @ (0x06 | 0x07)), l) if l == 1 + 2 * n => {
            if bits[l - 1] & 1 != p & 1 {
                return Err("inconsistent Y coordinate in hybrid encoding".into());
            }
            let mut u = bits.to_vec();
            u[0] = 0x04;
            u
        }
        _ => return Err("invalid point encoding".into()),
    };
    // p256 and p384 (elliptic-curve 0.14) name the trait `ToSec1Point`, k256 (0.13) `ToEncodedPoint`
    macro_rules! decode {
        ($c:ident, $tr:ident, $m:ident) => {{
            use $c::elliptic_curve::sec1::$tr as _;
            let pk = $c::PublicKey::from_sec1_bytes(&sec1).map_err(|e| e.to_string())?;
            let ep = pk.$m(false);
            match (ep.x(), ep.y()) {
                (Some(x), Some(y)) => (x.to_vec(), y.to_vec()),
                _ => return Err("point at infinity".into()),
            }
        }};
    }
    Ok(match curve {
        Curve::P256 => decode!(p256, ToSec1Point, to_sec1_point),
        Curve::P384 => decode!(p384, ToSec1Point, to_sec1_point),
        Curve::K256 => decode!(k256, ToEncodedPoint, to_encoded_point),
    })
}

const ED25519_P_LE: [u8; 32] = {
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

/// `Ed25519.validatePublicKeyFull`: a canonical encoding of a point of the prime-order subgroup that is not the identity.
///
/// [CANTON-NOTE: SEMANTICS] Measured: the identity, the order-2 and order-4 points, the non-canonical encoding of the
/// identity and y values that are not on the curve are all refused. A point with the sign bit flipped is a valid key.
pub(super) fn validate_ed25519_point(bits: &[u8]) -> Result<(), String> {
    let arr: [u8; 32] = bits
        .try_into()
        .map_err(|_| "an Ed25519 public key is 32 bytes".to_string())?;
    let mut y = arr;
    y[31] &= 0x7f;
    // y must be below p = 2^255 - 19 (little endian, compare from the most significant byte)
    let y_ge_p = y
        .iter()
        .rev()
        .zip(ED25519_P_LE.iter().rev())
        .find(|(a, b)| a != b)
        .is_none_or(|(a, b)| a > b);
    if y_ge_p {
        return Err("y is not canonical".into());
    }
    let point = CompressedEdwardsY(arr)
        .decompress()
        .ok_or("not a point on the curve")?;
    if point.is_identity() || !point.is_torsion_free() {
        return Err("not a point of the prime-order subgroup".into());
    }
    Ok(())
}

/// The X.509 encoding the node derives for an Ed25519 public key.
pub(super) fn ed25519_spki(key: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    out.extend_from_slice(key);
    out
}

pub(super) fn ec_spki(curve: Curve, point: &[u8]) -> Vec<u8> {
    let mut alg = vec![0x06, OID_EC_PUBLIC_KEY.len() as u8];
    alg.extend_from_slice(OID_EC_PUBLIC_KEY);
    alg.extend_from_slice(&[0x06, curve.oid().len() as u8]);
    alg.extend_from_slice(curve.oid());
    let mut body = vec![0x30, alg.len() as u8];
    body.extend_from_slice(&alg);
    body.extend_from_slice(&[0x03, (point.len() + 1) as u8, 0x00]);
    body.extend_from_slice(point);
    let mut out = vec![0x30, body.len() as u8];
    out.extend_from_slice(&body);
    out
}
