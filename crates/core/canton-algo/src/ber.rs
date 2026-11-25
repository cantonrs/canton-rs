//! A small ASN.1 reader that is as lenient as the Bouncy Castle parser the Canton 3.7.2 node uses (U-12).
//!
//! The RustCrypto `der` crate is strict DER: it refuses non-minimal lengths and indefinite lengths. The node does not
//! (`SubjectPublicKeyInfo.getInstance`, `PrivateKeyInfo.getInstance`), so a key that the node accepts would be refused here
//! if its container were parsed by `der`.
//!
//! [CANTON-NOTE: SEMANTICS] Measured on a Canton 3.7.2 node (tests/oracle/canton-crypto `pk` and `sk` lines):
//! - a definite length may be written in a non-minimal long form (`30 84 00 00 00 59 ...`): accepted;
//! - an indefinite length (`30 80 ... 00 00`) is accepted for EC SubjectPublicKeyInfo and for every PKCS#8 key;
//! - bytes after the single top-level element are refused ("extra data");
//! - a BIT STRING whose unused-bits count is not 0 has its last byte masked (`ASN1BitString.getBytes`).
//!
//! [CANTON-NOTE: LIMITATION] High tag numbers, OBJECT IDENTIFIERs written with a non-minimal arc encoding and BER
//! constructed strings are refused here; the node was not asked about them.

/// One parsed element: its tag byte and the bytes between the header and the end (without the end-of-content marker).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Node<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    /// The length was written as `0x80` (BER indefinite form).
    pub indefinite: bool,
}

pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const BIT_STRING: u8 = 0x03;
pub(crate) const OCTET_STRING: u8 = 0x04;
pub(crate) const NULL: u8 = 0x05;
pub(crate) const OID: u8 = 0x06;

/// Reads one element and returns it with the input that follows it.
pub(crate) fn read_node(input: &[u8]) -> Result<(Node<'_>, &[u8]), String> {
    let (&tag, rest) = input.split_first().ok_or("unexpected end of input")?;
    if tag & 0x1f == 0x1f {
        return Err("high tag numbers are not supported".into());
    }
    let (&first, rest) = rest.split_first().ok_or("missing length")?;
    if first == 0x80 {
        if tag & 0x20 == 0 {
            return Err("indefinite length on a primitive element".into());
        }
        // children follow until a pair of zero bytes
        let mut cursor = rest;
        loop {
            if cursor.starts_with(&[0, 0]) {
                let content = &rest[..rest.len() - cursor.len()];
                return Ok((
                    Node {
                        tag,
                        content,
                        indefinite: true,
                    },
                    &cursor[2..],
                ));
            }
            let (_, next) = read_node(cursor)?;
            cursor = next;
        }
    }
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n > 4 || first == 0xff {
            return Err("length longer than 4 bytes".into());
        }
        if rest.len() < n {
            return Err("truncated length".into());
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    if len > rest.len() {
        return Err("length exceeds the input".into());
    }
    Ok((
        Node {
            tag,
            content: &rest[..len],
            indefinite: false,
        },
        &rest[len..],
    ))
}

/// Reads the single element of `input` and refuses anything after it.
pub(crate) fn read_only(input: &[u8]) -> Result<Node<'_>, String> {
    let (node, rest) = read_node(input)?;
    if !rest.is_empty() {
        return Err("extra data detected in stream".into());
    }
    Ok(node)
}

/// All children of a constructed element.
pub(crate) fn children<'a>(node: &Node<'a>) -> Result<Vec<Node<'a>>, String> {
    let mut out = Vec::new();
    let mut rest = node.content;
    while !rest.is_empty() {
        let (child, next) = read_node(rest)?;
        out.push(child);
        rest = next;
    }
    Ok(out)
}

/// An `AlgorithmIdentifier`: the algorithm OID (content bytes) and what follows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AlgorithmId {
    pub oid: Vec<u8>,
    pub params: Params,
}

/// Parsed RFC 5480 / SEC 1 explicit `ECParameters` (`X9ECParameters`) for a prime-field curve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExplicitEcParams {
    pub prime: Vec<u8>,
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub base_point: Vec<u8>,
    pub order: Vec<u8>,
    pub cofactor: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Params {
    Absent,
    Null,
    Oid(Vec<u8>),
    Explicit(ExplicitEcParams),
    Other,
}

const OID_PRIME_FIELD: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01];

/// Validates ASN.1 BER/DER OID content octets: non-empty, terminated (`< 0x80`), no leading `0x80` padding in a VLQ arc.
pub(crate) fn validate_oid_content(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.last().is_none_or(|b| *b & 0x80 != 0) {
        return Err("malformed OID".into());
    }
    let mut at_arc_start = true;
    for &b in bytes {
        if at_arc_start && b == 0x80 {
            return Err("non-minimal OID subidentifier".into());
        }
        at_arc_start = b < 0x80;
    }
    Ok(())
}

fn parse_explicit_ec_params(node: &Node<'_>) -> Result<ExplicitEcParams, String> {
    let parts = children(node)?;
    if parts.len() < 5 || parts.len() > 6 {
        return Err("ECParameters must have 5 or 6 fields".into());
    }
    if parts[0].tag != INTEGER || parts[0].content != [1] {
        return Err("unsupported ECParameters version".into());
    }
    if parts[1].tag != SEQUENCE {
        return Err("ECParameters fieldID is not a SEQUENCE".into());
    }
    let field_parts = children(&parts[1])?;
    if field_parts.len() != 2 || field_parts[0].tag != OID || field_parts[1].tag != INTEGER {
        return Err("malformed ECParameters fieldID".into());
    }
    validate_oid_content(field_parts[0].content)?;
    if field_parts[0].content != OID_PRIME_FIELD {
        return Err("unsupported EC field type".into());
    }
    if parts[2].tag != SEQUENCE {
        return Err("ECParameters curve is not a SEQUENCE".into());
    }
    let curve_parts = children(&parts[2])?;
    if curve_parts.len() < 2
        || curve_parts.len() > 3
        || curve_parts[0].tag != OCTET_STRING
        || curve_parts[1].tag != OCTET_STRING
        || (curve_parts.len() == 3 && curve_parts[2].tag != BIT_STRING)
    {
        return Err("malformed ECParameters curve".into());
    }
    if parts[3].tag != OCTET_STRING || parts[4].tag != INTEGER {
        return Err("malformed ECParameters base or order".into());
    }
    let cofactor = if let Some(cof) = parts.get(5) {
        if cof.tag != INTEGER {
            return Err("malformed ECParameters cofactor".into());
        }
        Some(cof.content.to_vec())
    } else {
        None
    };
    Ok(ExplicitEcParams {
        prime: field_parts[1].content.to_vec(),
        a: curve_parts[0].content.to_vec(),
        b: curve_parts[1].content.to_vec(),
        base_point: parts[3].content.to_vec(),
        order: parts[4].content.to_vec(),
        cofactor,
    })
}

pub(crate) fn algorithm_id(node: &Node<'_>) -> Result<AlgorithmId, String> {
    if node.tag != SEQUENCE {
        return Err("algorithm identifier is not a SEQUENCE".into());
    }
    let parts = children(node)?;
    if parts.is_empty() || parts.len() > 2 || parts[0].tag != OID {
        return Err("bad algorithm identifier".into());
    }
    validate_oid_content(parts[0].content)?;
    let params = match parts.get(1) {
        None => Params::Absent,
        Some(p) if p.tag == NULL && p.content.is_empty() => Params::Null,
        Some(p) if p.tag == OID => {
            validate_oid_content(p.content)?;
            Params::Oid(p.content.to_vec())
        }
        Some(p) if p.tag == SEQUENCE => Params::Explicit(parse_explicit_ec_params(p)?),
        Some(_) => Params::Other,
    };
    Ok(AlgorithmId {
        oid: parts[0].content.to_vec(),
        params,
    })
}

/// A parsed `SubjectPublicKeyInfo`.
#[derive(Debug, Clone)]
pub(crate) struct Spki {
    pub algorithm: AlgorithmId,
    /// The BIT STRING bytes; the unused bits of the last byte are cleared as Bouncy Castle does.
    pub key_bits: Vec<u8>,
    pub unused_bits: u8,
    pub indefinite: bool,
}

pub(crate) fn parse_spki(bytes: &[u8]) -> Result<Spki, String> {
    let top = read_only(bytes)?;
    if top.tag != SEQUENCE {
        return Err("SubjectPublicKeyInfo is not a SEQUENCE".into());
    }
    let parts = children(&top)?;
    if parts.len() != 2 {
        return Err("SubjectPublicKeyInfo needs exactly two elements".into());
    }
    let algorithm = algorithm_id(&parts[0])?;
    let bits = &parts[1];
    if bits.tag != BIT_STRING || bits.content.is_empty() {
        return Err("public key is not a BIT STRING".into());
    }
    let unused_bits = bits.content[0];
    let mut key_bits = bits.content[1..].to_vec();
    if unused_bits > 7 || (key_bits.is_empty() && unused_bits != 0) {
        return Err("illegal unused-bits count in the BIT STRING".into());
    }
    if let Some(last) = key_bits.last_mut() {
        *last &= 0xffu8 << unused_bits;
    }
    Ok(Spki {
        algorithm,
        key_bits,
        unused_bits,
        indefinite: top.indefinite,
    })
}

/// A parsed PKCS#8 `PrivateKeyInfo`: the algorithm and the content of the private-key OCTET STRING.
#[derive(Debug, Clone)]
pub(crate) struct Pkcs8 {
    pub algorithm: AlgorithmId,
    pub private_key: Vec<u8>,
}

pub(crate) fn parse_pkcs8(bytes: &[u8]) -> Result<Pkcs8, String> {
    let top = read_only(bytes)?;
    if top.tag != SEQUENCE {
        return Err("PrivateKeyInfo is not a SEQUENCE".into());
    }
    let parts = children(&top)?;
    if parts.len() < 3 || parts[0].tag != INTEGER || parts[2].tag != OCTET_STRING {
        return Err("PrivateKeyInfo needs a version, an algorithm and a key".into());
    }
    // [CANTON-NOTE: SEMANTICS] Bouncy Castle accepts version 0 and 1 and refuses 2 (measured: sk `outerVersion1`, `outerVersion2`).
    let version = match parts[0].content {
        [0] => 0u8,
        [1] => 1u8,
        _ => return Err("invalid version for private key info".into()),
    };
    // Optional RFC 5208 / RFC 5958 trailing fields: attributes [0] (0xa0) and publicKey [1] (0x81, v1 only).
    let mut seen_attrs = false;
    let mut seen_pub = false;
    for opt in &parts[3..] {
        match opt.tag {
            0xa0 if !seen_attrs && !seen_pub => {
                // Validate inner attributes set elements as BER TLVs.
                let _ = children(opt)?;
                seen_attrs = true;
            }
            0x81 if version == 1 && !seen_pub => {
                if opt.content.is_empty() || opt.content[0] > 7 {
                    return Err("malformed publicKey bit string in PrivateKeyInfo".into());
                }
                seen_pub = true;
            }
            _ => return Err("invalid optional field in PrivateKeyInfo".into()),
        }
    }
    Ok(Pkcs8 {
        algorithm: algorithm_id(&parts[1])?,
        private_key: parts[2].content.to_vec(),
    })
}
