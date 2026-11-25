//! The nesting bound of decoding untrusted bytes.
//!
//! [CANTON-NOTE: WHY] prost's own bound is a compile-time 100 that `no-recursion-limit` lifts for the whole binary (Cargo unifies
//! features), and Daml-LF packages need it lifted. Canton parses with protobuf-java, whose bound is per parse:
//! `CodedInputStream.DEFAULT_RECURSION_LIMIT` (100) for gRPC messages and protocol messages, `EXTENDED_PROTOBUF_RECURSION_LIMIT`
//! (1000, `daml-lf/archive/.../package.scala`) for Daml-LF packages. This module measures the nesting of the bytes from the schema
//! before prost decodes them, so each boundary applies Canton's bound and no input reaches prost's unbounded recursion.
use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

use prost::Message;

/// protobuf-java's `CodedInputStream.DEFAULT_RECURSION_LIMIT`: what Canton applies to every gRPC request and protocol message.
pub const DEFAULT_RECURSION_LIMIT: u32 = 100;
/// Canton's `EXTENDED_PROTOBUF_RECURSION_LIMIT`, for Daml-LF packages.
pub const LF_PACKAGE_RECURSION_LIMIT: u32 = 1000;

/// Why bytes were not decoded.
#[derive(Debug)]
pub enum BoundedDecodeError {
    /// The message nests deeper than the bound.
    TooDeep {
        limit: u32,
    },
    Decode(prost::DecodeError),
}

impl fmt::Display for BoundedDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooDeep { limit } => write!(
                f,
                "failed to decode Protobuf message: recursion limit reached (nesting deeper than {limit})"
            ),
            Self::Decode(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for BoundedDecodeError {}

/// Decodes `bytes` as `M`, refusing a message that nests deeper than [`DEFAULT_RECURSION_LIMIT`].
pub fn decode<M: Message + Default + prost::Name>(bytes: &[u8]) -> Result<M, BoundedDecodeError> {
    decode_within(bytes, DEFAULT_RECURSION_LIMIT)
}

/// Decodes `bytes` as `M`, refusing a message that nests deeper than `limit`.
pub fn decode_within<M: Message + Default + prost::Name>(
    bytes: &[u8],
    limit: u32,
) -> Result<M, BoundedDecodeError> {
    check(&M::full_name(), bytes, limit)?;
    M::decode(bytes).map_err(BoundedDecodeError::Decode)
}

/// Refuses `bytes` when, read as the message `full_name` (`com.digitalasset.canton.protocol.v30.RecipientsTree`), they nest deeper
/// than `limit`: more than `limit` messages (or groups) inside the outermost one, as protobuf-java counts. Bytes that are not
/// well-formed pass: the decoder that follows reports them.
pub fn check(full_name: &str, bytes: &[u8], limit: u32) -> Result<(), BoundedDecodeError> {
    let index = schema();
    let mut walk = Walk { index, limit };
    let mut buf = bytes;
    match walk.message(index.get(full_name), &mut buf, 0, None) {
        Err(Stop::TooDeep) => Err(BoundedDecodeError::TooDeep { limit }),
        Ok(()) | Err(Stop::Malformed) => Ok(()),
    }
}

/// For each message type, its message-typed (and group) fields: field number to the field's message type.
type Schema = HashMap<String, HashMap<u32, String>>;

fn schema() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        use prost_types::field_descriptor_proto::Type;
        use prost_types::{DescriptorProto, FileDescriptorSet};
        fn add(schema: &mut Schema, scope: &str, msg: &DescriptorProto) {
            let name = format!("{scope}.{}", msg.name());
            let fields = msg
                .field
                .iter()
                .filter(|f| matches!(f.r#type(), Type::Message | Type::Group))
                .map(|f| {
                    let number = u32::try_from(f.number()).unwrap_or(0);
                    (number, f.type_name().trim_start_matches('.').to_string())
                })
                .collect();
            for nested in &msg.nested_type {
                add(schema, &name, nested);
            }
            schema.insert(name, fields);
        }
        let mut schema = Schema::new();
        // [CANTON-NOTE: DEFENSIVE] The set is compiled into this crate by build.rs; an unreadable set leaves the schema empty, and
        // every field is then read as opaque (nothing nests), which bounds only groups.
        let set = FileDescriptorSet::decode(crate::FILE_DESCRIPTOR_SET).unwrap_or_default();
        for file in &set.file {
            for msg in &file.message_type {
                add(&mut schema, file.package(), msg);
            }
        }
        schema
    })
}

enum Stop {
    TooDeep,
    Malformed,
}

struct Walk<'a> {
    index: &'a Schema,
    limit: u32,
}

impl Walk<'_> {
    /// Reads the fields of one message (or, with `group`, of a group up to its end tag) at nesting `depth`.
    fn message(
        &mut self,
        fields: Option<&HashMap<u32, String>>,
        buf: &mut &[u8],
        depth: u32,
        group: Option<u32>,
    ) -> Result<(), Stop> {
        while !buf.is_empty() {
            let key = varint(buf)?;
            let number = u32::try_from(key >> 3).map_err(|_| Stop::Malformed)?;
            let child = fields
                .and_then(|f| f.get(&number))
                .and_then(|t| self.index.get(t));
            match key & 7 {
                0 => {
                    varint(buf)?;
                }
                1 => skip(buf, 8)?,
                5 => skip(buf, 4)?,
                2 => {
                    let len = usize::try_from(varint(buf)?).map_err(|_| Stop::Malformed)?;
                    let mut body = buf.get(..len).ok_or(Stop::Malformed)?;
                    *buf = &buf[len..];
                    let is_message = fields.is_some_and(|f| f.contains_key(&number));
                    if is_message {
                        self.enter(depth)?;
                        self.message(child, &mut body, depth + 1, None)?;
                    }
                }
                3 => {
                    self.enter(depth)?;
                    self.message(child, buf, depth + 1, Some(number))?;
                }
                4 => {
                    return if group == Some(number) {
                        Ok(())
                    } else {
                        Err(Stop::Malformed)
                    };
                }
                _ => return Err(Stop::Malformed),
            }
        }
        match group {
            Some(_) => Err(Stop::Malformed),
            None => Ok(()),
        }
    }

    fn enter(&self, depth: u32) -> Result<(), Stop> {
        if depth >= self.limit {
            Err(Stop::TooDeep)
        } else {
            Ok(())
        }
    }
}

fn varint(buf: &mut &[u8]) -> Result<u64, Stop> {
    prost::encoding::decode_varint(buf).map_err(|_| Stop::Malformed)
}

fn skip(buf: &mut &[u8], n: usize) -> Result<(), Stop> {
    *buf = buf.get(n..).ok_or(Stop::Malformed)?;
    Ok(())
}

/// The gRPC codec of the generated services and clients: prost's, with the decoded message bounded by [`DEFAULT_RECURSION_LIMIT`]
/// (grpc-java parses a message with a fresh `CodedInputStream`, so this is Canton's bound on every request it serves).
#[cfg(feature = "grpc")]
pub struct BoundedCodec<T, U>(std::marker::PhantomData<(T, U)>);

#[cfg(feature = "grpc")]
impl<T, U> Default for BoundedCodec<T, U> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

#[cfg(feature = "grpc")]
impl<T, U> tonic::codec::Codec for BoundedCodec<T, U>
where
    T: Message + Send + 'static,
    U: Message + Default + prost::Name + Send + 'static,
{
    type Encode = T;
    type Decode = U;
    type Encoder = tonic_prost::ProstEncoder<T>;
    type Decoder = BoundedDecoder<U>;

    fn encoder(&mut self) -> Self::Encoder {
        tonic_prost::ProstEncoder::default()
    }

    fn decoder(&mut self) -> Self::Decoder {
        BoundedDecoder(std::marker::PhantomData)
    }
}

/// The decoder of [`BoundedCodec`].
#[cfg(feature = "grpc")]
pub struct BoundedDecoder<U>(std::marker::PhantomData<U>);

#[cfg(feature = "grpc")]
impl<U: Message + Default + prost::Name> tonic::codec::Decoder for BoundedDecoder<U> {
    type Item = U;
    type Error = tonic::Status;

    fn decode(
        &mut self,
        buf: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<U>, tonic::Status> {
        use prost::bytes::Buf;
        let bytes = buf.copy_to_bytes(buf.remaining());
        // tonic-prost reports an undecodable message as INTERNAL, as grpc-java does
        check(&U::full_name(), &bytes, DEFAULT_RECURSION_LIMIT)
            .map_err(|e| tonic::Status::internal(e.to_string()))?;
        U::decode(bytes)
            .map(Some)
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::com::digitalasset::canton::protocol::v30::RecipientsTree;

    fn nested(levels: usize) -> Vec<u8> {
        let mut tree = RecipientsTree::default();
        for _ in 0..levels {
            tree = RecipientsTree {
                recipients: vec!["MED::1".into()],
                children: vec![tree],
            };
        }
        tree.encode_to_vec()
    }

    /// `levels` groups of the unknown field 999, each inside the previous one, in an otherwise empty message.
    fn nested_groups(levels: usize) -> Vec<u8> {
        let start = (999u64 << 3) | 3;
        let end = (999u64 << 3) | 4;
        let mut out = Vec::new();
        for _ in 0..levels {
            prost::encoding::encode_varint(start, &mut out);
        }
        for _ in 0..levels {
            prost::encoding::encode_varint(end, &mut out);
        }
        out
    }

    #[test]
    fn a_message_nested_to_the_bound_is_decoded() {
        let tree: RecipientsTree = decode(&nested(DEFAULT_RECURSION_LIMIT as usize)).unwrap();
        assert_eq!(tree.children.len(), 1);
    }

    #[test]
    fn a_message_nested_past_the_bound_is_refused() {
        let res = decode::<RecipientsTree>(&nested(DEFAULT_RECURSION_LIMIT as usize + 1));
        assert!(
            matches!(res, Err(BoundedDecodeError::TooDeep { limit: 100 })),
            "{res:?}"
        );
        assert!(decode_within::<RecipientsTree>(&nested(101), 1000).is_ok());
    }

    #[test]
    fn unknown_groups_nested_past_the_bound_are_refused() {
        assert!(decode::<RecipientsTree>(&nested_groups(100)).is_ok());
        let res = decode::<RecipientsTree>(&nested_groups(101));
        assert!(
            matches!(res, Err(BoundedDecodeError::TooDeep { .. })),
            "{res:?}"
        );
    }

    #[test]
    fn bytes_fields_do_not_nest() {
        use crate::com::digitalasset::canton::protocol::v30::{
            blindable_node::BlindedOrNot, BlindableNode,
        };
        let mut node = BlindableNode::default();
        for _ in 0..200 {
            node = BlindableNode {
                blinded_or_not: Some(BlindedOrNot::Unblinded(node.encode_to_vec())),
            };
        }
        assert!(decode::<BlindableNode>(&node.encode_to_vec()).is_ok());
    }
}
