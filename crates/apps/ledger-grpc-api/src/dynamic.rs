//! A tonic codec for dynamic (descriptor-driven) protobuf messages, used by the server and by the oracle client.
use prost::Message;
use prost_reflect::{DynamicMessage, MessageDescriptor};
use tonic::{
    codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder},
    Status,
};

/// Encodes any `DynamicMessage` and decodes messages of the given type.
#[derive(Clone)]
pub struct DynCodec {
    decode_as: MessageDescriptor,
}

impl DynCodec {
    pub fn new(decode_as: MessageDescriptor) -> Self {
        Self { decode_as }
    }
}

pub struct DynEncoder;
pub struct DynDecoder(MessageDescriptor);

impl Encoder for DynEncoder {
    type Item = DynamicMessage;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        item.encode(dst)
            .map_err(|e| Status::internal(format!("encode: {e}")))
    }
}

impl Decoder for DynDecoder {
    type Item = DynamicMessage;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        use bytes::Buf;
        let bytes = src.copy_to_bytes(src.remaining());
        canton_proto::depth::check(
            self.0.full_name(),
            &bytes,
            canton_proto::depth::DEFAULT_RECURSION_LIMIT,
        )
        // grpc-java answers a request it cannot parse with INTERNAL (`ProtoLiteUtils`: "Invalid protobuf byte sequence")
        .map_err(|e| Status::internal(format!("Invalid protobuf byte sequence: {e}")))?;
        DynamicMessage::decode(self.0.clone(), bytes)
            .map(Some)
            .map_err(|e| Status::invalid_argument(format!("decode: {e}")))
    }
}

impl Codec for DynCodec {
    type Encode = DynamicMessage;
    type Decode = DynamicMessage;
    type Encoder = DynEncoder;
    type Decoder = DynDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        DynEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        DynDecoder(self.decode_as.clone())
    }
}
