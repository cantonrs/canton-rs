//! A protobuf wire reader that behaves like the Java parser the Canton 3.7.2 node uses (ScalaPB on `CodedInputStream`), U-13.
//!
//! prost is strict where protobuf-java is not: a known field number with the wrong wire type is an error in prost and an
//! unknown (skipped) field in the node. Whether a signature message is accepted is decided by the node's reading, so the
//! messages that carry signatures are read with this reader instead of prost.
//!
//! [CANTON-NOTE: SEMANTICS] Measured on a Canton 3.7.2 node (tests/oracle/canton-crypto `sgp` lines, `v30.Signature`):
//! - field order does not matter; a repeated scalar keeps the LAST value; a repeated embedded message is MERGED field by field;
//! - an unknown field of any wire type (varint, fixed32, fixed64, length-delimited, a terminated group) is skipped;
//! - a known field number with the wrong wire type is skipped as unknown (so the field keeps its default);
//! - an enum or int32 is a varint cut to its low 32 bits (`2^32 + 3` reads as 3, a 10-byte `-1` reads as -1);
//! - a varint longer than 10 bytes, a zero field number, wire type 6 or 7, an unmatched end-group tag, a missing end of
//!   group, a length that runs past the end and a string that is not valid UTF-8 are errors.

/// What went wrong while reading, grouped as the node's exception types are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// `InvalidProtocolBufferException` (malformed varint, invalid tag, truncated message, invalid UTF-8, bad group).
    Malformed(&'static str),
    /// `InvalidWireTypeException`: the tag carries wire type 6 or 7.
    InvalidWireType,
}

impl WireError {
    /// The class name the node's exception has.
    pub fn class(&self) -> &'static str {
        match self {
            WireError::Malformed(_) => "InvalidProtocolBufferException",
            WireError::InvalidWireType => "InvalidWireTypeException",
        }
    }
}

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// What follows a tag.
pub(crate) enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    /// The field was skipped (an unknown field, or a known number with a different wire type).
    Skipped,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn varint64(&mut self) -> Result<u64, WireError> {
        let mut v = 0u64;
        for i in 0..10 {
            let b = *self
                .buf
                .get(self.pos)
                .ok_or(WireError::Malformed("truncated message"))?;
            self.pos += 1;
            v |= u64::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(WireError::Malformed("malformed varint"))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .ok_or(WireError::Malformed("truncated message"))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// The next tag: `None` at the end of the input. The field number is never zero.
    pub(crate) fn tag(&mut self) -> Result<Option<(u32, u8)>, WireError> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }
        // protobuf-java reads a tag as a 32-bit varint: a longer value is cut to its low 32 bits
        let tag = self.varint64()? as u32;
        if tag >> 3 == 0 {
            return Err(WireError::Malformed("invalid tag (zero)"));
        }
        Ok(Some((tag >> 3, (tag & 7) as u8)))
    }

    /// Reads the value of a field the caller knows, if the wire type is the expected one; otherwise skips the field.
    pub(crate) fn value(
        &mut self,
        field: u32,
        wire_type: u8,
        expected: u8,
    ) -> Result<Value<'a>, WireError> {
        if wire_type != expected {
            self.skip(field, wire_type)?;
            return Ok(Value::Skipped);
        }
        match wire_type {
            0 => Ok(Value::Varint(self.varint64()?)),
            2 => {
                // the length is a signed 32-bit varint
                let len = self.varint64()? as u32 as i32;
                let len =
                    usize::try_from(len).map_err(|_| WireError::Malformed("negative size"))?;
                Ok(Value::Bytes(self.take(len)?))
            }
            _ => unreachable!("only varint and length-delimited fields are read as values"),
        }
    }

    /// Skips the value of a field with this number and wire type.
    pub(crate) fn skip(&mut self, field: u32, wire_type: u8) -> Result<(), WireError> {
        match wire_type {
            0 => {
                self.varint64()?;
            }
            1 => {
                self.take(8)?;
            }
            2 => {
                let len = self.varint64()? as u32 as i32;
                let len =
                    usize::try_from(len).map_err(|_| WireError::Malformed("negative size"))?;
                self.take(len)?;
            }
            3 => self.skip_group(field)?,
            4 => {
                return Err(WireError::Malformed(
                    "end-group tag did not match expected tag",
                ))
            }
            5 => {
                self.take(4)?;
            }
            _ => return Err(WireError::InvalidWireType),
        }
        Ok(())
    }

    fn skip_group(&mut self, field: u32) -> Result<(), WireError> {
        loop {
            let Some((f, wt)) = self.tag()? else {
                return Err(WireError::Malformed(
                    "end-group tag did not match expected tag",
                ));
            };
            if wt == 4 {
                return if f == field {
                    Ok(())
                } else {
                    Err(WireError::Malformed(
                        "end-group tag did not match expected tag",
                    ))
                };
            }
            self.skip(f, wt)?;
        }
    }
}

/// An enum or int32 field: the low 32 bits of the varint.
pub(crate) fn as_i32(v: u64) -> i32 {
    v as u32 as i32
}

/// A string field: the bytes must be valid UTF-8.
pub(crate) fn utf8(bytes: &[u8]) -> Result<String, WireError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| WireError::Malformed("invalid UTF-8"))
}

/// A packed repeated enum / int32 field: varints concatenated inside a length-delimited value.
pub(crate) fn packed_i32s(bytes: &[u8]) -> Result<Vec<i32>, WireError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let mut val = 0u64;
        let mut shift = 0u32;
        let mut count = 0usize;
        loop {
            let Some(&b) = bytes.get(i) else {
                return Err(WireError::Malformed("truncated varint"));
            };
            i += 1;
            if count == 9 && b > 1 {
                return Err(WireError::Malformed("malformed varint"));
            }
            val |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            count += 1;
        }
        out.push(as_i32(val));
    }
    Ok(out)
}
