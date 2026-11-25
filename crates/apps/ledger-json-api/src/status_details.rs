//! The `details` of a stored completion status read back as the Ledger API shows them (U-47): the participant keeps a rejected completion's
//! `google.rpc.Status` details as protobuf bytes (a repeated field 1 of `google.protobuf.Any`), and the JSON API prints each `Any` with its type, its
//! bytes in base64 and the message decoded (`valueDecoded`).
//!
//! [CANTON-NOTE: SEMANTICS] Measured on the hub's participant (a `DUPLICATE_COMMAND` completion): an `ErrorInfo` decodes to `reason`, `domain` and
//! `metadata` (a map of texts) and a `RequestInfo` to `requestId` and `servingData`, each with an empty `unknownFields`, as the `Any` itself. A `ResourceInfo`
//! (the refusals of `refusal_status_details`) decodes to its four texts. Another type is refused rather than shown without its decoding.
use serde_json::{json, Map, Value as Json};

/// The fields of a protobuf message: `(number, wire type, value)` with the value of a length-delimited field as bytes (a varint as its number).
fn fields(mut bytes: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    fn varint(bytes: &mut &[u8]) -> Result<u64, String> {
        let (mut value, mut shift) = (0u64, 0);
        loop {
            let (&b, rest) = bytes.split_first().ok_or("a varint that ends early")?;
            *bytes = rest;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                return Err("a varint that is too long".into());
            }
        }
    }
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let key = varint(&mut bytes)?;
        match key & 7 {
            2 => {
                let len = varint(&mut bytes)? as usize;
                if bytes.len() < len {
                    return Err("a field that runs past the end".into());
                }
                out.push((key >> 3, bytes[..len].to_vec()));
                bytes = &bytes[len..];
            }
            0 => {
                let v = varint(&mut bytes)?;
                out.push((key >> 3, v.to_string().into_bytes()));
            }
            other => return Err(format!("wire type {other} is not read")),
        }
    }
    Ok(out)
}

fn text(bytes: &[u8]) -> Result<String, String> {
    String::from_utf8(bytes.to_vec()).map_err(|e| e.to_string())
}

fn first_text(fields: &[(u64, Vec<u8>)], number: u64) -> Result<String, String> {
    fields
        .iter()
        .find(|(n, _)| *n == number)
        .map_or(Ok(String::new()), |(_, v)| text(v))
}

/// The message inside an `Any` of type `type_name` (without the `type.googleapis.com/` prefix) as the JSON API decodes it.
fn decoded(type_name: &str, value: &[u8]) -> Result<Json, String> {
    let f = fields(value)?;
    let no_unknown = json!({"fields": {}});
    match type_name {
        "google.rpc.ErrorInfo" => {
            let mut metadata = Map::new();
            for (n, entry) in &f {
                if *n == 3 {
                    let kv = fields(entry)?;
                    metadata.insert(first_text(&kv, 1)?, Json::String(first_text(&kv, 2)?));
                }
            }
            Ok(json!({
                "reason": first_text(&f, 1)?,
                "domain": first_text(&f, 2)?,
                "metadata": metadata,
                "unknownFields": no_unknown
            }))
        }
        "google.rpc.RequestInfo" => Ok(json!({
            "requestId": first_text(&f, 1)?,
            "servingData": first_text(&f, 2)?,
            "unknownFields": no_unknown
        })),
        "google.rpc.ResourceInfo" => Ok(json!({
            "resourceType": first_text(&f, 1)?,
            "resourceName": first_text(&f, 2)?,
            "owner": first_text(&f, 3)?,
            "description": first_text(&f, 4)?,
            "unknownFields": no_unknown
        })),
        other => Err(format!("the status detail type {other} is not decoded")),
    }
}

/// The `details` of a completion's status from the bytes the participant stored.
pub fn status_details(bytes: &[u8]) -> Result<Vec<Json>, String> {
    let mut out = Vec::new();
    for (number, any) in fields(bytes)? {
        if number != 1 {
            return Err(format!("field {number} of the status details is not read"));
        }
        let parts = fields(&any)?;
        let type_url = first_text(&parts, 1)?;
        let value = parts
            .iter()
            .find(|(n, _)| *n == 2)
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let name = type_url
            .strip_prefix("type.googleapis.com/")
            .unwrap_or(&type_url);
        out.push(json!({
            "typeUrl": type_url,
            "value": crate::v2::base64(&value),
            "valueDecoded": decoded(name, &value)?,
            "unknownFields": {"fields": {}}
        }));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The details of the `DUPLICATE_COMMAND` completion of the hub's participant (`lapi_command_completions.rejection_status_details`).
    const DUPLICATE_COMMAND: &str = "0ad3030a28747970652e676f6f676c65617069732e636f6d2f676f6f676c652e7270632e4572726f72496e666f12a6030a114455504c49434154455f434f4d4d414e441a1b0a0b7061727469636970616e74120c7061727469636970616e74311a89010a086368616e67654964127d4368616e67654964287061727469636970616e745f61646d696e2c6c6f79616c74792d7265712d3030312c536574284973737565723a3a313232303033313263313135366337393634643064303763313433346536643166333864373630383765346130333361326666613435313431333931656132653233336229291a170a11636f6d706c6574696f6e5f6f6666736574120232371a100a0861636365707465641204747275651a270a0470736964121f6875622d73796e633a3a3132323034653862666265642e2e2e3a3a33372d301a0e0a0863617465676f7279120231301a270a03746964122061326661393334656531323862366133346632306239363332666332353466631a170a0f646566696e6974655f616e737765721204747275651a420a146578697374696e675375626d697373696f6e4964122a536f6d652833306536646631322d326137322d346135632d383761342d306439383232313062303336290a500a2a747970652e676f6f676c65617069732e636f6d2f676f6f676c652e7270632e52657175657374496e666f12220a206132666139333465653132386236613334663230623936333266633235346663";

    #[test]
    fn the_details_of_a_stored_duplicate_command_rejection_are_decoded() {
        let details = status_details(&hex::decode(DUPLICATE_COMMAND).unwrap()).unwrap();
        assert_eq!(details.len(), 2);
        assert_eq!(
            details[0]["typeUrl"],
            "type.googleapis.com/google.rpc.ErrorInfo"
        );
        assert_eq!(details[0]["valueDecoded"]["reason"], "DUPLICATE_COMMAND");
        assert_eq!(
            details[0]["valueDecoded"]["metadata"]["completion_offset"],
            "27"
        );
        assert_eq!(
            details[0]["valueDecoded"]["metadata"]["existingSubmissionId"],
            "Some(30e6df12-2a72-4a5c-87a4-0d982210b036)"
        );
        assert_eq!(
            details[1]["typeUrl"],
            "type.googleapis.com/google.rpc.RequestInfo"
        );
        assert_eq!(
            details[1]["valueDecoded"]["requestId"],
            "a2fa934ee128b6a34f20b9632fc254fc"
        );
        // the bytes of the second detail as the official JSON API printed them
        assert_eq!(
            details[1]["value"],
            "CiBhMmZhOTM0ZWUxMjhiNmEzNGYyMGI5NjMyZmMyNTRmYw=="
        );
    }

    #[test]
    fn an_unknown_detail_type_is_refused() {
        let url = b"type.googleapis.com/foo.Unknown";
        let mut any = vec![0x0a, url.len() as u8];
        any.extend_from_slice(url);
        let mut bytes = vec![0x0a, any.len() as u8];
        bytes.extend(any);
        assert!(status_details(&bytes).is_err());
        // a message that ends in the middle of a field
        assert!(status_details(&[0x0a, 0x09, 0x01]).is_err());
    }
}
