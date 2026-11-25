//! JSON conversions between protobuf JSON (what `prost-reflect` reads and writes) and the JSON encoding of the Canton JSON
//! Ledger API, which differs in one way that matters here: a `oneof` member is written as `{"CaseName": {"value": ...}}`
//! (the capitalized JSON name of the field, wrapping the payload in `value`) instead of a plain field.
use prost::Message;
use prost_reflect::{
    DeserializeOptions, DynamicMessage, FieldDescriptor, Kind, MessageDescriptor, SerializeOptions,
};
use serde_json::{Map, Value as Json};

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
        .unwrap_or_default()
}

fn snake_to_camel(s: &str) -> String {
    let mut out = String::new();
    let mut up = false;
    for c in s.chars() {
        if c == '_' {
            up = true;
        } else if up {
            out.extend(c.to_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

fn camel_to_snake(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn is_field_mask(m: &MessageDescriptor) -> bool {
    m.full_name() == "google.protobuf.FieldMask"
}

fn well_known(m: &MessageDescriptor) -> bool {
    m.full_name().starts_with("google.protobuf.")
}

/// Applies `convert` to the message-typed parts of a field value (single, repeated or map values).
fn convert_field(
    f: &FieldDescriptor,
    v: &Json,
    convert: &dyn Fn(&MessageDescriptor, &Json) -> Json,
    to_proto: bool,
) -> Json {
    let Kind::Message(md) = f.kind() else {
        return v.clone();
    };
    if md.full_name() == "google.protobuf.Duration" {
        // Canton's JSON writes `{"seconds": 75, "nanos": 0}`; protobuf JSON a string like `75s`
        return match (to_proto, v) {
            (true, Json::Object(o)) => {
                let secs = o.get("seconds").and_then(Json::as_i64).unwrap_or(0);
                let nanos = o.get("nanos").and_then(Json::as_i64).unwrap_or(0);
                Json::String(if nanos == 0 {
                    format!("{secs}s")
                } else {
                    format!("{secs}.{nanos:09}s")
                })
            }
            (false, Json::String(s)) => {
                if let Some((secs, nanos)) = parse_proto_duration(s) {
                    serde_json::json!({ "seconds": secs, "nanos": nanos })
                } else {
                    v.clone()
                }
            }
            _ => v.clone(),
        };
    }
    if md.full_name() == "com.daml.ledger.api.v2.interactive.PreparedTransaction" {
        // The JSON API carries `PreparedTransaction` as base64-encoded protobuf bytes, whereas gRPC
        // expects/returns the `PreparedTransaction` message itself.
        return match (to_proto, v) {
            (true, Json::String(b64)) => {
                let bytes = crate::table::decode_base64_str(b64);
                let opts = SerializeOptions::new()
                    .skip_default_fields(true)
                    .stringify_64_bit_integers(false);
                DynamicMessage::decode(md, bytes.as_slice())
                    .ok()
                    .and_then(|msg| {
                        msg.serialize_with_options(serde_json::value::Serializer, &opts)
                            .ok()
                    })
                    .unwrap_or_else(|| v.clone())
            }
            (false, Json::Object(_)) => {
                let opts = DeserializeOptions::new().deny_unknown_fields(false);
                DynamicMessage::deserialize_with_options(md, v.clone(), &opts)
                    .map(|msg| Json::String(crate::table::encode_base64(&msg.encode_to_vec())))
                    .unwrap_or_else(|_| v.clone())
            }
            _ => v.clone(),
        };
    }
    if is_field_mask(&md) {
        // protobuf JSON writes a field mask as one string of camelCase paths; Canton's JSON as `{"paths": [snake_case]}`
        return match (to_proto, v) {
            (true, Json::Object(o)) => Json::String(
                o.get("paths")
                    .and_then(Json::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Json::as_str)
                            .map(snake_to_camel)
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default(),
            ),
            (false, Json::String(t)) => json_paths(t),
            _ => v.clone(),
        };
    }
    if md.full_name() == "google.protobuf.Any" {
        // The JSON API prints a status detail as `{"typeUrl", "value" (base64), "valueDecoded", "unknownFields"}`; protobuf JSON writes the message
        // itself with an `@type` member (the types of `google/rpc/error_details.proto`). `valueDecoded` carries the message's fields.
        let one = |x: &Json| -> Json {
            match (to_proto, x) {
                (true, Json::Object(o)) if o.contains_key("typeUrl") => {
                    let mut message = match o.get("valueDecoded") {
                        Some(Json::Object(m)) => m.clone(),
                        _ => serde_json::Map::new(),
                    };
                    message.remove("unknownFields");
                    message.insert("@type".into(), o["typeUrl"].clone());
                    Json::Object(message)
                }
                _ => x.clone(),
            }
        };
        return match v {
            Json::Array(items) if f.is_list() => Json::Array(items.iter().map(one).collect()),
            other => one(other),
        };
    }
    if f.is_map() {
        let (Json::Object(entries), Some(value_field)) = (v, md.get_field_by_name("value")) else {
            return v.clone();
        };
        return Json::Object(
            entries
                .iter()
                .map(|(k, x)| (k.clone(), convert_field(&value_field, x, convert, to_proto)))
                .collect(),
        );
    }
    if well_known(&md) {
        return v.clone();
    }
    match v {
        Json::Array(items) if f.is_list() => {
            Json::Array(items.iter().map(|e| convert(&md, e)).collect())
        }
        other => convert(&md, other),
    }
}

/// Canton JSON API encoding -> protobuf JSON.
///
/// A `oneof` named `kind` is a field `kind` holding `{"CaseName": {"value": payload}}`; protobuf JSON has the case as a field
/// of the message itself.
pub fn canton_to_proto(desc: &MessageDescriptor, v: &Json) -> Json {
    let Json::Object(obj) = v else {
        return v.clone();
    };
    // the JSON API writes an `Event` as `{"CreatedEvent": {...}}` (no `event` field, no `value` wrapper)
    if desc.full_name() == "com.daml.ledger.api.v2.Event" {
        let mut out = Map::new();
        for (case, payload) in obj {
            if let Some(f) = desc
                .fields()
                .find(|f| capitalize(f.json_name()) == case.replace("Event", ""))
            {
                out.insert(
                    f.json_name().to_string(),
                    convert_field(&f, payload, &canton_to_proto, true),
                );
            }
        }
        return Json::Object(out);
    }
    let mut out = Map::new();
    for (key, val) in obj {
        if let Some(f) = desc.get_field_by_json_name(key) {
            out.insert(key.clone(), convert_field(&f, val, &canton_to_proto, true));
        } else if desc
            .oneofs()
            .any(|o| !o.is_synthetic() && snake_to_camel(o.name()) == *key)
        {
            let oneof = desc
                .oneofs()
                .find(|o| snake_to_camel(o.name()) == *key)
                .expect("oneof");
            if let Json::Object(case) = val {
                for (case_name, payload) in case {
                    if let Some(f) = oneof
                        .fields()
                        .find(|f| capitalize(f.json_name()) == case_name.trim_start_matches("Js"))
                    {
                        let inner = payload.get("value").unwrap_or(payload);
                        out.insert(
                            f.json_name().to_string(),
                            convert_field(&f, inner, &canton_to_proto, true),
                        );
                    }
                }
            }
        }
    }
    Json::Object(out)
}

/// Protobuf JSON -> Canton JSON API encoding.
pub fn proto_to_canton(desc: &MessageDescriptor, v: &Json) -> Json {
    let Json::Object(obj) = v else {
        return v.clone();
    };
    let mut out = Map::new();
    for (key, val) in obj {
        let Some(f) = desc.get_field_by_json_name(key) else {
            out.insert(key.clone(), val.clone());
            continue;
        };
        let converted = convert_field(&f, val, &proto_to_canton, false);
        match f.containing_oneof().filter(|o| !o.is_synthetic()) {
            Some(oneof) => {
                let slot = out
                    .entry(snake_to_camel(oneof.name()))
                    .or_insert_with(|| Json::Object(Map::new()));
                if let Json::Object(m) = slot {
                    m.insert(
                        capitalize(key),
                        Json::Object(Map::from_iter([("value".to_string(), converted)])),
                    );
                }
            }
            None => {
                out.insert(key.clone(), converted);
            }
        }
    }
    Json::Object(out)
}

fn parse_proto_duration(s: &str) -> Option<(i64, i64)> {
    let body = s.strip_suffix('s')?;
    if let Some((sec_s, nano_s)) = body.split_once('.') {
        let secs: i64 = sec_s.parse().ok()?;
        let mut padded = nano_s.chars().take(9).collect::<String>();
        while padded.len() < 9 {
            padded.push('0');
        }
        let mut nanos: i64 = padded.parse().ok()?;
        if secs < 0 {
            nanos = -nanos;
        }
        Some((secs, nanos))
    } else {
        Some((body.parse().ok()?, 0))
    }
}

fn json_paths(text: &str) -> Json {
    Json::Object(Map::from_iter([(
        "paths".to_string(),
        Json::Array(
            text.split(',')
                .filter(|p| !p.is_empty())
                .map(|p| Json::String(camel_to_snake(p)))
                .collect(),
        ),
    )]))
}
