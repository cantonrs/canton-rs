//! S-API-023 (U-4 + U-14): Extended explicit disclosure (`SecretNote` unkeyed + `KeyedBox` LF 2.3
//! keyed), unseen foreign contract disclosure (zero ACS leak + consumed-inactive tracking),
//! `readAs` visibility, 3-tier NUCK resolution, and two-stage U-14 tamper rejection against
//! live Canton 3.7.2 sandbox recordings (`tests/oracle/disclosure-ext/expected.jsonl`).

#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ledger_json_api::{start_test_server, ExecutionService};
use lf_eval::fat_contract::{
    authenticate_fat_contract, compute_key_hash, decode_fat_contract_blob, decode_strict_base64,
    encode_base64, encode_fat_contract, FatContractInput,
};
use lf_eval::typed_json::Types;
use lf_eval::{Value, World};
use serde_json::{json, Value as Json};

fn oracle_dir() -> PathBuf {
    std::env::var_os("DISCLOSURE_EXT_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/disclosure-ext"),
        PathBuf::from,
    )
}

fn call(port: u16, method: &str, path: &str, body: &[u8], ctype: &str) -> (u16, Json) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let head = if body.is_empty() && method == "GET" {
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    } else {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
    };
    s.write_all(head.as_bytes()).unwrap();
    if !(body.is_empty() && method == "GET") {
        s.write_all(body).unwrap();
    }
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let at = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |i| i + 4);
    let status: u16 = String::from_utf8_lossy(&raw[..at])
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let text = String::from_utf8_lossy(&raw[at..]);
    let parsed = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "_text": text }));
    (status, parsed)
}

fn post(port: u16, path: &str, body: Json) -> (u16, Json) {
    call(
        port,
        "POST",
        path,
        body.to_string().as_bytes(),
        "application/json",
    )
}

fn get(port: u16, path: &str) -> (u16, Json) {
    call(port, "GET", path, &[], "application/json")
}

fn alloc_party(port: u16, hint: &str) -> String {
    let (st, b) = post(
        port,
        "/v2/parties",
        json!({ "partyIdHint": hint, "identityProviderId": "" }),
    );
    assert_eq!(st, 200, "allocate {hint} failed: {b}");
    b["partyDetails"]["party"].as_str().unwrap().to_string()
}

#[derive(Clone)]
struct CreatedInfo {
    contract_id: String,
    template_id: String,
    created_event_blob: String,
    contract_key_hash: String,
    synchronizer_id: String,
}

impl CreatedInfo {
    fn disclosed(&self, blob_override: Option<&str>) -> Json {
        json!({
            "templateId": self.template_id,
            "contractId": self.contract_id,
            "createdEventBlob": blob_override.unwrap_or(&self.created_event_blob),
            "synchronizerId": self.synchronizer_id,
        })
    }
}

fn create_contract(port: u16, act_as: &str, tpl: &str, args: Json, cmd_id: &str) -> CreatedInfo {
    let (st, b) = post(
        port,
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{ "CreateCommand": { "templateId": tpl, "createArguments": args } }],
                "commandId": cmd_id,
                "actAs": [act_as],
                "userId": "participant_admin"
            },
            "transactionFormat": {
                "eventFormat": {
                    "filtersByParty": {
                        act_as: { "cumulative": [{ "identifierFilter": { "WildcardFilter": { "value": { "includeCreatedEventBlob": true } } } }] }
                    },
                    "verbose": true
                },
                "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
            }
        }),
    );
    assert_eq!(st, 200, "create {tpl} failed: {b}");
    let ev = &b["transaction"]["events"][0]["CreatedEvent"];
    CreatedInfo {
        contract_id: ev["contractId"].as_str().unwrap().to_string(),
        template_id: ev["templateId"].as_str().unwrap().to_string(),
        created_event_blob: ev["createdEventBlob"].as_str().unwrap().to_string(),
        contract_key_hash: ev["contractKeyHash"].as_str().unwrap_or("").to_string(),
        synchronizer_id: b["transaction"]["synchronizerId"]
            .as_str()
            .unwrap()
            .to_string(),
    }
}

fn submit(
    port: u16,
    act_as: &[&str],
    cmds: Json,
    read_as: &[&str],
    disclosed: Option<Vec<Json>>,
    cmd_id: &str,
) -> (u16, Json) {
    let mut cmd_obj = serde_json::Map::new();
    cmd_obj.insert("commands".into(), cmds);
    cmd_obj.insert("commandId".into(), json!(cmd_id));
    cmd_obj.insert("actAs".into(), json!(act_as));
    cmd_obj.insert("userId".into(), json!("participant_admin"));
    if !read_as.is_empty() {
        cmd_obj.insert("readAs".into(), json!(read_as));
    }
    if let Some(d) = disclosed {
        cmd_obj.insert("disclosedContracts".into(), Json::Array(d));
    }
    let viewer = act_as[0];
    post(
        port,
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": Json::Object(cmd_obj),
            "transactionFormat": {
                "eventFormat": {
                    "filtersByParty": {
                        viewer: { "cumulative": [{ "identifierFilter": { "WildcardFilter": { "value": { "includeCreatedEventBlob": true } } } }] }
                    },
                    "verbose": true
                },
                "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
            }
        }),
    )
}

fn first_exercise_result(body: &Json) -> Json {
    body["transaction"]["events"]
        .as_array()
        .and_then(|evs| {
            evs.iter().find_map(|e| {
                e.get("ExercisedEvent")
                    .and_then(|x| x.get("exerciseResult"))
            })
        })
        .cloned()
        .unwrap_or(Json::Null)
}

fn acs_summary(port: u16, party: &str) -> Json {
    let (st, end_b) = get(port, "/v2/state/ledger-end");
    assert_eq!(st, 200, "ledger-end failed: {end_b}");
    let (st, b) = post(
        port,
        "/v2/state/active-contracts",
        json!({
            "eventFormat": {
                "filtersByParty": {
                    party: { "cumulative": [{ "identifierFilter": { "WildcardFilter": { "value": { "includeCreatedEventBlob": false } } } }] }
                },
                "verbose": true
            },
            "activeAtOffset": end_b["offset"]
        }),
    );
    assert_eq!(st, 200, "acs failed: {b}");
    let mut out = Vec::new();
    for entry in b.as_array().unwrap() {
        let ce = &entry["contractEntry"]["JsActiveContract"]["createdEvent"];
        let tpl = ce["templateId"]
            .as_str()
            .unwrap()
            .split_once(':')
            .unwrap()
            .1
            .to_string();
        let mut args = serde_json::Map::new();
        if let Some(obj) = ce["createArgument"].as_object() {
            for k in ["secret", "k", "val"] {
                if let Some(v) = obj.get(k) {
                    args.insert(k.to_string(), v.clone());
                }
            }
        }
        out.push(json!({ "template": tpl, "args": Json::Object(args) }));
    }
    Json::Array(out)
}

fn read_varint(buf: &[u8], pos: &mut usize) -> u64 {
    let mut val = 0u64;
    let mut shift = 0u32;
    loop {
        let b = buf[*pos];
        *pos += 1;
        val |= u64::from(b & 0x7F) << shift;
        if (b & 0x80) == 0 {
            return val;
        }
        shift += 7;
    }
}

fn find_fat_create_arg_range(raw: &[u8]) -> (usize, usize) {
    let mut pos = 0usize;
    let mut fat_slice = None;
    while pos < raw.len() {
        let tag = read_varint(raw, &mut pos);
        let (fn_, wt) = (tag >> 3, tag & 7);
        match wt {
            0 => {
                let _ = read_varint(raw, &mut pos);
            }
            2 => {
                let ln = read_varint(raw, &mut pos) as usize;
                if fn_ == 2 {
                    fat_slice = Some((pos, pos + ln));
                    break;
                }
                pos += ln;
            }
            1 => pos += 8,
            5 => pos += 4,
            other => panic!("unsupported wire type {other}"),
        }
    }
    let (mut pos, end) = fat_slice.expect("Versioned field 2 missing");
    while pos < end {
        let tag = read_varint(raw, &mut pos);
        let (fn_, wt) = (tag >> 3, tag & 7);
        match wt {
            0 => {
                let _ = read_varint(raw, &mut pos);
            }
            2 => {
                let ln = read_varint(raw, &mut pos) as usize;
                if fn_ == 4 {
                    return (pos, pos + ln);
                }
                pos += ln;
            }
            1 => pos += 8,
            5 => pos += 4,
            other => panic!("unsupported wire type {other} in FatContractInstance"),
        }
    }
    panic!("FatContractInstance field 4 missing");
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn check_row(expected: &HashMap<String, Json>, id: &str, st: u16, body: &Json, box20_cid: &str) {
    let want = expected
        .get(id)
        .unwrap_or_else(|| panic!("missing oracle row {id}"));
    let want_st = want["status"].as_u64().unwrap() as u16;
    assert_eq!(
        st, want_st,
        "{id}: status mismatch: got {st} ({body}) vs Canton {want_st}"
    );
    if want_st != 200 {
        assert_eq!(
            body["code"], want["code"],
            "{id}: error code mismatch: got {} vs Canton {}",
            body["code"], want["code"]
        );
    } else if let Some(want_res) = want.get("exerciseResult") {
        let mut got_res = first_exercise_result(body);
        if got_res.as_str() == Some(box20_cid) {
            got_res = json!("{box20_cid}");
        }
        assert_eq!(
            &got_res, want_res,
            "{id}: exerciseResult mismatch: got {got_res} vs Canton {want_res}"
        );
    }
}

#[test]
fn canton_blobs_round_trip_and_disclosed_scenarios_match_live_oracle() {
    let dir = oracle_dir();
    let dar_bytes = std::fs::read(dir.join("disclosure-ext-1.0.0.dar")).unwrap();
    let expected_raw = std::fs::read_to_string(dir.join("expected.jsonl")).unwrap();
    let mut expected: HashMap<String, Json> = HashMap::new();
    for line in expected_raw.lines().filter(|l| !l.trim().is_empty()) {
        let row: Json = serde_json::from_str(line).unwrap();
        expected.insert(row["id"].as_str().unwrap().to_string(), row);
    }

    // 1. Decode & Stage-2-authenticate Canton's real SecretNote and KeyedBox blobs + verify keyHash
    let world = World::open(&dir.join("disclosure-ext-1.0.0.dar")).unwrap();
    let types = Types::new(&world);
    let pkg_id = world.main_package_id();
    let pkg_name = types.package_name(pkg_id).unwrap();

    let setup = &expected["setup"];
    assert_eq!(setup["sn"]["contractKeyHash"], "");
    for name in ["sn", "box10", "box20"] {
        let info = &setup[name];
        let b64 = info["createdEventBlob"].as_str().unwrap();
        let bytes = decode_strict_base64(b64).unwrap();
        let raw = decode_fat_contract_blob(&bytes).unwrap();
        assert_eq!(raw.contract_id, info["contractId"].as_str().unwrap());
        let auth = authenticate_fat_contract(&world, &raw).unwrap();
        let reencoded = encode_fat_contract(
            &world,
            &FatContractInput {
                contract_id: &auth.contract_id,
                package_id: &auth.package_id,
                package_name: &auth.package_name,
                module_name: &auth.module_name,
                entity_name: &auth.entity_name,
                payload: &auth.payload,
                signatories: &auth.signatories,
                observers: &auth.observers,
                created_at_micros: auth.created_at_micros,
                salt: &auth.salt,
                key: auth.key.as_ref(),
                key_maintainers: &auth.key_maintainers,
                key_hash: auth.key_hash.as_ref(),
            },
        )
        .unwrap();
        assert_eq!(
            reencoded, bytes,
            "Canton {name} blob must round-trip bit-for-bit"
        );
    }
    let key_ty = types
        .template_key_type(pkg_id, "DiscloseExt:KeyedBox")
        .unwrap()
        .unwrap();
    let alice_canton = setup["alice"].as_str().unwrap();
    let kh = compute_key_hash(
        &types,
        &pkg_name,
        "DiscloseExt:KeyedBox",
        &key_ty,
        &Value::Record {
            tycon: None,
            fields: vec![
                ("_1".into(), Value::Party(alice_canton.into())),
                ("_2".into(), Value::Text("dup".into())),
            ],
        },
    )
    .unwrap();
    assert_eq!(
        encode_base64(&kh),
        setup["box10"]["contractKeyHash"].as_str().unwrap()
    );
    assert_eq!(
        setup["box10"]["contractKeyHash"],
        setup["box20"]["contractKeyHash"]
    );

    // 2. Replay all recorded Canton scenarios against Rust ledger-json-api
    let (port, stop) = start_test_server(Arc::new(ExecutionService::new()));
    let (up_st, up_b) = call(
        port,
        "POST",
        "/v2/dars",
        &dar_bytes,
        "application/octet-stream",
    );
    assert_eq!(up_st, 200, "DAR upload failed: {up_b}");

    let alice = alloc_party(port, "alice");
    let bob = alloc_party(port, "bob");

    let sn = create_contract(
        port,
        &alice,
        "#disclosure-ext:DiscloseExt:SecretNote",
        json!({ "owner": alice, "secret": "top-secret" }),
        "c-sn",
    );
    let box10 = create_contract(
        port,
        &alice,
        "#disclosure-ext:DiscloseExt:KeyedBox",
        json!({ "owner": alice, "k": "dup", "val": "10" }),
        "c-box10",
    );
    let box20 = create_contract(
        port,
        &alice,
        "#disclosure-ext:DiscloseExt:KeyedBox",
        json!({ "owner": alice, "k": "dup", "val": "20" }),
        "c-box20",
    );
    let box_burn = create_contract(
        port,
        &alice,
        "#disclosure-ext:DiscloseExt:KeyedBox",
        json!({ "owner": alice, "k": "burn", "val": "30" }),
        "c-burn",
    );
    let helper = create_contract(
        port,
        &alice,
        "#disclosure-ext:DiscloseExt:Helper",
        json!({ "owner": alice, "actor": bob }),
        "c-helper",
    );

    assert_eq!(sn.contract_key_hash, "");
    assert!(!box10.contract_key_hash.is_empty());
    assert_eq!(box10.contract_key_hash, box20.contract_key_hash);

    // Non-consuming disclosed exercises -> zero ACS leak
    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:SecretNote", "contractId": sn.contract_id, "choice": "Inspect", "choiceArgument": { "reader": bob } } }]),
        &[],
        Some(vec![sn.disclosed(None)]),
        "s-nc-sn",
    );
    check_row(&expected, "nc_inspect_sn", st, &b, &box20.contract_id);

    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:KeyedBox", "contractId": box10.contract_id, "choice": "ReadBox", "choiceArgument": { "reader": bob } } }]),
        &[],
        Some(vec![box10.disclosed(None)]),
        "s-nc-box",
    );
    check_row(&expected, "nc_read_box10", st, &b, &box20.contract_id);
    assert_eq!(acs_summary(port, &bob), expected["bob_acs_after_nc"]["acs"]);

    // Consuming disclosed exercises -> once + inactive replay
    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:SecretNote", "contractId": sn.contract_id, "choice": "Burn", "choiceArgument": { "burner": bob } } }]),
        &[],
        Some(vec![sn.disclosed(None)]),
        "s-burn-sn",
    );
    check_row(&expected, "consume_burn_sn", st, &b, &box20.contract_id);

    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:KeyedBox", "contractId": box_burn.contract_id, "choice": "TakeBox", "choiceArgument": { "taker": bob } } }]),
        &[],
        Some(vec![box_burn.disclosed(None)]),
        "s-take-burn",
    );
    check_row(
        &expected,
        "consume_take_box_burn",
        st,
        &b,
        &box20.contract_id,
    );
    assert_eq!(
        acs_summary(port, &alice),
        expected["alice_acs_after_consume"]["acs"]
    );
    assert_eq!(
        acs_summary(port, &bob),
        expected["bob_acs_after_consume"]["acs"]
    );

    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:SecretNote", "contractId": sn.contract_id, "choice": "Burn", "choiceArgument": { "burner": bob } } }]),
        &[],
        Some(vec![sn.disclosed(None)]),
        "s-replay-sn",
    );
    check_row(&expected, "replay_burn_sn", st, &b, &box20.contract_id);

    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:KeyedBox", "contractId": box_burn.contract_id, "choice": "TakeBox", "choiceArgument": { "taker": bob } } }]),
        &[],
        Some(vec![box_burn.disclosed(None)]),
        "s-replay-burn",
    );
    check_row(
        &expected,
        "replay_take_box_burn",
        st,
        &b,
        &box20.contract_id,
    );

    // readAs visibility & ExerciseByKeyCommand
    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:Helper", "contractId": helper.contract_id, "choice": "LookupBox", "choiceArgument": { "k": "dup" } } }]),
        &[],
        None,
        "s-lk-none",
    );
    check_row(&expected, "readas_lookup_none", st, &b, &box20.contract_id);

    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:Helper", "contractId": helper.contract_id, "choice": "LookupBox", "choiceArgument": { "k": "dup" } } }]),
        &[&alice],
        None,
        "s-lk-some",
    );
    check_row(&expected, "readas_lookup_some", st, &b, &box20.contract_id);

    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:Helper", "contractId": helper.contract_id, "choice": "FetchBox", "choiceArgument": { "k": "dup" } } }]),
        &[],
        None,
        "s-fetch-miss",
    );
    check_row(
        &expected,
        "readas_fetch_missing",
        st,
        &b,
        &box20.contract_id,
    );

    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:Helper", "contractId": helper.contract_id, "choice": "FetchBox", "choiceArgument": { "k": "dup" } } }]),
        &[&alice],
        None,
        "s-fetch-lifo",
    );
    check_row(&expected, "readas_fetch_lifo", st, &b, &box20.contract_id);

    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseByKeyCommand": { "templateId": "#disclosure-ext:DiscloseExt:KeyedBox", "contractKey": { "_1": alice, "_2": "dup" }, "choice": "ReadBox", "choiceArgument": { "reader": bob } } }]),
        &[],
        None,
        "s-ebk-no",
    );
    check_row(&expected, "exbykey_no_readas", st, &b, &box20.contract_id);

    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseByKeyCommand": { "templateId": "#disclosure-ext:DiscloseExt:KeyedBox", "contractKey": { "_1": alice, "_2": "dup" }, "choice": "ReadBox", "choiceArgument": { "reader": bob } } }]),
        &[&alice],
        None,
        "s-ebk-yes",
    );
    check_row(&expected, "exbykey_with_readas", st, &b, &box20.contract_id);

    // 3-tier NUCK priority
    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:Helper", "contractId": helper.contract_id, "choice": "FetchBox", "choiceArgument": { "k": "dup" } } }]),
        &[],
        Some(vec![box10.disclosed(None), box20.disclosed(None)]),
        "s-nuck-10-20",
    );
    check_row(&expected, "nuck_tier2_10_20", st, &b, &box20.contract_id);

    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:Helper", "contractId": helper.contract_id, "choice": "FetchBox", "choiceArgument": { "k": "dup" } } }]),
        &[],
        Some(vec![box20.disclosed(None), box10.disclosed(None)]),
        "s-nuck-20-10",
    );
    check_row(&expected, "nuck_tier2_20_10", st, &b, &box20.contract_id);

    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:Helper", "contractId": helper.contract_id, "choice": "FetchBox", "choiceArgument": { "k": "dup" } } }]),
        &[&alice],
        Some(vec![box10.disclosed(None)]),
        "s-nuck-t2-t3",
    );
    check_row(
        &expected,
        "nuck_tier2_beats_tier3_readas",
        st,
        &b,
        &box20.contract_id,
    );

    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseByKeyCommand": { "templateId": "#disclosure-ext:DiscloseExt:KeyedBox", "contractKey": { "_1": alice, "_2": "dup" }, "choice": "ReadBox", "choiceArgument": { "reader": bob } } }]),
        &[&alice],
        Some(vec![box10.disclosed(None)]),
        "s-ebk-t2-t3",
    );
    check_row(
        &expected,
        "nuck_exbykey_tier2_beats_tier3",
        st,
        &b,
        &box20.contract_id,
    );

    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:Helper", "contractId": helper.contract_id, "choice": "InTxBeatsDisclosed", "choiceArgument": { "k": "dup" } } }]),
        &[],
        Some(vec![box10.disclosed(None)]),
        "s-nuck-t1-t2",
    );
    check_row(
        &expected,
        "nuck_tier1_beats_tier2",
        st,
        &b,
        &box20.contract_id,
    );

    // U-14 two-stage tamper contrast
    let box10_raw = decode_strict_base64(&box10.created_event_blob).unwrap();
    let (c_start, c_end) = find_fat_create_arg_range(&box10_raw);

    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:KeyedBox", "contractId": box10.contract_id, "choice": "ReadBox", "choiceArgument": { "reader": bob } } }]),
        &[],
        Some(vec![box10.disclosed(Some("aGl="))]),
        "s-u14-pad",
    );
    check_row(
        &expected,
        "u14_stage1_bad_b64_pad",
        st,
        &b,
        &box20.contract_id,
    );

    let trunc_b64 = encode_base64(&box10_raw[..box10_raw.len() - 4]);
    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:KeyedBox", "contractId": box10.contract_id, "choice": "ReadBox", "choiceArgument": { "reader": bob } } }]),
        &[],
        Some(vec![box10.disclosed(Some(&trunc_b64))]),
        "s-u14-trunc",
    );
    check_row(
        &expected,
        "u14_stage1_trunc_proto",
        st,
        &b,
        &box20.contract_id,
    );

    let ca_bytes = &box10_raw[c_start..c_end];
    let p_idx = find_subslice(ca_bytes, alice.as_bytes()).expect("alice party in create_arg");
    let mut raw_bad_party = box10_raw.clone();
    raw_bad_party[c_start + p_idx..c_start + p_idx + 5].copy_from_slice(b"alic!");
    let bad_party_b64 = encode_base64(&raw_bad_party);
    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:KeyedBox", "contractId": box10.contract_id, "choice": "ReadBox", "choiceArgument": { "reader": bob } } }]),
        &[],
        Some(vec![box10.disclosed(Some(&bad_party_b64))]),
        "s-u14-party",
    );
    check_row(
        &expected,
        "u14_stage1_bad_party",
        st,
        &b,
        &box20.contract_id,
    );

    let dup_idx = find_subslice(ca_bytes, b"dup").expect("dup key text");
    let val_rel = find_subslice(&ca_bytes[dup_idx..], &[0x18, 0x14]).expect("sint64(10)");
    let mut raw_forged_keyed = box10_raw;
    raw_forged_keyed[c_start + dup_idx + val_rel..c_start + dup_idx + val_rel + 2]
        .copy_from_slice(&[0x18, 0x62]);
    let forged_keyed_b64 = encode_base64(&raw_forged_keyed);
    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:KeyedBox", "contractId": box10.contract_id, "choice": "ReadBox", "choiceArgument": { "reader": bob } } }]),
        &[],
        Some(vec![box10.disclosed(Some(&forged_keyed_b64))]),
        "s-u14-forge-keyed",
    );
    check_row(
        &expected,
        "u14_stage2_forged_keyed_val",
        st,
        &b,
        &box20.contract_id,
    );

    let sn2 = create_contract(
        port,
        &alice,
        "#disclosure-ext:DiscloseExt:SecretNote",
        json!({ "owner": alice, "secret": "keep-valid" }),
        "c-sn2",
    );
    let mut sn2_raw = decode_strict_base64(&sn2.created_event_blob).unwrap();
    let (s2_start, s2_end) = find_fat_create_arg_range(&sn2_raw);
    let s2_rel = find_subslice(&sn2_raw[s2_start..s2_end], b"keep-valid").expect("keep-valid");
    sn2_raw[s2_start + s2_rel..s2_start + s2_rel + 10].copy_from_slice(b"forged-val");
    let forged_sn2_b64 = encode_base64(&sn2_raw);
    let (st, b) = submit(
        port,
        &[&bob],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:SecretNote", "contractId": sn2.contract_id, "choice": "Inspect", "choiceArgument": { "reader": bob } } }]),
        &[],
        Some(vec![sn2.disclosed(Some(&forged_sn2_b64))]),
        "s-u14-forge-unkeyed",
    );
    check_row(
        &expected,
        "u14_stage2_forged_unkeyed_val",
        st,
        &b,
        &box20.contract_id,
    );

    // 3. True unseen foreign disclosure across two separate ExecutionService instances
    let (port_f, stop_f) = start_test_server(Arc::new(ExecutionService::new()));
    let (up2_st, up2_b) = call(
        port_f,
        "POST",
        "/v2/dars",
        &dar_bytes,
        "application/octet-stream",
    );
    assert_eq!(up2_st, 200, "foreign DAR upload failed: {up2_b}");
    let alice_f = alloc_party(port_f, "alice");
    let bob_f = alloc_party(port_f, "bob");
    assert_eq!(
        alice_f, alice,
        "party ids must match across independent services"
    );
    assert_eq!(
        bob_f, bob,
        "party ids must match across independent services"
    );

    let (st, b) = submit(
        port_f,
        &[&bob_f],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:SecretNote", "contractId": sn2.contract_id, "choice": "Inspect", "choiceArgument": { "reader": bob_f } } }]),
        &[],
        Some(vec![sn2.disclosed(None)]),
        "f-nc-sn2",
    );
    assert_eq!(st, 200, "foreign non-consuming Inspect failed: {b}");
    assert_eq!(first_exercise_result(&b), json!("keep-valid"));

    let (st, b) = submit(
        port_f,
        &[&bob_f],
        json!([{ "ExerciseByKeyCommand": { "templateId": "#disclosure-ext:DiscloseExt:KeyedBox", "contractKey": { "_1": alice_f, "_2": "dup" }, "choice": "ReadBox", "choiceArgument": { "reader": bob_f } } }]),
        &[],
        Some(vec![box20.disclosed(None), box10.disclosed(None)]),
        "f-nc-ebk",
    );
    assert_eq!(st, 200, "foreign ExerciseByKeyCommand failed: {b}");
    assert_eq!(first_exercise_result(&b), json!("20"));
    assert_eq!(acs_summary(port_f, &alice_f), json!([]));
    assert_eq!(acs_summary(port_f, &bob_f), json!([]));

    let (st, b) = submit(
        port_f,
        &[&bob_f],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:KeyedBox", "contractId": box10.contract_id, "choice": "ReadBox", "choiceArgument": { "reader": bob_f } } }]),
        &[],
        Some(vec![box10.disclosed(Some(&forged_keyed_b64))]),
        "f-u14-forge",
    );
    assert_eq!(st, 400, "{b}");
    assert_eq!(
        b["code"],
        "INTERPRETATION_UPGRADE_ERROR_AUTHENTICATION_FAILED"
    );

    let (st, b) = submit(
        port_f,
        &[&bob_f],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:SecretNote", "contractId": sn2.contract_id, "choice": "Burn", "choiceArgument": { "burner": bob_f } } }]),
        &[],
        Some(vec![sn2.disclosed(None)]),
        "f-burn-sn2",
    );
    assert_eq!(st, 200, "foreign consuming Burn failed: {b}");
    assert_eq!(acs_summary(port_f, &alice_f), json!([]));
    assert_eq!(acs_summary(port_f, &bob_f), json!([]));

    let (st, b) = submit(
        port_f,
        &[&bob_f],
        json!([{ "ExerciseCommand": { "templateId": "#disclosure-ext:DiscloseExt:SecretNote", "contractId": sn2.contract_id, "choice": "Burn", "choiceArgument": { "burner": bob_f } } }]),
        &[],
        Some(vec![sn2.disclosed(None)]),
        "f-burn-replay",
    );
    assert_eq!(st, 404, "foreign replay must be 404: {b}");
    assert_eq!(b["code"], "LOCAL_VERDICT_INACTIVE_CONTRACTS");

    stop_f.store(true, std::sync::atomic::Ordering::SeqCst);
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    eprintln!(
        "disclosure-ext: {} oracle rows + cross-service foreign disclosure verified",
        expected.len()
    );
}
