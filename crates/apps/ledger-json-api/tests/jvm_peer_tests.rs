//! G11 B4 (S-G11-001): the **mixed JVM peer**. The JSON API service with a Rust participant (`Node`) behind it joins the official Canton
//! 3.7.2 synchronizer of `scripts/verify-sequencer-connect.sh` (sequencer s1, mediator m1) and hosts a party **together with the official
//! participant p1**. The transactions the JSON API path builds (`ExecutionService` → `NodeCommitter` → `Node`), not hand-built views, are sent
//! to p1, which has to validate them with its own engine and confirm its share of the party.
//!
//! Evidence per request, read from the sandbox's log: the mediator registers the request of this node (`Phase 2`), p1 validates it
//! (`Phase 3`) and sends `approved=…, rejected=0` (`Phase 4`), and the mediator finalizes it `with verdict Approve` (`Phase 6`).
//!
//! [CANTON-NOTE: LIMITATION] The party has threshold 1 and the Rust node confirms for it too, so the **verdict** alone does not show that p1
//! agreed: p1's own `Phase 4` line does. A rejection by p1 would not turn the verdict (the node's approval meets the threshold).
//!
//! Needs the sandbox's facts in the environment (`CANTON_RS_SEQUENCER_URL`, `CANTON_RS_MEMBER_P1`, `CANTON_RS_CONTAINER`,
//! `CANTON_RS_WORK_DIR`); compiled only with the `jvm-peer-tests` feature, run by `scripts/verify-sequencer-connect.sh`.
#![cfg(feature = "jvm-peer-tests")]
#![allow(clippy::unwrap_used, reason = "integration test helper")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use canton_participant::node::Node;
use ledger_json_api::models::json_api::*;
use ledger_json_api::models::ledger_api::*;
use ledger_json_api::protocol::NodeCommitter;
use ledger_json_api::service::ExecutionService;
use ledger_json_api::{HttpRequest, HttpResponse};
use serde_json::json;

fn var(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} must be set (scripts/verify-sequencer-connect.sh)"))
}

const PREPARE_PATH: &str = "/v2/interactive-submission/prepare";

thread_local! {
    /// The `prepare` bodies this test thread sent to each participant (S-SIM-001 R9), without their command ids and once each.
    static PREPARE_NOTES: std::cell::RefCell<Vec<serde_json::Value>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Notes a `prepare` body sent to `side` (`p1` or `rust`) for the inputs record of the oracle case.
fn note_prepare(side: &str, body: &serde_json::Value) {
    let mut body = body.clone();
    if let Some(fields) = body.as_object_mut() {
        fields.remove("commandId");
    }
    let note = json!({"side": side, "body": body});
    PREPARE_NOTES.with(|notes| {
        let mut notes = notes.borrow_mut();
        if !notes.contains(&note) {
            notes.push(note);
        }
    });
}

/// The Rust JSON API's answer to `req`; a `prepare` body is noted first (see [`note_prepare`]).
fn dispatch_request(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    if req.path == PREPARE_PATH {
        note_prepare(
            "rust",
            &serde_json::from_slice(&req.body).unwrap_or(serde_json::Value::Null),
        );
    }
    ledger_json_api::dispatch_request(service, req)
}

/// S-SIM-001 R9: what oracle case `case` was given, next to its raw answers when `SIM_ORACLE_OUT` names a directory:
/// `<dir>/inputs/<case>.json` with the traffic control in force (`traffic`, as the console reported it), the DARs by SHA-256, the members
/// in `topology`, and every distinct `prepare` body each participant received.
fn write_inputs(case: &str, traffic: Option<&str>, topology: serde_json::Value) {
    use sha2::{Digest, Sha256};
    let prepares = PREPARE_NOTES.with(|notes| std::mem::take(&mut *notes.borrow_mut()));
    let Ok(out) = std::env::var("SIM_ORACLE_OUT") else {
        return;
    };
    let dars: serde_json::Map<String, serde_json::Value> = [
        "contracts/target/sample-contract.dar",
        "contracts/fixtures/chain/target/nested-chain.dar",
        "contracts/fixtures/extfetch/target/ext-fetch.dar",
    ]
    .iter()
    .filter_map(|rel| {
        let bytes = std::fs::read(dar(rel)).ok()?;
        Some((
            (*rel).to_string(),
            json!(format!("{:x}", Sha256::digest(&bytes))),
        ))
    })
    .collect();
    let dir = format!("{out}/inputs");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        format!("{dir}/{case}.json"),
        serde_json::to_vec_pretty(&json!({
            "case": case,
            "traffic": traffic,
            "dars": dars,
            "topology": topology,
            "prepares": prepares,
        }))
        .unwrap(),
    )
    .unwrap();
}

fn dar(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(rel)
}

fn unique(prefix: &str) -> String {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst) % 1000;
    format!("{prefix}-{}{n:03}", nanos % 1_000_000_000_000)
}

/// The log of the sandbox container (every node's lines).
fn node_log() -> String {
    let out = std::process::Command::new("docker")
        .args(["logs", &var("CANTON_RS_CONTAINER")])
        .output()
        .expect("docker logs");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Waits up to `secs` seconds for a log line containing every needle.
fn log_line_with(needles: &[&str], secs: u32) -> Option<String> {
    for _ in 0..secs {
        if let Some(l) = node_log()
            .lines()
            .find(|l| needles.iter().all(|n| l.contains(n)))
        {
            return Some(l.to_string());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    None
}

/// Has p1 co-sign the topology transaction whose hash is `hash` (the console script's watcher, `/work/authorize/<n>.req`).
///
/// [CANTON-NOTE: WHY] p1 can authorize only a proposal it has stored: a request that arrives before the broadcast reached p1 fails
/// (`SCF authorize_failed`, measured on the first run). The request is repeated until p1 says `authorized`.
fn have_p1_authorize(hash: &[u8]) {
    let dir = Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    std::fs::create_dir_all(&dir).unwrap();
    let hex_hash = hex::encode(hash);
    let count = |what: &str| {
        node_log()
            .lines()
            .filter(|l| l.contains(&format!("SCF {what}={hex_hash}")))
            .count()
    };
    for _ in 0..30 {
        let failed_before = count("authorize_failed");
        let name = format!("{}.req", unique("json-api-authorize"));
        std::fs::write(dir.join(format!("{name}.tmp")), &hex_hash).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(name)).unwrap();
        for _ in 0..30 {
            if count("authorized") > 0 {
                return;
            }
            if count("authorize_failed") > failed_before {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    panic!("p1 never authorized {hex_hash}");
}

/// A JSON API service whose node joined the official synchronizer and hosts `shared` together with p1 (p1 co-signs through the console's
/// watcher). The DARs in `uploads` are uploaded through `POST /v2/packages` (the node vets them on the synchronizer).
struct Peer {
    service: Arc<ExecutionService>,
    member: String,
    /// the party hosted with p1
    party: String,
    /// the main package of each upload
    packages: Vec<String>,
}

fn peer(name: &str, shared: &str, uploads: &[&str]) -> Peer {
    let boot = dar("contracts/target/sample-contract.dar");
    let mut node = Node::connect(&var("CANTON_RS_SEQUENCER_URL"), &unique(name), &boot)
        .expect("the node joins the official synchronizer");
    let member = node.identity.member();
    let p1_uid = var("CANTON_RS_MEMBER_P1")
        .trim_start_matches("PAR::")
        .to_string();
    let party = node
        .host_shared_party(
            shared,
            &p1_uid,
            &mut |hash| have_p1_authorize(hash),
            Duration::from_secs(90),
        )
        .expect("the party is hosted by the node and p1");
    let service = Arc::new(ExecutionService::new());
    service.load_dar(&boot).expect("load the boot DAR");
    let committer = Arc::new(NodeCommitter::new(
        node,
        "sample-contract",
        Duration::from_secs(60),
    ));
    committer.show_remote_transactions_in(Arc::clone(&service));
    service.set_committer(committer);
    // the party is hosted already: this only makes the service know it
    assert_eq!(service.protocol_party(shared).unwrap().unwrap(), party);
    let mut packages = Vec::new();
    for rel in uploads {
        let path = dar(rel);
        let response = dispatch_request(
            &service,
            &HttpRequest {
                method: "POST".into(),
                path: "/v2/packages".into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: std::fs::read(&path).unwrap(),
            },
        );
        assert_eq!(
            response.status,
            200,
            "upload {rel}: {}",
            String::from_utf8_lossy(&response.body)
        );
        packages.push(lf_archive::parse_dar_file(&path).unwrap().main_package_id);
    }
    Peer {
        service,
        member,
        party,
        packages,
    }
}

/// The node's log shortens a member to `PAR::name::1220<12 hex>...`.
fn log_name(member: &str) -> String {
    member.rsplit_once("::").unwrap().0.to_string()
}

/// The times of the confirmation requests of `member` the mediator registered, in order (at least `count`, waiting up to a minute).
fn registered_requests(member: &str, count: usize) -> Vec<String> {
    let needle = format!("submittingParticipant={}", log_name(member));
    for _ in 0..60 {
        let times: Vec<String> = node_log()
            .lines()
            .filter(|l| l.contains("Phase 2: Registered request") && l.contains(&needle))
            .filter_map(|l| {
                l.split("request=")
                    .nth(1)
                    .and_then(|t| t.split([' ', ',', ')']).next())
                    .map(str::to_string)
            })
            .collect();
        if times.len() >= count {
            return times;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    panic!("the mediator did not register {count} requests of {member}");
}

/// What p1 and the mediator said about the request registered at `time`.
struct Judged {
    p1: Vec<String>,
    verdict: String,
}

fn judged(time: &str) -> Judged {
    let verdict = log_line_with(
        &[
            "mediator=m1",
            "Phase 6: Finalized request",
            &format!("RequestId({time})"),
        ],
        60,
    )
    .unwrap_or_else(|| panic!("the mediator did not finalize the request {time}"));
    let p1 = match log_line_with(
        &[
            "participant=p1",
            "Phase 3: Validating Transaction",
            &format!("request={time}"),
        ],
        5,
    ) {
        None => Vec::new(),
        Some(phase3) => {
            let tid = phase3
                .split("tid:")
                .nth(1)
                .and_then(|t| t.split(' ').next())
                .expect("a trace id")
                .to_string();
            // p1 sends its response before the verdict; the line is there by now, give the log a moment
            std::thread::sleep(Duration::from_secs(2));
            node_log()
                .lines()
                .filter(|l| l.contains("participant=p1") && l.contains(&format!("tid:{tid}")))
                .map(str::to_string)
                .collect()
        }
    };
    Judged { p1, verdict }
}

/// p1 validated the request and approved its share without a rejection, and the mediator approved.
fn assert_p1_approved(what: &str, j: &Judged) {
    let phase4 =
        j.p1.iter()
            .find(|l| l.contains("Phase 4: Sending for request"))
            .unwrap_or_else(|| panic!("{what}: p1 sent no response:\n{}", j.p1.join("\n")));
    assert!(
        phase4.contains("rejected=0") && !phase4.contains("approved=0"),
        "{what}: p1 did not approve: {phase4}"
    );
    assert!(
        !j.p1
            .iter()
            .any(|l| l.contains("WARN") || l.contains("LOCAL_VERDICT")),
        "{what}: p1 complained:\n{}",
        j.p1.join("\n")
    );
    assert!(
        j.verdict.contains("with verdict Approve"),
        "{what}: {}",
        j.verdict
    );
}

fn exercise(
    service: &ExecutionService,
    party: &str,
    template_id: TemplateId,
    contract_id: &str,
    choice: &str,
    argument: serde_json::Value,
) -> JsonApiResponse<ExerciseResult> {
    service
        .json_exercise(
            &[party.to_string()],
            ExerciseRequest {
                template_id,
                contract_id: contract_id.to_string(),
                choice: choice.into(),
                argument,
                meta: None,
            },
        )
        .unwrap_or_else(|e| panic!("{choice}: {e}"))
}

fn create(
    service: &ExecutionService,
    party: &str,
    template_id: TemplateId,
    payload: serde_json::Value,
) -> String {
    service
        .json_create(
            &[party.to_string()],
            CreateRequest {
                template_id,
                payload,
                meta: None,
            },
        )
        .unwrap_or_else(|e| panic!("create: {e}"))
        .result
        .contract_id
}

/// G8 P6 through the JSON API, judged by the official participant: a choice whose `try` block fetched and threw (`Scratch.Attempt`, a rollback
/// node holding a fetch) and one that creates a contract after such a rollback (`AttemptThenCreate`, S-SPL-027).
#[test]
fn p1_confirms_rollback_transactions_the_json_api_built() {
    let peer = peer(
        "json-rollback",
        "erin",
        &["contracts/fixtures/lookup/target/lookup-view.dar"],
    );
    let erin = peer.party.clone();
    let scratch = TemplateId::new(&peer.packages[0], "Lookup", "Scratch");
    let id = create(
        &peer.service,
        &erin,
        scratch.clone(),
        json!({"owner": erin}),
    );
    exercise(
        &peer.service,
        &erin,
        scratch.clone(),
        &id,
        "Attempt",
        json!({}),
    );
    exercise(
        &peer.service,
        &erin,
        scratch,
        &id,
        "AttemptThenCreate",
        json!({}),
    );
    let times = registered_requests(&peer.member, 3);
    for (what, time) in ["create Scratch", "Attempt", "AttemptThenCreate"]
        .iter()
        .zip(&times)
    {
        assert_p1_approved(what, &judged(time));
    }
    assert_eq!(
        peer.service
            .get_active_contracts(&[])
            .unwrap()
            .active_contracts
            .len(),
        2,
        "AttemptThenCreate created one more Scratch"
    );
}

/// G8 P4 through the JSON API, judged by the official participant: `Entry.Probe` looks a key up (`lookupByKey`) that nobody holds and one
/// that the node's own contract holds; an `ExerciseByKeyCommand` renames a keyed contract.
#[test]
fn p1_confirms_key_lookups_and_an_exercise_by_key_the_json_api_built() {
    let peer = peer(
        "json-lookup",
        "erin",
        &[
            "contracts/fixtures/lookup/target/lookup-view.dar",
            "contracts/fixtures/keyed/target/keyed-vault.dar",
        ],
    );
    let erin = peer.party.clone();
    let entry = TemplateId::new(&peer.packages[0], "Lookup", "Entry");
    let id = create(
        &peer.service,
        &erin,
        entry.clone(),
        json!({"owner": erin, "name": "present"}),
    );
    let missing = exercise(
        &peer.service,
        &erin,
        entry.clone(),
        &id,
        "Probe",
        json!({"wanted": {"_1": erin, "_2": "missing"}}),
    );
    assert_eq!(
        missing.result.result_value,
        Some(ValueBox(lf_eval::Value::Bool(false)))
    );
    let present = exercise(
        &peer.service,
        &erin,
        entry,
        &id,
        "Probe",
        json!({"wanted": {"_1": erin, "_2": "present"}}),
    );
    assert_eq!(
        present.result.result_value,
        Some(ValueBox(lf_eval::Value::Bool(true)))
    );
    let keyed = &peer.packages[1];
    create(
        &peer.service,
        &erin,
        TemplateId::new(keyed, "Keyed", "Registry"),
        json!({"owner": erin, "name": "k1", "payload": "v1"}),
    );
    let body = json!({
        "commands": [{
            "ExerciseByKeyCommand": {
                "templateId": format!("{keyed}:Keyed:Registry"),
                "contractKey": {"_1": erin, "_2": "k1"},
                "choice": "Rename",
                "choiceArgument": {"newName": "k2"}
            }
        }],
        "commandId": unique("rename-by-key"),
        "userId": "participant_admin",
        "actAs": [erin]
    });
    let response = dispatch_request(
        &peer.service,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/commands/submit-and-wait".into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: serde_json::to_vec(&body).unwrap(),
        },
    );
    assert_eq!(
        response.status,
        200,
        "ExerciseByKeyCommand: {}",
        String::from_utf8_lossy(&response.body)
    );
    let times = registered_requests(&peer.member, 5);
    for (what, time) in [
        "create Entry",
        "Probe (no contract holds the key)",
        "Probe (the node's contract holds the key)",
        "create Registry",
        "Rename by key",
    ]
    .iter()
    .zip(&times)
    {
        assert_p1_approved(what, &judged(time));
    }
}

/// U-21 through the JSON API, judged by the official participant: `lookupNByKey` (Daml-LF `QueryByKey`) over three contracts that share a
/// key, asking for all of them (`n = 10`), for two (`n = 2`), and for a key nothing holds. p1 reinterprets each view with the key
/// resolutions it states; a resolution that is not what p1's engine finds is a model conformance failure on p1's side.
#[test]
fn p1_confirms_queries_of_n_contracts_by_key_the_json_api_built() {
    let peer = peer(
        "json-querynkey",
        "erin",
        &["contracts/fixtures/querynkey/target/querynkey-view.dar"],
    );
    let erin = peer.party.clone();
    let item = TemplateId::new(&peer.packages[0], "QueryN", "Item");
    let mut ids = Vec::new();
    for note in ["a", "b", "c"] {
        ids.push(create(
            &peer.service,
            &erin,
            item.clone(),
            json!({"owner": erin, "label": "k", "note": note}),
        ));
    }
    for (n, wanted) in [(10, "k"), (2, "k"), (5, "none")] {
        exercise(
            &peer.service,
            &erin,
            item.clone(),
            &ids[0],
            "QueryN",
            json!({"n": n.to_string(), "wanted": wanted}),
        );
    }
    let times = registered_requests(&peer.member, 6);
    for (what, time) in [
        "create Item a",
        "create Item b",
        "create Item c",
        "QueryN 10 (all three)",
        "QueryN 2 (two of three)",
        "QueryN on a key nothing holds",
    ]
    .iter()
    .zip(&times)
    {
        assert_p1_approved(what, &judged(time));
    }
}

/// UNRESOLVED U-3 through the JSON API, judged by the official participant: **one submission of three commands** (two creates and an
/// exercise of a contract made earlier) is one transaction with three roots. p1 rebuilds every view and recomputes each contract id
/// from the node seeds the transaction states (`Unicum`), so its approval shows the ids the Rust participant derived for the second and
/// third roots are the ones the official engine derives.
#[test]
fn p1_confirms_a_submission_of_several_commands_the_json_api_built() {
    // uploading the boot DAR through the API vets it on this node too: without it p1 refuses every view with `UnvettedPackages`
    let peer = peer(
        "json-multi",
        "erin",
        &["contracts/target/sample-contract.dar"],
    );
    let erin = peer.party.clone();
    let holding = TemplateId::asset_holding();
    let payload = |symbol: &str| json!({"bank": erin, "owner": erin, "auditor": erin, "assetSymbol": symbol, "amount": "1.0"});
    let earlier = create(&peer.service, &erin, holding.clone(), payload("OLD"));
    let template = format!(
        "{}:{}:{}",
        holding.package_id, holding.module_name, holding.entity_name
    );
    let body = json!({
        "commands": [
            {"CreateCommand": {"templateId": template, "createArguments": payload("NEW1")}},
            {"CreateCommand": {"templateId": template, "createArguments": payload("NEW2")}},
            {"ExerciseCommand": {"templateId": template, "contractId": earlier, "choice": "Settle", "choiceArgument": {}}}
        ],
        "commandId": unique("multi"),
        "userId": "participant_admin",
        "actAs": [erin]
    });
    let response = dispatch_request(
        &peer.service,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/commands/submit-and-wait".into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: serde_json::to_vec(&body).unwrap(),
        },
    );
    assert_eq!(
        response.status,
        200,
        "three commands in one submission: {}",
        String::from_utf8_lossy(&response.body)
    );
    let times = registered_requests(&peer.member, 2);
    for (what, time) in [
        "create OLD",
        "one submission: create NEW1, create NEW2, Settle OLD",
    ]
    .iter()
    .zip(&times)
    {
        assert_p1_approved(what, &judged(time));
    }
}

/// G8 P5 through the JSON API, judged by the official participant: `Poke`, a choice of the interface `IHolding`, exercised through the
/// interface on a `Holding`.
#[test]
fn p1_confirms_an_interface_exercise_the_json_api_built() {
    let peer = peer(
        "json-iface",
        "erin",
        &["contracts/fixtures/iface/target/iface-view.dar"],
    );
    let erin = peer.party.clone();
    let pkg = &peer.packages[0];
    let id = create(
        &peer.service,
        &erin,
        TemplateId::new(pkg, "Iface", "Holding"),
        json!({"owner": erin}),
    );
    exercise(
        &peer.service,
        &erin,
        TemplateId::new(pkg, "Iface", "IHolding"),
        &id,
        "Poke",
        json!({}),
    );
    let times = registered_requests(&peer.member, 2);
    for (what, time) in ["create Holding", "Poke through IHolding"]
        .iter()
        .zip(&times)
    {
        assert_p1_approved(what, &judged(time));
    }
}

/// The control: the same rollback transaction for a party **only the Rust node** hosts is approved by the mediator without p1 ever validating
/// it. What the tests above read from p1's log is there because p1 co-hosts the party, not because p1 logs every request.
#[test]
fn p1_does_not_judge_the_transactions_of_a_party_it_does_not_host() {
    // the node hosts `erin` with p1 as in the other tests; `solo` it hosts alone
    let peer = peer(
        "json-solo",
        "erin",
        &["contracts/fixtures/lookup/target/lookup-view.dar"],
    );
    let solo = peer
        .service
        .protocol_party("solo")
        .unwrap()
        .expect("the node hosts the party alone");
    let scratch = TemplateId::new(&peer.packages[0], "Lookup", "Scratch");
    let id = create(
        &peer.service,
        &solo,
        scratch.clone(),
        json!({"owner": solo}),
    );
    exercise(&peer.service, &solo, scratch, &id, "Attempt", json!({}));
    let times = registered_requests(&peer.member, 2);
    for time in &times[..2] {
        let j = judged(time);
        assert!(j.verdict.contains("with verdict Approve"), "{}", j.verdict);
        assert!(
            j.p1.is_empty(),
            "p1 validated a request of a party it does not host:\n{}",
            j.p1.join("\n")
        );
    }
}

fn post(
    service: &ExecutionService,
    path: &str,
    body: &serde_json::Value,
) -> (u16, serde_json::Value) {
    let response = dispatch_request(
        service,
        &HttpRequest {
            method: "POST".into(),
            path: path.into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: serde_json::to_vec(body).unwrap(),
        },
    );
    let json = serde_json::from_slice(&response.body).unwrap_or_else(|_| {
        serde_json::Value::String(String::from_utf8_lossy(&response.body).to_string())
    });
    (response.status, json)
}

/// U-31 (S-G11-001), the Rust half: the official participant p1 **vetoes** a command of the JSON API. The same shape as the JVM reference
/// `an_official_participant_reports_the_veto_of_another_as_a_failed_completion` (`tests/oracle/u31-veto/jvm-veto.json`): `fay` owns an
/// `AssetHolding` whose bank `gus` signed while this node alone hosted both; then `gus` is re-hosted so that only p1 confirms for him (this node
/// observes), and p1 never saw the contract. `fay`'s `Transfer` reaches p1, which refuses; the JSON API answers with an error and records a
/// failed completion.
#[test]
fn the_json_api_reports_the_veto_of_the_official_participant_as_a_failed_completion() {
    let boot = dar("contracts/target/sample-contract.dar");
    let mut node = Node::connect(&var("CANTON_RS_SEQUENCER_URL"), &unique("json-veto"), &boot)
        .expect("the node joins the official synchronizer");
    let me = node.identity.uid();
    // vetted on the synchronizer, so that p1's only objection is the contract it never saw (measured without: p1 also noted
    // `UnvettedPackages` for this node)
    node.upload_and_vet_dar(&boot, Duration::from_secs(60))
        .unwrap();
    let fay = node.host_party("fay", Duration::from_secs(60)).unwrap();
    let gus = node.host_party("gus", Duration::from_secs(60)).unwrap();
    let service = Arc::new(ExecutionService::new());
    service.load_dar(&boot).unwrap();
    let committer = Arc::new(NodeCommitter::new(
        node,
        "sample-contract",
        Duration::from_secs(60),
    ));
    service.set_committer(Arc::<NodeCommitter>::clone(&committer));
    service.protocol_party("fay").unwrap().unwrap();
    service.protocol_party("gus").unwrap().unwrap();
    let cid = service
        .json_create(
            &[gus.clone(), fay.clone()],
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!({"bank": gus, "owner": fay, "auditor": fay, "assetSymbol": "USD", "amount": "100.0"}),
                meta: None,
            },
        )
        .expect("the holding is created while this node alone hosts both")
        .result
        .contract_id;
    // take the node back to re-host gus: p1 confirms for him, this node only observes
    service.clear_committer();
    let mut node = Arc::try_unwrap(committer)
        .ok()
        .expect("nobody else holds the committer")
        .into_node();
    let p1_uid = var("CANTON_RS_MEMBER_P1")
        .trim_start_matches("PAR::")
        .to_string();
    node.rehost_party(
        "gus",
        &[(me.as_str(), 3), (p1_uid.as_str(), 2)],
        2,
        &mut |hash| have_p1_authorize(hash),
        Duration::from_secs(90),
    )
    .expect("gus is re-hosted");
    service.set_committer(Arc::new(NodeCommitter::new(
        node,
        "sample-contract",
        Duration::from_secs(60),
    )));
    let command_id = unique("u31-transfer");
    let (status, error) = post(
        &service,
        "/v2/commands/submit-and-wait",
        &json!({
            "commands": [{"ExerciseCommand": {"templateId": "#sample-contract:AssetHolding:AssetHolding", "contractId": cid, "choice": "Transfer", "choiceArgument": {"newOwner": gus}}}],
            "commandId": command_id, "actAs": [fay], "userId": "participant_admin"
        }),
    );
    println!("U31R submit status={status} body={error}");
    let (_, completions) = post(
        &service,
        "/v2/commands/command-completions",
        &json!({"parties": [fay], "beginExclusive": 0}),
    );
    println!("U31R completions body={completions}");
    // what the official participant reports for the same veto (an_official_participant_reports_the_veto_of_another_as_a_failed_completion)
    let jvm: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dar("tests/oracle/u31-veto/jvm-veto.json")).unwrap())
            .unwrap();
    let jvm_body = &jvm["submit_and_wait"]["body"];
    assert_eq!(
        u64::from(status),
        jvm["submit_and_wait"]["status"].as_u64().unwrap(),
        "{error}"
    );
    for field in ["code", "cause", "errorCategory", "grpcCodeValue"] {
        assert_eq!(error[field], jvm_body[field], "{field}: {error}");
    }
    // the error's context: the same keys, and the values that do not depend on the run (the parties, participants and ids differ per run)
    let keys = |v: &serde_json::Value| {
        v["context"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert_eq!(keys(&error), keys(jvm_body), "context keys: {error}");
    for field in ["category", "definite_answer"] {
        assert_eq!(
            error["context"][field], jvm_body["context"][field],
            "{field}: {error}"
        );
    }
    let list = |v: &serde_json::Value| {
        v["context"]["CONTRACT_ID"]
            .as_str()
            .unwrap()
            .starts_with("List(0")
    };
    assert!(
        list(&error) && list(jvm_body),
        "CONTRACT_ID is `List(<id>)`: {error}"
    );
    let psid = error["context"]["psid"].as_str().unwrap();
    assert!(
        psid.contains("::")
            && psid.ends_with("...::37-0")
            && jvm_body["context"]["psid"]
                .as_str()
                .unwrap()
                .ends_with("...::37-0"),
        "psid is the synchronizer id with its fingerprint cut: {psid}"
    );
    assert!(
        error["context"]["reported_by_participant_id"]
            .as_str()
            .unwrap()
            .starts_with("PAR::"),
        "{error}"
    );
    // one resource per contract, `[CONTRACT_ID, <id>]`, the id the context lists
    let id = error["context"]["CONTRACT_ID"]
        .as_str()
        .unwrap()
        .trim_start_matches("List(")
        .trim_end_matches(')');
    assert_eq!(
        error["resources"],
        serde_json::json!([["CONTRACT_ID", id]]),
        "{error}"
    );
    assert_eq!(jvm_body["resources"].as_array().unwrap().len(), 1);
    // the trace id of the error is the one of its context
    assert_eq!(error["traceId"], error["context"]["tid"], "{error}");
    let ours = completions
        .as_array()
        .unwrap()
        .iter()
        .find_map(|c| {
            let v = c.pointer("/completionResponse/Completion/value")?;
            (v["commandId"] == command_id.as_str()).then_some(v)
        })
        .unwrap_or_else(|| panic!("a completion for the vetoed command: {completions}"));
    let theirs = &jvm["completion"]["completionResponse"]["Completion"]["value"];
    assert_eq!(ours["status"]["code"], theirs["status"]["code"], "{ours}");
    assert_eq!(ours["updateId"], theirs["updateId"], "{ours}");
    // the message is `CODE(category,<trace id>): cause`: the same but for the trace id
    let shape = |m: &str| {
        let (head, cause) = m.split_once("): ").unwrap();
        (
            head.split(',').next().unwrap().to_string(),
            cause.to_string(),
        )
    };
    assert_eq!(
        shape(ours["status"]["message"].as_str().unwrap()),
        shape(theirs["status"]["message"].as_str().unwrap()),
        "{ours}"
    );
    // the status details: the same three entries (ErrorInfo, RequestInfo, ResourceInfo of the contract), the error info with the same reason
    // and the same context keys, the resource naming the contract the context lists
    let (ours_details, theirs_details) = (
        ours["status"]["details"].as_array().unwrap(),
        theirs["status"]["details"].as_array().unwrap(),
    );
    let urls = |d: &[serde_json::Value]| d.iter().map(|x| x["typeUrl"].clone()).collect::<Vec<_>>();
    assert_eq!(urls(ours_details), urls(theirs_details), "{ours}");
    let (ours_info, theirs_info) = (
        &ours_details[0]["valueDecoded"],
        &theirs_details[0]["valueDecoded"],
    );
    assert_eq!(ours_info["reason"], theirs_info["reason"]);
    let metadata_keys = |v: &serde_json::Value| {
        v["metadata"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert_eq!(
        metadata_keys(ours_info),
        metadata_keys(theirs_info),
        "{ours}"
    );
    assert_eq!(
        ours_details[2]["valueDecoded"]["resourceType"],
        theirs_details[2]["valueDecoded"]["resourceType"]
    );
    assert_eq!(
        ours_details[1]["valueDecoded"]["requestId"], ours_info["metadata"]["tid"],
        "the request info carries the trace id of the context"
    );
    assert!(
        ours_details
            .iter()
            .all(|d| d["value"].as_str().is_some_and(|v| !v.is_empty())),
        "{ours}"
    );
}

fn p1_http_bytes(
    method: &str,
    path: &str,
    content_type: Option<&str>,
    payload: &[u8],
) -> (u16, serde_json::Value) {
    use std::io::{Read, Write};
    let addr = var("CANTON_RS_P1_HTTP");
    let mut stream = std::net::TcpStream::connect(&addr).expect("p1 JSON API is reachable");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(60)))
        .expect("set p1 HTTP read timeout");
    let ct_header = content_type
        .map(|ct| format!("Content-Type: {ct}\r\n"))
        .unwrap_or_default();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{ct_header}Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(head.as_bytes())
        .expect("write p1 HTTP head");
    if !payload.is_empty() {
        stream.write_all(payload).expect("write p1 HTTP body");
    }
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, rest) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body_text = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        let mut out = String::new();
        let mut cursor = rest;
        while let Some((size_line, after)) = cursor.split_once("\r\n") {
            let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
            if size == 0 || after.len() < size {
                break;
            }
            out.push_str(&after[..size]);
            cursor = after[size..].trim_start_matches("\r\n");
        }
        out
    } else {
        rest.to_string()
    };
    (
        status,
        serde_json::from_str(&body_text).unwrap_or(serde_json::Value::String(body_text)),
    )
}

fn p1_http(method: &str, path: &str, body: Option<&serde_json::Value>) -> (u16, serde_json::Value) {
    if path == PREPARE_PATH {
        if let Some(b) = body {
            note_prepare("p1", b);
        }
    }
    let payload = body.map(|b| b.to_string()).unwrap_or_default();
    p1_http_bytes(method, path, Some("application/json"), payload.as_bytes())
}

/// S-SIM-001 step 1 (K-01, K-07 expectations): the official participant's `/v2/interactive-submission/prepare` answer for the same create
/// with no cost hints, with `estimateTrafficCost.disabled = true`, and with `expectedSignatures`. The synchronizer of this sandbox has no
/// traffic control (`τ = ⊥`), so an estimate, when present, is expected to be zero. When `SIM_ORACLE_OUT` names a directory, the raw
/// answers are written there as the oracle evidence.
#[test]
fn p1_prepare_cost_estimation_shapes_are_recorded() {
    let hint = unique("sim001");
    let (st, alloc) = p1_http("POST", "/v2/parties", Some(&json!({ "partyIdHint": hint })));
    assert_eq!(st, 200, "p1 POST /v2/parties: {alloc}");
    let party = alloc["partyDetails"]["party"]
        .as_str()
        .expect("p1 allocated party")
        .to_string();
    let (st_sync, synchronizers) = p1_http(
        "GET",
        &format!("/v2/state/connected-synchronizers?party={party}"),
        None,
    );
    assert_eq!(st_sync, 200, "p1 connected synchronizers: {synchronizers}");
    let synchronizer_id = synchronizers["connectedSynchronizers"][0]["synchronizerId"]
        .as_str()
        .expect("p1 is connected to a synchronizer")
        .to_string();
    let prepare = |label: &str, hints: Option<serde_json::Value>| {
        let mut body = json!({
            "commandId": unique(&format!("sim001-{label}")),
            "userId": "participant_admin",
            "actAs": [party],
            "synchronizerId": synchronizer_id,
            "packageIdSelectionPreference": [],
            "commands": [{"CreateCommand": {
                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                "createArguments": {"bank": party, "owner": party, "auditor": party, "assetSymbol": "USD", "amount": "1.0"}
            }}]
        });
        if let Some(h) = hints {
            body["estimateTrafficCost"] = h;
        }
        let (status, answer) = p1_http("POST", "/v2/interactive-submission/prepare", Some(&body));
        if let Ok(dir) = std::env::var("SIM_ORACLE_OUT") {
            std::fs::create_dir_all(&dir).unwrap();
            let recorded = json!({"request": body, "status": status, "response": answer});
            std::fs::write(
                format!("{dir}/{label}.json"),
                serde_json::to_vec_pretty(&recorded).unwrap(),
            )
            .unwrap();
        }
        (status, answer)
    };
    // the official JSON codec requires `expectedSignatures` whenever `estimateTrafficCost` is given (400 "Missing required field")
    let (st_missing, missing) = prepare(
        "disabled-without-signatures",
        Some(json!({"disabled": true})),
    );
    assert_eq!(
        st_missing, 400,
        "hints without expectedSignatures: {missing}"
    );
    let (st_default, default) = prepare("no-hints", None);
    assert_eq!(st_default, 200, "prepare without hints: {default}");
    let (st_disabled, disabled) = prepare(
        "disabled",
        Some(json!({"disabled": true, "expectedSignatures": []})),
    );
    assert_eq!(st_disabled, 200, "prepare with disabled hints: {disabled}");
    let (st_sigs, sigs) = prepare(
        "expected-signatures",
        Some(
            json!({"disabled": false, "expectedSignatures": ["SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256"]}),
        ),
    );
    assert_eq!(st_sigs, 200, "prepare with expected signatures: {sigs}");
    write_inputs("K-01-K-07", None, json!({"p1": var("CANTON_RS_MEMBER_P1")}));
    // what the shape is decides K-07; it is printed so the run log shows it even without SIM_ORACLE_OUT
    println!(
        "SIM001 no-hints costEstimation={}",
        default
            .get("costEstimation")
            .map_or("<absent>".to_string(), |v| v.to_string())
    );
    println!(
        "SIM001 disabled costEstimation={}",
        disabled
            .get("costEstimation")
            .map_or("<absent>".to_string(), |v| v.to_string())
    );
}

/// S-SIM-001 K-07 (hint validation, review R1-F4): the same `prepare` bodies with `expectedSignatures` naming an algorithm the official
/// validator refuses (`CryptoValidator.validateSigningAlgorithmSpec`: only Ed25519 and EC-DSA SHA-256/384) or one the JSON codec does not
/// know, and with `disabled = true` and such a name (not validated). The Rust JSON API answers each as p1 does: the status, the error code
/// and the cause. When `SIM_ORACLE_OUT` names a directory, both answers are written there.
#[test]
fn sim001_k07_hint_validation_answers_as_the_official_participant() {
    let peer = peer(
        "sim001-k07",
        "simk07",
        &["contracts/target/sample-contract.dar"],
    );
    let party = peer.party.clone();
    let logical = canton_participant::multi_node::logical(&var("CANTON_RS_EXPECT_SYNCHRONIZER"));
    peer.service
        .v2_state()
        .set_synchronizer_id_for_test(&logical);
    let body = |hints: serde_json::Value| {
        json!({
            "commandId": unique("sim001-k07"), "userId": "participant_admin", "actAs": [party],
            "synchronizerId": logical, "packageIdSelectionPreference": [],
            "commands": [{"CreateCommand": {
                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                "createArguments": {"bank": party, "owner": party, "auditor": party, "assetSymbol": "USD", "amount": "1.0"}}}],
            "estimateTrafficCost": hints
        })
    };
    let ask_rust = |b: &serde_json::Value| {
        let r = dispatch_request(
            &peer.service,
            &HttpRequest {
                method: "POST".into(),
                path: PREPARE_PATH.into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: serde_json::to_vec(b).unwrap(),
            },
        );
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or_else(|_| {
                serde_json::Value::String(String::from_utf8_lossy(&r.body).to_string())
            }),
        )
    };
    // what decides a refusal: the status, and for a Canton error its code and cause (the correlation and trace ids differ by request)
    let shape = |status: u16, answer: &serde_json::Value| -> serde_json::Value {
        if status == 200 {
            return json!({"status": 200, "estimated": !answer["costEstimation"].is_null()});
        }
        match answer.get("code") {
            Some(code) => json!({"status": status, "code": code, "cause": answer["cause"],
                "grpcCodeValue": answer["grpcCodeValue"], "errorCategory": answer["errorCategory"]}),
            None => json!({"status": status, "body": answer}),
        }
    };
    let cases = [
        (
            "unspecified",
            json!({"disabled": false, "expectedSignatures": ["SIGNING_ALGORITHM_SPEC_UNSPECIFIED"]}),
        ),
        (
            "ml-dsa-65",
            json!({"disabled": false, "expectedSignatures": ["SIGNING_ALGORITHM_SPEC_ML_DSA_65"]}),
        ),
        (
            "unknown-name",
            json!({"disabled": false, "expectedSignatures": ["NOT_AN_ALGORITHM"]}),
        ),
        (
            "ed25519-then-unspecified",
            json!({"disabled": false, "expectedSignatures": ["SIGNING_ALGORITHM_SPEC_ED25519", "SIGNING_ALGORITHM_SPEC_UNSPECIFIED"]}),
        ),
        (
            "disabled-unspecified",
            json!({"disabled": true, "expectedSignatures": ["SIGNING_ALGORITHM_SPEC_UNSPECIFIED"]}),
        ),
        (
            "disabled",
            json!({"disabled": true, "expectedSignatures": []}),
        ),
        (
            "ec-dsa-384",
            json!({"disabled": false, "expectedSignatures": ["SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_384"]}),
        ),
    ];
    let mut recorded = serde_json::Map::new();
    let mut differ = Vec::new();
    for (label, hints) in cases {
        let (p1_status, p1_answer) = p1_http("POST", PREPARE_PATH, Some(&body(hints.clone())));
        let (rust_status, rust_answer) = ask_rust(&body(hints));
        let (official, rust) = (
            shape(p1_status, &p1_answer),
            shape(rust_status, &rust_answer),
        );
        println!("SIM001 K-07 {label}: p1={official} rust={rust}");
        if official != rust {
            differ.push(format!("{label}: p1 {official} rust {rust}"));
        }
        recorded.insert(label.into(), json!({"p1": p1_answer, "rust": rust_answer}));
    }
    write_inputs(
        "K-07-hints",
        None,
        json!({"p1": var("CANTON_RS_MEMBER_P1"), "rust": peer.member}),
    );
    if let Ok(out) = std::env::var("SIM_ORACLE_OUT") {
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            format!("{out}/K-07-hints.json"),
            serde_json::to_vec_pretty(&recorded).unwrap(),
        )
        .unwrap();
    }
    assert!(differ.is_empty(), "K-07: {}", differ.join("; "));
}

/// S-SIM-001 step 7 (first part, C-A5): with traffic control **on** (factor 200, base event cost 7, responses not free), the official
/// participant's `prepare` estimates the confirmation response at the cost of the mock response `TrafficCostEstimator` builds; the Rust
/// mock response (`participant_runtime::mock_confirmation_response`) priced with the same formula gives the same number. The official
/// request estimate is recorded for step 5. **It turns traffic control on for the shared sandbox (and off at the end): run it alone.**
#[test]
#[ignore = "turns traffic control on for the shared sandbox; run it alone"]
fn p1_prepare_cost_estimation_with_traffic_control_on() {
    let dir = Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    std::fs::create_dir_all(&dir).unwrap();
    let traffic = |command: &str| -> String {
        let file = format!("{}.trafficcmd", unique("sim001tc"));
        std::fs::write(dir.join(format!("{file}.tmp")), command).unwrap();
        std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
        log_line_with(&["SCF trafficcmd_done=", &file], 60)
            .unwrap_or_else(|| panic!("the console never finished {command}"))
    };
    /// Turns traffic control off again however the test ends.
    struct Off<'a>(&'a dyn Fn(&str) -> String);
    impl Drop for Off<'_> {
        fn drop(&mut self) {
            println!("SIM001 traffic disable: {}", (self.0)("disable"));
        }
    }
    let hint = unique("sim001tc");
    let (st, alloc) = p1_http("POST", "/v2/parties", Some(&json!({ "partyIdHint": hint })));
    assert_eq!(st, 200, "p1 POST /v2/parties: {alloc}");
    let party = alloc["partyDetails"]["party"]
        .as_str()
        .expect("party")
        .to_string();
    let (_, syncs) = p1_http("GET", "/v2/state/connected-synchronizers", None);
    let synchronizer_id = syncs["connectedSynchronizers"][0]["synchronizerId"]
        .as_str()
        .expect("p1 is connected")
        .to_string();
    let enabled = traffic("enable,1000000,200,7");
    println!("SIM001 traffic enable: {enabled}");
    assert!(
        enabled.contains("=ok"),
        "traffic control turned on: {enabled}"
    );
    let _off = Off(&traffic);
    let body = json!({
        "commandId": unique("sim001-traffic-on"),
        "userId": "participant_admin",
        "actAs": [party],
        "synchronizerId": synchronizer_id,
        "packageIdSelectionPreference": [],
        "commands": [{"CreateCommand": {
            "templateId": "#sample-contract:AssetHolding:AssetHolding",
            "createArguments": {"bank": party, "owner": party, "auditor": party, "assetSymbol": "USD", "amount": "1.0"}
        }}],
        "estimateTrafficCost": {"disabled": false, "expectedSignatures": []}
    });
    // the parameters reach p1's topology some time after the proposal
    let mut answer = json!(null);
    for _ in 0..60 {
        let (status, a) = p1_http("POST", "/v2/interactive-submission/prepare", Some(&body));
        assert_eq!(status, 200, "prepare with traffic control on: {a}");
        answer = a;
        if answer["costEstimation"]["totalTrafficCostEstimation"]
            .as_u64()
            .unwrap_or(0)
            > 0
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    write_inputs(
        "traffic-on",
        Some(&enabled),
        json!({"p1": var("CANTON_RS_MEMBER_P1")}),
    );
    let cost = &answer["costEstimation"];
    println!("SIM001 traffic-on costEstimation={cost}");
    if let Ok(out) = std::env::var("SIM_ORACLE_OUT") {
        std::fs::create_dir_all(&out).unwrap();
        let recorded = json!({
            "request": body,
            "status": 200,
            "response": answer,
            "traffic": {"readVsWriteScalingFactor": 200, "baseEventCost": 7, "freeConfirmationResponses": false},
            "member": var("CANTON_RS_MEMBER_P1"),
            "physicalSynchronizerId": var("CANTON_RS_EXPECT_SYNCHRONIZER"),
        });
        std::fs::write(
            format!("{out}/traffic-on.json"),
            serde_json::to_vec_pretty(&recorded).unwrap(),
        )
        .unwrap();
    }
    let official_response = cost["confirmationResponseTrafficCostEstimation"]
        .as_u64()
        .unwrap_or_else(|| panic!("an estimate with traffic control on: {answer}"));
    assert!(
        official_response > 0,
        "traffic control reached p1: {answer}"
    );
    // the executing participant confirms for its admin party and the submitting party it hosts; the sandbox has one mediator
    let member = var("CANTON_RS_MEMBER_P1");
    let admin = member.strip_prefix("PAR::").unwrap_or(&member).to_string();
    let mut confirming = vec![admin, party];
    confirming.sort();
    // [CANTON-NOTE: WHY] the request id is the topology time of the estimate; any time of this era has the same varint length
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    let envelope = canton_participant::participant_runtime::mock_confirmation_response(
        &var("CANTON_RS_EXPECT_SYNCHRONIZER"),
        &member,
        &confirming,
        at,
        1,
    );
    let rust_response =
        canton_algo::traffic_cost::event_cost(200, 7, &[(envelope.size, envelope.recipients)]);
    println!(
        "SIM001 response official={official_response} rust={rust_response} (content {} bytes)",
        envelope.size
    );
    assert_eq!(
        rust_response, official_response,
        "the confirmation response estimate"
    );
}

/// S-SIM-001 step 5 and 7 (C-A1 for a create and an exercise): with traffic control on, the confirmation request the Rust JSON API builds without sending
/// it for `prepare` costs what the official sequencer charges for the same request when it is sent. The base traffic is set below the
/// request's cost, so the official sequencer refuses the paid request with `AboveTrafficLimit` and names its `trafficCost` (and does not
/// say `IncorrectEventCost`, which shows the node paid the right cost). **It turns traffic control on for the shared sandbox (and off at the
/// end): run it alone.**
#[test]
#[ignore = "turns traffic control on for the shared sandbox; run it alone"]
fn rust_prepare_estimates_the_request_cost_the_official_sequencer_charges() {
    // [CANTON-NOTE: WHY] measured over 10 rounds of a create (2026-11-24): the differences were 0 to 15 and their mean -1.9 (standard
    // deviation about 6, so about 2 for the mean of 10). A round may differ by 1% of the charged cost; the mean may be off by at most 8
    // (about four times its spread). A systematic error, e.g. a mediator group counted as no member, moves the mean by about 25.
    const ROUNDS: usize = 10;
    // C-A1 (가): the mean difference is at most 8, compared in integers as `|sum| <= 8 * rounds` (no floats on a cost path)
    const MAX_MEAN_BIAS: i64 = 8;
    let peer = peer("sim001-req", "sima", &[]);
    let sima = peer.party.clone();
    let holding = TemplateId::asset_holding();
    let template = format!(
        "{}:{}:{}",
        holding.package_id, holding.module_name, holding.entity_name
    );
    let payload = json!({"bank": sima, "owner": sima, "auditor": sima, "assetSymbol": "USD", "amount": "1.0"});
    // the contract the exercise rounds use, created while traffic control is off; the paid exercises are refused, so it stays active
    let held = create(&peer.service, &sima, holding, payload.clone());
    let dir = Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    std::fs::create_dir_all(&dir).unwrap();
    let traffic = |command: &str| -> String {
        let file = format!("{}.trafficcmd", unique("sim001rq"));
        std::fs::write(dir.join(format!("{file}.tmp")), command).unwrap();
        std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
        log_line_with(&["SCF trafficcmd_done=", &file], 60)
            .unwrap_or_else(|| panic!("the console never finished {command}"))
    };
    /// Turns traffic control off again however the test ends.
    struct Off<'a>(&'a dyn Fn(&str) -> String);
    impl Drop for Off<'_> {
        fn drop(&mut self) {
            println!("SIM001 traffic disable: {}", (self.0)("disable"));
        }
    }
    let call = |method: &str, path: &str, body: Option<&serde_json::Value>| {
        let r = dispatch_request(
            &peer.service,
            &HttpRequest {
                method: method.into(),
                path: path.into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: body.map_or_else(Vec::new, |b| serde_json::to_vec(b).unwrap()),
            },
        );
        (r.status, String::from_utf8_lossy(&r.body).to_string())
    };
    let (_, syncs) = call("GET", "/v2/state/connected-synchronizers", None);
    let synchronizer_id = serde_json::from_str::<serde_json::Value>(&syncs).unwrap()
        ["connectedSynchronizers"][0]["synchronizerId"]
        .as_str()
        .expect("the Rust service is connected")
        .to_string();
    // 1000 bytes of base traffic: less than a confirmation request costs (about 3000), more than the topology change that turns it off
    let enabled = traffic("enable,1000,200,7");
    assert!(
        enabled.contains("=ok"),
        "traffic control turned on: {enabled}"
    );
    let _off = Off(&traffic);
    // the node learns the new parameters from the topology it reads; until then it answers and pays as without traffic control
    let probe = json!({
        "commandId": unique("sim001-probe"), "userId": "participant_admin", "actAs": [sima],
        "synchronizerId": synchronizer_id, "packageIdSelectionPreference": [],
        "commands": [{"CreateCommand": {"templateId": template, "createArguments": payload}}],
        "estimateTrafficCost": {"disabled": false, "expectedSignatures": []}
    });
    let learned = (0..60).any(|_| {
        let (_, body) = call("POST", "/v2/interactive-submission/prepare", Some(&probe));
        let total = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["costEstimation"]["totalTrafficCostEstimation"].as_u64());
        if total.is_some_and(|t| t > 0) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
        false
    });
    assert!(learned, "the Rust node learned that traffic control is on");
    let kinds = [
        (
            "create",
            json!([{"CreateCommand": {"templateId": template, "createArguments": payload}}]),
        ),
        (
            "exercise",
            json!([{"ExerciseCommand": {"templateId": template, "contractId": held, "choice": "Settle", "choiceArgument": {}}}]),
        ),
    ];
    // [CANTON-NOTE: LIMITATION] the views are Zstd-compressed before they are encrypted and carry fresh salts and keys, so two builds of
    // the same request differ by a few bytes (measured: 1728 and 1730 bytes for the encrypted view of one create); the official estimator
    // builds its own request with fresh randomness too. The estimate is therefore compared over several builds, within a tolerance.
    let mut recorded = Vec::new();
    for (kind, commands) in &kinds {
        let mut pairs = Vec::new();
        for round in 0..ROUNDS {
            // the same command id for the estimate and the submission: it is part of the request's views
            let command_id = unique(&format!("sim001-{kind}-{round:02}"));
            let prepare = json!({
                "commandId": command_id, "userId": "participant_admin", "actAs": [sima],
                "synchronizerId": synchronizer_id,
                "packageIdSelectionPreference": [], "commands": commands,
                "estimateTrafficCost": {"disabled": false, "expectedSignatures": []}
            });
            let (status, body) = call("POST", "/v2/interactive-submission/prepare", Some(&prepare));
            assert_eq!(status, 200, "Rust prepare of a {kind}: {body}");
            let estimate =
                serde_json::from_str::<serde_json::Value>(&body).unwrap()["costEstimation"].clone();
            let rust: u64 = estimate["confirmationRequestTrafficCostEstimation"]
                .as_u64()
                .unwrap_or_else(|| {
                    panic!("an estimate of a {kind} with traffic control on: {estimate}")
                });
            let (status, refusal) = call(
                "POST",
                "/v2/commands/submit-and-wait",
                Some(
                    &json!({"commands": commands, "commandId": command_id, "userId": "participant_admin", "actAs": [sima]}),
                ),
            );
            assert!(
                refusal.contains("AboveTrafficLimit") && !refusal.contains("IncorrectEventCost"),
                "the paid {kind} is refused only for want of traffic: {status} {refusal}"
            );
            let charged: u64 = refusal
                .split("trafficCost = ")
                .nth(1)
                .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| {
                    panic!("the official sequencer names the cost: {status} {refusal}")
                });
            println!(
                "SIM001 request kind={kind} round={round} rust={rust} official-charged={charged}"
            );
            pairs.push((rust, charged));
            recorded.push(json!({"kind": kind, "rust": rust, "officialCharged": charged, "costEstimation": estimate, "refusal": refusal}));
        }
        let mut bias = 0i64;
        for (rust, charged) in &pairs {
            assert!(
                rust.abs_diff(*charged) * 100 <= *charged,
                "the {kind} request estimate {rust} is within 1% of what the official sequencer charges ({charged})"
            );
            bias += *rust as i64 - *charged as i64;
        }
        let rounds = i64::try_from(ROUNDS).unwrap();
        println!("SIM001 request kind={kind} bias sum={bias} over {rounds} rounds");
        assert!(
            bias.abs() <= MAX_MEAN_BIAS * rounds,
            "the {kind} request estimate is not biased: the differences sum to {bias} over {rounds} rounds"
        );
    }
    write_inputs(
        "K-08",
        Some(&enabled),
        json!({"p1": var("CANTON_RS_MEMBER_P1"), "rust": peer.member}),
    );
    if let Ok(out) = std::env::var("SIM_ORACLE_OUT") {
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            format!("{out}/traffic-on-rust-request.json"),
            serde_json::to_vec_pretty(&json!({"rounds": recorded})).unwrap(),
        )
        .unwrap();
    }
}

/// The Rust participant pays its traffic (S-SIM-001 follow-up, §1.4 of the plan): with traffic control on (and enough base traffic), a create
/// submitted through the Rust JSON API is sequenced and approved, its confirmation response is paid too, and a DAR upload's vetting
/// broadcast to all members is sequenced. Without the cost, the official sequencer refuses the first submission with `IncorrectEventCost`.
/// **It turns traffic control on for the shared sandbox (and off at the end): run it alone.**
#[test]
#[ignore = "turns traffic control on for the shared sandbox; run it alone"]
fn rust_participant_pays_its_traffic_and_is_approved() {
    let peer = peer("sim001-pay", "simp", &[]);
    let simp = peer.party.clone();
    let dir = Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    std::fs::create_dir_all(&dir).unwrap();
    let traffic = |command: &str| -> String {
        let file = format!("{}.trafficcmd", unique("sim001pay"));
        std::fs::write(dir.join(format!("{file}.tmp")), command).unwrap();
        std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
        log_line_with(&["SCF trafficcmd_done=", &file], 60)
            .unwrap_or_else(|| panic!("the console never finished {command}"))
    };
    /// Turns traffic control off again however the test ends.
    struct Off<'a>(&'a dyn Fn(&str) -> String);
    impl Drop for Off<'_> {
        fn drop(&mut self) {
            println!("SIM001 traffic disable: {}", (self.0)("disable"));
        }
    }
    let enabled = traffic("enable,1000000,200,7");
    assert!(
        enabled.contains("=ok"),
        "traffic control turned on: {enabled}"
    );
    let _off = Off(&traffic);
    // the parameters reach the node's topology some time after the proposal: until then it does not pay, and is refused
    let holding = TemplateId::asset_holding();
    let mut answer = String::new();
    let mut approved = false;
    for round in 0..30 {
        let (status, body) = {
            let r = dispatch_request(
                &peer.service,
                &HttpRequest {
                    method: "POST".into(),
                    path: "/v2/commands/submit-and-wait".into(),
                    query_params: HashMap::new(),
                    headers: HashMap::new(),
                    body: serde_json::to_vec(&json!({
                        "commands": [{"CreateCommand": {"templateId": format!("{}:{}:{}", holding.package_id, holding.module_name, holding.entity_name),
                            "createArguments": {"bank": simp, "owner": simp, "auditor": simp, "assetSymbol": "USD", "amount": "1.0"}}}],
                        "commandId": unique(&format!("sim001-pay-{round}")),
                        "userId": "participant_admin",
                        "actAs": [simp]
                    }))
                    .unwrap(),
                },
            );
            (r.status, String::from_utf8_lossy(&r.body).to_string())
        };
        println!(
            "SIM001 pay round={round} status={status} answer={}",
            body.chars().take(300).collect::<String>()
        );
        answer = body;
        if status == 200 {
            approved = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(
        approved,
        "a paid create is approved with traffic control on: {answer}"
    );
    let path = dar("contracts/fixtures/iface/target/iface-view.dar");
    let r = dispatch_request(
        &peer.service,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/packages".into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: std::fs::read(&path).unwrap(),
        },
    );
    println!("SIM001 pay upload status={}", r.status);
    assert_eq!(
        r.status,
        200,
        "a DAR upload (vetting broadcast to all members) is sequenced with traffic control on: {}",
        String::from_utf8_lossy(&r.body)
    );
}

/// U-56 (ⓓ): an externally signed create, then an externally signed exercise of the contract it made (`Settle`), executed on the
/// official participant and observed by a party the Rust node hosts. The Rust node
/// receives the root view with the external authorization; the tree is kept with what the external signer signed (the prepared
/// transaction, its hash and the signature) as the test vector the recomputation of the externally signed hash must meet. When
/// `U56_VECTOR_OUT` names a directory the vector is written there.
#[test]
fn p1_externally_signed_create_reaches_the_rust_observer_with_its_authorization() {
    let _turn = EXTERNAL_TREES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use canton_algo::prepared_hash::{decode_base64, encode_base64};
    use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
    use sha2::{Digest, Sha256};
    // uploading the boot DAR through the API vets it on this node too: p1 selects a package only if every host of a party vetted it
    let peer = peer(
        "u56-vec",
        "extobs",
        &[
            "contracts/target/sample-contract.dar",
            "contracts/fixtures/chain/target/nested-chain.dar",
            "contracts/fixtures/extfetch/target/ext-fetch.dar",
        ],
    );
    // the rest of `peer` (its service and node, which receive the requests) lives to the end of the test
    let observer = peer.party;
    canton_participant::view_decision::external_trees::start();
    let logical_sync =
        canton_participant::multi_node::logical(&var("CANTON_RS_EXPECT_SYNCHRONIZER"));
    let hint = unique("u56ext");
    let seed: [u8; 32] = Sha256::digest(hint.as_bytes()).into();
    let sk = SigningKey::from_bytes(&seed);
    let spki = sk
        .verifying_key()
        .to_public_key_der()
        .expect("ed25519 spki");
    let public_key = json!({
        "format": "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
        "keyData": encode_base64(spki.as_bytes()),
        "keySpec": "SIGNING_KEY_SPEC_EC_CURVE25519"
    });
    let signature_json = |payload: &[u8], fingerprint: &str| {
        json!({
            "format": "SIGNATURE_FORMAT_CONCAT",
            "signature": encode_base64(&sk.sign(payload).to_bytes()),
            "signedBy": fingerprint,
            "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
        })
    };
    let (st, generated) = p1_http(
        "POST",
        "/v2/parties/external/generate-topology",
        Some(&json!({"synchronizer": logical_sync, "partyHint": hint, "publicKey": public_key})),
    );
    assert_eq!(st, 200, "generate-topology on p1: {generated}");
    let party = generated["partyId"].as_str().expect("partyId").to_string();
    let fingerprint = generated["publicKeyFingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_string();
    // the onboarding multihash is signed as a 34-byte multihash
    let mut multi_hash =
        decode_base64(generated["multiHash"].as_str().expect("multiHash")).unwrap();
    if multi_hash.len() == 32 {
        multi_hash.splice(0..0, [0x12, 0x20]);
    }
    let onboarding: Vec<serde_json::Value> = generated["topologyTransactions"]
        .as_array()
        .expect("topologyTransactions")
        .iter()
        .map(|tx| json!({"transaction": tx, "signatures": []}))
        .collect();
    let (st, allocated) = p1_http(
        "POST",
        "/v2/parties/external/allocate",
        Some(
            &json!({"synchronizer": logical_sync, "onboardingTransactions": onboarding,
            "multiHashSignatures": [signature_json(&multi_hash, &fingerprint)]}),
        ),
    );
    assert_eq!(st, 200, "external/allocate on p1: {allocated}");
    // prepares `commands` for the external party, signs the hash and executes it on p1; the answer of the execution
    let run = |label: &str, commands: serde_json::Value, endpoint: &str| {
        let prepare_body = json!({
            "commandId": unique(&format!("u56-{label}")), "userId": "participant_admin", "actAs": [party],
            "synchronizerId": logical_sync, "packageIdSelectionPreference": [], "commands": commands
        });
        // the party is known to p1's topology some time after the allocation
        let mut prepared = serde_json::Value::Null;
        let mut last = String::new();
        for _ in 0..60 {
            let (st, answer) = p1_http(
                "POST",
                "/v2/interactive-submission/prepare",
                Some(&prepare_body),
            );
            if st == 200 {
                prepared = answer;
                break;
            }
            last = format!("{st} {answer}");
            std::thread::sleep(Duration::from_millis(500));
        }
        let prepared_tx = prepared["preparedTransaction"]
            .as_str()
            .unwrap_or_else(|| panic!("p1 prepared the externally signed {label}: {last}"))
            .to_string();
        // [CANTON-NOTE: SEMANTICS] the transaction hash is signed as the 32 bytes `preparedTransactionHash` gives (measured: a signature
        // over the 34-byte multihash is refused with `Received 0 valid signatures`), unlike the onboarding multihash above
        let hash =
            decode_base64(prepared["preparedTransactionHash"].as_str().expect("hash")).unwrap();
        let signature = signature_json(&hash, &fingerprint);
        let (st, executed) = p1_http(
            "POST",
            endpoint,
            Some(&json!({
                "preparedTransaction": prepared_tx,
                "partySignatures": {"signatures": [{"party": party, "signatures": [signature]}]},
                "submissionId": unique(&format!("u56-{label}-submission")),
                "userId": "participant_admin",
                "hashingSchemeVersion": prepared["hashingSchemeVersion"],
                "deduplicationPeriod": {"Empty": {}}
            })),
        );
        println!(
            "U56 p1 {label} status={st} answer={}",
            executed.to_string().chars().take(400).collect::<String>()
        );
        assert_eq!(
            st, 200,
            "p1 executed the externally signed {label}: {executed}"
        );
        (prepare_body, prepared, signature, executed)
    };
    let create = run(
        "create",
        json!([{"CreateCommand": {"templateId": "#sample-contract:AssetHolding:AssetHolding",
            "createArguments": {"bank": party, "owner": party, "auditor": observer, "assetSymbol": "USD", "amount": "1.0"}}}]),
        "/v2/interactive-submission/executeAndWaitForTransaction",
    );
    let contract_id = create.3["transaction"]["events"]
        .as_array()
        .and_then(|events| {
            events
                .iter()
                .find_map(|e| e["CreatedEvent"]["contractId"].as_str())
        })
        .unwrap_or_else(|| panic!("the create's transaction names the contract: {}", create.3))
        .to_string();
    let exercise = run(
        "exercise",
        json!([{"ExerciseCommand": {"templateId": "#sample-contract:AssetHolding:AssetHolding",
            "contractId": contract_id, "choice": "Settle", "choiceArgument": {}}}]),
        "/v2/interactive-submission/executeAndWait",
    );
    // an exercise with an action below it: `Forward` on a `Hop` (consuming, so its observer is an informee of the root view) creates a
    // `Note` in the same view
    let hop = run(
        "hop-create",
        json!([{"CreateCommand": {"templateId": "#nested-chain:Chain:Hop",
            "createArguments": {"owner": party, "peer1": observer, "peer2": observer, "msg": "u56"}}}]),
        "/v2/interactive-submission/executeAndWaitForTransaction",
    );
    let hop_id = hop.3["transaction"]["events"]
        .as_array()
        .and_then(|events| {
            events
                .iter()
                .find_map(|e| e["CreatedEvent"]["contractId"].as_str())
        })
        .unwrap_or_else(|| panic!("the Hop's transaction names the contract: {}", hop.3))
        .to_string();
    let forward = run(
        "forward",
        json!([{"ExerciseCommand": {"templateId": "#nested-chain:Chain:Hop",
            "contractId": hop_id, "choice": "Forward", "choiceArgument": {}}}]),
        "/v2/interactive-submission/executeAndWait",
    );
    // an exercise with a fetch below it: `ReadAndClose` on a `Book` (consuming, so its watcher is an informee of the root view) fetches
    // another book of the same owner in the same view
    let book = |title: &str| {
        let made = run(
            &format!("book-{title}"),
            json!([{"CreateCommand": {"templateId": "#ext-fetch:ExtFetch:Book",
                "createArguments": {"owner": party, "watcher": observer, "title": title}}}]),
            "/v2/interactive-submission/executeAndWaitForTransaction",
        );
        made.3["transaction"]["events"]
            .as_array()
            .and_then(|events| {
                events
                    .iter()
                    .find_map(|e| e["CreatedEvent"]["contractId"].as_str())
            })
            .unwrap_or_else(|| panic!("the book's transaction names the contract: {}", made.3))
            .to_string()
    };
    let (read, other) = (book("read"), book("other"));
    let fetch = run(
        "fetch",
        json!([{"ExerciseCommand": {"templateId": "#ext-fetch:ExtFetch:Book", "contractId": read,
            "choice": "ReadAndClose", "choiceArgument": {"other": other}}}]),
        "/v2/interactive-submission/executeAndWait",
    );
    // an exercise with a subview: `Forward` on a `Hop` whose `peer2` is hosted by a second Rust node (and p1) creates a `Note` that node's
    // party observes; the second node hosts no informee of `Forward`, so the `Note` is a view of its own below the root view
    let second = crate::peer(
        "u56-vec2",
        "extsub",
        &[
            "contracts/target/sample-contract.dar",
            "contracts/fixtures/chain/target/nested-chain.dar",
        ],
    );
    let hop2 = run(
        "hop2-create",
        json!([{"CreateCommand": {"templateId": "#nested-chain:Chain:Hop",
            "createArguments": {"owner": party, "peer1": observer, "peer2": second.party, "msg": "u56 subview"}}}]),
        "/v2/interactive-submission/executeAndWaitForTransaction",
    );
    let hop2_id = hop2.3["transaction"]["events"]
        .as_array()
        .and_then(|events| {
            events
                .iter()
                .find_map(|e| e["CreatedEvent"]["contractId"].as_str())
        })
        .unwrap_or_else(|| {
            panic!(
                "the second Hop's transaction names the contract: {}",
                hop2.3
            )
        })
        .to_string();
    let forward_subview = run(
        "forward-subview",
        json!([{"ExerciseCommand": {"templateId": "#nested-chain:Chain:Hop",
            "contractId": hop2_id, "choice": "Forward", "choiceArgument": {}}}]),
        "/v2/interactive-submission/executeAndWait",
    );
    // the Rust node reads each request when it next reads events
    let seen = (0..120).any(|_| {
        if canton_participant::view_decision::external_trees::len() >= 9 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
        false
    });
    let captured = canton_participant::view_decision::external_trees::take();
    assert!(
        seen,
        "the Rust observer received the nine externally signed requests: {}",
        captured.len()
    );
    if let Ok(out) = std::env::var("U56_VECTOR_OUT") {
        std::fs::create_dir_all(&out).unwrap();
        for ((label, (prepare_body, prepared, signature, executed)), (trees, _)) in [
            ("create", &create),
            ("exercise", &exercise),
            ("hop-create", &hop),
            ("forward", &forward),
            // the two books are creates like the first: no vector of their own
            ("", &fetch),
            ("", &fetch),
            ("fetch", &fetch),
            ("", &fetch),
            ("forward-subview", &forward_subview),
        ]
        .into_iter()
        .zip(&captured)
        {
            if label.is_empty() {
                continue;
            }
            let vector = json!({
                "party": party,
                "publicKeySpki": encode_base64(spki.as_bytes()),
                "publicKeyFingerprint": fingerprint,
                "observer": observer,
                "prepareRequest": prepare_body,
                "prepareAnswer": prepared,
                "signature": signature,
                "executeAnswer": executed,
                "physicalSynchronizerId": var("CANTON_RS_EXPECT_SYNCHRONIZER"),
                "trees": trees.iter().map(|t| encode_base64(t)).collect::<Vec<_>>(),
            });
            std::fs::write(
                format!("{out}/p1-external-{label}.json"),
                serde_json::to_vec_pretty(&vector).unwrap(),
            )
            .unwrap();
        }
    }
    // the Rust node verified the parties' signatures over the hash it recomputed from each root view (U-56)
    for ((label, _), (_, verified)) in [
        ("create", ()),
        ("exercise", ()),
        ("hop-create", ()),
        ("forward", ()),
        ("book-read", ()),
        ("book-other", ()),
        ("fetch", ()),
        ("hop2-create", ()),
        ("forward-subview", ()),
    ]
    .into_iter()
    .zip(&captured)
    {
        assert_eq!(
            verified,
            &Ok(()),
            "the Rust observer verified the external authorization of the {label}"
        );
    }
}

/// The tests that keep the trees of externally signed requests (`view_decision::external_trees`, one per process) take turns.
static EXTERNAL_TREES: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// An external party onboarded on the official participant (U-56): its id, its key's fingerprint, and the signing key the test holds.
struct ExternalOnP1 {
    party: String,
    fingerprint: String,
    key: ed25519_dalek::SigningKey,
}

impl ExternalOnP1 {
    /// Generates the party's topology on p1 for a fresh Ed25519 key and allocates it with the key's signature over the onboarding multihash.
    fn onboard(hint: &str) -> Self {
        use canton_algo::prepared_hash::{decode_base64, encode_base64};
        use ed25519_dalek::{pkcs8::EncodePublicKey, SigningKey};
        use sha2::{Digest, Sha256};
        let logical_sync =
            canton_participant::multi_node::logical(&var("CANTON_RS_EXPECT_SYNCHRONIZER"));
        let seed: [u8; 32] = Sha256::digest(hint.as_bytes()).into();
        let key = SigningKey::from_bytes(&seed);
        let spki = key
            .verifying_key()
            .to_public_key_der()
            .expect("ed25519 spki");
        let (st, generated) = p1_http(
            "POST",
            "/v2/parties/external/generate-topology",
            Some(
                &json!({"synchronizer": logical_sync, "partyHint": hint, "publicKey": {
                "format": "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
                "keyData": encode_base64(spki.as_bytes()),
                "keySpec": "SIGNING_KEY_SPEC_EC_CURVE25519"}}),
            ),
        );
        assert_eq!(st, 200, "generate-topology on p1: {generated}");
        let party = generated["partyId"].as_str().expect("partyId").to_string();
        let fingerprint = generated["publicKeyFingerprint"]
            .as_str()
            .expect("fingerprint")
            .to_string();
        let mut multi_hash =
            decode_base64(generated["multiHash"].as_str().expect("multiHash")).unwrap();
        if multi_hash.len() == 32 {
            multi_hash.splice(0..0, [0x12, 0x20]);
        }
        let onboarding: Vec<serde_json::Value> = generated["topologyTransactions"]
            .as_array()
            .expect("topologyTransactions")
            .iter()
            .map(|tx| json!({"transaction": tx, "signatures": []}))
            .collect();
        let external = Self {
            party,
            fingerprint,
            key,
        };
        let (st, allocated) = p1_http(
            "POST",
            "/v2/parties/external/allocate",
            Some(
                &json!({"synchronizer": logical_sync, "onboardingTransactions": onboarding,
                "multiHashSignatures": [external.signature(&multi_hash)]}),
            ),
        );
        assert_eq!(st, 200, "external/allocate on p1: {allocated}");
        external
    }

    /// The party's signature over `payload`, as the Ledger API takes it.
    fn signature(&self, payload: &[u8]) -> serde_json::Value {
        use ed25519_dalek::Signer;
        json!({
            "format": "SIGNATURE_FORMAT_CONCAT",
            "signature": canton_algo::prepared_hash::encode_base64(&self.key.sign(payload).to_bytes()),
            "signedBy": self.fingerprint,
            "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
        })
    }
}

/// U-56 (send side): the Rust participant executes externally signed transactions (a create, `Settle` on it, a `Hop`, and `Forward` on it
/// with a `Note` below) for a party the official participant hosts. The Rust JSON
/// API prepares it, the party signs the 32-byte hash, the Rust node sends the request with the party's external authorization, and p1
/// (which hosts the party and so confirms for it) recomputes the hash and accepts the signature: the execution is approved. The Rust node,
/// which hosts the observer, receives its own request and verifies the authorization too.
#[test]
fn rust_executes_an_externally_signed_create_the_official_participant_confirms() {
    let _turn = EXTERNAL_TREES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let peer = peer(
        "u56-send",
        "extsend",
        &[
            "contracts/target/sample-contract.dar",
            "contracts/fixtures/chain/target/nested-chain.dar",
            "contracts/fixtures/extfetch/target/ext-fetch.dar",
        ],
    );
    let observer = peer.party.clone();
    // the service answers for the synchronizer its node is connected to, as the daemon sets it up
    peer.service
        .v2_state()
        .set_synchronizer_id_for_test(&canton_participant::multi_node::logical(&var(
            "CANTON_RS_EXPECT_SYNCHRONIZER",
        )));
    canton_participant::view_decision::external_trees::start();
    let external = ExternalOnP1::onboard(&unique("u56snd"));
    let party = external.party.clone();
    let call = |method: &str, path: &str, body: Option<&serde_json::Value>| {
        let r = dispatch_request(
            &peer.service,
            &HttpRequest {
                method: method.into(),
                path: path.into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: body.map_or_else(Vec::new, |b| serde_json::to_vec(b).unwrap()),
            },
        );
        (r.status, String::from_utf8_lossy(&r.body).to_string())
    };
    let (_, syncs) = call("GET", "/v2/state/connected-synchronizers", None);
    let synchronizer_id = serde_json::from_str::<serde_json::Value>(&syncs).unwrap()
        ["connectedSynchronizers"][0]["synchronizerId"]
        .as_str()
        .expect("the Rust service is connected")
        .to_string();
    // prepares `commands` on the Rust JSON API for the external party, signs the hash and executes it on the Rust node
    let run = |label: &str, commands: serde_json::Value, endpoint: &str| -> serde_json::Value {
        let prepare_body = json!({
            "commandId": unique(&format!("u56-send-{label}")), "userId": "participant_admin", "actAs": [party],
            "synchronizerId": synchronizer_id, "packageIdSelectionPreference": [], "commands": commands
        });
        // the Rust node knows the party's keys once it read the party's onboarding from the topology
        let mut prepared = serde_json::Value::Null;
        let mut last = String::new();
        for _ in 0..60 {
            let (status, body) = call(
                "POST",
                "/v2/interactive-submission/prepare",
                Some(&prepare_body),
            );
            if status == 200 {
                prepared = serde_json::from_str(&body).unwrap();
                break;
            }
            last = format!("{status} {body}");
            std::thread::sleep(Duration::from_millis(500));
        }
        let prepared_tx = prepared["preparedTransaction"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("the Rust JSON API prepared the externally signed {label}: {last}")
            })
            .to_string();
        let hash = canton_algo::prepared_hash::decode_base64(
            prepared["preparedTransactionHash"].as_str().expect("hash"),
        )
        .unwrap();
        // U-56 review R1-F3: a signature over the 34-byte multihash (the onboarding form) is refused at once, as p1 refuses it, and
        // nothing is submitted
        let multihash: Vec<u8> = [0x12, 0x20].iter().chain(hash.iter()).copied().collect();
        let multihash_body = json!({
            "preparedTransaction": prepared_tx,
            "partySignatures": {"signatures": [{"party": party, "signatures": [external.signature(&multihash)]}]},
            "submissionId": unique(&format!("u56-send-{label}-multihash")),
            "userId": "participant_admin",
            "hashingSchemeVersion": prepared["hashingSchemeVersion"],
            "deduplicationPeriod": {"Empty": {}}
        });
        let mut refused = String::new();
        for _ in 0..60 {
            refused = call("POST", endpoint, Some(&multihash_body)).1;
            if !refused.contains("Could not find party signing keys") {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        // refused by the executing participant itself, before anything is sent (a confirmer's refusal would say the same about the
        // signatures, under another code)
        assert!(
            refused.contains("FAILED_TO_EXECUTE_TRANSACTION")
                && refused.contains("Received 0 valid signatures from distinct keys (1 invalid)"),
            "a multihash signature of the {label} is refused at execution as p1 refuses it: {refused}"
        );
        let execute_body = json!({
            "preparedTransaction": prepared_tx,
            "partySignatures": {"signatures": [{"party": party, "signatures": [external.signature(&hash)]}]},
            "submissionId": unique(&format!("u56-send-{label}-submission")),
            "userId": "participant_admin",
            "hashingSchemeVersion": prepared["hashingSchemeVersion"],
            "deduplicationPeriod": {"Empty": {}}
        });
        // the keys the signatures are checked against come from the topology the node reads: until it read the party's onboarding, the
        // execution is refused before anything is submitted (as on the official participant), so it is asked again
        let (mut status, mut executed) = (0, String::new());
        for _ in 0..60 {
            (status, executed) = call("POST", endpoint, Some(&execute_body));
            if !executed.contains("Could not find party signing keys") {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        println!(
            "U56 send {label} status={status} answer={}",
            executed.chars().take(500).collect::<String>()
        );
        assert_eq!(
            status, 200,
            "the externally signed {label} the Rust node sent was approved: {executed}"
        );
        serde_json::from_str(&executed).unwrap()
    };
    let created_id = |answer: &serde_json::Value| -> String {
        answer["transaction"]["events"]
            .as_array()
            .and_then(|events| {
                events
                    .iter()
                    .find_map(|e| e["CreatedEvent"]["contractId"].as_str())
            })
            .unwrap_or_else(|| panic!("the transaction names the contract it created: {answer}"))
            .to_string()
    };
    let holding = TemplateId::asset_holding();
    let template = format!(
        "{}:{}:{}",
        holding.package_id, holding.module_name, holding.entity_name
    );
    let create = run(
        "create",
        json!([{"CreateCommand": {"templateId": template,
            "createArguments": {"bank": party, "owner": party, "auditor": observer, "assetSymbol": "USD", "amount": "1.0"}}}]),
        "/v2/interactive-submission/executeAndWaitForTransaction",
    );
    run(
        "exercise",
        json!([{"ExerciseCommand": {"templateId": template, "contractId": created_id(&create),
            "choice": "Settle", "choiceArgument": {}}}]),
        "/v2/interactive-submission/executeAndWait",
    );
    let hop = run(
        "hop-create",
        json!([{"CreateCommand": {"templateId": "#nested-chain:Chain:Hop",
            "createArguments": {"owner": party, "peer1": observer, "peer2": observer, "msg": "u56"}}}]),
        "/v2/interactive-submission/executeAndWaitForTransaction",
    );
    run(
        "forward",
        json!([{"ExerciseCommand": {"templateId": "#nested-chain:Chain:Hop", "contractId": created_id(&hop),
            "choice": "Forward", "choiceArgument": {}}}]),
        "/v2/interactive-submission/executeAndWait",
    );
    let read = run(
        "book-read",
        json!([{"CreateCommand": {"templateId": "#ext-fetch:ExtFetch:Book",
            "createArguments": {"owner": party, "watcher": observer, "title": "read"}}}]),
        "/v2/interactive-submission/executeAndWaitForTransaction",
    );
    let other = run(
        "book-other",
        json!([{"CreateCommand": {"templateId": "#ext-fetch:ExtFetch:Book",
            "createArguments": {"owner": party, "watcher": observer, "title": "other"}}}]),
        "/v2/interactive-submission/executeAndWaitForTransaction",
    );
    run(
        "fetch",
        json!([{"ExerciseCommand": {"templateId": "#ext-fetch:ExtFetch:Book", "contractId": created_id(&read),
            "choice": "ReadAndClose", "choiceArgument": {"other": created_id(&other)}}}]),
        "/v2/interactive-submission/executeAndWait",
    );
    // a subview: `Forward` on a `Hop` whose `peer2` is hosted by a second Rust node (and p1), which hosts no informee of `Forward`
    let second = crate::peer(
        "u56-send2",
        "extsend2",
        &[
            "contracts/target/sample-contract.dar",
            "contracts/fixtures/chain/target/nested-chain.dar",
        ],
    );
    let hop2 = run(
        "hop2-create",
        json!([{"CreateCommand": {"templateId": "#nested-chain:Chain:Hop",
            "createArguments": {"owner": party, "peer1": observer, "peer2": second.party, "msg": "u56 subview"}}}]),
        "/v2/interactive-submission/executeAndWaitForTransaction",
    );
    run(
        "forward-subview",
        json!([{"ExerciseCommand": {"templateId": "#nested-chain:Chain:Hop", "contractId": created_id(&hop2),
            "choice": "Forward", "choiceArgument": {}}}]),
        "/v2/interactive-submission/executeAndWait",
    );
    // the Rust node is an informee of each (it hosts the observer): it verified the authorization of its own requests
    let seen = (0..60).any(|_| {
        if canton_participant::view_decision::external_trees::len() >= 9 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
        false
    });
    let captured = canton_participant::view_decision::external_trees::take();
    assert!(
        seen,
        "the Rust node received its nine externally signed requests: {}",
        captured.len()
    );
    for (label, (_, verified)) in [
        "create",
        "exercise",
        "hop-create",
        "forward",
        "book-read",
        "book-other",
        "fetch",
        "hop2-create",
        "forward-subview",
    ]
    .into_iter()
    .zip(&captured)
    {
        assert_eq!(
            verified,
            &Ok(()),
            "the Rust node verified its own {label}'s external authorization"
        );
    }
}

/// S-SIM-001 with external parties (U-56): with traffic control on, the request cost the Rust JSON API estimates for an externally signed
/// create and exercise (built with mock signatures of the party's key, `cost_estimation::mock_external_authorization`) is what the official
/// sequencer charges for the request the Rust node then sends with the party's real signature. The base traffic is set below the request's
/// cost, so the paid request is refused with `AboveTrafficLimit` and its `trafficCost`. **It turns traffic control on for the shared
/// sandbox (and off at the end): run it alone.**
#[test]
#[ignore = "turns traffic control on for the shared sandbox; run it alone"]
fn rust_prepare_estimates_an_externally_signed_request_the_official_sequencer_charges() {
    // [CANTON-NOTE: WHY] as `rust_prepare_estimates_the_request_cost_the_official_sequencer_charges` (whose measurement set the tolerances):
    // a round may differ by 1% of the charged cost, the mean by at most 8
    const ROUNDS: usize = 6;
    // C-A1 (가): the mean difference is at most 8, compared in integers as `|sum| <= 8 * rounds` (no floats on a cost path)
    const MAX_MEAN_BIAS: i64 = 8;
    let peer = peer(
        "sim-ext",
        "simext",
        &["contracts/target/sample-contract.dar"],
    );
    let observer = peer.party.clone();
    peer.service
        .v2_state()
        .set_synchronizer_id_for_test(&canton_participant::multi_node::logical(&var(
            "CANTON_RS_EXPECT_SYNCHRONIZER",
        )));
    let external = ExternalOnP1::onboard(&unique("simext"));
    let party = external.party.clone();
    let call = |method: &str, path: &str, body: Option<&serde_json::Value>| {
        let r = dispatch_request(
            &peer.service,
            &HttpRequest {
                method: method.into(),
                path: path.into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: body.map_or_else(Vec::new, |b| serde_json::to_vec(b).unwrap()),
            },
        );
        (r.status, String::from_utf8_lossy(&r.body).to_string())
    };
    let (_, syncs) = call("GET", "/v2/state/connected-synchronizers", None);
    let synchronizer_id = serde_json::from_str::<serde_json::Value>(&syncs).unwrap()
        ["connectedSynchronizers"][0]["synchronizerId"]
        .as_str()
        .expect("the Rust service is connected")
        .to_string();
    // prepares `commands` for the external party until the node can (it knows the party once it read its onboarding): the answer
    let prepare = |label: &str, commands: &serde_json::Value| -> (String, serde_json::Value) {
        let command_id = unique(&format!("simext-{label}"));
        let body = json!({
            "commandId": command_id, "userId": "participant_admin", "actAs": [party],
            "synchronizerId": synchronizer_id, "packageIdSelectionPreference": [], "commands": commands,
            "estimateTrafficCost": {"disabled": false, "expectedSignatures": []}
        });
        let mut last = String::new();
        for _ in 0..60 {
            let (status, answer) = call("POST", "/v2/interactive-submission/prepare", Some(&body));
            if status == 200 {
                return (command_id, serde_json::from_str(&answer).unwrap());
            }
            last = format!("{status} {answer}");
            std::thread::sleep(Duration::from_millis(500));
        }
        panic!("the Rust JSON API prepared the externally signed {label}: {last}")
    };
    // signs the prepared hash and executes it: the answer (the keys come from the topology the node reads, as in `prepare`)
    let execute = |label: &str, prepared: &serde_json::Value, endpoint: &str| -> (u16, String) {
        let hash = canton_algo::prepared_hash::decode_base64(
            prepared["preparedTransactionHash"].as_str().expect("hash"),
        )
        .unwrap();
        let body = json!({
            "preparedTransaction": prepared["preparedTransaction"],
            "partySignatures": {"signatures": [{"party": party, "signatures": [external.signature(&hash)]}]},
            "submissionId": unique(&format!("simext-{label}-submission")),
            "userId": "participant_admin",
            "hashingSchemeVersion": prepared["hashingSchemeVersion"],
            "deduplicationPeriod": {"Empty": {}}
        });
        let mut answer = (0, String::new());
        for _ in 0..60 {
            answer = call("POST", endpoint, Some(&body));
            if !answer.1.contains("Could not find party signing keys") {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        answer
    };
    let holding = TemplateId::asset_holding();
    let template = format!(
        "{}:{}:{}",
        holding.package_id, holding.module_name, holding.entity_name
    );
    let create = json!([{"CreateCommand": {"templateId": template,
        "createArguments": {"bank": party, "owner": party, "auditor": observer, "assetSymbol": "USD", "amount": "1.0"}}}]);
    // the contract the exercise rounds use, created while traffic control is off; the paid exercises are refused, so it stays active
    let (_, held) = prepare("held", &create);
    let (status, made) = execute(
        "held",
        &held,
        "/v2/interactive-submission/executeAndWaitForTransaction",
    );
    assert_eq!(status, 200, "the held contract is created: {made}");
    let held_id = serde_json::from_str::<serde_json::Value>(&made).unwrap()["transaction"]
        ["events"]
        .as_array()
        .and_then(|events| {
            events
                .iter()
                .find_map(|e| e["CreatedEvent"]["contractId"].as_str())
        })
        .expect("the held contract's id")
        .to_string();
    let dir = Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    std::fs::create_dir_all(&dir).unwrap();
    let traffic = |command: &str| -> String {
        let file = format!("{}.trafficcmd", unique("simexttc"));
        std::fs::write(dir.join(format!("{file}.tmp")), command).unwrap();
        std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
        log_line_with(&["SCF trafficcmd_done=", &file], 60)
            .unwrap_or_else(|| panic!("the console never finished {command}"))
    };
    /// Turns traffic control off again however the test ends.
    struct Off<'a>(&'a dyn Fn(&str) -> String);
    impl Drop for Off<'_> {
        fn drop(&mut self) {
            println!("SIM001 traffic disable: {}", (self.0)("disable"));
        }
    }
    // 1000 bytes of base traffic: less than a confirmation request costs, more than the topology change that turns it off. The base event
    // cost is large enough (100) that an estimate leaving it out falls outside C-A1 (the master's negative control on K-02)
    let enabled = traffic("enable,1000,200,100");
    assert!(
        enabled.contains("=ok"),
        "traffic control turned on: {enabled}"
    );
    let _off = Off(&traffic);
    // the node learns the new parameters from the topology it reads; until then it estimates and pays as without traffic control
    let learned = (0..60).any(|_| {
        let (_, answer) = prepare("probe", &create);
        if answer["costEstimation"]["totalTrafficCostEstimation"]
            .as_u64()
            .is_some_and(|t| t > 0)
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
        false
    });
    assert!(learned, "the Rust node learned that traffic control is on");
    let exercise = json!([{"ExerciseCommand": {"templateId": template, "contractId": held_id,
        "choice": "Settle", "choiceArgument": {}}}]);
    let mut recorded = Vec::new();
    for (kind, commands) in [("create", &create), ("exercise", &exercise)] {
        let mut bias = 0i64;
        for round in 0..ROUNDS {
            let (_, prepared) = prepare(&format!("{kind}-{round}"), commands);
            let rust = prepared["costEstimation"]["confirmationRequestTrafficCostEstimation"]
                .as_u64()
                .unwrap_or_else(|| {
                    panic!("an estimate of the externally signed {kind}: {prepared}")
                });
            let (status, refusal) = execute(
                &format!("{kind}-{round}"),
                &prepared,
                "/v2/interactive-submission/executeAndWait",
            );
            assert!(
                refusal.contains("AboveTrafficLimit") && !refusal.contains("IncorrectEventCost"),
                "the paid externally signed {kind} is refused only for want of traffic: {status} {refusal}"
            );
            let charged: u64 = refusal
                .split("trafficCost = ")
                .nth(1)
                .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| {
                    panic!("the official sequencer names the cost: {status} {refusal}")
                });
            println!(
                "SIM001 external kind={kind} round={round} rust={rust} official-charged={charged}"
            );
            assert!(
                rust.abs_diff(charged) * 100 <= charged,
                "the externally signed {kind} estimate {rust} is within 1% of what the official sequencer charges ({charged})"
            );
            bias += rust as i64 - charged as i64;
            recorded.push(json!({"kind": kind, "rust": rust, "officialCharged": charged}));
        }
        let rounds = i64::try_from(ROUNDS).unwrap();
        println!("SIM001 external kind={kind} bias sum={bias} over {rounds} rounds");
        assert!(
            bias.abs() <= MAX_MEAN_BIAS * rounds,
            "the externally signed {kind} estimate is not biased: the differences sum to {bias} over {rounds} rounds"
        );
    }
    write_inputs(
        "K-02",
        Some(&enabled),
        json!({"p1": var("CANTON_RS_MEMBER_P1"), "rust": peer.member}),
    );
    if let Ok(out) = std::env::var("SIM_ORACLE_OUT") {
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            format!("{out}/traffic-on-rust-external-request.json"),
            serde_json::to_vec_pretty(&json!({"rounds": recorded})).unwrap(),
        )
        .unwrap();
    }
}

/// S-SIM-001 K-06 (C-A5): with traffic control on and confirmation responses free, the official participant's and the Rust JSON API's
/// estimates of an externally signed create both say the response costs nothing and the request something. **It turns traffic control on
/// for the shared sandbox (and off at the end): run it alone.**
#[test]
#[ignore = "turns traffic control on for the shared sandbox; run it alone"]
fn sim001_k06_free_confirmation_responses_cost_nothing_on_both_participants() {
    let peer = peer(
        "sim-k06",
        "simk06",
        &["contracts/target/sample-contract.dar"],
    );
    let observer = peer.party.clone();
    let logical = canton_participant::multi_node::logical(&var("CANTON_RS_EXPECT_SYNCHRONIZER"));
    peer.service
        .v2_state()
        .set_synchronizer_id_for_test(&logical);
    let external = ExternalOnP1::onboard(&unique("simk06"));
    let party = external.party;
    let dir = Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    std::fs::create_dir_all(&dir).unwrap();
    let traffic = |command: &str| -> String {
        let file = format!("{}.trafficcmd", unique("simk06tc"));
        std::fs::write(dir.join(format!("{file}.tmp")), command).unwrap();
        std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
        log_line_with(&["SCF trafficcmd_done=", &file], 60)
            .unwrap_or_else(|| panic!("the console never finished {command}"))
    };
    /// Turns traffic control off again however the test ends.
    struct Off<'a>(&'a dyn Fn(&str) -> String);
    impl Drop for Off<'_> {
        fn drop(&mut self) {
            println!("SIM001 traffic disable: {}", (self.0)("disable"));
        }
    }
    let enabled = traffic("enable,1000000,200,7,free");
    assert!(
        enabled.contains("=ok"),
        "traffic control turned on with free responses: {enabled}"
    );
    let _off = Off(&traffic);
    let holding = TemplateId::asset_holding();
    let body = |sync: &str| {
        json!({
            "commandId": unique("simk06"), "userId": "participant_admin", "actAs": [party],
            "synchronizerId": sync, "packageIdSelectionPreference": [],
            "commands": [{"CreateCommand": {
                "templateId": format!("{}:{}:{}", holding.package_id, holding.module_name, holding.entity_name),
                "createArguments": {"bank": party, "owner": party, "auditor": observer, "assetSymbol": "USD", "amount": "1.0"}}}],
            "estimateTrafficCost": {"disabled": false, "expectedSignatures": []}
        })
    };
    // both participants learn the parameters from their topology: asked until the estimate is not the one without traffic control
    let estimate_on =
        |label: &str, ask: &dyn Fn() -> (u16, serde_json::Value)| -> serde_json::Value {
            let mut last = serde_json::Value::Null;
            for _ in 0..60 {
                let (status, answer) = ask();
                if status == 200
                    && answer["costEstimation"]["confirmationRequestTrafficCostEstimation"]
                        .as_u64()
                        .is_some_and(|r| r > 0)
                {
                    println!(
                        "SIM001 K-06 {label} costEstimation={}",
                        answer["costEstimation"]
                    );
                    return answer["costEstimation"].clone();
                }
                last = answer;
                std::thread::sleep(Duration::from_millis(500));
            }
            panic!("{label} estimated with traffic control on: {last}")
        };
    let official = estimate_on("p1", &|| {
        p1_http(
            "POST",
            "/v2/interactive-submission/prepare",
            Some(&body(&logical)),
        )
    });
    let rust = estimate_on("rust", &|| {
        let r = dispatch_request(
            &peer.service,
            &HttpRequest {
                method: "POST".into(),
                path: "/v2/interactive-submission/prepare".into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: serde_json::to_vec(&body(&logical)).unwrap(),
            },
        );
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(serde_json::Value::Null),
        )
    });
    for (who, cost) in [("p1", &official), ("rust", &rust)] {
        assert_eq!(
            cost["confirmationResponseTrafficCostEstimation"].as_u64(),
            Some(0),
            "{who}: free responses cost nothing: {cost}"
        );
        assert_eq!(
            cost["totalTrafficCostEstimation"].as_u64(),
            cost["confirmationRequestTrafficCostEstimation"].as_u64(),
            "{who}: the total is the request alone: {cost}"
        );
    }
    write_inputs(
        "K-06",
        Some(&enabled),
        json!({"p1": var("CANTON_RS_MEMBER_P1"), "rust": peer.member}),
    );
    if let Ok(out) = std::env::var("SIM_ORACLE_OUT") {
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            format!("{out}/K-06.json"),
            serde_json::to_vec_pretty(&json!({"official": official, "rust": rust})).unwrap(),
        )
        .unwrap();
    }
}

/// S-SIM-001 K-04, K-09 and K-10 with an externally signed exercise that creates a contract (`Forward` on a `Hop`): with traffic control on,
/// the Rust estimate of the request is what the official sequencer charges for the request the Rust node sends (K-04); two estimates of the
/// same command differ by at most 1% (K-09: a request's size moves by a few bytes between builds, §1.4 of the plan); and many prepares
/// change neither the Rust ledger end nor p1's (K-10). **It turns traffic control on for the shared sandbox (and off at the end): run it
/// alone.**
#[test]
#[ignore = "turns traffic control on for the shared sandbox; run it alone"]
fn sim001_k04_k09_k10_nested_exercise_estimate_determinism_and_no_side_effects() {
    const PREPARES: usize = 100;
    let peer = peer(
        "sim-k04",
        "simk04",
        &[
            "contracts/target/sample-contract.dar",
            "contracts/fixtures/chain/target/nested-chain.dar",
        ],
    );
    let observer = peer.party.clone();
    let logical = canton_participant::multi_node::logical(&var("CANTON_RS_EXPECT_SYNCHRONIZER"));
    peer.service
        .v2_state()
        .set_synchronizer_id_for_test(&logical);
    let external = ExternalOnP1::onboard(&unique("simk04"));
    let party = external.party.clone();
    let call = |path: &str, body: &serde_json::Value| {
        let r = dispatch_request(
            &peer.service,
            &HttpRequest {
                method: "POST".into(),
                path: path.into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: serde_json::to_vec(body).unwrap(),
            },
        );
        (r.status, String::from_utf8_lossy(&r.body).to_string())
    };
    let prepare = |commands: &serde_json::Value| -> serde_json::Value {
        let body = json!({
            "commandId": unique("simk04"), "userId": "participant_admin", "actAs": [party],
            "synchronizerId": logical, "packageIdSelectionPreference": [], "commands": commands,
            "estimateTrafficCost": {"disabled": false, "expectedSignatures": []}
        });
        let mut last = String::new();
        for _ in 0..60 {
            let (status, answer) = call("/v2/interactive-submission/prepare", &body);
            if status == 200 {
                return serde_json::from_str(&answer).unwrap();
            }
            last = format!("{status} {answer}");
            std::thread::sleep(Duration::from_millis(500));
        }
        panic!("the Rust JSON API prepared: {last}")
    };
    let execute = |prepared: &serde_json::Value, endpoint: &str| -> (u16, String) {
        let hash = canton_algo::prepared_hash::decode_base64(
            prepared["preparedTransactionHash"].as_str().expect("hash"),
        )
        .unwrap();
        let body = json!({
            "preparedTransaction": prepared["preparedTransaction"],
            "partySignatures": {"signatures": [{"party": party, "signatures": [external.signature(&hash)]}]},
            "submissionId": unique("simk04-submission"), "userId": "participant_admin",
            "hashingSchemeVersion": prepared["hashingSchemeVersion"], "deduplicationPeriod": {"Empty": {}}
        });
        let mut answer = (0, String::new());
        for _ in 0..60 {
            answer = call(endpoint, &body);
            if !answer.1.contains("Could not find party signing keys") {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        answer
    };
    // the Hop, created while traffic control is off through p1 (prepared and executed there): no Rust `prepare` runs before K-10's first
    // observation, so a Rust `prepare` that changes state is caught by K-10 itself (review R1-F2). The paid Forward is refused later, so
    // the Hop stays active
    let p1_prepared = (0..60)
        .find_map(|_| {
            let (status, answer) = p1_http(
                "POST",
                PREPARE_PATH,
                Some(&json!({
                    "commandId": unique("simk04-hop"), "userId": "participant_admin", "actAs": [party],
                    "synchronizerId": logical, "packageIdSelectionPreference": [],
                    "commands": [{"CreateCommand": {"templateId": "#nested-chain:Chain:Hop",
                        "createArguments": {"owner": party, "peer1": observer, "peer2": observer, "msg": "k04"}}}]
                })),
            );
            if status == 200 {
                Some(answer)
            } else {
                std::thread::sleep(Duration::from_millis(500));
                None
            }
        })
        .expect("p1 prepares the Hop");
    let hop_hash = canton_algo::prepared_hash::decode_base64(
        p1_prepared["preparedTransactionHash"]
            .as_str()
            .expect("hash"),
    )
    .unwrap();
    let (st_made, made) = p1_http(
        "POST",
        "/v2/interactive-submission/executeAndWaitForTransaction",
        Some(&json!({
            "preparedTransaction": p1_prepared["preparedTransaction"],
            "partySignatures": {"signatures": [{"party": party, "signatures": [external.signature(&hop_hash)]}]},
            "submissionId": unique("simk04-hop-submission"), "userId": "participant_admin",
            "hashingSchemeVersion": p1_prepared["hashingSchemeVersion"], "deduplicationPeriod": {"Empty": {}}
        })),
    );
    assert_eq!(st_made, 200, "p1 creates the Hop: {made}");
    let hop = made["transaction"]["events"]
        .as_array()
        .and_then(|events| {
            events
                .iter()
                .find_map(|e| e["CreatedEvent"]["contractId"].as_str())
        })
        .expect("the Hop's id")
        .to_string();
    let forward = json!([{"ExerciseCommand": {"templateId": "#nested-chain:Chain:Hop", "contractId": hop,
        "choice": "Forward", "choiceArgument": {}}}]);
    let dir = Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    std::fs::create_dir_all(&dir).unwrap();
    let traffic = |command: &str| -> String {
        let file = format!("{}.trafficcmd", unique("simk04tc"));
        std::fs::write(dir.join(format!("{file}.tmp")), command).unwrap();
        std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
        log_line_with(&["SCF trafficcmd_done=", &file], 60)
            .unwrap_or_else(|| panic!("the console never finished {command}"))
    };
    /// Turns traffic control off again however the test ends.
    struct Off<'a>(&'a dyn Fn(&str) -> String);
    impl Drop for Off<'_> {
        fn drop(&mut self) {
            println!("SIM001 traffic disable: {}", (self.0)("disable"));
        }
    }
    // K-10's observations (S-SIM protocol §3.3), on the Rust node unless named: the hash of its ACS and update projections after S-DX-005
    // `norm`'s deletions (offsets, update and command ids, times, trace context; the contract and party renaming of `norm` is the identity
    // when one node is compared with itself), its ledger end, its completions, its deduplication entries, and p1's ledger end
    let observe = || -> serde_json::Value {
        use sha2::{Digest, Sha256};
        fn strip(v: &mut serde_json::Value) {
            match v {
                serde_json::Value::Object(fields) => {
                    for k in [
                        "offset",
                        "updateId",
                        "recordTime",
                        "commandId",
                        "workflowId",
                        "traceContext",
                        "synchronizerId",
                        "effectiveAt",
                        "createdAt",
                    ] {
                        fields.remove(k);
                    }
                    fields.values_mut().for_each(strip);
                }
                serde_json::Value::Array(items) => items.iter_mut().for_each(strip),
                _ => {}
            }
        }
        let end = peer.service.v2_ledger_end();
        let wildcard = json!({"cumulative": [{"identifierFilter": {"WildcardFilter": {"value": {"includeCreatedEventBlob": false}}}}]});
        let (st_acs, acs) = call(
            "/v2/state/active-contracts",
            &json!({"activeAtOffset": end, "eventFormat": {"filtersByParty": {observer.clone(): wildcard}, "verbose": true}}),
        );
        let (st_updates, updates) = call(
            "/v2/updates",
            &json!({"beginExclusive": 0, "endInclusive": end, "updateFormat": {"includeTransactions": {
                "eventFormat": {"filtersByParty": {observer.clone(): wildcard}, "verbose": true},
                "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"}}}),
        );
        assert!(
            st_acs == 200 && st_updates == 200,
            "K-10 observes the Rust ledger: {st_acs} {acs} / {st_updates} {updates}"
        );
        let mut projection: serde_json::Value = json!([
            serde_json::from_str::<serde_json::Value>(&acs).unwrap_or(serde_json::Value::Null),
            serde_json::from_str::<serde_json::Value>(&updates).unwrap_or(serde_json::Value::Null),
        ]);
        strip(&mut projection);
        json!({
            "obsHash": format!("{:x}", Sha256::digest(projection.to_string().as_bytes())),
            "rustLedgerEnd": end,
            "completions": peer.service.get_completions("participant_admin", 0).completions.len(),
            "dedupEntries": peer.service.v2_state().dedup_entry_count(),
            "p1LedgerEnd": p1_http("GET", "/v2/state/ledger-end", None).1["offset"],
        })
    };
    // the Rust node knows the Hop before the window opens (it hosts the observers), seen through its ACS, not through a prepare
    let last_acs = std::cell::RefCell::new(String::new());
    let knows_hop = (0..120).any(|_| {
        let end = peer.service.v2_ledger_end();
        let (_, acs) = call(
            "/v2/state/active-contracts",
            &json!({"activeAtOffset": end, "eventFormat": {"filtersByParty": {observer.clone(): {"cumulative": [{"identifierFilter":
                {"WildcardFilter": {"value": {"includeCreatedEventBlob": false}}}}]}}, "verbose": true}}),
        );
        let known = acs.contains(&hop);
        if !known {
            *last_acs.borrow_mut() = acs;
            std::thread::sleep(Duration::from_millis(500));
        }
        known
    });
    assert!(
        knows_hop,
        "the Rust node has the Hop {hop} p1 created; its ACS: {}",
        last_acs.borrow().chars().take(1500).collect::<String>()
    );
    let enabled = traffic("enable,1000,200,7");
    assert!(
        enabled.contains("=ok"),
        "traffic control turned on: {enabled}"
    );
    let _off = Off(&traffic);
    // the window opens after traffic control is on (turning it on is a topology change p1's ledger end counts) and before any Rust prepare
    std::thread::sleep(Duration::from_secs(3));
    let observed_before = observe();
    let request_of = |p: &serde_json::Value| {
        p["costEstimation"]["confirmationRequestTrafficCostEstimation"]
            .as_u64()
            .unwrap_or(0)
    };
    // a prepare that does not panic: inside K-10's window a failure is judged by K-10's observations, not by the prepare
    let try_prepare = |commands: &serde_json::Value| -> Option<serde_json::Value> {
        let body = json!({
            "commandId": unique("simk04"), "userId": "participant_admin", "actAs": [party],
            "synchronizerId": logical, "packageIdSelectionPreference": [], "commands": commands,
            "estimateTrafficCost": {"disabled": false, "expectedSignatures": []}
        });
        let (status, answer) = call(PREPARE_PATH, &body);
        (status == 200).then(|| serde_json::from_str(&answer).unwrap())
    };
    // the sequencer-side observation: in the Rust node's traffic state on the official sequencer, what it consumed and what it last paid
    // stay the same and its base traffic does not go down (the state's own timestamp moves even when nothing is consumed, so it is no
    // measure)
    let sequenced = || {
        let state = traffic(&format!("state,{}", peer.member));
        let field = |name: &str| -> u64 {
            state
                .split(&format!("{name} = "))
                .nth(1)
                .and_then(|rest| rest.split([',', ')']).next())
                .and_then(|n| n.trim().parse().ok())
                .unwrap_or_else(|| panic!("K-10: no {name} in the traffic state: {state}"))
        };
        (
            field("extraTrafficConsumed"),
            field("lastConsumedCost"),
            field("baseTrafficRemainder"),
        )
    };
    // R2-F1: with only 1000 bytes of base traffic a leaked request would be refused for want of traffic and consume nothing, so the
    // sequencer-side observation could not see it. During the window the Rust node has purchased extra traffic: a request a prepare
    // sent would be sequenced and paid for, which moves its last cost and its consumption. The purchase is taken back before K-04
    let limit_of = |state: &str| -> Option<u64> {
        state
            .split("extraTrafficLimit = ")
            .nth(1)?
            .split([',', ')'])
            .next()?
            .trim()
            .parse()
            .ok()
    };
    let purchase = |serial: u32, balance: u64| {
        let answer = traffic(&format!("set,{},{serial},{balance}", peer.member));
        assert!(
            answer.contains("=ok"),
            "the purchase {serial} of {balance} is set: {answer}"
        );
        let in_force = (0..60).any(|_| {
            let limit = limit_of(&traffic(&format!("state,{}", peer.member)));
            if limit != Some(balance) {
                std::thread::sleep(Duration::from_millis(500));
            }
            limit == Some(balance)
        });
        assert!(in_force, "the purchase {serial} of {balance} is in force");
    };
    purchase(1, 1_000_000);
    let sequenced_before = sequenced();
    let learned = (0..60).any(|_| {
        if try_prepare(&forward).is_some_and(|p| request_of(&p) > 0) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
        false
    });
    let estimates: Vec<Option<u64>> = (0..PREPARES)
        .map(|_| try_prepare(&forward).map(|p| request_of(&p)))
        .collect();
    let sequenced_after = sequenced();
    let observed_after = observe();
    println!("SIM001 K-10 observed before={observed_before} after={observed_after}");
    println!(
        "SIM001 K-10 traffic state of the Rust node (consumed, last cost, base remainder) before={sequenced_before:?} after={sequenced_after:?}"
    );
    let k10 = json!({"before": observed_before, "after": observed_after,
        "sequencerBefore": [sequenced_before.0, sequenced_before.1, sequenced_before.2],
        "sequencerAfter": [sequenced_after.0, sequenced_after.1, sequenced_after.2]});
    if let Ok(out) = std::env::var("SIM_ORACLE_OUT") {
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            format!("{out}/K-10.json"),
            serde_json::to_vec_pretty(&k10).unwrap(),
        )
        .unwrap();
    }
    assert!(
        sequenced_after.0 == sequenced_before.0
            && sequenced_after.1 == sequenced_before.1
            && sequenced_after.2 >= sequenced_before.2,
        "K-10: the official sequencer sequenced nothing the Rust node paid for during the prepares: {sequenced_before:?} -> {sequenced_after:?}"
    );
    assert_eq!(
        observed_after, observed_before,
        "K-10: the ledgers, completions and deduplication entries are as they were after {PREPARES} prepares"
    );
    // K-04 needs the paid request refused for want of traffic (its refusal names the charge): the purchase is taken back
    purchase(2, 0);
    assert!(learned, "the Rust node learned that traffic control is on");
    let estimates: Vec<u64> = estimates
        .into_iter()
        .map(|e| e.expect("every prepare of Forward answers"))
        .collect();
    // P3 (master S-SIM-001 premise, review R1-F3): the official estimate of the same command in the same state, 100 times
    let p1_estimates: Vec<u64> = (0..PREPARES)
        .map(|_| {
            let (status, answer) = p1_http(
                "POST",
                PREPARE_PATH,
                Some(&json!({
                    "commandId": unique("simk04-p3"), "userId": "participant_admin", "actAs": [party],
                    "synchronizerId": logical, "packageIdSelectionPreference": [], "commands": forward,
                    "estimateTrafficCost": {"disabled": false, "expectedSignatures": []}
                })),
            );
            assert_eq!(status, 200, "p1 prepares Forward: {answer}");
            request_of(&answer)
        })
        .collect();
    let (p1_lo, p1_hi) = (
        *p1_estimates.iter().min().unwrap(),
        *p1_estimates.iter().max().unwrap(),
    );
    println!("SIM001 P3 {PREPARES} official estimates of Forward: min={p1_lo} max={p1_hi}");
    // K-09: the estimates of one command agree within 1%
    let (lo, hi) = (
        *estimates.iter().min().unwrap(),
        *estimates.iter().max().unwrap(),
    );
    println!("SIM001 K-09 {PREPARES} estimates of Forward: min={lo} max={hi}");
    // C-A8 (R2-F2): the spread is at most twice the official spread measured in the same run (P3) and within 1% of the least
    assert!(
        (hi - lo) * 100 <= lo && hi - lo <= 2 * (p1_hi - p1_lo),
        "K-09: the estimates of one command spread {lo}..{hi}, more than 1% or twice the official {p1_lo}..{p1_hi}"
    );
    // K-04: the estimate is what the official sequencer charges for the request the Rust node sends
    let prepared = prepare(&forward);
    let rust = request_of(&prepared);
    let (status, refusal) = execute(&prepared, "/v2/interactive-submission/executeAndWait");
    assert!(
        refusal.contains("AboveTrafficLimit") && !refusal.contains("IncorrectEventCost"),
        "the paid Forward is refused only for want of traffic: {status} {refusal}"
    );
    let charged: u64 = refusal
        .split("trafficCost = ")
        .nth(1)
        .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse().ok())
        .expect("the official sequencer names the cost");
    println!("SIM001 K-04 Forward rust={rust} official-charged={charged}");
    assert!(
        rust.abs_diff(charged) * 100 <= charged,
        "K-04: {rust} is within 1% of {charged}"
    );
    write_inputs(
        "K-04-K-09-K-10",
        Some(&enabled),
        json!({"p1": var("CANTON_RS_MEMBER_P1"), "rust": peer.member}),
    );
    if let Ok(out) = std::env::var("SIM_ORACLE_OUT") {
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            format!("{out}/K-04-K-09-K-10.json"),
            serde_json::to_vec_pretty(
                &json!({"k04": {"rust": rust, "officialCharged": charged}, "k09": estimates, "p3Official": p1_estimates,
                "k10": k10}),
            )
            .unwrap(),
        )
        .unwrap();
    }
}

/// S-SIM-001 K-03 (C-A6) and K-05: the official participant and the Rust JSON API estimate an externally signed create for the same party.
/// The participants differ, so their estimates do not; what one change of the command adds must not differ: an observer moved to a party a
/// further participant hosts (K-03, which must make the request dearer), and three ECDSA signatures named in `expectedSignatures` (K-05).
/// Each estimate is the least of several (a request's size moves by a few bytes between builds). **It turns traffic control on for the
/// shared sandbox (and off at the end): run it alone.**
#[test]
#[ignore = "turns traffic control on for the shared sandbox; run it alone"]
fn sim001_k03_k05_what_a_change_adds_is_what_it_adds_on_the_official_participant() {
    let peer = peer(
        "sim-k03",
        "simk03",
        &["contracts/target/sample-contract.dar"],
    );
    let observer = peer.party.clone();
    let other = crate::peer(
        "sim-k03b",
        "simk03b",
        &["contracts/target/sample-contract.dar"],
    );
    let logical = canton_participant::multi_node::logical(&var("CANTON_RS_EXPECT_SYNCHRONIZER"));
    peer.service
        .v2_state()
        .set_synchronizer_id_for_test(&logical);
    let external = ExternalOnP1::onboard(&unique("simk03"));
    let party = external.party.clone();
    let dir = Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    std::fs::create_dir_all(&dir).unwrap();
    let traffic = |command: &str| -> String {
        let file = format!("{}.trafficcmd", unique("simk03tc"));
        std::fs::write(dir.join(format!("{file}.tmp")), command).unwrap();
        std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
        log_line_with(&["SCF trafficcmd_done=", &file], 60)
            .unwrap_or_else(|| panic!("the console never finished {command}"))
    };
    /// Turns traffic control off again however the test ends.
    struct Off<'a>(&'a dyn Fn(&str) -> String);
    impl Drop for Off<'_> {
        fn drop(&mut self) {
            println!("SIM001 traffic disable: {}", (self.0)("disable"));
        }
    }
    // K-03 (가) first: at a read-vs-write scaling factor of 10000 every recipient of an envelope costs as much as writing it, so a recipient
    // counted wrongly moves the estimate far from what the official sequencer charges (at 200 a recipient is about 2% of a view's size, inside
    // the C-A1 tolerances). 1000 bytes of base traffic: less than the request costs, so the paid request is refused and the refusal names
    // the charge
    let enabled_high = traffic("enable,1000,10000,7");
    assert!(
        enabled_high.contains("=ok"),
        "traffic control turned on: {enabled_high}"
    );
    let _off = Off(&traffic);
    let holding = TemplateId::asset_holding();
    let body = |auditor: &str, hints: serde_json::Value| {
        json!({
            "commandId": unique("simk03"), "userId": "participant_admin", "actAs": [party],
            "synchronizerId": logical, "packageIdSelectionPreference": [],
            "commands": [{"CreateCommand": {
                "templateId": format!("{}:{}:{}", holding.package_id, holding.module_name, holding.entity_name),
                "createArguments": {"bank": party, "owner": party, "auditor": auditor, "assetSymbol": "USD", "amount": "1.0"}}}],
            "estimateTrafficCost": hints
        })
    };
    let ask_p1 =
        |b: &serde_json::Value| p1_http("POST", "/v2/interactive-submission/prepare", Some(b));
    let ask_rust = |b: &serde_json::Value| {
        let r = dispatch_request(
            &peer.service,
            &HttpRequest {
                method: "POST".into(),
                path: "/v2/interactive-submission/prepare".into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: serde_json::to_vec(b).unwrap(),
            },
        );
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(serde_json::Value::Null),
        )
    };
    // the least request estimate of several asks, once the participant estimates with traffic control on
    let least = |ask: &dyn Fn(&serde_json::Value) -> (u16, serde_json::Value),
                 auditor: &str,
                 hints: serde_json::Value|
     -> u64 {
        let mut seen = Vec::new();
        for _ in 0..120 {
            let (status, answer) = ask(&body(auditor, hints.clone()));
            if let Some(r) = answer["costEstimation"]["confirmationRequestTrafficCostEstimation"]
                .as_u64()
                .filter(|r| status == 200 && *r > 0)
            {
                seen.push(r);
                if seen.len() == 5 {
                    break;
                }
            } else {
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        *seen
            .iter()
            .min()
            .unwrap_or_else(|| panic!("an estimate with traffic control on for auditor {auditor}"))
    };
    let plain = json!({"disabled": false, "expectedSignatures": []});
    let ecdsa = json!({"disabled": false, "expectedSignatures": [
        "SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256", "SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256", "SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256"]});
    let call_rust = |path: &str, body: &serde_json::Value| {
        let r = dispatch_request(
            &peer.service,
            &HttpRequest {
                method: "POST".into(),
                path: path.into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: serde_json::to_vec(body).unwrap(),
            },
        );
        (r.status, String::from_utf8_lossy(&r.body).to_string())
    };
    const CHARGED_ROUNDS: usize = 3;
    let mut charged_rounds = Vec::new();
    for round in 0..CHARGED_ROUNDS {
        let (prepared, rust) = (0..120)
            .find_map(|_| {
                let (status, answer) = ask_rust(&body(&other.party, plain.clone()));
                let estimate =
                    answer["costEstimation"]["confirmationRequestTrafficCostEstimation"].as_u64();
                // the parameters reach the Rust node some time after the proposal: a request this size costs well over 5000 at 10000
                match estimate.filter(|r| status == 200 && *r > 5000) {
                    Some(r) => Some((answer, r)),
                    None => {
                        std::thread::sleep(Duration::from_millis(500));
                        None
                    }
                }
            })
            .expect("the Rust node estimates with the scaling factor of 10000");
        let hash = canton_algo::prepared_hash::decode_base64(
            prepared["preparedTransactionHash"].as_str().expect("hash"),
        )
        .unwrap();
        let execute = json!({
            "preparedTransaction": prepared["preparedTransaction"],
            "partySignatures": {"signatures": [{"party": party, "signatures": [external.signature(&hash)]}]},
            "submissionId": unique("simk03-submission"), "userId": "participant_admin",
            "hashingSchemeVersion": prepared["hashingSchemeVersion"], "deduplicationPeriod": {"Empty": {}}
        });
        let mut refusal = String::new();
        for _ in 0..60 {
            refusal = call_rust("/v2/interactive-submission/executeAndWait", &execute).1;
            if !refusal.contains("Could not find party signing keys") {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        assert!(
            refusal.contains("AboveTrafficLimit") && !refusal.contains("IncorrectEventCost"),
            "K-03 (가): the paid request is refused only for want of traffic: {refusal}"
        );
        let charged: u64 = refusal
            .split("trafficCost = ")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse().ok())
            .expect("the official sequencer names the cost");
        println!("SIM001 K-03 (가) round={round} rust={rust} official-charged={charged}");
        charged_rounds.push(json!({"rust": rust, "officialCharged": charged}));
        assert!(
            rust.abs_diff(charged) * 100 <= charged,
            "K-03 (가): the estimate {rust} of a request to a further participant is within 1% of what the official sequencer charges ({charged})"
        );
    }
    // K-03 (나), K-05: what a change adds, compared at 200. At 10000 it is no measure: the two executing participants start from different
    // recipients (p1 alone for p1, p1 and the Rust node for the Rust node: the executing participant's admin party confirms the root views,
    // `TransactionViewDecompositionFactory.informeesParticipantsAndThreshold`), so what a larger view adds is multiplied by different counts
    let enabled = traffic("enable,1000000,200,7");
    assert!(
        enabled.contains("=ok"),
        "traffic control turned to 200: {enabled}"
    );
    let at_200 = |ask: &dyn Fn(&serde_json::Value) -> (u16, serde_json::Value)| {
        (0..120).any(|_| {
            let (status, answer) = ask(&body(&party, plain.clone()));
            let low = answer["costEstimation"]["confirmationRequestTrafficCostEstimation"]
                .as_u64()
                .is_some_and(|r| status == 200 && r > 0 && r < 5000);
            if !low {
                std::thread::sleep(Duration::from_millis(500));
            }
            low
        })
    };
    assert!(
        at_200(&ask_p1) && at_200(&ask_rust),
        "both participants estimate with the scaling factor of 200"
    );
    let mut deltas = serde_json::Map::new();
    // K-03: the base command's observer is the party itself (hosted by p1 alone); the changed one's is a party a participant other than the
    // executing one also hosts, which adds exactly one participant to the request's recipients: the Rust node's party for p1, the second
    // Rust node's for the Rust node
    for (who, ask, further) in [
        (
            "p1",
            &ask_p1 as &dyn Fn(&serde_json::Value) -> (u16, serde_json::Value),
            observer.as_str(),
        ),
        ("rust", &ask_rust, other.party.as_str()),
    ] {
        let base = least(ask, &party, plain.clone());
        let elsewhere = least(ask, further, plain.clone());
        let hinted = least(ask, &party, ecdsa.clone());
        println!("SIM001 K-03/K-05 {who}: base={base} observer-elsewhere={elsewhere} three-ecdsa={hinted}");
        assert!(
            elsewhere > base,
            "K-03 (C-A6) {who}: an observer on a further participant makes the request dearer"
        );
        deltas.insert(who.into(), json!({"base": base, "k03": elsewhere as i64 - base as i64, "k05": hinted as i64 - base as i64}));
    }
    // the raw values and the inputs are written before they are judged, so a failing run leaves its evidence
    write_inputs(
        "K-03-K-05",
        Some(&format!("{enabled_high} | {enabled}")),
        json!({"p1": var("CANTON_RS_MEMBER_P1"), "rust": peer.member, "furtherRust": other.member}),
    );
    deltas.insert("k03Charged".into(), json!(charged_rounds));
    if let Ok(out) = std::env::var("SIM_ORACLE_OUT") {
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            format!("{out}/K-03-K-05.json"),
            serde_json::to_vec_pretty(&deltas).unwrap(),
        )
        .unwrap();
    }
    // U-57: the root hash message goes in one envelope to every participant's group, as the official request sends it, so what an
    // observer on a further participant adds is the same on both
    let mut differ = Vec::new();
    for case in ["k03", "k05"] {
        let (official, rust) = (
            deltas["p1"][case].as_i64().unwrap(),
            deltas["rust"][case].as_i64().unwrap(),
        );
        println!("SIM001 {case} adds p1={official} rust={rust}");
        if (rust - official).abs() > 20.max(official.abs() / 10) {
            differ.push(format!("{case}: what the change adds on Rust ({rust}) is not what it adds on p1 ({official})"));
        }
    }
    assert!(differ.is_empty(), "{}", differ.join("; "));
}

/// R-14 / A-8 parity oracle: allocates 1 party on official `p1` and 1 on Rust `ExecutionService` and compares
/// exact update/event counts, event kind, `participantPermission`, bare `participantId` (no `PAR::`), and `synchronizerId`.
#[test]
fn topology_transaction_stream_matches_official_canton_p1() {
    use std::collections::BTreeSet;
    let p1_ledger_end = || {
        let (st, json) = p1_http("GET", "/v2/state/ledger-end", None);
        assert_eq!(st, 200, "p1 /v2/state/ledger-end: {json}");
        json["offset"]
            .as_u64()
            .or_else(|| json["offset"].as_str()?.parse().ok())
            .unwrap_or_else(|| panic!("p1 ledger-end offset: {json}"))
    };

    let p1_before = p1_ledger_end();
    let p1_hint = unique("r14-p1");
    let (st_p1_alloc, alloc_p1) = p1_http(
        "POST",
        "/v2/parties",
        Some(&json!({ "partyIdHint": p1_hint })),
    );
    assert_eq!(st_p1_alloc, 200, "p1 POST /v2/parties: {alloc_p1}");
    let p1_party = alloc_p1["partyDetails"]["party"]
        .as_str()
        .expect("p1 allocated party")
        .to_string();
    let p1_after = p1_ledger_end();
    assert!(
        p1_after > p1_before,
        "p1 party allocation must advance ledger end: before={p1_before}, after={p1_after}"
    );

    let p1_topo_req = json!({
        "beginExclusive": p1_before,
        "endInclusive": p1_after,
        "updateFormat": {
            "includeTopologyEvents": {
                "includeParticipantAuthorizationEvents": { "parties": [p1_party] }
            }
        }
    });
    let (p1_status, p1_updates) = p1_http("POST", "/v2/updates", Some(&p1_topo_req));
    assert_eq!(p1_status, 200, "p1 /v2/updates: {p1_updates}");
    let p1_arr = p1_updates
        .as_array()
        .unwrap_or_else(|| panic!("p1 updates array: {p1_updates}"));
    let p1_matching_topos: Vec<&serde_json::Value> = p1_arr
        .iter()
        .filter_map(|u| u.pointer("/update/TopologyTransaction/value"))
        .collect();
    assert_eq!(
        p1_matching_topos.len(),
        1,
        "1 party allocation on p1 must emit exactly 1 TopologyTransaction update for {p1_party}: {p1_updates}"
    );
    let p1_topo = p1_matching_topos[0];
    let p1_events = p1_topo["events"].as_array().expect("p1 events array");
    assert_eq!(
        p1_events.len(),
        1,
        "1 party allocation on p1 must emit exactly 1 authorization event: {p1_topo}"
    );
    let p1_added = p1_events[0]
        .pointer("/event/ParticipantAuthorizationAdded/value")
        .unwrap_or_else(|| panic!("expected ParticipantAuthorizationAdded on p1: {p1_topo}"));

    let svc = ExecutionService::new();
    let expected_sync = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let logical_sync = canton_participant::multi_node::logical(&expected_sync);
    svc.v2_state().set_synchronizer_id_for_test(&logical_sync);
    let rust_before = svc.v2_ledger_end();
    let (st_alloc, alloc_resp) = post(&svc, "/v2/parties", &json!({ "partyIdHint": "parity" }));
    assert_eq!(st_alloc, 200, "{alloc_resp}");
    let rust_parity_party = alloc_resp["partyDetails"]["party"]
        .as_str()
        .expect("allocated parity party")
        .to_string();
    let rust_after = svc.v2_ledger_end();
    assert!(
        rust_after > rust_before,
        "single party allocation on Rust must advance ledger_end: before={rust_before}, after={rust_after}"
    );
    let rust_topo_req = json!({
        "beginExclusive": rust_before,
        "endInclusive": rust_after,
        "updateFormat": {
            "includeTopologyEvents": {
                "includeParticipantAuthorizationEvents": { "parties": [] }
            }
        }
    });
    let (rust_status, rust_updates) = post(&svc, "/v2/updates", &rust_topo_req);
    assert_eq!(rust_status, 200, "{rust_updates}");
    let rust_arr = rust_updates.as_array().expect("rust updates array");
    assert_eq!(
        rust_arr.len(),
        1,
        "1 party allocation on Rust must emit exactly 1 TopologyTransaction update: {rust_updates}"
    );
    let rust_topo = rust_arr[0]
        .pointer("/update/TopologyTransaction/value")
        .unwrap_or_else(|| panic!("Rust missing TopologyTransaction: {rust_updates}"));
    let rust_events = rust_topo["events"].as_array().expect("rust events array");
    assert_eq!(
        rust_events.len(),
        1,
        "1 party allocation on Rust must emit exactly 1 authorization event: {rust_topo}"
    );
    let rust_added = rust_events[0]
        .pointer("/event/ParticipantAuthorizationAdded/value")
        .unwrap_or_else(|| panic!("expected ParticipantAuthorizationAdded on Rust: {rust_topo}"));

    let keys_of = |v: &serde_json::Value| -> BTreeSet<String> {
        v.as_object()
            .expect("JSON object for key parity check")
            .keys()
            .cloned()
            .collect()
    };
    assert_eq!(
        keys_of(rust_topo),
        keys_of(p1_topo),
        "TopologyTransaction value keys: rust={rust_topo} vs p1={p1_topo}"
    );
    assert_eq!(
        keys_of(rust_added),
        keys_of(p1_added),
        "ParticipantAuthorizationAdded keys: rust={rust_added} vs p1={p1_added}"
    );
    assert_eq!(
        rust_added["partyId"].as_str(),
        Some(rust_parity_party.as_str())
    );
    assert_eq!(p1_added["partyId"].as_str(), Some(p1_party.as_str()));
    assert_eq!(
        p1_added["participantPermission"],
        json!("PARTICIPANT_PERMISSION_SUBMISSION"),
        "p1 permission: {p1_added}"
    );
    assert_eq!(
        rust_added["participantPermission"], p1_added["participantPermission"],
        "permission enum value parity: rust={rust_added} vs p1={p1_added}"
    );

    // Per Member.scala:467-477 & TopologyTransactionDiff.scala:181, participantId is bare UID (no `PAR::`).
    let rust_pid = rust_added["participantId"]
        .as_str()
        .expect("rust participantId");
    let p1_pid = p1_added["participantId"]
        .as_str()
        .expect("p1 participantId");
    let expected_p1_uid = var("CANTON_RS_MEMBER_P1");
    let expected_p1_bare = expected_p1_uid
        .strip_prefix("PAR::")
        .unwrap_or(&expected_p1_uid);
    assert!(
        !p1_pid.starts_with("PAR::") && p1_pid.contains("::1220"),
        "p1 participantId must be bare UID without PAR::: {p1_pid}"
    );
    assert_eq!(p1_pid, expected_p1_bare);
    assert!(
        !rust_pid.starts_with("PAR::") && rust_pid.contains("::1220"),
        "rust participantId must be bare UID without PAR::: {rust_pid}"
    );
    assert_eq!(rust_pid, svc.participant_id());

    let p1_sync = p1_topo["synchronizerId"]
        .as_str()
        .expect("p1 synchronizerId");
    let rust_sync = rust_topo["synchronizerId"]
        .as_str()
        .expect("rust synchronizerId");
    assert!(
        !p1_sync.is_empty()
            && p1_sync.contains("::1220")
            && (p1_sync == logical_sync || p1_sync == expected_sync),
        "p1 synchronizerId format mismatch: p1={p1_sync}, logical={logical_sync}"
    );
    assert_eq!(rust_sync, logical_sync, "rust synchronizerId: {rust_topo}");

    // Negative control: omitting includeTopologyEvents omits TopologyTransaction on both p1 and Rust.
    let no_topo_for = |party: &str, begin: u64, end: u64| {
        json!({
            "beginExclusive": begin,
            "endInclusive": end,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": {
                        "filtersByParty": {
                            party: {
                                "cumulative": [{
                                    "identifierFilter": {
                                        "WildcardFilter": {
                                            "value": { "includeCreatedEventBlob": false }
                                        }
                                    }
                                }]
                            }
                        }
                    },
                    "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
                }
            }
        })
    };
    let alice = var("CANTON_RS_ALICE");
    for (who, (st, resp)) in [
        (
            "p1",
            p1_http(
                "POST",
                "/v2/updates",
                Some(&no_topo_for(&alice, 0, p1_after)),
            ),
        ),
        (
            "rust",
            post(
                &svc,
                "/v2/updates",
                &no_topo_for(&rust_parity_party, 0, rust_after),
            ),
        ),
    ] {
        assert_eq!(st, 200, "{who}: {resp}");
        assert!(
            !resp
                .as_array()
                .expect("updates response array")
                .iter()
                .any(|u| u.pointer("/update/TopologyTransaction").is_some()),
            "{who} leaked TopologyTransaction when omitted: {resp}"
        );
    }
}

/// R-5 parity oracle: uploads an upgrade v1 DAR with an extra `Color` enum to both official `p1` and Rust,
/// then compares `POST /v2/dars/validate` status and error code for both a compatible and an incompatible DAR.
#[test]
fn r5_validate_dar_matches_official_canton_p1() {
    use lf_archive::proto::daml_lf::{archive_payload::Sum, Archive, ArchivePayload, HashFunction};
    use lf_archive::proto::daml_lf_2::{def_data_type, DefDataType, InternedDottedName};
    use prost::Message;

    fn crc32(data: &[u8]) -> u32 {
        let mut c = !0u32;
        for &b in data {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
        }
        !c
    }

    fn stored_zip(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        let u16le = |v: usize| u16::try_from(v).expect("u16").to_le_bytes();
        let u32le = |v: usize| u32::try_from(v).expect("u32").to_le_bytes();
        let (mut out, mut central) = (Vec::new(), Vec::new());
        for (name, data) in entries {
            let offset = out.len();
            let crc = crc32(data).to_le_bytes();
            let common = [
                &[20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0][..],
                &crc,
                &u32le(data.len()),
                &u32le(data.len()),
            ]
            .concat();
            out.extend([0x50, 0x4b, 0x03, 0x04]);
            out.extend(&common);
            out.extend(u16le(name.len()));
            out.extend([0, 0]);
            out.extend(name.as_bytes());
            out.extend(data);
            central.extend([0x50, 0x4b, 0x01, 0x02, 20, 0]);
            central.extend(&common);
            central.extend(u16le(name.len()));
            central.extend([0; 12]);
            central.extend(u32le(offset));
            central.extend(name.as_bytes());
        }
        let central_offset = out.len();
        out.extend(&central);
        out.extend([0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0]);
        out.extend(u16le(entries.len()));
        out.extend(u16le(entries.len()));
        out.extend(u32le(central.len()));
        out.extend(u32le(central_offset));
        out.extend([0, 0]);
        out
    }

    let v1_path = dar("tests/oracle/upgrade/upg-1.0.0.dar");
    let v1_bytes = std::fs::read(&v1_path).expect("read upg-1.0.0.dar");
    let v1_dar = lf_archive::load_dar_file(&v1_path).expect("load upg-1.0.0.dar");
    let main = v1_dar.archive.main_package_id.clone();
    let mut edited = false;
    let mut entries = Vec::new();
    for (id, archive, payload) in lf_archive::dalf_entries(&v1_bytes).expect("dalf entries") {
        if id != main {
            entries.push((format!("{id}.dalf"), archive));
            continue;
        }
        let mut payload = ArchivePayload::decode(payload.as_slice()).expect("decode payload");
        let mut pkg = v1_dar.packages[&main].clone();
        if !edited {
            edited = true;
            let mut intern = |s: &str| {
                pkg.interned_strings.push(s.to_string());
                i32::try_from(pkg.interned_strings.len() - 1).expect("intern idx")
            };
            let name = intern("Color");
            let cons = vec![intern("Red"), intern("Blue")];
            pkg.interned_dotted_names.push(InternedDottedName {
                segments_interned_str: vec![name],
            });
            let name_idx = i32::try_from(pkg.interned_dotted_names.len() - 1).expect("name idx");
            pkg.modules[0].data_types.push(DefDataType {
                name_interned_dname: name_idx,
                serializable: true,
                data_cons: Some(def_data_type::DataCons::Enum(
                    def_data_type::EnumConstructors {
                        constructors_interned_str: cons,
                    },
                )),
                ..Default::default()
            });
        }
        payload.sum = Some(Sum::DamlLf2(pkg.encode_to_vec()));
        let encoded_payload = payload.encode_to_vec();
        let new_archive = Archive {
            hash_function: HashFunction::Sha256 as i32,
            hash: lf_archive::compute_sha256(&encoded_payload),
            payload: encoded_payload,
        };
        entries.insert(0, ("main.dalf".to_string(), new_archive.encode_to_vec()));
    }
    fn wrap_manifest_line(line: &str) -> String {
        let mut out = String::new();
        let mut start = 0;
        let mut first = true;
        while start < line.len() {
            let max = if first { 70 } else { 69 };
            let end = (start + max).min(line.len());
            if !first {
                out.push(' ');
            }
            out.push_str(&line[start..end]);
            out.push_str("\r\n");
            start = end;
            first = false;
        }
        out
    }
    let dalf_names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    let manifest = format!(
        "Manifest-Version: 1.0\r\nCreated-By: damlc\r\nName: upg-1.0.0\r\nSdk-Version: 3.7.0\r\n{}{}Format: daml-lf\r\nEncryption: non-encrypted\r\n",
        wrap_manifest_line("Main-Dalf: main.dalf"),
        wrap_manifest_line(&format!("Dalfs: {}", dalf_names.join(", "))),
    );
    entries.insert(0, ("META-INF/MANIFEST.MF".into(), manifest.into_bytes()));
    let v1_with_color = stored_zip(&entries);
    let v2_bytes =
        std::fs::read(dar("tests/oracle/upgrade/upg-2.0.0.dar")).expect("read upg-2.0.0.dar");

    let svc = ExecutionService::new();
    let rust_raw = |method: &str, path: &str, bytes: Vec<u8>| {
        let resp = dispatch_request(
            &svc,
            &HttpRequest {
                method: method.into(),
                path: path.into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: bytes,
            },
        );
        let parsed: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or(
            serde_json::Value::String(String::from_utf8_lossy(&resp.body).to_string()),
        );
        (resp.status, parsed)
    };

    let (st_r_up, body_r_up) = rust_raw("POST", "/v2/dars", v1_with_color.clone());
    assert_eq!(st_r_up, 200, "Rust upload v1_with_color: {body_r_up}");
    let (st_p1_up, body_p1_up) = p1_http_bytes(
        "POST",
        "/v2/dars",
        Some("application/octet-stream"),
        &v1_with_color,
    );
    assert_eq!(st_p1_up, 200, "p1 upload v1_with_color: {body_p1_up}");

    // Negative control: validate incompatible upg-2.0.0.dar against vetted v1_with_color lineage.
    let (st_r_bad, body_r_bad) = rust_raw("POST", "/v2/dars/validate", v2_bytes.clone());
    let (st_p1_bad, body_p1_bad) = p1_http_bytes(
        "POST",
        "/v2/dars/validate",
        Some("application/octet-stream"),
        &v2_bytes,
    );
    assert_eq!(
        st_p1_bad, 400,
        "p1 /v2/dars/validate bad DAR: {body_p1_bad}"
    );
    assert_eq!(
        st_r_bad, st_p1_bad,
        "status parity: rust={body_r_bad} vs p1={body_p1_bad}"
    );
    assert_eq!(
        body_p1_bad["code"],
        json!("NOT_VALID_UPGRADE_PACKAGE"),
        "p1 code: {body_p1_bad}"
    );
    assert_eq!(
        body_r_bad["code"], body_p1_bad["code"],
        "error code parity: rust={body_r_bad} vs p1={body_p1_bad}"
    );

    // Positive control: validating compatible v1_with_color succeeds with 200 on both.
    let (st_r_ok, body_r_ok) = rust_raw("POST", "/v2/dars/validate", v1_with_color.clone());
    let (st_p1_ok, body_p1_ok) = p1_http_bytes(
        "POST",
        "/v2/dars/validate",
        Some("application/octet-stream"),
        &v1_with_color,
    );
    assert_eq!(
        st_p1_ok, 200,
        "p1 /v2/dars/validate compatible DAR: {body_p1_ok}"
    );
    assert_eq!(
        st_r_ok, st_p1_ok,
        "positive validate parity: rust={body_r_ok} vs p1={body_p1_ok}"
    );
}

/// R-14 parity oracle (beyond simple `Added`): exercises `Changed`, unilateral `Proposal` (must NOT emit
/// `TopologyTransaction`), `Revoked`, and external party onboarding (`/v2/parties/external/{generate-topology,allocate}`)
/// against live official Canton 3.7.2 `p1` and Rust `ExecutionService` (including R-7 physical->logical normalization).
#[test]
fn r14_topology_change_revoke_proposal_and_external_party_match_official_canton_p1() {
    use std::collections::BTreeSet;

    use canton_proto::com::digitalasset::canton::crypto::v30::{
        Signature, SignatureFormat, SigningAlgorithmSpec,
    };
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        enums::{ParticipantPermission, TopologyChangeOp},
        party_to_participant::HostingParticipant,
        topology_mapping::Mapping,
        PartyToParticipant, SignedTopologyTransaction, TopologyMapping, TopologyTransaction,
    };
    use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
    use ledger_json_api::admin_state::{
        add_topology_txs_in_store, authorize_party_to_participant_in_store,
    };
    use prost::Message as _;

    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let b64_encode = |data: &[u8]| -> String {
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            out.push(B64[(b[0] >> 2) as usize] as char);
            out.push(B64[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
            out.push(if chunk.len() > 1 {
                B64[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                B64[(b[2] & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        out
    };
    let b64_decode = |s: &str| -> Vec<u8> {
        let idx = |c: u8| -> u8 { B64.iter().position(|&x| x == c).unwrap_or(0) as u8 };
        let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        let mut out = Vec::new();
        for chunk in clean.chunks(4) {
            if chunk.len() < 4 {
                break;
            }
            let (a, b, c, d) = (idx(chunk[0]), idx(chunk[1]), idx(chunk[2]), idx(chunk[3]));
            out.push((a << 2) | (b >> 4));
            if chunk[2] != b'=' {
                out.push((b << 4) | (c >> 2));
            }
            if chunk[3] != b'=' {
                out.push((c << 6) | d);
            }
        }
        out
    };
    let signed_ptp = |party: &str,
                      participant_uid: &str,
                      perm: i32,
                      serial: u32,
                      op: TopologyChangeOp,
                      proposal: bool|
     -> Vec<u8> {
        let mapping = PartyToParticipant {
            party: party.to_string(),
            threshold: 1,
            participants: vec![HostingParticipant {
                participant_uid: participant_uid.to_string(),
                permission: perm,
                onboarding: None,
            }],
            party_signing_keys: None,
        };
        let tx = TopologyTransaction {
            operation: op as i32,
            serial,
            mapping: Some(TopologyMapping {
                mapping: Some(Mapping::PartyToParticipant(mapping)),
            }),
        };
        SignedTopologyTransaction {
            transaction: tx.encode_to_vec(),
            signatures: vec![Signature {
                format: SignatureFormat::Raw as i32,
                signature: vec![1u8; 64],
                signed_by: "k1".into(),
                signing_algorithm_spec: SigningAlgorithmSpec::Ed25519 as i32,
                signature_delegation: None,
            }],
            proposal,
            multi_transaction_signatures: Vec::new(),
        }
        .encode_to_vec()
    };
    let keys_of = |v: &serde_json::Value| -> BTreeSet<String> {
        v.as_object()
            .expect("JSON object for key parity check")
            .keys()
            .cloned()
            .collect()
    };
    let p1_ledger_end = || -> u64 {
        let (st, json) = p1_http("GET", "/v2/state/ledger-end", None);
        assert_eq!(st, 200, "p1 /v2/state/ledger-end: {json}");
        json["offset"]
            .as_u64()
            .or_else(|| json["offset"].as_str()?.parse().ok())
            .unwrap_or_else(|| panic!("p1 ledger-end offset: {json}"))
    };
    let fetch_p1_topo_until = |party: &str, begin: u64, kind: &str| -> (u64, serde_json::Value) {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while std::time::Instant::now() < deadline {
            let end = p1_ledger_end();
            if end > begin {
                let (st, updates) = p1_http(
                    "POST",
                    "/v2/updates",
                    Some(&json!({
                        "beginExclusive": begin,
                        "endInclusive": end,
                        "updateFormat": {
                            "includeTopologyEvents": {
                                "includeParticipantAuthorizationEvents": { "parties": [party] }
                            }
                        }
                    })),
                );
                assert_eq!(st, 200, "p1 /v2/updates: {updates}");
                if let Some(arr) = updates.as_array() {
                    if let Some(topo) = arr.iter().find_map(|u| {
                        let t = u.pointer("/update/TopologyTransaction/value")?;
                        let has_kind = t["events"]
                            .as_array()?
                            .iter()
                            .any(|ev| ev.pointer(&format!("/event/{kind}/value")).is_some());
                        has_kind.then_some(t.clone())
                    }) {
                        return (end, topo);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("timed out waiting for p1 {kind} TopologyTransaction for {party} after {begin}");
    };
    let run_ptpcmd = |cmd: &str| {
        let dir = Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
        let fname = format!("{}.ptpcmd", unique("ptp"));
        std::fs::write(dir.join(format!("{fname}.tmp")), cmd).expect("write ptpcmd tmp");
        std::fs::rename(dir.join(format!("{fname}.tmp")), dir.join(&fname)).expect("rename ptpcmd");
        let line = log_line_with(&["SCF ptpcmd_done=", &fname], 25)
            .unwrap_or_else(|| panic!("p1 never finished ptpcmd {cmd} ({fname}):\n{}", node_log()));
        assert!(
            line.contains(&format!("SCF ptpcmd_done={fname}=ok")),
            "p1 ptpcmd failed for {cmd}: {line}"
        );
    };

    let expected_sync = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let logical_sync = canton_participant::multi_node::logical(&expected_sync);
    let expected_p1_uid = var("CANTON_RS_MEMBER_P1");
    let expected_p1_bare = expected_p1_uid
        .strip_prefix("PAR::")
        .unwrap_or(&expected_p1_uid)
        .to_string();

    let svc = ExecutionService::new();
    svc.v2_state().set_synchronizer_id_for_test(&logical_sync);

    // 1. Added -> Changed (`Submission` -> `Confirmation`).
    let p1_b0 = p1_ledger_end();
    let (st_p1_a, alloc_p1) = p1_http(
        "POST",
        "/v2/parties",
        Some(&json!({ "partyIdHint": unique("r14-chg-p1") })),
    );
    assert_eq!(st_p1_a, 200, "p1 allocate party: {alloc_p1}");
    let p1_party = alloc_p1["partyDetails"]["party"]
        .as_str()
        .expect("p1 party")
        .to_string();
    let (p1_b1, _p1_add_topo) =
        fetch_p1_topo_until(&p1_party, p1_b0, "ParticipantAuthorizationAdded");

    let r_b0 = svc.v2_ledger_end();
    let (st_r_a, alloc_r) = post(
        &svc,
        "/v2/parties",
        &json!({ "partyIdHint": unique("r14-chg-rust") }),
    );
    assert_eq!(st_r_a, 200, "rust allocate party: {alloc_r}");
    let r_party = alloc_r["partyDetails"]["party"]
        .as_str()
        .expect("rust party")
        .to_string();
    let r_b1 = svc.v2_ledger_end();
    assert!(r_b1 > r_b0);

    run_ptpcmd(&format!("change,{p1_party},Confirmation"));
    let (p1_b2, p1_chg_topo) =
        fetch_p1_topo_until(&p1_party, p1_b1, "ParticipantAuthorizationChanged");

    // Pass physical synchronizer id to verify R-7 normalizes `synchronizerId` to logical_sync.
    add_topology_txs_in_store(
        &svc,
        &expected_sync,
        true,
        vec![signed_ptp(
            &r_party,
            &svc.participant_id(),
            ParticipantPermission::Confirmation as i32,
            2,
            TopologyChangeOp::AddReplace,
            false,
        )],
    )
    .expect("rust add_topology_txs Changed");
    let r_b2 = svc.v2_ledger_end();
    let (st_r_chg, r_chg_updates) = post(
        &svc,
        "/v2/updates",
        &json!({
            "beginExclusive": r_b1,
            "endInclusive": r_b2,
            "updateFormat": {
                "includeTopologyEvents": {
                    "includeParticipantAuthorizationEvents": { "parties": [&r_party] }
                }
            }
        }),
    );
    assert_eq!(st_r_chg, 200, "rust updates Changed: {r_chg_updates}");
    let r_chg_topo = r_chg_updates.as_array().expect("rust updates array")[0]
        .pointer("/update/TopologyTransaction/value")
        .expect("rust Changed topo")
        .clone();

    let p1_chg_ev = p1_chg_topo["events"][0]
        .pointer("/event/ParticipantAuthorizationChanged/value")
        .expect("p1 ParticipantAuthorizationChanged");
    let r_chg_ev = r_chg_topo["events"][0]
        .pointer("/event/ParticipantAuthorizationChanged/value")
        .expect("rust ParticipantAuthorizationChanged");
    assert_eq!(keys_of(&r_chg_topo), keys_of(&p1_chg_topo));
    assert_eq!(keys_of(r_chg_ev), keys_of(p1_chg_ev));
    assert_eq!(
        p1_chg_ev["participantPermission"],
        json!("PARTICIPANT_PERMISSION_CONFIRMATION")
    );
    assert_eq!(
        r_chg_ev["participantPermission"],
        p1_chg_ev["participantPermission"]
    );
    assert_eq!(p1_chg_ev["participantId"], json!(expected_p1_bare));
    assert_eq!(r_chg_ev["participantId"], json!(svc.participant_id()));
    assert_eq!(p1_chg_topo["synchronizerId"], json!(logical_sync));
    assert_eq!(r_chg_topo["synchronizerId"], json!(logical_sync));

    // 2. Unilateral proposal (`mustFullyAuthorize = false` / `proposal = true`) must NOT emit updates.
    let prop_alloc_before = p1_ledger_end();
    let (st_p1_p, alloc_p1_prop) = p1_http(
        "POST",
        "/v2/parties",
        Some(&json!({ "partyIdHint": unique("r14-prop-p1") })),
    );
    assert_eq!(st_p1_p, 200, "p1 allocate prop party: {alloc_p1_prop}");
    let p1_prop_party = alloc_p1_prop["partyDetails"]["party"]
        .as_str()
        .expect("p1 prop party")
        .to_string();
    let (prop_before, _) = fetch_p1_topo_until(
        &p1_prop_party,
        prop_alloc_before,
        "ParticipantAuthorizationAdded",
    );
    run_ptpcmd(&format!("proposal,{p1_prop_party}"));
    std::thread::sleep(Duration::from_secs(2));
    let prop_after = p1_ledger_end();
    let (st_p1_pu, p1_prop_updates) = p1_http(
        "POST",
        "/v2/updates",
        Some(&json!({
            "beginExclusive": prop_before,
            "endInclusive": prop_after,
            "updateFormat": {
                "includeTopologyEvents": {
                    "includeParticipantAuthorizationEvents": { "parties": [&p1_prop_party] }
                }
            }
        })),
    );
    assert_eq!(st_p1_pu, 200, "{p1_prop_updates}");
    let p1_prop_topos: Vec<&serde_json::Value> = p1_prop_updates
        .as_array()
        .expect("p1 proposal updates array")
        .iter()
        .filter_map(|u| u.pointer("/update/TopologyTransaction"))
        .collect();
    assert!(
        p1_prop_topos.is_empty(),
        "p1 unilateral proposal must NOT emit TopologyTransaction updates: {p1_prop_updates}"
    );

    let r_prop_before = svc.v2_ledger_end();
    add_topology_txs_in_store(
        &svc,
        &expected_sync,
        true,
        vec![signed_ptp(
            &r_party,
            &svc.participant_id(),
            ParticipantPermission::Observation as i32,
            2,
            TopologyChangeOp::AddReplace,
            true,
        )],
    )
    .expect("rust store unilateral proposal");
    authorize_party_to_participant_in_store(&svc, "r14-auth-only", None, false, Some("Authorized"))
        .expect("Authorized store staging");
    assert_eq!(
        svc.v2_ledger_end(),
        r_prop_before,
        "Rust proposal and Authorized-store staging must NOT emit TopologyTransaction updates"
    );

    // 3. Revoked (`Remove`): parity on ParticipantAuthorizationRevoked key set, absent participantPermission, bare participantId, logical synchronizerId.
    run_ptpcmd(&format!("revoke,{p1_party}"));
    let (_p1_b3, p1_rev_topo) =
        fetch_p1_topo_until(&p1_party, p1_b2, "ParticipantAuthorizationRevoked");

    add_topology_txs_in_store(
        &svc,
        &expected_sync,
        true,
        vec![signed_ptp(
            &r_party,
            &svc.participant_id(),
            ParticipantPermission::Confirmation as i32,
            3,
            TopologyChangeOp::Remove,
            false,
        )],
    )
    .expect("rust add_topology_txs Revoked");
    let r_b3 = svc.v2_ledger_end();
    let (st_r_rev, r_rev_updates) = post(
        &svc,
        "/v2/updates",
        &json!({
            "beginExclusive": r_b2,
            "endInclusive": r_b3,
            "updateFormat": {
                "includeTopologyEvents": {
                    "includeParticipantAuthorizationEvents": { "parties": [&r_party] }
                }
            }
        }),
    );
    assert_eq!(st_r_rev, 200, "rust updates Revoked: {r_rev_updates}");
    let r_rev_topo = r_rev_updates
        .as_array()
        .expect("rust revoked updates array")[0]
        .pointer("/update/TopologyTransaction/value")
        .expect("rust Revoked topo")
        .clone();
    let p1_rev_ev = p1_rev_topo["events"][0]
        .pointer("/event/ParticipantAuthorizationRevoked/value")
        .expect("p1 ParticipantAuthorizationRevoked");
    let r_rev_ev = r_rev_topo["events"][0]
        .pointer("/event/ParticipantAuthorizationRevoked/value")
        .expect("rust ParticipantAuthorizationRevoked");
    assert_eq!(keys_of(&r_rev_topo), keys_of(&p1_rev_topo));
    assert_eq!(keys_of(r_rev_ev), keys_of(p1_rev_ev));
    assert!(p1_rev_ev.get("participantPermission").is_none());
    assert!(r_rev_ev.get("participantPermission").is_none());
    assert_eq!(p1_rev_ev["participantId"], json!(expected_p1_bare));
    assert_eq!(r_rev_ev["participantId"], json!(svc.participant_id()));
    assert_eq!(p1_rev_topo["synchronizerId"], json!(logical_sync));
    assert_eq!(r_rev_topo["synchronizerId"], json!(logical_sync));

    // 4. External party allocation (`/v2/parties/external/{generate-topology,allocate}`) parity.
    let onboard_external = |use_p1: bool, seed: [u8; 32], hint: &str| -> serde_json::Value {
        let sk = SigningKey::from_bytes(&seed);
        let spki = sk
            .verifying_key()
            .to_public_key_der()
            .expect("ed25519 spki");
        let gen_body = json!({
            "synchronizer": &logical_sync,
            "partyHint": hint,
            "publicKey": {
                "format": "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
                "keyData": b64_encode(spki.as_bytes()),
                "keySpec": "SIGNING_KEY_SPEC_EC_CURVE25519"
            }
        });
        let (st_gen, gen_resp) = if use_p1 {
            p1_http(
                "POST",
                "/v2/parties/external/generate-topology",
                Some(&gen_body),
            )
        } else {
            post(&svc, "/v2/parties/external/generate-topology", &gen_body)
        };
        assert_eq!(st_gen, 200, "generate-topology (p1={use_p1}): {gen_resp}");
        let ext_party = gen_resp["partyId"]
            .as_str()
            .expect("external partyId")
            .to_string();
        let fp = gen_resp["publicKeyFingerprint"]
            .as_str()
            .expect("external publicKeyFingerprint")
            .to_string();
        let multi_hash = b64_decode(gen_resp["multiHash"].as_str().expect("external multiHash"));
        let mut payload = Vec::new();
        if multi_hash.len() == 32 {
            payload.extend([0x12, 0x20]);
        }
        payload.extend(multi_hash);
        let sig_json = json!({
            "format": "SIGNATURE_FORMAT_CONCAT",
            "signature": b64_encode(&sk.sign(&payload).to_bytes()),
            "signedBy": fp,
            "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
        });
        let onboarding: Vec<serde_json::Value> = gen_resp["topologyTransactions"]
            .as_array()
            .expect("external topologyTransactions array")
            .iter()
            .map(|tx| json!({ "transaction": tx, "signatures": [] }))
            .collect();
        let alloc_body = json!({
            "synchronizer": &logical_sync,
            "onboardingTransactions": onboarding,
            "multiHashSignatures": [sig_json]
        });
        let before = if use_p1 {
            p1_ledger_end()
        } else {
            svc.v2_ledger_end()
        };
        let (st_alloc, alloc_resp) = if use_p1 {
            p1_http("POST", "/v2/parties/external/allocate", Some(&alloc_body))
        } else {
            post(&svc, "/v2/parties/external/allocate", &alloc_body)
        };
        assert_eq!(
            st_alloc, 200,
            "external/allocate (p1={use_p1}): {alloc_resp}"
        );
        if use_p1 {
            let (_end, topo) =
                fetch_p1_topo_until(&ext_party, before, "ParticipantAuthorizationAdded");
            topo
        } else {
            let (st_u, upd) = post(
                &svc,
                "/v2/updates",
                &json!({
                    "beginExclusive": before,
                    "endInclusive": svc.v2_ledger_end(),
                    "updateFormat": {
                        "includeTopologyEvents": {
                            "includeParticipantAuthorizationEvents": { "parties": [&ext_party] }
                        }
                    }
                }),
            );
            assert_eq!(st_u, 200, "{upd}");
            upd.as_array().expect("rust external updates array")[0]
                .pointer("/update/TopologyTransaction/value")
                .expect("rust external party Added topo")
                .clone()
        }
    };

    let p1_ext_topo = onboard_external(true, [21u8; 32], &unique("ext-p1"));
    let r_ext_topo = onboard_external(false, [22u8; 32], &unique("ext-rust"));
    let p1_ext_ev = p1_ext_topo["events"][0]
        .pointer("/event/ParticipantAuthorizationAdded/value")
        .expect("p1 external ParticipantAuthorizationAdded");
    let r_ext_ev = r_ext_topo["events"][0]
        .pointer("/event/ParticipantAuthorizationAdded/value")
        .expect("rust external ParticipantAuthorizationAdded");
    assert_eq!(keys_of(&r_ext_topo), keys_of(&p1_ext_topo));
    assert_eq!(keys_of(r_ext_ev), keys_of(p1_ext_ev));
    assert_eq!(
        p1_ext_ev["participantPermission"],
        json!("PARTICIPANT_PERMISSION_CONFIRMATION")
    );
    assert_eq!(
        r_ext_ev["participantPermission"],
        p1_ext_ev["participantPermission"]
    );
    assert_eq!(p1_ext_ev["participantId"], json!(expected_p1_bare));
    assert_eq!(r_ext_ev["participantId"], json!(svc.participant_id()));
    assert_eq!(p1_ext_topo["synchronizerId"], json!(logical_sync));
    assert_eq!(r_ext_topo["synchronizerId"], json!(logical_sync));
}
