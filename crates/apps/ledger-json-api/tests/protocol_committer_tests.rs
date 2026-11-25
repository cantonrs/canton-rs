//! F4: the seam between the JSON API service and a synchronizer (`ProtocolCommitter`). A fake synchronizer stands in: it chooses the contract
//! ids, sees every transaction before it is applied, and can reject one.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ledger_json_api::models::json_api::*;
use ledger_json_api::models::ledger_api::*;
use ledger_json_api::service::{ApiError, ExecutionService, ProtocolCommitter, TransactionCommit};
use lf_eval::engine::NewContract;
use serde_json::json;

fn sample_dar() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

#[derive(Default)]
struct Fake {
    next: AtomicUsize,
    reject: AtomicBool,
    /// `(created contract ids, consumed contract ids)` of every transaction judged
    judged: Mutex<Vec<(Vec<String>, Vec<String>)>>,
}

impl ProtocolCommitter for Fake {
    fn allocate_contract_id(
        &self,
        _new: &NewContract<'_>,
        _session: &mut Option<u64>,
    ) -> Option<String> {
        Some(format!(
            "proto-{}",
            self.next.fetch_add(1, Ordering::SeqCst) + 1
        ))
    }

    fn commit(&self, commit: &TransactionCommit) -> Result<(), ApiError> {
        self.judged.lock().unwrap().push((
            commit
                .created_contracts
                .iter()
                .map(|c| c.contract_id.clone())
                .collect(),
            commit.consumed_cids.clone(),
        ));
        if self.reject.load(Ordering::SeqCst) {
            return Err(ApiError::Ledger(
                "the synchronizer rejected the transaction".into(),
            ));
        }
        Ok(())
    }
}

fn payload() -> serde_json::Value {
    json!({"bank": "Bank", "owner": "Bank", "auditor": "Auditor", "assetSymbol": "USD", "amount": "100.0"})
}

fn service(fake: &Arc<Fake>) -> ExecutionService {
    let service = ExecutionService::new();
    service.load_dar(&sample_dar()).expect("load sample dar");
    service.set_committer(Arc::clone(fake) as Arc<_>);
    service
}

fn create(service: &ExecutionService) -> Result<String, ApiError> {
    service
        .json_create(
            &["Bank".to_string()],
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: payload(),
                meta: None,
            },
        )
        .map(|r| r.result.contract_id)
}

#[test]
fn the_synchronizer_chooses_the_contract_id_and_sees_the_transaction_before_it_is_applied() {
    let fake = Arc::new(Fake::default());
    let service = service(&fake);
    let id = create(&service).expect("approved");
    assert_eq!(
        id, "proto-1",
        "the id is the synchronizer's, not the service's numbering"
    );
    assert_eq!(
        fake.judged.lock().unwrap().as_slice(),
        &[(vec!["proto-1".to_string()], vec![])]
    );
    let acs = service.get_active_contracts(&[]).unwrap();
    assert_eq!(acs.active_contracts.len(), 1);
    assert_eq!(acs.active_contracts[0].contract_id, "proto-1");
    // a consuming exercise of that contract is judged with the contract consumed
    service
        .json_exercise(
            &["Bank".to_string()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: id.clone(),
                choice: "Settle".into(),
                argument: json!({}),
                meta: None,
            },
        )
        .expect("approved");
    let judged = fake.judged.lock().unwrap();
    assert_eq!(judged.len(), 2);
    assert_eq!(judged[1].1, vec![id]);
}

#[test]
fn a_transaction_the_synchronizer_rejects_is_not_applied() {
    let fake = Arc::new(Fake::default());
    let service = service(&fake);
    let id = create(&service).unwrap();
    fake.reject.store(true, Ordering::SeqCst);
    let error = create(&service).expect_err("rejected");
    assert!(
        error
            .to_string()
            .contains("the synchronizer rejected the transaction"),
        "{error}"
    );
    let settled = service.json_exercise(
        &["Bank".to_string()],
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: id.clone(),
            choice: "Settle".into(),
            argument: json!({}),
            meta: None,
        },
    );
    assert!(settled.is_err());
    // neither the rejected create nor the rejected consumption changed the ledger
    let acs = service.get_active_contracts(&[]).unwrap();
    assert_eq!(acs.active_contracts.len(), 1);
    assert_eq!(acs.active_contracts[0].contract_id, id);
}

#[test]
fn without_a_synchronizer_the_service_numbers_contracts_as_before() {
    let service = ExecutionService::new();
    service.load_dar(&sample_dar()).unwrap();
    assert_eq!(create(&service).unwrap(), "#0:0");
}

/// R-13a: `command_recorded()` must be invoked iff a completion/update was actually recorded, never unconditionally after
/// `submit_inner` fails post-commit (and never twice on normal success).
#[test]
fn r13a_command_recorded_is_called_only_when_recording_succeeds() {
    use ledger_json_api::http::{dispatch_request, HttpRequest};
    use std::collections::HashMap;

    #[derive(Default)]
    struct TrackingCommitter {
        next: AtomicUsize,
        reuse_last: AtomicBool,
        reject_sync: AtomicBool,
        recorded: AtomicUsize,
    }

    impl ProtocolCommitter for TrackingCommitter {
        fn allocate_contract_id(
            &self,
            _new: &NewContract<'_>,
            _session: &mut Option<u64>,
        ) -> Option<String> {
            let n = if self.reuse_last.load(Ordering::SeqCst) {
                self.next.load(Ordering::SeqCst).max(1)
            } else {
                self.next.fetch_add(1, Ordering::SeqCst) + 1
            };
            Some(format!("proto-{n}"))
        }

        fn commit(&self, _commit: &TransactionCommit) -> Result<(), ApiError> {
            if self.reject_sync.load(Ordering::SeqCst) {
                return Err(ApiError::SynchronizerRejected {
                    code: "LOCAL_VERDICT_LOCKED_CONTRACTS".into(),
                    cause: "Aborted".into(),
                    grpc_code: 10,
                    http_status: 409,
                    category: 2,
                    details: None,
                });
            }
            Ok(())
        }

        fn command_recorded(&self) {
            self.recorded.fetch_add(1, Ordering::SeqCst);
        }
    }

    let tracker = Arc::new(TrackingCommitter::default());
    let svc = ExecutionService::new();
    svc.load_dar(&sample_dar()).expect("load sample dar");
    svc.set_committer(Arc::clone(&tracker) as Arc<_>);
    let alloc = dispatch_request(
        &svc,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/parties".into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: br#"{"partyIdHint":"bank","identityProviderId":""}"#.to_vec(),
        },
    );
    assert_eq!(alloc.status, 200);
    let bank = serde_json::from_slice::<serde_json::Value>(&alloc.body).unwrap()["partyDetails"]
        ["party"]
        .as_str()
        .unwrap()
        .to_string();

    let submit_cmd = |path: &str, cmd_id: &str| {
        dispatch_request(
            &svc,
            &HttpRequest {
                method: "POST".into(),
                path: path.into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: serde_json::to_vec(&json!({
                    "commands": [{
                        "CreateCommand": {
                            "templateId": "#sample-contract:AssetHolding:AssetHolding",
                            "createArguments": {
                                "bank": &bank, "owner": &bank, "auditor": &bank,
                                "assetSymbol": "USD", "amount": "10.0"
                            }
                        }
                    }],
                    "userId": "participant_admin",
                    "commandId": cmd_id,
                    "actAs": [&bank]
                }))
                .unwrap(),
            },
        )
    };

    // 1. Positive control: normal approved create calls `command_recorded` exactly ONCE (not twice).
    let ok1 = submit_cmd("/v2/commands/submit-and-wait", "r13a-ok");
    assert_eq!(ok1.status, 200, "{}", String::from_utf8_lossy(&ok1.body));
    assert_eq!(
        tracker.recorded.load(Ordering::SeqCst),
        1,
        "approved v2 submit must mark recorded exactly once"
    );

    // 2. Post-commit recording failure (`committer.commit` returned Ok, then `apply_commit` fails due to duplicate cid):
    // no completion or update is recorded, so `command_recorded` must NOT be called.
    tracker.reuse_last.store(true, Ordering::SeqCst);
    let fail_apply = submit_cmd("/v2/commands/submit-and-wait", "r13a-fail-apply");
    assert_ne!(fail_apply.status, 200);
    assert_eq!(
        tracker.recorded.load(Ordering::SeqCst),
        1,
        "sync submit failing post-commit before completion/update recording must NOT call command_recorded"
    );
    let fail_async = submit_cmd("/v2/commands/async/submit", "r13a-fail-async");
    assert_ne!(fail_async.status, 200);
    assert_eq!(
        tracker.recorded.load(Ordering::SeqCst),
        1,
        "async submit failing post-commit before recording must NOT call command_recorded"
    );

    // 3. SynchronizerRejected IS recorded as a failed completion, so `command_recorded` increments once (to 2).
    tracker.reuse_last.store(false, Ordering::SeqCst);
    tracker.reject_sync.store(true, Ordering::SeqCst);
    let rej = submit_cmd("/v2/commands/submit-and-wait", "r13a-rejected");
    assert_ne!(rej.status, 200);
    assert_eq!(
        tracker.recorded.load(Ordering::SeqCst),
        2,
        "recorded synchronizer rejection must mark awaited fate recorded once"
    );
}

#[test]
fn r13a_journal_sink_failure_prevents_command_recorded_in_unit_committer() {
    use ledger_json_api::http::{dispatch_request, HttpRequest};
    use std::collections::HashMap;

    #[derive(Default)]
    struct CounterCommitter {
        next: AtomicUsize,
        recorded: AtomicUsize,
    }

    impl ProtocolCommitter for CounterCommitter {
        fn allocate_contract_id(
            &self,
            _new: &NewContract<'_>,
            _session: &mut Option<u64>,
        ) -> Option<String> {
            Some(format!(
                "proto-sink-{}",
                self.next.fetch_add(1, Ordering::SeqCst) + 1
            ))
        }

        fn commit(&self, _commit: &TransactionCommit) -> Result<(), ApiError> {
            Ok(())
        }

        fn command_recorded(&self) {
            self.recorded.fetch_add(1, Ordering::SeqCst);
        }
    }

    let tracker = Arc::new(CounterCommitter::default());
    let svc = ExecutionService::new();
    svc.load_dar(&sample_dar()).expect("load sample dar");
    svc.set_committer(Arc::clone(&tracker) as Arc<_>);
    let alloc = dispatch_request(
        &svc,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/parties".into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: br#"{"partyIdHint":"bank","identityProviderId":""}"#.to_vec(),
        },
    );
    assert_eq!(alloc.status, 200);
    let bank = serde_json::from_slice::<serde_json::Value>(&alloc.body).unwrap()["partyDetails"]
        ["party"]
        .as_str()
        .unwrap()
        .to_string();

    svc.set_journal_sink_for_test(Arc::new(|key, _| {
        if key == "updates.journal" {
            Err("injected disk full error".into())
        } else {
            Ok(())
        }
    }));

    let fail_resp = dispatch_request(
        &svc,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/commands/submit-and-wait".into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: serde_json::to_vec(&json!({
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#sample-contract:AssetHolding:AssetHolding",
                        "createArguments": {
                            "bank": &bank, "owner": &bank, "auditor": &bank,
                            "assetSymbol": "USD", "amount": "15.0"
                        }
                    }
                }],
                "userId": "participant_admin",
                "commandId": "r13a-sink-err",
                "actAs": [&bank]
            }))
            .unwrap(),
        },
    );
    assert_eq!(
        fail_resp.status,
        500,
        "failing updates.journal sink must surface HTTP 500: {}",
        String::from_utf8_lossy(&fail_resp.body)
    );
    assert_eq!(
        tracker.recorded.load(Ordering::SeqCst),
        0,
        "failing journal sink must NOT invoke command_recorded"
    );
}
