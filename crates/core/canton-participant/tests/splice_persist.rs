//! S-STORE-020 (AT-D10): the Splice apps keep their state in a journal; after a crash the client's retry and the automation worker's
//! retry are each applied exactly once, and a second worker on the same state is refused. Directory store here; the PostgreSQL store is
//! `tests/splice_persist_pg.rs` (feature `pg-tests`, `scripts/verify-pg-store.sh`).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use canton_participant::splice_persist::{PersistentSplice, JOURNAL_KEY};
use canton_participant::state_store::{FileStore, StateStore};
use canton_participant::SpliceBootstrapConfig;
use serde_json::{json, Value as Json};

fn splice_dar_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("tests/oracle/splice-dars")
}

fn fresh_dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "canton-rs-splice-{name}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn call(
    app: &PersistentSplice,
    method: &str,
    path: &str,
    user: Option<&str>,
    body: Option<Json>,
) -> (u16, Json) {
    let headers: Vec<(String, String)> = user
        .map(|u| vec![("x-wallet-user".to_string(), u.to_string())])
        .unwrap_or_default();
    let bytes = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
    let resp = app.handle_http(method, path, &headers, &bytes);
    let parsed = serde_json::from_str(&resp.body).unwrap_or_else(|_| json!({ "raw": resp.body }));
    (resp.status, parsed)
}

fn open(store: Arc<dyn StateStore>, dir_lock: Option<&Path>) -> (PersistentSplice, usize, bool) {
    let (app, report) = PersistentSplice::open(
        &splice_dar_dir(),
        SpliceBootstrapConfig::default(),
        store,
        true,
        dir_lock,
    )
    .expect("open persistent Splice runtime");
    (app, report.replayed, report.bootstrapped)
}

fn balance(app: &PersistentSplice, user: &str) -> Json {
    call(app, "GET", "/v0/wallet/balance", Some(user), None).1["effective_unlocked_qty"].clone()
}

/// A directory store whose next `append` can be made to fail: the request's state changes in memory, its journal line never lands.
struct FlakyStore {
    inner: Arc<FileStore>,
    fail_next_append: AtomicBool,
}

impl StateStore for FlakyStore {
    fn read(&self, key: &str) -> Result<Option<String>, String> {
        self.inner.read(key)
    }
    fn write(&self, key: &str, text: &str) -> Result<(), String> {
        self.inner.write(key, text)
    }
    fn append(&self, key: &str, line: &str) -> Result<(), String> {
        if self.fail_next_append.swap(false, Ordering::SeqCst) {
            return Err("injected: the journal write was lost".into());
        }
        self.inner.append(key, line)
    }
    fn create_new(&self, key: &str, text: &str) -> Result<bool, String> {
        self.inner.create_new(key, text)
    }
    fn describe(&self) -> String {
        self.inner.describe()
    }
}

#[test]
fn at_d10_client_and_worker_retries_after_a_crash_apply_once() {
    let dir = fresh_dir("atd10");
    let (app, replayed, bootstrapped) = open(FileStore::new(&dir).unwrap(), Some(&dir));
    assert_eq!((replayed, bootstrapped), (0, true));

    let alice = call(
        &app,
        "POST",
        "/v0/admin/users",
        None,
        Some(json!({ "name": "alice" })),
    )
    .1["party_id"]
        .as_str()
        .unwrap()
        .to_string();
    let bob = call(
        &app,
        "POST",
        "/v0/admin/users",
        None,
        Some(json!({ "name": "bob" })),
    )
    .1["party_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, tap) = call(
        &app,
        "POST",
        "/api/wallet/v0/wallet/tap",
        Some("alice"),
        Some(json!({ "amount": "500.0" })),
    );
    assert_eq!(st, 200, "tap: {tap}");
    let expires_at = app.runtime().lock().unwrap().now_micros() + 3_600_000_000;
    let offer = json!({
        "receiver_party_id": bob,
        "amount": "125.5",
        "description": "AT-D10",
        "expires_at": expires_at,
        "tracking_id": "at-d10-1",
    });
    let (st, created) = call(
        &app,
        "POST",
        "/v0/wallet/transfer-offers",
        Some("alice"),
        Some(offer.clone()),
    );
    assert_eq!(st, 200, "create offer: {created}");
    let offer_cid = created["offer_contract_id"].as_str().unwrap().to_string();

    // crash 1: the offer was committed and journaled, the client never saw the answer
    drop(app);
    let (app, replayed, bootstrapped) = open(FileStore::new(&dir).unwrap(), Some(&dir));
    assert!(replayed >= 5 && !bootstrapped, "replayed {replayed}");
    let (st, retry) = call(
        &app,
        "POST",
        "/v0/wallet/transfer-offers",
        Some("alice"),
        Some(offer.clone()),
    );
    assert_eq!(st, 200, "client retry after crash: {retry}");
    assert_eq!(
        retry["offer_contract_id"],
        json!(offer_cid),
        "the retry is answered by the offer that survived, not a second one"
    );
    let (st, offers) = call(&app, "GET", "/v0/wallet/transfer-offers", Some("bob"), None);
    assert_eq!(st, 200);
    assert_eq!(offers["offers"].as_array().unwrap().len(), 1);
    let (st, acc) = call(
        &app,
        "POST",
        &format!("/v0/wallet/transfer-offers/{offer_cid}/accept"),
        Some("bob"),
        None,
    );
    assert_eq!(st, 200, "accept: {acc}");

    // the automation worker settles the transfer, then crash 2 before anyone saw its report
    let tick = app.automation_tick().expect("worker tick");
    assert_eq!(tick.transfers_completed, 1);
    drop(app);
    let (app, _, _) = open(FileStore::new(&dir).unwrap(), Some(&dir));
    // the worker retries its tick and the client retries its create: neither is applied again
    let tick = app.automation_tick().expect("worker retry tick");
    assert_eq!(
        tick.transfers_completed, 0,
        "the settled transfer is not settled twice"
    );
    let (st, again) = call(
        &app,
        "POST",
        "/v0/wallet/transfer-offers",
        Some("alice"),
        Some(offer),
    );
    assert_eq!(st, 409, "a completed tracking id is not reused: {again}");
    let (st, status) = call(
        &app,
        "GET",
        "/v0/wallet/transfer-offers/at-d10-1/status",
        None,
        None,
    );
    assert_eq!(st, 200);
    assert_eq!(status["status"], json!("completed"));
    assert_eq!(balance(&app, "alice"), json!("374.5000000000"));
    assert_eq!(balance(&app, "bob"), json!("125.5000000000"));
    let _ = alice;
    drop(app);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_request_whose_journal_write_is_lost_is_applied_once_on_retry() {
    let dir = fresh_dir("lost");
    let flaky = Arc::new(FlakyStore {
        inner: FileStore::new(&dir).unwrap(),
        fail_next_append: AtomicBool::new(false),
    });
    let (app, _, _) = open(Arc::clone(&flaky) as Arc<_>, Some(&dir));
    call(
        &app,
        "POST",
        "/v0/admin/users",
        None,
        Some(json!({ "name": "alice" })),
    );

    // the tap changes memory but its journal line never lands: the answer is 503, and no further change is taken
    flaky.fail_next_append.store(true, Ordering::SeqCst);
    let (st, _) = call(
        &app,
        "POST",
        "/api/wallet/v0/wallet/tap",
        Some("alice"),
        Some(json!({ "amount": "40.0" })),
    );
    assert_eq!(st, 503);
    let (st, _) = call(
        &app,
        "POST",
        "/api/wallet/v0/wallet/tap",
        Some("alice"),
        Some(json!({ "amount": "1.0" })),
    );
    assert_eq!(st, 503, "a runtime ahead of its journal refuses changes");
    assert!(app.automation_tick().is_err());
    drop(app);

    // restart: the unjournaled tap is gone; the client's retry applies it exactly once
    let (app, _, _) = open(FileStore::new(&dir).unwrap(), Some(&dir));
    assert_eq!(balance(&app, "alice"), json!("0.0000000000"));
    let (st, tap) = call(
        &app,
        "POST",
        "/api/wallet/v0/wallet/tap",
        Some("alice"),
        Some(json!({ "amount": "40.0" })),
    );
    assert_eq!(st, 200, "{tap}");
    assert_eq!(balance(&app, "alice"), json!("40.0000000000"));
    drop(app);
    let (app, _, _) = open(FileStore::new(&dir).unwrap(), Some(&dir));
    assert_eq!(balance(&app, "alice"), json!("40.0000000000"));
    drop(app);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_second_worker_on_the_same_directory_is_refused() {
    let dir = fresh_dir("fence");
    let (first, _, _) = open(FileStore::new(&dir).unwrap(), Some(&dir));
    let err = PersistentSplice::open(
        &splice_dar_dir(),
        SpliceBootstrapConfig::default(),
        FileStore::new(&dir).unwrap(),
        true,
        Some(&dir),
    )
    .err()
    .expect("a second worker must not start");
    assert!(err.contains("another worker"), "{err}");
    // reads and reads-only POSTs (scan) leave no journal line
    let journal_before = FileStore::new(&dir).unwrap().read(JOURNAL_KEY).unwrap();
    let (st, _) = call(&first, "GET", "/api/scan/v0/dso", None, None);
    assert_eq!(st, 200);
    assert_eq!(
        FileStore::new(&dir).unwrap().read(JOURNAL_KEY).unwrap(),
        journal_before
    );
    drop(first);
    let (second, replayed, bootstrapped) = open(FileStore::new(&dir).unwrap(), Some(&dir));
    assert!(replayed >= 1 && !bootstrapped);
    drop(second);
    let _ = std::fs::remove_dir_all(&dir);
}
