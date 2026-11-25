//! S-STORE-020 (AT-D10) on PostgreSQL: the Splice journal in `canton_rs_state`, a crash between commit and answer, the client's and the
//! worker's retries applied once, and a second worker on the same state name refused by the session advisory lock.
//!
//! Needs `CANTON_RS_PG_URL` (a missing variable panics, it never skips); compiled only with the `pg-tests` feature
//! (`scripts/verify-pg-store.sh`).
#![cfg(feature = "pg-tests")]

use std::path::PathBuf;

use canton_participant::splice_persist::PersistentSplice;
use canton_participant::state_store::PgStore;
use canton_participant::SpliceBootstrapConfig;
use serde_json::{json, Value as Json};

fn url() -> String {
    std::env::var("CANTON_RS_PG_URL").expect("CANTON_RS_PG_URL must point at a PostgreSQL server")
}

fn splice_dar_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("tests/oracle/splice-dars")
}

fn open(name: &str) -> PersistentSplice {
    let store = PgStore::connect(&url(), name).expect("the state store");
    PersistentSplice::open(
        &splice_dar_dir(),
        SpliceBootstrapConfig::default(),
        store,
        true,
        None,
    )
    .expect("open persistent Splice runtime")
    .0
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
    (
        resp.status,
        serde_json::from_str(&resp.body).unwrap_or_else(|_| json!({ "raw": resp.body })),
    )
}

#[test]
fn splice_journal_on_postgres_survives_crashes_and_fences_a_second_worker() {
    let name = format!(
        "splice-at-d10-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let app = open(&name);
    // a second worker on the same state name is refused while the first holds it
    let err = PgStore::connect(&url(), &name)
        .err()
        .expect("second worker");
    assert!(!err.is_empty());

    call(
        &app,
        "POST",
        "/v0/admin/users",
        None,
        Some(json!({ "name": "alice" })),
    );
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
    assert_eq!(
        call(
            &app,
            "POST",
            "/api/wallet/v0/wallet/tap",
            Some("alice"),
            Some(json!({ "amount": "300.0" }))
        )
        .0,
        200
    );
    let expires_at = app.runtime().lock().unwrap().now_micros() + 3_600_000_000;
    let offer = json!({
        "receiver_party_id": bob, "amount": "100.0", "description": "AT-D10 pg",
        "expires_at": expires_at, "tracking_id": "at-d10-pg",
    });
    let (st, created) = call(
        &app,
        "POST",
        "/v0/wallet/transfer-offers",
        Some("alice"),
        Some(offer.clone()),
    );
    assert_eq!(st, 200, "{created}");
    let offer_cid = created["offer_contract_id"].as_str().unwrap().to_string();
    drop(app); // crash: the connection (and the lock) goes with the process

    let app = open(&name);
    let (st, retry) = call(
        &app,
        "POST",
        "/v0/wallet/transfer-offers",
        Some("alice"),
        Some(offer),
    );
    assert_eq!(st, 200);
    assert_eq!(retry["offer_contract_id"], json!(offer_cid));
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/v0/wallet/transfer-offers/{offer_cid}/accept"),
            Some("bob"),
            None
        )
        .0,
        200
    );
    assert_eq!(app.automation_tick().unwrap().transfers_completed, 1);
    drop(app);

    let app = open(&name);
    assert_eq!(app.automation_tick().unwrap().transfers_completed, 0);
    let bal = |u: &str| {
        call(&app, "GET", "/v0/wallet/balance", Some(u), None).1["effective_unlocked_qty"].clone()
    };
    assert_eq!(bal("alice"), json!("200.0000000000"));
    assert_eq!(bal("bob"), json!("100.0000000000"));
}
