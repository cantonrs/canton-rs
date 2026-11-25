//! S-API-015: JWT authentication and rights on the JSON API, with the behaviors measured on a Canton 3.7.2 sandbox that has the
//! `unsafe-jwt-hmac-256` auth service (the gRPC oracle `tests/oracle/grpc-auth` compares the same rules over gRPC).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::collections::HashMap;

use ledger_json_api::{
    auth::sign_token, dispatch_request, AuthConfig, ExecutionService, HttpRequest,
};
use serde_json::{json, Value};

const SECRET: &str = "testsecret";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn token(sub: &str) -> String {
    sign_token(
        SECRET,
        &json!({ "sub": sub, "scope": "daml_ledger_api", "exp": now() + 120 }),
    )
}

fn call(
    svc: &ExecutionService,
    method: &str,
    path: &str,
    body: Value,
    token: Option<&str>,
) -> (u16, Value) {
    let mut headers = HashMap::new();
    if let Some(t) = token {
        headers.insert("authorization".to_string(), format!("Bearer {t}"));
    }
    let resp = dispatch_request(
        svc,
        &HttpRequest {
            method: method.into(),
            path: path.into(),
            query_params: HashMap::new(),
            headers,
            body: if body.is_null() {
                vec![]
            } else {
                body.to_string().into_bytes()
            },
        },
    );
    (
        resp.status,
        serde_json::from_slice(&resp.body).unwrap_or(Value::Null),
    )
}

fn service() -> ExecutionService {
    let svc = ExecutionService::new();
    svc.set_auth(AuthConfig::hmac(SECRET));
    svc
}

#[test]
fn a_call_without_a_valid_token_is_unauthenticated_with_the_generic_error() {
    let svc = service();
    let wrong = sign_token(
        "other",
        &json!({ "sub": "participant_admin", "scope": "daml_ledger_api", "exp": now() + 120 }),
    );
    let expired = sign_token(
        SECRET,
        &json!({ "sub": "participant_admin", "scope": "daml_ledger_api", "exp": now() - 30 }),
    );
    let no_scope = sign_token(
        SECRET,
        &json!({ "sub": "participant_admin", "exp": now() + 120 }),
    );
    let too_long = sign_token(
        SECRET,
        &json!({ "sub": "participant_admin", "scope": "daml_ledger_api", "exp": now() + 4000 }),
    );
    for t in [
        None,
        Some("abc.def.ghi"),
        Some(wrong.as_str()),
        Some(expired.as_str()),
        Some(no_scope.as_str()),
        Some(too_long.as_str()),
    ] {
        let (status, body) = call(&svc, "GET", "/v2/state/ledger-end", Value::Null, t);
        assert_eq!(status, 401, "{t:?}");
        assert_eq!(body["code"], "NA");
        assert_eq!(body["grpcCodeValue"], 16);
        assert_eq!(body["errorCategory"], -1);
    }
    // the health endpoints stay open
    assert_eq!(call(&svc, "GET", "/livez", Value::Null, None).0, 200);
}

#[test]
fn a_valid_token_of_an_unknown_user_is_forbidden() {
    let svc = service();
    let (status, body) = call(
        &svc,
        "GET",
        "/v2/state/ledger-end",
        Value::Null,
        Some(&token("ghost")),
    );
    assert_eq!((status, &body["grpcCodeValue"]), (403, &json!(7)));
}

#[test]
fn rights_decide_what_a_user_may_do() {
    let svc = service();
    let admin = token("participant_admin");
    let (s, b) = call(
        &svc,
        "POST",
        "/v2/parties",
        json!({"partyIdHint": "p1", "identityProviderId": ""}),
        Some(&admin),
    );
    assert_eq!(s, 200);
    let p1 = b["partyDetails"]["party"].as_str().unwrap().to_string();
    let right = |k: &str, party: Option<&str>| json!({"kind": {k: {"value": party.map_or(json!({}), |p| json!({"party": p}))}}});
    for (id, rights) in [
        ("actor", vec![right("CanActAs", Some(&p1))]),
        ("reader", vec![right("CanReadAs", Some(&p1))]),
        ("nobody", vec![]),
    ] {
        let (s, _) = call(
            &svc,
            "POST",
            "/v2/users",
            json!({"user": {"id": id}, "rights": rights}),
            Some(&admin),
        );
        assert_eq!(s, 200, "{id}");
    }
    let acs = json!({"eventFormat": {"filtersByParty": {&p1: {}}}, "activeAtOffset": 0});
    let submit =
        |user: &str| json!({"commands": [], "commandId": "c", "actAs": [&p1], "userId": user});
    // administrators manage but do not read or act as a party by that alone
    assert_eq!(
        call(&svc, "GET", "/v2/users", Value::Null, Some(&admin)).0,
        200
    );
    assert_eq!(
        call(
            &svc,
            "POST",
            "/v2/state/active-contracts",
            acs.clone(),
            Some(&admin)
        )
        .0,
        403
    );
    assert_eq!(
        call(
            &svc,
            "POST",
            "/v2/commands/submit-and-wait",
            submit("participant_admin"),
            Some(&admin)
        )
        .0,
        403
    );
    // readers and actors read the party, only the actor acts as it, neither manages
    assert_eq!(
        call(
            &svc,
            "POST",
            "/v2/state/active-contracts",
            acs.clone(),
            Some(&token("reader"))
        )
        .0,
        200
    );
    assert_eq!(
        call(
            &svc,
            "POST",
            "/v2/state/active-contracts",
            acs.clone(),
            Some(&token("actor"))
        )
        .0,
        200
    );
    assert_eq!(
        call(
            &svc,
            "POST",
            "/v2/commands/submit-and-wait",
            submit("reader"),
            Some(&token("reader"))
        )
        .0,
        403
    );
    assert_ne!(
        call(
            &svc,
            "POST",
            "/v2/commands/submit-and-wait",
            submit("actor"),
            Some(&token("actor"))
        )
        .0,
        403
    );
    assert_eq!(
        call(&svc, "GET", "/v2/users", Value::Null, Some(&token("actor"))).0,
        403
    );
    // everyone reads their own user, nobody else's unless an administrator
    assert_eq!(
        call(
            &svc,
            "GET",
            "/v2/users/nobody",
            Value::Null,
            Some(&token("nobody"))
        )
        .0,
        200
    );
    assert_eq!(
        call(
            &svc,
            "GET",
            "/v2/users/actor",
            Value::Null,
            Some(&token("nobody"))
        )
        .0,
        403
    );
    assert_eq!(
        call(
            &svc,
            "POST",
            "/v2/state/active-contracts",
            acs,
            Some(&token("nobody"))
        )
        .0,
        403
    );
}

/// `filtersForAnyParty` asks for what every party sees: it needs the right to read as any party, whatever `filtersByParty` says
/// (`RequiredClaims.scala`: a `ReadAs` claim per `filtersByParty` key, and `ReadAsAnyParty` when `filtersForAnyParty` is set).
#[test]
fn the_any_party_filter_needs_the_right_to_read_as_any_party() {
    let svc = service();
    let admin = token("participant_admin");
    let (s, b) = call(
        &svc,
        "POST",
        "/v2/parties",
        json!({"partyIdHint": "p1", "identityProviderId": ""}),
        Some(&admin),
    );
    assert_eq!(s, 200);
    let p1 = b["partyDetails"]["party"].as_str().unwrap().to_string();
    for (id, rights) in [
        (
            "reader",
            vec![json!({"kind": {"CanReadAs": {"value": {"party": &p1}}}})],
        ),
        (
            "anyreader",
            vec![json!({"kind": {"CanReadAsAnyParty": {"value": {}}}})],
        ),
        ("nobody", vec![]),
    ] {
        let (s, _) = call(
            &svc,
            "POST",
            "/v2/users",
            json!({"user": {"id": id}, "rights": rights}),
            Some(&admin),
        );
        assert_eq!(s, 200, "{id}");
    }
    let wildcard = json!({"cumulative": [{"identifierFilter": {"WildcardFilter": {"value": {"includeCreatedEventBlob": false}}}}]});
    let any_with_no_party = json!({
        "eventFormat": {"filtersByParty": {}, "filtersForAnyParty": wildcard},
        "activeAtOffset": 0
    });
    let any_with_own_party = json!({
        "eventFormat": {"filtersByParty": {&p1: {}}, "filtersForAnyParty": wildcard},
        "activeAtOffset": 0
    });
    let any_alone = json!({"eventFormat": {"filtersForAnyParty": wildcard}, "activeAtOffset": 0});
    let updates = |format: &Value| json!({"beginExclusive": 0, "updateFormat": {"includeTransactions": {"eventFormat": format["eventFormat"], "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"}}});
    for (user, expected) in [("nobody", 403), ("reader", 403), ("anyreader", 200)] {
        for (name, body) in [
            ("empty filtersByParty", &any_with_no_party),
            ("own party in filtersByParty", &any_with_own_party),
            ("no filtersByParty", &any_alone),
        ] {
            assert_eq!(
                call(
                    &svc,
                    "POST",
                    "/v2/state/active-contracts",
                    body.clone(),
                    Some(&token(user))
                )
                .0,
                expected,
                "active contracts, {user}, {name}"
            );
            assert_eq!(
                call(
                    &svc,
                    "POST",
                    "/v2/updates",
                    updates(body),
                    Some(&token(user))
                )
                .0,
                expected,
                "updates, {user}, {name}"
            );
        }
    }
}

/// Executing a prepared transaction needs the right to execute as each of ITS `actAs` parties
/// (`InteractiveSubmissionServiceAuthorization.getExecuteSubmissionClaims`, Canton 3.7.2): a right over some other party is not enough.
#[test]
fn executing_a_prepared_transaction_needs_the_rights_of_its_act_as_parties() {
    let svc = service();
    svc.load_dar(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar"),
    )
    .unwrap();
    let admin = token("participant_admin");
    let party = |hint: &str| {
        let (s, b) = call(
            &svc,
            "POST",
            "/v2/parties",
            json!({"partyIdHint": hint, "identityProviderId": ""}),
            Some(&admin),
        );
        assert_eq!(s, 200, "{b}");
        b["partyDetails"]["party"].as_str().unwrap().to_string()
    };
    let (p1, p2) = (party("p1"), party("p2"));
    for (id, of) in [("owner", &p1), ("other", &p2)] {
        let (s, b) = call(
            &svc,
            "POST",
            "/v2/users",
            json!({"user": {"id": id}, "rights": [{"kind": {"CanActAs": {"value": {"party": of}}}}]}),
            Some(&admin),
        );
        assert_eq!(s, 200, "{b}");
    }
    let sync_id = call(
        &svc,
        "GET",
        "/v2/state/connected-synchronizers",
        Value::Null,
        Some(&admin),
    )
    .1["connectedSynchronizers"][0]["synchronizerId"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, prep) = call(
        &svc,
        "POST",
        "/v2/interactive-submission/prepare",
        json!({
            "commandId": "c1",
            "userId": "owner",
            "actAs": [&p1],
            "synchronizerId": sync_id,
            "packageIdSelectionPreference": [],
            "commands": [{"CreateCommand": {
                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                "createArguments": {"bank": &p1, "owner": &p1, "auditor": &p1, "assetSymbol": "USD", "amount": "1.0"}
            }}]
        }),
        Some(&token("owner")),
    );
    assert_eq!(s, 200, "{prep}");
    let execute = json!({
        "preparedTransaction": prep["preparedTransaction"],
        "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V2",
        "deduplicationPeriod": {"Empty": {}},
        "submissionId": "s1",
        "partySignatures": {"signatures": []}
    });
    for path in [
        "/v2/interactive-submission/execute",
        "/v2/interactive-submission/executeAndWait",
        "/v2/interactive-submission/executeAndWaitForTransaction",
    ] {
        assert_eq!(
            call(&svc, "POST", path, execute.clone(), Some(&token("other"))).0,
            403,
            "{path}: a user with rights over another party"
        );
        assert_eq!(
            call(&svc, "POST", path, execute.clone(), Some(&admin)).0,
            403,
            "{path}: an administrator without the party's rights"
        );
        // the party's own user passes the authorization (and is then refused for the missing signature, not for its rights)
        assert_eq!(
            call(&svc, "POST", path, execute.clone(), Some(&token("owner"))).0,
            400,
            "{path}: the user that may act as the party"
        );
    }
}

/// The parties a call reads as are checked wherever the request states a filter: the routes read the filter from different places of
/// the body (`eventFormat`, `updateFormat.includeTransactions.eventFormat`, `filter`, a submission's `transactionFormat`), so a filter
/// the check does not look at must not be the one that is served.
#[test]
fn every_filter_of_a_request_names_only_parties_the_user_may_read() {
    let svc = service();
    let admin = token("participant_admin");
    let party = |hint: &str| {
        let (s, b) = call(
            &svc,
            "POST",
            "/v2/parties",
            json!({"partyIdHint": hint, "identityProviderId": ""}),
            Some(&admin),
        );
        assert_eq!(s, 200, "{b}");
        b["partyDetails"]["party"].as_str().unwrap().to_string()
    };
    let (p1, p2) = (party("p1"), party("p2"));
    for (id, kind) in [("reader", "CanReadAs"), ("actor", "CanActAs")] {
        let (s, b) = call(
            &svc,
            "POST",
            "/v2/users",
            json!({"user": {"id": id}, "rights": [{"kind": {kind: {"value": {"party": &p1}}}}]}),
            Some(&admin),
        );
        assert_eq!(s, 200, "{b}");
    }
    let of = |party: &str| json!({"filtersByParty": {party: {}}});
    let shape = "TRANSACTION_SHAPE_ACS_DELTA";
    let reader = token("reader");
    // the check's first place names the user's own party, the place the route reads names another
    for (path, body) in [
        (
            "/v2/updates",
            json!({"beginExclusive": 0, "eventFormat": of(&p1),
                   "updateFormat": {"includeTransactions": {"eventFormat": of(&p2), "transactionShape": shape}}}),
        ),
        (
            "/v2/updates/flats",
            json!({"beginExclusive": 0, "eventFormat": of(&p1), "filter": of(&p2)}),
        ),
        (
            "/v2/updates/flats",
            json!({"beginExclusive": 0, "eventFormat": of(&p1),
                   "updateFormat": {"includeTransactions": {"eventFormat": of(&p2), "transactionShape": shape}}}),
        ),
    ] {
        assert_eq!(
            call(&svc, "POST", path, body.clone(), Some(&reader)).0,
            403,
            "{path} {body}"
        );
    }
    // control: the same routes with the user's own party in both places
    assert_eq!(
        call(
            &svc,
            "POST",
            "/v2/updates",
            json!({"beginExclusive": 0, "eventFormat": of(&p1),
                   "updateFormat": {"includeTransactions": {"eventFormat": of(&p1), "transactionShape": shape}}}),
            Some(&reader),
        )
        .0,
        200
    );

    // a submission returns its transaction as the parties of `transactionFormat` see it: those are read rights too
    // (`CommandServiceAuthorization`, Canton 3.7.2)
    let actor = token("actor");
    let submit = |format: Value| {
        json!({
            "commands": {"commands": [], "commandId": "c", "actAs": [&p1], "userId": "actor"},
            "transactionFormat": {"eventFormat": format, "transactionShape": shape}
        })
    };
    let path = "/v2/commands/submit-and-wait-for-transaction";
    assert_eq!(
        call(&svc, "POST", path, submit(of(&p2)), Some(&actor)).0,
        403,
        "another party's view of the transaction"
    );
    assert_eq!(
        call(
            &svc,
            "POST",
            path,
            submit(json!({"filtersForAnyParty": {}})),
            Some(&actor)
        )
        .0,
        403,
        "every party's view of the transaction"
    );
    assert_ne!(
        call(&svc, "POST", path, submit(of(&p1)), Some(&actor)).0,
        403,
        "its own view of the transaction"
    );
}
