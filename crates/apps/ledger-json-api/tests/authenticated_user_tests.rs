//! `GET /v2/authenticated-user` answers with the user the bearer token names (its `sub`), as the official participant does: the Wallet SDK asks for
//! it first (S-SDK-001, `scripts/compare-wallet-sdk-traces.py` compares it with the official node). Without a token there is no authenticated user.
use ledger_json_api::service::ExecutionService;
use ledger_json_api::{dispatch_request, HttpRequest};
use serde_json::Value;

fn token(sub: &str) -> String {
    // the payload is all a handler reads: the signature is checked (or not) before it, by the auth layer
    let b64 = |s: &str| {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let bytes = s.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            for i in 0..=chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        out
    };
    format!(
        "{}.{}.sig",
        b64(r#"{"alg":"HS256","typ":"JWT"}"#),
        b64(&format!(r#"{{"sub":"{sub}"}}"#))
    )
}

fn get(service: &ExecutionService, bearer: Option<String>) -> (u16, Value) {
    let mut headers = std::collections::HashMap::new();
    if let Some(t) = bearer {
        headers.insert("Authorization".to_string(), format!("Bearer {t}"));
    }
    let resp = dispatch_request(
        service,
        &HttpRequest {
            method: "GET".into(),
            path: "/v2/authenticated-user".into(),
            query_params: Default::default(),
            headers,
            body: Vec::new(),
        },
    );
    (
        resp.status,
        serde_json::from_slice(&resp.body).unwrap_or_default(),
    )
}

#[test]
fn the_authenticated_user_is_the_one_of_the_token() {
    let service = ExecutionService::new();
    let (status, body) = get(&service, Some(token("participant_admin")));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["user"]["id"], "participant_admin");
}

#[test]
fn a_token_of_an_unknown_user_is_not_found_and_no_token_is_refused() {
    let service = ExecutionService::new();
    let (status, body) = get(&service, Some(token("nobody")));
    assert_eq!(status, 404, "{body}");
    let (status, body) = get(&service, None);
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["code"], "INVALID_TOKEN");
}
