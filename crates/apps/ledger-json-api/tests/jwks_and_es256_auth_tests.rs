#![allow(clippy::unwrap_used, reason = "integration test")]
//! S-API-029: JWKS, ES256, multi auth-services, Wildcard, target-scope, leeway, dynamic IDP JWKS,
//! and HOCON `include` integration tests for `ledger-json-api`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{SystemTime, UNIX_EPOCH};

use ledger_json_api::auth::sign_token;
use ledger_json_api::auth_jwks::JwksCacheConfig;
#[cfg(feature = "protocol")]
use ledger_json_api::canton_conf;
use ledger_json_api::{dispatch_request, AuthConfig, ExecutionService, HttpRequest};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value as Json};

fn b64url(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in data.chunks(3) {
        let b0 = c[0] as u32;
        let b1 = *c.get(1).unwrap_or(&0) as u32;
        let b2 = *c.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        if c.len() > 1 {
            out.push(TABLE[(n >> 6) as usize & 63] as char);
        }
        if c.len() > 2 {
            out.push(TABLE[n as usize & 63] as char);
        }
    }
    out
}

fn sign_es256(kp: &EcdsaKeyPair, header: &Json, claims: &Json) -> String {
    let h = b64url(header.to_string().as_bytes());
    let p = b64url(claims.to_string().as_bytes());
    let input = format!("{h}.{p}");
    let rng = SystemRandom::new();
    let sig = kp.sign(&rng, input.as_bytes()).unwrap();
    let s = b64url(sig.as_ref());
    format!("{input}.{s}")
}

fn req(method: &str, path: &str, token: Option<&str>, body: Json) -> HttpRequest {
    let mut headers = HashMap::new();
    if let Some(t) = token {
        headers.insert("authorization".into(), format!("Bearer {t}"));
    }
    HttpRequest {
        method: method.into(),
        path: path.into(),
        query_params: HashMap::new(),
        headers,
        body: if body.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&body).unwrap()
        },
    }
}

fn spawn_jwks_server(jwks_body: Json) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let bytes = serde_json::to_vec(&jwks_body).unwrap();
    std::thread::spawn(move || {
        for _ in 0..8 {
            let Ok((mut s, _)) = listener.accept() else {
                break;
            };
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf);
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            let _ = s.write_all(hdr.as_bytes());
            let _ = s.write_all(&bytes);
        }
    });
    format!("http://127.0.0.1:{port}/.well-known/jwks.json")
}

#[test]
fn jwks_es256_multi_wildcard_and_dynamic_idp() {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let kp =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let pub_bytes = kp.public_key().as_ref();
    assert_eq!(pub_bytes[0], 0x04);
    let x = b64url(&pub_bytes[1..33]);
    let y = b64url(&pub_bytes[33..65]);
    let jwks_url = spawn_jwks_server(json!({
        "keys": [{ "kty": "EC", "crv": "P-256", "kid": "ec-1", "use": "sig", "x": x, "y": y }]
    }));

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let svc = ExecutionService::new();
    let cfg_jwks = AuthConfig::jwks(&jwks_url, JwksCacheConfig::default());
    let cfg_hmac = AuthConfig::hmac("s1").with_target_scope("custom_scope");
    svc.set_auth(AuthConfig::multi(vec![cfg_jwks, cfg_hmac]));

    // 1. ES256 JWKS token with `kid` succeeds; missing `kid` fails with 401.
    let valid_es256 = sign_es256(
        &kp,
        &json!({ "alg": "ES256", "typ": "JWT", "kid": "ec-1" }),
        &json!({ "sub": "participant_admin", "scope": "daml_ledger_api", "exp": now + 120 }),
    );
    let no_kid_es256 = sign_es256(
        &kp,
        &json!({ "alg": "ES256", "typ": "JWT" }),
        &json!({ "sub": "participant_admin", "scope": "daml_ledger_api", "exp": now + 120 }),
    );
    assert_eq!(
        dispatch_request(
            &svc,
            &req("GET", "/v2/version", Some(&valid_es256), Json::Null)
        )
        .status,
        200
    );
    assert_eq!(
        dispatch_request(
            &svc,
            &req("GET", "/v2/version", Some(&no_kid_es256), Json::Null)
        )
        .status,
        401
    );

    // 2. target-scope check on second validator in multi().
    let good_scope = sign_token(
        "s1",
        &json!({ "sub": "participant_admin", "scope": "custom_scope", "exp": now + 120 }),
    );
    let wrong_scope = sign_token(
        "s1",
        &json!({ "sub": "participant_admin", "scope": "daml_ledger_api", "exp": now + 120 }),
    );
    assert_eq!(
        dispatch_request(
            &svc,
            &req("GET", "/v2/version", Some(&good_scope), Json::Null)
        )
        .status,
        200
    );
    assert_eq!(
        dispatch_request(
            &svc,
            &req("GET", "/v2/version", Some(&wrong_scope), Json::Null)
        )
        .status,
        401
    );

    // 3. Dynamic IDP JWKS: register IDP + IDP-scoped user, verify cross-IDP & deactivation rejection.
    let idp_url = spawn_jwks_server(json!({
        "keys": [{ "kty": "EC", "crv": "P-256", "kid": "idp-k", "use": "sig", "x": x, "y": y }]
    }));
    let r_idp = dispatch_request(
        &svc,
        &req(
            "POST",
            "/v2/idps",
            Some(&valid_es256),
            json!({
                "identityProviderConfig": {
                    "identityProviderId": "idp-alpha",
                    "isDeactivated": false,
                    "issuer": "https://idp.alpha.example",
                    "jwksUrl": &idp_url,
                    "audience": "ledger-aud"
                }
            }),
        ),
    );
    assert_eq!(r_idp.status, 200);
    let r_usr = dispatch_request(
        &svc,
        &req(
            "POST",
            "/v2/users",
            Some(&valid_es256),
            json!({
                "user": { "id": "u_alpha", "identityProviderId": "idp-alpha" },
                "rights": [{ "kind": { "ParticipantAdmin": { "value": {} } } }]
            }),
        ),
    );
    assert_eq!(r_usr.status, 200);

    let idp_tok = sign_es256(
        &kp,
        &json!({ "alg": "ES256", "typ": "JWT", "kid": "idp-k" }),
        &json!({
            "sub": "u_alpha",
            "iss": "https://idp.alpha.example",
            "aud": "ledger-aud",
            "exp": now + 120
        }),
    );
    assert_eq!(
        dispatch_request(&svc, &req("GET", "/v2/version", Some(&idp_tok), Json::Null)).status,
        200
    );

    // Cross-IDP user rejection: default user `participant_admin` cannot auth under `idp-alpha`.
    let cross_tok = sign_es256(
        &kp,
        &json!({ "alg": "ES256", "typ": "JWT", "kid": "idp-k" }),
        &json!({
            "sub": "participant_admin",
            "iss": "https://idp.alpha.example",
            "aud": "ledger-aud",
            "exp": now + 120
        }),
    );
    assert_eq!(
        dispatch_request(
            &svc,
            &req("GET", "/v2/version", Some(&cross_tok), Json::Null)
        )
        .status,
        403
    );

    // 4. Wildcard grants full access with no bearer header.
    let w_svc = ExecutionService::new();
    w_svc.set_auth(AuthConfig::wildcard());
    assert_eq!(
        dispatch_request(&w_svc, &req("GET", "/v2/version", None, Json::Null)).status,
        200
    );

    // 5. ES256 X.509 certificate (`jwt-es-256-crt`) accepts valid P-256 JWT and rejects wrong sig.
    let mut spki = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    spki.extend_from_slice(pub_bytes);
    let mut tbs = vec![
        0x02, 0x01, 0x01, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00,
    ];
    tbs.extend_from_slice(&spki);
    let mut tbs_tlv = vec![0x30, tbs.len() as u8];
    tbs_tlv.extend_from_slice(&tbs);
    let mut cert_inner = tbs_tlv;
    cert_inner.extend_from_slice(&[0x30, 0x00, 0x03, 0x01, 0x00]);
    let mut cert_der = vec![0x30, 0x81, cert_inner.len() as u8];
    if cert_inner.len() < 128 {
        cert_der = vec![0x30, cert_inner.len() as u8];
    }
    cert_der.extend_from_slice(&cert_inner);
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        b64(&cert_der)
    );
    let cert_svc = ExecutionService::new();
    cert_svc.set_auth(AuthConfig::es256_certificate(&pem).unwrap());
    let es256_plain = sign_es256(
        &kp,
        &json!({ "alg": "ES256", "typ": "JWT" }),
        &json!({ "sub": "participant_admin", "scope": "daml_ledger_api", "exp": now + 120 }),
    );
    assert_eq!(
        dispatch_request(
            &cert_svc,
            &req("GET", "/v2/version", Some(&es256_plain), Json::Null)
        )
        .status,
        200
    );
    assert_eq!(
        dispatch_request(
            &cert_svc,
            &req("GET", "/v2/version", Some(&good_scope), Json::Null)
        )
        .status,
        401
    );
}

fn b64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let b0 = c[0] as u32;
        let b1 = *c.get(1).unwrap_or(&0) as u32;
        let b2 = *c.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(feature = "protocol")]
#[test]
fn canton_conf_supports_hocon_include_multi_auth_and_traffic_enforcement() {
    let dir = std::env::temp_dir().join(format!(
        "canton-conf-inc-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let inc = dir.join("auth-shared.conf");
    let main_conf = dir.join("canton.conf");
    std::fs::write(
        &inc,
        r#"
        _shared.auth = {
          type = unsafe-jwt-hmac-256
          secret = "included-secret"
          target-scope = "my-scope"
        }
        "#,
    )
    .unwrap();
    std::fs::write(
        &main_conf,
        r#"
        include "auth-shared.conf"
        canton.participants.p1 {
          http-ledger-api {
            port = 7575
            traffic-enforcement = true
          }
          ledger-api {
            port = 6501
            max-token-life = 1h
            jwt-timestamp-leeway.default = 15s
            auth-services = [${_shared.auth}, { type = wildcard }]
          }
        }
        "#,
    )
    .unwrap();

    let loaded = canton_conf::read(&main_conf, Some("p1"), None, None).unwrap();
    assert!(loaded.traffic_enforcement);
    assert_eq!(loaded.http_port, Some(7575));
    assert_eq!(
        loaded.auth_services,
        vec!["unsafe-jwt-hmac-256", "wildcard"]
    );
    assert!(loaded.auth.is_some());

    let svc = ExecutionService::new();
    svc.set_auth(loaded.auth.unwrap());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let tok = sign_token(
        "included-secret",
        &json!({ "sub": "participant_admin", "scope": "my-scope", "exp": now + 1800 }),
    );
    assert_eq!(
        dispatch_request(&svc, &req("GET", "/v2/version", Some(&tok), Json::Null)).status,
        200
    );
    let _ = std::fs::remove_dir_all(&dir);
}
