//! Official gRPC Ledger API v2 service interfaces, JWT token parsing,
//! command deduplication window, and transaction update stream.

use std::collections::HashMap;

use crate::models::ledger_api::DeduplicationPeriod;
use crate::service::ApiError;

/// Parsed Daml Ledger API JWT claims (RFC 7519 / Daml JWT v1/v2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JwtClaims {
    #[serde(default)]
    pub sub: String,
    #[serde(default, alias = "actAs")]
    pub act_as: Vec<String>,
    #[serde(default, alias = "readAs")]
    pub read_as: Vec<String>,
    #[serde(default)]
    pub admin: bool,
    #[serde(default, alias = "applicationId")]
    pub application_id: Option<String>,
    #[serde(default)]
    pub exp: Option<u64>,
}

impl JwtClaims {
    pub fn new(sub: impl Into<String>, act_as: Vec<String>, read_as: Vec<String>) -> Self {
        Self {
            sub: sub.into(),
            act_as,
            read_as,
            admin: false,
            application_id: None,
            exp: None,
        }
    }

    /// Parses a Bearer token or raw auth string.
    /// Supports:
    /// 1. Standard Daml JWT: 3 base64/base64url segments `header.payload.sig`.
    /// 2. Raw JSON string `{"actAs": ["Alice"], ...}`.
    /// 3. Legacy party string: `"Alice"` or `"Bank,Alice"`.
    pub fn parse_bearer_token(token: &str) -> Result<Self, ApiError> {
        let trimmed = token.trim();
        let payload_str = if trimmed.starts_with('{') {
            trimmed.to_string()
        } else if trimmed.contains('.') {
            // JWT format: header.payload.signature
            let parts: Vec<&str> = trimmed.split('.').collect();
            if parts.len() >= 2 {
                let payload_b64 = parts[1];
                let decoded = base64_decode_flexible(payload_b64).map_err(|e| {
                    ApiError::Unauthorized(format!("Invalid JWT payload base64: {e}"))
                })?;
                String::from_utf8(decoded)
                    .map_err(|e| ApiError::Unauthorized(format!("Invalid JWT UTF-8: {e}")))?
            } else {
                return Err(ApiError::Unauthorized("Malformed JWT token".into()));
            }
        } else {
            // Comma-separated party names
            let parties: Vec<String> = trimmed
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let sub = parties
                .first()
                .cloned()
                .unwrap_or_else(|| "anonymous".into());
            return Ok(Self {
                sub,
                act_as: parties.clone(),
                read_as: parties,
                admin: false,
                application_id: None,
                exp: None,
            });
        };

        let claims: JwtClaims = serde_json::from_str(&payload_str)
            .map_err(|e| ApiError::Unauthorized(format!("Malformed JWT claims JSON: {e}")))?;

        // Verify expiration if present
        if let Some(exp) = claims.exp {
            let now = crate::clock::now_secs();
            if exp > 0 && exp < now {
                return Err(ApiError::Unauthorized(format!(
                    "JWT token expired: exp {exp} < current {now}"
                )));
            }
        }

        Ok(claims)
    }
}

fn base64_decode_flexible(s: &str) -> Result<Vec<u8>, String> {
    // Standard and URL-safe base64 decoding with padding tolerance
    let mut normalized = s.replace('-', "+").replace('_', "/");
    while !normalized.len().is_multiple_of(4) {
        normalized.push('=');
    }
    use base64_crate_inline::decode;
    decode(&normalized).map_err(|e| e.to_string())
}

mod base64_crate_inline {
    pub fn decode(input: &str) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0;
        for &b in input.as_bytes() {
            if b == b'=' {
                break;
            }
            let val = match b {
                b'A'..=b'Z' => (b - b'A') as u32,
                b'a'..=b'z' => (b - b'a' + 26) as u32,
                b'0'..=b'9' => (b - b'0' + 52) as u32,
                b'+' => 62,
                b'/' => 63,
                b' ' | b'\r' | b'\n' | b'\t' => continue,
                _ => return Err("invalid character"),
            };
            buf = (buf << 6) | val;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
        Ok(out)
    }
}

/// Deduplication window tracker entry.
#[derive(Debug, Clone)]
pub struct DedupEntry {
    pub submission_time: u64,
    pub expiry_time: u64,
    pub offset: u64,
}

/// Command Deduplication Store (AT-U01, AT-T03).
#[derive(Debug, Clone, Default)]
pub struct DeduplicationStore {
    entries: HashMap<(String, String), DedupEntry>,
}

impl DeduplicationStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> &HashMap<(String, String), DedupEntry> {
        &self.entries
    }

    pub fn from_entries(entries: HashMap<(String, String), DedupEntry>) -> Self {
        Self { entries }
    }

    /// Checks if a command is already tracked within its deduplication period.
    /// If duplicate, returns ApiError::PreconditionFailed.
    /// Otherwise, inserts the record and returns Ok(()).
    pub fn check_and_insert(
        &mut self,
        app_id: &str,
        command_id: &str,
        period: Option<&DeduplicationPeriod>,
        current_time: u64,
        offset: u64,
    ) -> Result<(), ApiError> {
        let key = (app_id.to_string(), command_id.to_string());
        let duration_secs = match period {
            Some(DeduplicationPeriod::DurationInSeconds(d)) => *d,
            _ => 300, // default 5 minutes deduplication window
        };
        let expiry = current_time + duration_secs;

        if let Some(existing) = self.entries.get(&key) {
            if current_time < existing.expiry_time {
                return Err(ApiError::PreconditionFailed(format!(
                    "Command deduplication rejection: duplicate command_id '{command_id}' for application '{app_id}' within active window (expires at {})",
                    existing.expiry_time
                )));
            }
        }

        self.entries.insert(
            key,
            DedupEntry {
                submission_time: current_time,
                expiry_time: expiry,
                offset,
            },
        );

        Ok(())
    }

    pub fn prune_expired(&mut self, current_time: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, v| v.expiry_time > current_time);
        before - self.entries.len()
    }

    pub fn is_tracked(&self, app_id: &str, command_id: &str, current_time: u64) -> bool {
        if let Some(entry) = self
            .entries
            .get(&(app_id.to_string(), command_id.to_string()))
        {
            entry.expiry_time > current_time
        } else {
            false
        }
    }
}

/// Completion response event for CommandCompletionService.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommandCompletion {
    pub command_id: String,
    pub application_id: String,
    pub status_code: u32,
    pub offset: u64,
}

/// Completion stream response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompletionStreamResponse {
    pub offset: u64,
    pub completions: Vec<CommandCompletion>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_claims_parsing_plain() {
        let claims = JwtClaims::parse_bearer_token("Alice,Bank").expect("parse claims");
        assert_eq!(claims.act_as, vec!["Alice", "Bank"]);
        assert_eq!(claims.read_as, vec!["Alice", "Bank"]);
    }

    #[test]
    fn test_jwt_claims_parsing_json() {
        let json_token = r#"{"sub": "user1", "actAs": ["Alice"], "readAs": ["Bank"], "admin": true, "exp": 9999999999}"#;
        let claims = JwtClaims::parse_bearer_token(json_token).expect("parse json jwt");
        assert_eq!(claims.sub, "user1");
        assert_eq!(claims.act_as, vec!["Alice"]);
        assert_eq!(claims.read_as, vec!["Bank"]);
        assert!(claims.admin);
    }

    #[test]
    fn test_deduplication_store_window_and_rejection() {
        let mut store = DeduplicationStore::new();
        let app = "test-app";
        let cmd = "cmd-001";
        let period = DeduplicationPeriod::DurationInSeconds(60);

        store
            .check_and_insert(app, cmd, Some(&period), 100, 1)
            .expect("first insert ok");

        // Duplicate within 60s window -> MUST REJECT
        let dup = store.check_and_insert(app, cmd, Some(&period), 120, 2);
        assert!(dup.is_err());

        // After window expiry (at t=161 > 160) -> MUST SUCCEED
        store
            .check_and_insert(app, cmd, Some(&period), 161, 3)
            .expect("insert after expiry ok");
    }
}
