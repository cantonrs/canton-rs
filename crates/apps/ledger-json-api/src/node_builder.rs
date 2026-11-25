//! `CantonNodeBuilder` — Embeddable In-Process Pure-Rust Daml-LF 2 & Ledger API SDK (`reth` NodeBuilder pattern).
//!
//! Allows SI, custody, HSM, and trading systems to embed a single-node in-process Canton ExecutionService
//! + `lf-eval` engine + privacy-scoped [`CantonExEx`](crate::exex) hooks inside a host Rust process.
//!
//! For multi-node Canton synchronizer protocol participation, attach a real `ProtocolCommitter` / `canton-rs json-api --sequencer`.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use serde_json::{json, Value as Json};

use crate::auth::AuthConfig;
use crate::exex::{ExExNotification, ExExPartyScope, ExExSubscriberStats};
use crate::http::{route_internal, run_server, HttpRequest};
use crate::service::{ExecutionService, GenericContract};

/// Specification of a channel-backed ExEx registered during [`CantonNodeBuilder`] assembly.
struct PendingFileExEx {
    name: String,
    scope: ExExPartyScope,
    path: PathBuf,
    capacity: usize,
}

/// Declarative, type-safe builder for assembling an embedded [`CantonEmbeddedNode`].
pub struct CantonNodeBuilder {
    service: Arc<ExecutionService>,
    synchronizer_id: String,
    dar_files: Vec<PathBuf>,
    dar_blobs: Vec<Vec<u8>>,
    max_dedup: Option<Duration>,
    auth: Option<AuthConfig>,
    traffic_enforcement: bool,
    pending_file_exexes: Vec<PendingFileExEx>,
}

impl Default for CantonNodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CantonNodeBuilder {
    /// Starts configuring a new embedded Canton Participant + Daml-LF 2 runtime.
    pub fn new() -> Self {
        Self {
            service: Arc::new(ExecutionService::new()),
            synchronizer_id: "embedded-sync::1220cantonrs".to_string(),
            dar_files: Vec::new(),
            dar_blobs: Vec::new(),
            max_dedup: None,
            auth: None,
            traffic_enforcement: false,
            pending_file_exexes: Vec::new(),
        }
    }

    /// Sets the logical synchronizer identifier reported on Ledger API v2 updates and ExEx events.
    pub fn synchronizer_id(mut self, sync_id: impl Into<String>) -> Self {
        self.synchronizer_id = sync_id.into();
        self
    }

    /// Queues a `.dar` archive path to be typechecked and loaded on [`Self::build`].
    pub fn with_dar_file(mut self, path: impl AsRef<Path>) -> Self {
        self.dar_files.push(path.as_ref().to_path_buf());
        self
    }

    /// Queues in-memory `.dar` archive bytes to be typechecked and loaded on [`Self::build`].
    pub fn with_dar_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.dar_blobs.push(bytes);
        self
    }

    /// Configures command deduplication window duration (protects recent offsets from pruning).
    pub fn with_max_dedup(mut self, duration: Duration) -> Self {
        self.max_dedup = Some(duration);
        self
    }

    /// Enables JWT authentication (`HS256`, `RS256`, `ES256`–`ES512`, or `JWKS`) when HTTP is served.
    pub fn with_auth(mut self, auth: AuthConfig) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Enables `/v2/traffic/*` enforcement endpoints.
    pub fn with_traffic_enforcement(mut self, enabled: bool) -> Self {
        self.traffic_enforcement = enabled;
        self
    }

    /// Installs an in-process [`CantonExEx`](crate::exex) channel hook with explicit party visibility scoping.
    pub fn install_exex(
        self,
        name: impl Into<String>,
        scope: ExExPartyScope,
        capacity: usize,
    ) -> (Self, mpsc::Receiver<ExExNotification>) {
        let rx = self.service.exex().register_channel(name, scope, capacity);
        (self, rx)
    }

    /// Installs a background JSONL file sink ExEx flushed on a dedicated OS thread.
    pub fn install_jsonl_exex(
        mut self,
        name: impl Into<String>,
        scope: ExExPartyScope,
        output_path: impl AsRef<Path>,
        capacity: usize,
    ) -> Self {
        self.pending_file_exexes.push(PendingFileExEx {
            name: name.into(),
            scope,
            path: output_path.as_ref().to_path_buf(),
            capacity,
        });
        self
    }

    /// Validates and initializes all queued DAR packages and ExEx hooks, returning a live [`CantonEmbeddedNode`].
    pub fn build(self) -> Result<CantonEmbeddedNode, String> {
        self.service
            .v2_state()
            .set_synchronizer(&self.synchronizer_id);
        if let Some(d) = self.max_dedup {
            self.service.set_max_dedup(d);
        }
        if let Some(auth) = self.auth {
            self.service.set_auth(auth);
        }
        self.service
            .set_traffic_enforcement(self.traffic_enforcement);

        for dar_path in &self.dar_files {
            self.service
                .load_dar(dar_path)
                .map_err(|e| format!("failed to load DAR {}: {e}", dar_path.display()))?;
        }
        for blob in self.dar_blobs {
            let mut headers = std::collections::HashMap::new();
            headers.insert(
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            );
            let req = HttpRequest {
                method: "POST".to_string(),
                path: "/v2/dars".to_string(),
                query_params: std::collections::HashMap::new(),
                headers,
                body: blob,
            };
            let resp = route_internal(&self.service, &req);
            if resp.status != 200 {
                return Err(format!(
                    "failed to load in-memory DAR bytes (HTTP {}): {}",
                    resp.status,
                    String::from_utf8_lossy(&resp.body)
                ));
            }
        }
        for pending in self.pending_file_exexes {
            self.service.exex().register_jsonl_file_sink(
                pending.name,
                pending.scope,
                &pending.path,
                pending.capacity,
            )?;
        }

        Ok(CantonEmbeddedNode {
            service: self.service,
        })
    }
}

/// Running handle to an embedded pure-Rust Canton Participant & Daml-LF 2 execution engine.
#[derive(Clone)]
pub struct CantonEmbeddedNode {
    service: Arc<ExecutionService>,
}

impl CantonEmbeddedNode {
    /// Returns the underlying [`ExecutionService`] handle for direct integration with gRPC/HTTP routers.
    pub fn execution_service(&self) -> &Arc<ExecutionService> {
        &self.service
    }

    /// Allocates a party on the embedded participant (`POST /v2/parties` equivalent without TCP).
    pub fn allocate_party(&self, hint: &str) -> Result<String, String> {
        let req = HttpRequest::json_post("/v2/parties", &json!({ "partyIdHint": hint }));
        let resp = route_internal(&self.service, &req);
        if resp.status != 200 {
            return Err(format!(
                "allocate_party('{hint}') failed (HTTP {}): {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }
        let parsed: Json = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
        parsed
            .get("partyDetails")
            .and_then(|d| d.get("party"))
            .and_then(Json::as_str)
            .map(String::from)
            .ok_or_else(|| "missing partyDetails.party in v2 response".to_string())
    }

    /// Submits an in-process `CreateCommand` via Ledger API v2 semantics and returns `(offset, contract_id)`.
    pub fn submit_create(
        &self,
        act_as: &[String],
        command_id: &str,
        template_id: &str,
        create_arguments: Json,
    ) -> Result<(u64, String), String> {
        let body = json!({
            "commands": {
                "userId": "embedded-sdk",
                "commandId": command_id,
                "actAs": act_as,
                "commands": [{
                    "CreateCommand": {
                        "templateId": template_id,
                        "createArguments": create_arguments,
                    }
                }]
            }
        });
        let req = HttpRequest::json_post("/v2/commands/submit-and-wait-for-transaction", &body);
        let resp = route_internal(&self.service, &req);
        if resp.status != 200 {
            return Err(format!(
                "submit_create failed (HTTP {}): {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }
        let parsed: Json = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
        let tx = parsed
            .get("transaction")
            .ok_or_else(|| "missing transaction in submit response".to_string())?;
        let offset = tx
            .get("offset")
            .and_then(Json::as_u64)
            .ok_or_else(|| "missing transaction.offset".to_string())?;
        let cid = tx
            .get("events")
            .and_then(Json::as_array)
            .and_then(|arr| arr.first())
            .and_then(|ev| ev.get("CreatedEvent"))
            .and_then(|ce| ce.get("contractId"))
            .and_then(Json::as_str)
            .map(String::from)
            .ok_or_else(|| "missing CreatedEvent.contractId".to_string())?;
        Ok((offset, cid))
    }

    /// Submits an in-process `ExerciseCommand` via Ledger API v2 semantics and returns the committed `offset`.
    pub fn submit_exercise(
        &self,
        act_as: &[String],
        command_id: &str,
        template_id: &str,
        contract_id: &str,
        choice: &str,
        choice_argument: Json,
    ) -> Result<u64, String> {
        let body = json!({
            "commands": {
                "userId": "embedded-sdk",
                "commandId": command_id,
                "actAs": act_as,
                "commands": [{
                    "ExerciseCommand": {
                        "templateId": template_id,
                        "contractId": contract_id,
                        "choice": choice,
                        "choiceArgument": choice_argument,
                    }
                }]
            }
        });
        let req = HttpRequest::json_post("/v2/commands/submit-and-wait-for-transaction", &body);
        let resp = route_internal(&self.service, &req);
        if resp.status != 200 {
            return Err(format!(
                "submit_exercise failed (HTTP {}): {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }
        let parsed: Json = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
        parsed
            .get("transaction")
            .and_then(|tx| tx.get("offset"))
            .and_then(Json::as_u64)
            .ok_or_else(|| "missing transaction.offset".to_string())
    }

    /// Registers a new live ExEx subscriber with optional historical backfill from `from_offset` under `commit_publish_lock`.
    pub fn subscribe_exex_with_backfill(
        &self,
        name: impl Into<String>,
        scope: ExExPartyScope,
        from_offset: Option<u64>,
        capacity: usize,
    ) -> (Vec<ExExNotification>, mpsc::Receiver<ExExNotification>) {
        let _publish_guard = self
            .service
            .v2_state()
            .commit_publish_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let backfilled = match from_offset {
            Some(from) => self.service.backfill_exex_from(from, &scope),
            None => Vec::new(),
        };
        let rx = self.service.exex().register_channel(name, scope, capacity);
        (backfilled, rx)
    }

    /// Returns active generic contracts currently visible to `party`.
    pub fn active_contracts_for_party(&self, party: &str) -> Vec<GenericContract> {
        self.service
            .v2_active_contracts()
            .into_iter()
            .filter(|c| {
                c.signatories.iter().any(|p| p == party)
                    || c.observers.iter().any(|p| p == party)
                    || c.witness_parties.iter().any(|p| p == party)
            })
            .collect()
    }

    /// Returns current Ledger End offset.
    pub fn ledger_end(&self) -> u64 {
        self.service.v2_state().ledger_end.load(Ordering::SeqCst)
    }

    /// Returns telemetry snapshots for all registered `CantonExEx` subscribers.
    pub fn exex_stats(&self) -> Vec<ExExSubscriberStats> {
        self.service.exex().stats()
    }

    /// Spawns a background HTTP/WebSocket Ledger API v2 server bound to `bind_addr` (`127.0.0.1:0` supported),
    /// returning `(bound_addr, shutdown_flag, join_handle)` so callers can observe shutdown drain and errors.
    pub fn serve_http_background(
        &self,
        bind_addr: &str,
    ) -> Result<
        (
            std::net::SocketAddr,
            Arc<AtomicBool>,
            std::thread::JoinHandle<std::io::Result<()>>,
        ),
        String,
    > {
        let listener =
            TcpListener::bind(bind_addr).map_err(|e| format!("cannot bind {bind_addr}: {e}"))?;
        let local_addr = listener.local_addr().map_err(|e| e.to_string())?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&shutdown);
        let svc = Arc::clone(&self.service);
        let handle = std::thread::spawn(move || run_server(svc, listener, stop_clone));
        Ok((local_addr, shutdown, handle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn embedded_node_builder_executes_daml_and_streams_privacy_scoped_exex() {
        let dar_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar");
        let (builder, rx_all) = CantonNodeBuilder::new()
            .synchronizer_id("sdk-sync::1220test")
            .with_dar_file(&dar_path)
            .install_exex("all-visible", ExExPartyScope::AllParticipantVisible, 16);
        let node = builder.build().expect("build embedded node");

        let alice = node.allocate_party("Alice").expect("allocate Alice");
        let bob = node.allocate_party("Bob").expect("allocate Bob");
        let eve = node.allocate_party("Eve").expect("allocate Eve");

        // Subscribe scoped ExExes for Alice and unauthorized Eve BEFORE submitting tx.
        let mut alice_set = BTreeSet::new();
        alice_set.insert(alice.clone());
        let mut eve_set = BTreeSet::new();
        eve_set.insert(eve);

        let (_bf_a, rx_alice) = node.subscribe_exex_with_backfill(
            "alice-exex",
            ExExPartyScope::Parties(alice_set.clone()),
            None,
            16,
        );
        let (_bf_e, rx_eve) = node.subscribe_exex_with_backfill(
            "eve-exex",
            ExExPartyScope::Parties(eve_set),
            None,
            16,
        );

        // Negative control: creating AssetHolding (signatory bank, owner) without owner Bob's auth must fail!
        let unauth = node.submit_create(
            std::slice::from_ref(&alice),
            "sdk-unauth-1",
            "#sample-contract:AssetHolding:AssetHolding",
            json!({
                "bank": alice,
                "owner": bob,
                "auditor": alice,
                "assetSymbol": "KRW_BOND",
                "amount": "500000.0"
            }),
        );
        assert!(
            unauth
                .as_ref()
                .is_err_and(|e| e.contains("DAML_AUTHORIZATION_ERROR")),
            "expected DAML_AUTHORIZATION_ERROR, got {unauth:?}"
        );

        let (offset, cid) = node
            .submit_create(
                &[alice.clone(), bob.clone()],
                "sdk-create-1",
                "#sample-contract:AssetHolding:AssetHolding",
                json!({
                    "bank": alice,
                    "owner": bob,
                    "auditor": alice,
                    "assetSymbol": "KRW_BOND",
                    "amount": "500000.0"
                }),
            )
            .expect("submit_create");
        assert!(offset >= 1);
        assert!(!cid.is_empty());

        // Live ExEx check: all-visible and Alice receive the committed contract; Eve receives NOTHING!
        assert!(rx_all.try_recv().is_ok());
        let alice_live = rx_alice.try_recv().expect("alice must receive live ExEx");
        let alice_json = serde_json::to_string(&alice_live).expect("json");
        assert!(alice_json.contains("KRW_BOND"));
        assert!(
            rx_eve.try_recv().is_err(),
            "negative control: Eve is not a stakeholder/witness and must receive zero ExEx events"
        );

        // Historical backfill check: late-joining ExEx from offset 1 receives the prior tx!
        let (backfilled, _rx_late) = node.subscribe_exex_with_backfill(
            "late-alice-indexer",
            ExExPartyScope::Parties(alice_set),
            Some(1),
            16,
        );
        assert_eq!(backfilled.len(), 1);
        assert_eq!(node.active_contracts_for_party(&bob).len(), 1);
    }

    #[test]
    fn with_auth_allows_internal_builder_calls_while_blocking_unauthenticated_http() {
        let dar_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar");
        let (builder, _) = CantonNodeBuilder::new()
            .synchronizer_id("sdk-sync::1220auth")
            .with_dar_file(&dar_path)
            .with_auth(AuthConfig::hmac("builder-secret"))
            .install_exex("all", ExExPartyScope::AllParticipantVisible, 8);
        let node = builder.build().expect("build authed node");

        let alice = node
            .allocate_party("AliceAuth")
            .expect("internal allocate_party");
        let end_after_party = node.ledger_end();
        let (off, cid) = node
            .submit_create(
                std::slice::from_ref(&alice),
                "sdk-auth-cmd",
                "#sample-contract:AssetHolding:AssetHolding",
                json!({
                    "bank": alice,
                    "owner": alice,
                    "auditor": alice,
                    "assetSymbol": "USD",
                    "amount": "10.0"
                }),
            )
            .expect("internal submit_create");
        assert_eq!(off, end_after_party + 1);
        assert!(!cid.is_empty());

        let unauth = crate::http::dispatch_request(
            node.execution_service(),
            &HttpRequest::json_post("/v2/parties", &json!({"partyIdHint": "Eve"})),
        );
        assert_eq!(unauth.status, 401);
    }
}
