//! `canton-rs splice bootstrap-ledger`: the Splice 0.10.1 DSO bootstrap run as Ledger API commands on a participant's JSON API (U-25).
//!
//! `canton-rs splice serve` runs the official Splice DARs in an engine of its own, so its contracts are in no participant's ledger and the
//! official Wallet SDK (which prepares, signs and executes commands on a participant and reads `AmuletRules` from scan) cannot use it.
//! This command puts the same contracts into a participant's ledger instead: it uploads the four DARs, allocates the DSO / SV / validator
//! parties, makes the user that submits, and runs the three steps `SpliceAppRuntime::bootstrap` runs in-process — create `DsoBootstrap`,
//! exercise `DsoBootstrap_Bootstrap`, exercise `DsoRules_OnboardValidator` — as `submit-and-wait-for-transaction` calls.
//!
//! [CANTON-NOTE: SEMANTICS] The create argument is `canton_participant::dso_bootstrap_payload`, the value the in-process runtime builds, so
//! both paths bootstrap the same configuration. Safe to run again: a ledger that already has a `DsoRules` is reported and left alone.
//! [CANTON-NOTE: LIMITATION] Plain HTTP (an optional bearer token); the time in the payload is this machine's clock, which is the ledger
//! time of the simulation-mode participant.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use canton_participant::{dso_bootstrap_payload, SpliceBootstrapConfig};
use clap::Args;
use serde_json::{json, Value as Json};

use super::json_http::{call_with_token, error_cause};

#[derive(Args, Debug)]
pub struct SpliceBootstrapLedgerArgs {
    /// The participant's JSON Ledger API host.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// The participant's JSON Ledger API port.
    #[arg(long, default_value_t = 7575)]
    pub port: u16,

    /// A bearer token with participant-admin rights, for a participant that checks JWTs (uploads the DARs, allocates the parties, makes the user).
    #[arg(long, env = "CANTON_RS_LEDGER_TOKEN")]
    pub token: Option<String>,

    /// The bearer token of `--user` (its `sub`) that reads the ledger and submits the bootstrap commands; the admin token when left out. A user
    /// that has only the participant-admin right cannot act as or read as a party, so with JWTs checked this is the token of the new user.
    #[arg(long, env = "CANTON_RS_LEDGER_USER_TOKEN")]
    pub user_token: Option<String>,

    /// Directory with the official Splice DAR archives.
    #[arg(long, default_value = "tests/oracle/splice-dars")]
    pub dar_dir: PathBuf,

    /// The user that submits the bootstrap commands and gets the right to act as the three parties (the Wallet SDK's `sub`).
    #[arg(long, default_value = "ledger-api-user")]
    pub user: String,

    /// Write the result (parties, synchronizer, contract ids) to this file as JSON too.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

struct Ledger<'a> {
    args: &'a SpliceBootstrapLedgerArgs,
}

impl Ledger<'_> {
    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Json>,
        content_type: &str,
    ) -> Result<(u16, Json), String> {
        let text = body.map(|b| b.to_string());
        call_with_token(
            &self.args.host,
            self.args.port,
            method,
            path,
            text.as_deref().map(|t| (t.as_bytes(), content_type)),
            self.token_for(path),
        )
    }

    /// The token of a call: the user's for what reads or submits as a party (the active contracts and the commands), else the admin's.
    fn token_for(&self, path: &str) -> Option<&str> {
        let as_user = path.starts_with("/v2/state/active-contracts")
            || path.starts_with("/v2/commands/")
            || path == "/v2/state/ledger-end";
        if as_user {
            self.args
                .user_token
                .as_deref()
                .or(self.args.token.as_deref())
        } else {
            self.args.token.as_deref()
        }
    }

    fn json(&self, method: &str, path: &str, body: Option<&Json>) -> Result<Json, String> {
        let (status, answer) = self.call(method, path, body, "application/json")?;
        if status / 100 != 2 {
            return Err(format!(
                "{method} {path} answered {status}: {}",
                error_cause(&answer)
            ));
        }
        Ok(answer)
    }

    fn upload_dar(&self, path: &Path) -> Result<(), String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let (status, answer) = super::json_http::call_with_token(
            &self.args.host,
            self.args.port,
            "POST",
            "/v2/dars",
            Some((&bytes, "application/octet-stream")),
            self.args.token.as_deref(),
        )?;
        if status / 100 != 2 {
            return Err(format!(
                "uploading {} answered {status}: {}",
                path.display(),
                error_cause(&answer)
            ));
        }
        Ok(())
    }

    /// The party `hint::…` (allocated now if the participant has none).
    fn party(&self, hint: &str) -> Result<String, String> {
        let listed = self.json("GET", "/v2/parties", None)?;
        let prefix = format!("{hint}::");
        if let Some(found) = listed["partyDetails"].as_array().and_then(|all| {
            all.iter()
                .filter_map(|p| p["party"].as_str())
                .find(|p| p.starts_with(&prefix))
        }) {
            return Ok(found.to_string());
        }
        let made = self.json(
            "POST",
            "/v2/parties",
            Some(&json!({ "partyIdHint": hint, "identityProviderId": "" })),
        )?;
        made["partyDetails"]["party"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| format!("allocating {hint}: no party in {made}"))
    }

    /// Creates `user` (act-as rights on `parties`) or adds the rights to the one that exists.
    fn user(&self, user: &str, parties: &[&str]) -> Result<(), String> {
        let rights: Vec<Json> = parties
            .iter()
            .map(|p| json!({ "kind": { "CanActAs": { "value": { "party": p } } } }))
            .chain(std::iter::once(
                json!({ "kind": { "ParticipantAdmin": { "value": {} } } }),
            ))
            .collect();
        let (status, answer) = self.call(
            "POST",
            "/v2/users",
            Some(&json!({
                "user": { "id": user, "isDeactivated": false, "primaryParty": "", "identityProviderId": "",
                          "metadata": { "resourceVersion": "", "annotations": {} } },
                "rights": rights,
            })),
            "application/json",
        )?;
        match status {
            200 => Ok(()),
            409 => {
                // The user exists (a second run, or the Wallet SDK's user made earlier): add the rights it may lack.
                self.json(
                    "POST",
                    &format!("/v2/users/{user}/rights"),
                    Some(&json!({ "userId": user, "identityProviderId": "", "rights": rights })),
                )
                .map(|_| ())
            }
            other => Err(format!(
                "creating user {user} answered {other}: {}",
                error_cause(&answer)
            )),
        }
    }

    /// One command as its own transaction; the events of the transaction.
    fn submit(
        &self,
        user: &str,
        act_as: &[&str],
        command_id: &str,
        command: Json,
    ) -> Result<Vec<Json>, String> {
        let answer = self.json(
            "POST",
            "/v2/commands/submit-and-wait-for-transaction",
            Some(&json!({
                "commands": {
                    "commands": [command],
                    "commandId": command_id,
                    "userId": user,
                    "actAs": act_as,
                    "readAs": [],
                },
                "transactionFormat": {
                    "eventFormat": {
                        "filtersByParty": act_as.iter().map(|p| (p.to_string(), json!({ "cumulative": [ { "identifierFilter": { "WildcardFilter": { "value": { "includeCreatedEventBlob": false } } } } ] }))).collect::<serde_json::Map<_, _>>(),
                        "verbose": true,
                    },
                    "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA",
                },
            })),
        )?;
        Ok(answer["transaction"]["events"]
            .as_array()
            .cloned()
            .unwrap_or_default())
    }
}

/// The contract id of the first created event of `template` (a `Module:Entity` suffix) among `events`.
fn created_cid(events: &[Json], template: &str) -> Option<String> {
    events.iter().find_map(|e| {
        let created = &e["CreatedEvent"];
        created["templateId"]
            .as_str()
            .filter(|t| t.ends_with(template))?;
        created["contractId"].as_str().map(String::from)
    })
}

pub fn execute_bootstrap_ledger(args: SpliceBootstrapLedgerArgs) -> Result<(), String> {
    let ledger = Ledger { args: &args };
    ledger.json("GET", "/v2/version", None).map_err(|e| {
        format!(
            "{e} (start a participant first: canton-rs json-api --port {})",
            args.port
        )
    })?;

    // 1. The four official DARs.
    let mut dars: Vec<PathBuf> = std::fs::read_dir(&args.dar_dir)
        .map_err(|e| format!("{}: {e}", args.dar_dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "dar"))
        .collect();
    dars.sort();
    if dars.is_empty() {
        return Err(format!("no .dar in {}", args.dar_dir.display()));
    }
    for dar in &dars {
        ledger.upload_dar(dar)?;
    }

    // 2. Parties (hosted on this participant), the submitting user, the synchronizer and the participant id.
    let dso = ledger.party("DSO")?;
    let sv = ledger.party("sv")?;
    let validator = ledger.party("validator")?;
    ledger.user(&args.user, &[&dso, &sv, &validator])?;
    let synchronizers = ledger.json("GET", "/v2/state/connected-synchronizers", None)?;
    let synchronizer_id = synchronizers["connectedSynchronizers"][0]["synchronizerId"]
        .as_str()
        .ok_or("the participant is connected to no synchronizer")?
        .to_string();
    let participant_id = ledger.json("GET", "/v2/parties/participant-id", None)?["participantId"]
        .as_str()
        .unwrap_or("PAR::participant::1220")
        .to_string();

    // 3. Already bootstrapped? (the ACS of the DSO party has a DsoRules)
    let ledger_end = ledger.json("GET", "/v2/state/ledger-end", None)?["offset"]
        .as_i64()
        .unwrap_or(0);
    let acs = ledger.json(
        "POST",
        "/v2/state/active-contracts",
        Some(&json!({
            "eventFormat": {
                "filtersByParty": { dso.as_str(): { "cumulative": [ { "identifierFilter": { "TemplateFilter": { "value": {
                    "templateId": "#splice-dso-governance:Splice.DsoRules:DsoRules", "includeCreatedEventBlob": false } } } } ] } },
                "verbose": false,
            },
            "activeAtOffset": ledger_end,
        })),
    )?;
    let existing = acs.as_array().into_iter().flatten().find_map(|c| {
        c["contractEntry"]["JsActiveContract"]["createdEvent"]["contractId"]
            .as_str()
            .map(String::from)
    });
    let (dso_rules_cid, bootstrapped) = match existing {
        Some(cid) => (cid, false),
        None => {
            let config = SpliceBootstrapConfig {
                dso_party: dso.clone(),
                sv_party: sv.clone(),
                validator_party: validator.clone(),
                synchronizer_id: synchronizer_id.clone(),
                sv_participant_id: participant_id,
                ..SpliceBootstrapConfig::default()
            };
            let now_micros = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_micros() as i64;
            let payload = dso_bootstrap_payload(&config, now_micros);
            let created = ledger.submit(
                &args.user,
                &[dso.as_str()],
                "splice-dso-bootstrap-create",
                json!({ "CreateCommand": {
                    "templateId": "#splice-dso-governance:Splice.DsoBootstrap:DsoBootstrap",
                    "createArguments": payload } }),
            )?;
            let bootstrap_cid = created_cid(&created, "DsoBootstrap:DsoBootstrap")
                .ok_or("creating DsoBootstrap produced no DsoBootstrap contract")?;
            let booted = ledger.submit(
                &args.user,
                &[dso.as_str()],
                "splice-dso-bootstrap",
                json!({ "ExerciseCommand": {
                    "templateId": "#splice-dso-governance:Splice.DsoBootstrap:DsoBootstrap",
                    "contractId": bootstrap_cid, "choice": "DsoBootstrap_Bootstrap", "choiceArgument": {} } }),
            )?;
            let dso_rules_cid = created_cid(&booted, "DsoRules:DsoRules")
                .ok_or("DsoBootstrap_Bootstrap produced no DsoRules contract")?;
            // [CANTON-NOTE: SEMANTICS] `DsoRules` has the DSO party as its only stakeholder (measured: no observers), as in the official
            // network, where an SV app acts as its own party *and* as the DSO party; so the sponsor acts together with the DSO party.
            ledger.submit(
                &args.user,
                &[sv.as_str(), dso.as_str()],
                "splice-onboard-primary-validator",
                json!({ "ExerciseCommand": {
                    "templateId": "#splice-dso-governance:Splice.DsoRules:DsoRules",
                    "contractId": dso_rules_cid, "choice": "DsoRules_OnboardValidator",
                    "choiceArgument": { "sponsor": sv, "validator": validator, "version": "0.10.1", "contactPoint": "" } } }),
            )?;
            (dso_rules_cid, true)
        }
    };

    let result = json!({
        "bootstrapped_now": bootstrapped,
        "dso_party": dso,
        "sv_party": sv,
        "validator_party": validator,
        "synchronizer_id": synchronizer_id,
        "dso_rules_contract_id": dso_rules_cid,
        "user": args.user,
    });
    let rendered = serde_json::to_string_pretty(&result)
        .map_err(|e| format!("failed to format bootstrap result: {e}"))?;
    if let Some(out) = &args.out {
        std::fs::write(out, &rendered).map_err(|e| format!("{}: {e}", out.display()))?;
    }
    println!("{rendered}");
    Ok(())
}
