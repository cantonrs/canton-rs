use super::acs::transaction_format;
use super::blobs::{blob_for, check_disclosed, enter_want_blob, enter_want_blob_for, value_json};
use super::errors::{
    bad_body, canton_error, map_error, parse_template, parseable_contract_id, Kind,
};
use super::events::{finish, record_rejected_completion};
use crate::http::{HttpRequest, HttpResponse};
use crate::models::json_api::{CreateRequest, ExerciseRequest, JsonEvent};
use crate::models::ledger_api::TemplateId;
use crate::service::{ApiError, ExecutionService, GenericContract};
use lf_eval::Value;
use serde_json::{json, Value as Json};
use std::sync::atomic::Ordering;

/// `POST /v2/commands/submit-and-wait` (flat `JsCommands`) and `.../submit-and-wait-for-transaction` (`{"commands": ...}`).
pub fn submit(
    service: &ExecutionService,
    req: &HttpRequest,
    with_transaction: bool,
) -> HttpResponse {
    // [CANTON-NOTE: INVARIANT] `command_recorded()` is invoked only inside the recording paths
    // (`finish_with_hash` / `record_rejected_completion`) after completion/update persistence succeeds,
    // never unconditionally when `submit_inner` fails post-commit.
    submit_inner(service, req, with_transaction, false)
}

/// `POST /v2/commands/async/submit`: the same submission, answered with `{}` once it was accepted.
pub fn submit_async(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    submit_inner(service, req, false, true)
}

/// Runs a dry-run interpretation for `/v2/interactive-submission/prepare` and reverts all ledger state mutations.
pub(crate) fn dry_run_prepare_commands(
    service: &ExecutionService,
    cmds: &Json,
    tx_uuid: &str,
) -> Result<
    (
        Vec<Ev>,
        Vec<crate::service::TransactionCommit>,
        Vec<GenericContract>,
        Vec<String>,
    ),
    HttpResponse,
> {
    let act_as: Vec<String> = cmds["actAs"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let commands = cmds["commands"].as_array().cloned().unwrap_or_default();
    if commands.is_empty() {
        return Err(canton_error(
            Kind::MissingField {
                name: "commands",
                correlated: true,
            },
            400,
            "MISSING_FIELD",
            "The submitted command is missing a mandatory field: commands".into(),
            8,
            3,
            json!([]),
        ));
    }
    let mut parsed = Vec::new();
    for c in &commands {
        parsed.push(preprocess(service, c)?);
    }
    let disclosed = check_disclosed(service, cmds)?;
    let read_as: Vec<String> = cmds
        .get("readAs")
        .and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let _cmd_guard = crate::service::enter_v2_command(disclosed.clone(), read_as.clone());
    let _prep_guard = crate::service::enter_v2_prepare_dry_run(tx_uuid.to_string());
    let _blob_guard = enter_want_blob(false);
    let executed = execute(service, &act_as, parsed);
    let commits = crate::service::take_dry_run_commits();
    match executed {
        Ok(events) => Ok((events, commits, disclosed, read_as)),
        Err(Fail::Resp(resp)) => Err(resp),
        Err(Fail::Api(e, cid)) => Err(map_error(e, cid.as_deref(), service)),
    }
}

pub(super) fn submit_inner(
    service: &ExecutionService,
    req: &HttpRequest,
    with_transaction: bool,
    asynchronous: bool,
) -> HttpResponse {
    let body: Json = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return bad_body("Invalid value for: body".to_string()),
    };
    let _trace = crate::trace_context::enter(crate::trace_context::of_request(&req.headers));
    let (cmds, prefix) = if with_transaction {
        (body.get("commands"), "commands.")
    } else {
        (Some(&body), "")
    };
    let Some(cmds) = cmds.filter(|c| c.is_object()) else {
        return bad_body(
            "Invalid value for: body (Missing required field at 'commands')".to_string(),
        );
    };
    let missing: Vec<String> = ["commands", "commandId", "actAs"]
        .iter()
        .filter(|k| cmds.get(**k).is_none())
        .map(|k| format!("Missing required field at '{prefix}{k}'"))
        .collect();
    if !missing.is_empty() {
        return bad_body(format!("Invalid value for: body ({})", missing.join(", ")));
    }
    let act_as: Vec<String> = cmds["actAs"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let commands = cmds["commands"].as_array().cloned().unwrap_or_default();
    if commands.is_empty() {
        return canton_error(
            Kind::MissingField {
                name: "commands",
                correlated: true,
            },
            400,
            "MISSING_FIELD",
            "The submitted command is missing a mandatory field: commands".into(),
            8,
            3,
            json!([]),
        );
    }
    let command_id = cmds["commandId"].as_str().unwrap_or("").to_string();
    if let Err(resp) = crate::dedup::validate_period(cmds.get("deduplicationPeriod")) {
        return resp;
    }

    // [CANTON-NOTE: SEMANTICS] Canton preprocesses every command of a submission (template, fields, choice) before it
    // interprets any: an unknown template in the second command is reported even if the first would fail its `ensure`.
    let mut parsed = Vec::new();
    for c in &commands {
        match preprocess(service, c) {
            Ok(p) => parsed.push(p),
            Err(resp) => return resp,
        }
    }
    // [CANTON-NOTE: SEMANTICS] Command deduplication (measured on the node, AT-T03): a command id of the same user and the same
    // set of act-as parties (in any order) that an earlier ACCEPTED command used is refused with 409 DUPLICATE_COMMAND while
    // the deduplication period is open, whatever the new command contains (`crate::dedup`).
    let user_id = cmds["userId"].as_str().unwrap_or("").to_string();
    let reservation = match crate::dedup::reserve(
        service,
        &user_id,
        &command_id,
        &act_as,
        cmds.get("deduplicationPeriod"),
    ) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let disclosed = match check_disclosed(service, cmds) {
        Ok(contracts) => contracts,
        Err(resp) => return resp,
    };
    let read_as: Vec<String> = cmds
        .get("readAs")
        .and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let v2_guard = crate::service::enter_v2_command(disclosed, read_as);
    let _blob_guard = enter_want_blob_for(&body);
    let command_guard = crate::service::enter_command(crate::service::CommandIdentity {
        command_id: command_id.clone(),
        user_id: user_id.clone(),
        submission_id: cmds["submissionId"].as_str().unwrap_or("").to_string(),
        act_as: act_as.clone(),
    });
    let executed = execute(service, &act_as, parsed);
    drop(command_guard);
    drop(v2_guard);
    match executed {
        Ok(events) => {
            let submission_id = cmds["submissionId"].as_str().map_or_else(
                || {
                    format!(
                        "00000000-0000-4000-8000-{:012x}",
                        service
                            .v2_state()
                            .submission_seq
                            .fetch_add(1, Ordering::SeqCst)
                    )
                },
                String::from,
            );
            let submission_for_dedup = submission_id.clone();
            let resp = finish(
                service,
                &command_id,
                &act_as,
                events,
                with_transaction,
                service.v2_state(),
                (user_id, submission_id),
                transaction_format(service, &body),
            );
            if resp.status == 200 {
                let offset = service.v2_state().ledger_end.load(Ordering::SeqCst);
                crate::dedup::record(service, reservation.key(), offset, submission_for_dedup);
            }
            if asynchronous && resp.status == 200 {
                HttpResponse::json(200, &json!({}))
            } else {
                resp
            }
        }
        Err(Fail::Resp(resp)) => resp,
        // [CANTON-NOTE: SEMANTICS] The wait for the command's completion ended first: it is not rejected and its completion is recorded
        // when its fate is known (`SubmissionTracker.timedOut`). An asynchronous submission was accepted.
        Err(Fail::Api(err, _)) if err.is_request_time_out() => {
            reservation.keep_in_flight();
            if asynchronous {
                return HttpResponse::json(200, &json!({}));
            }
            map_error(err, None, service)
        }
        Err(Fail::Api(err, cid)) => {
            if let ApiError::SynchronizerRejected {
                grpc_code, details, ..
            } = &err
            {
                let state = service.v2_state();
                let submission_id = cmds["submissionId"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map_or_else(
                        || {
                            format!(
                                "00000000-0000-4000-8000-{:012x}",
                                state.submission_seq.fetch_add(1, Ordering::SeqCst)
                            )
                        },
                        String::from,
                    );
                if record_rejected_completion(
                    state,
                    &command_id,
                    &user_id,
                    &submission_id,
                    &act_as,
                    None,
                    *grpc_code,
                    err.to_string(),
                    details.clone(),
                ) {
                    service.command_recorded_for(&command_id);
                }
                if asynchronous {
                    return HttpResponse::json(200, &json!({}));
                }
            }
            map_error(err, cid.as_deref(), service)
        }
    }
}

/// One command of a submission after the preprocessing checks.
#[derive(Clone)]
pub(super) enum Cmd {
    Create {
        template: TemplateId,
        args: Json,
    },
    Exercise {
        template: TemplateId,
        cid: String,
        choice: String,
        arg: Json,
    },
    ExerciseByKey {
        template: TemplateId,
        key: Json,
        choice: String,
        arg: Json,
    },
    CreateAndExercise {
        template: TemplateId,
        args: Json,
        choice: String,
        arg: Json,
    },
}

/// Why a submission failed: an error of the service (with the contract id of an exercise, for the error mapping) or a
/// response that is already final.
pub(super) enum Fail {
    Api(ApiError, Option<String>),
    Resp(HttpResponse),
}

impl From<ApiError> for Fail {
    fn from(e: ApiError) -> Self {
        Fail::Api(e, None)
    }
}

/// The "missing non-optional fields" error of the command preprocessor (`HashSet(..)` for a template's fields, `Set(..)`
/// for a choice's arguments; both measured).
pub(super) fn missing_fields(set: &str, missing: &[&str]) -> HttpResponse {
    canton_error(
        Kind::Preprocessing,
        400,
        "COMMAND_PREPROCESSING_FAILED",
        format!("Missing non-optional fields: {set}({})", missing.join(", ")),
        8,
        3,
        json!([]),
    )
}

pub(super) fn absent<'a>(fields: &'a [String], args: &Json) -> Vec<&'a str> {
    fields
        .iter()
        .filter(|f| args.get(f.as_str()).is_none())
        .map(String::as_str)
        .collect()
}

/// Canton checks a command's template first (404), then its fields, then its choice and the choice's arguments.
pub(super) fn preprocess(service: &ExecutionService, command: &Json) -> Result<Cmd, HttpResponse> {
    let kind = [
        "CreateCommand",
        "ExerciseCommand",
        "ExerciseByKeyCommand",
        "CreateAndExerciseCommand",
    ]
    .into_iter()
    .find(|k| command.get(*k).is_some());
    let Some(kind) = kind else {
        return Err(canton_error(
            Kind::Request,
            400,
            "INVALID_ARGUMENT",
            "Unsupported command (only CreateCommand, ExerciseCommand and CreateAndExerciseCommand)"
                .into(),
            8,
            3,
            json!([]),
        ));
    };
    let c = &command[kind];
    let template = parse_template(service, c["templateId"].as_str().unwrap_or(""))
        .map_err(|e| map_error(e, None, service))?;
    let fields = match service.v2_template_fields(&template) {
        Some(f) => f,
        None if kind == "ExerciseCommand" && service.v2_interface_exists(&template) => Vec::new(),
        None => {
            return Err(map_error(
                ApiError::TemplateNotFound(template.to_string()),
                None,
                service,
            ));
        }
    };
    let args = c.get("createArguments").cloned().unwrap_or(json!({}));
    if kind == "CreateCommand" || kind == "CreateAndExerciseCommand" {
        // an `Optional` field may be left out of the arguments (it is `None`)
        let required = service
            .v2_template_required_fields(&template)
            .unwrap_or_else(|| fields.clone());
        let missing = absent(&required, &args);
        if !missing.is_empty() {
            return Err(missing_fields("HashSet", &missing));
        }
        // [CANTON-NOTE: SEMANTICS] A field the template does not have is refused (measured on the node, AT-L08: a field of
        // version 2.0.0 given to the 1.0.0 template is `INVALID_ARGUMENT ... Unexpected fields: note`).
        let unexpected: Vec<&str> = args
            .as_object()
            .map(|o| {
                o.keys()
                    .map(String::as_str)
                    .filter(|k| !fields.iter().any(|f| f == k))
                    .collect()
            })
            .unwrap_or_default();
        if !unexpected.is_empty() {
            return Err(canton_error(
                Kind::Preprocessing,
                400,
                "INVALID_ARGUMENT",
                format!(
                    "The submitted request has invalid arguments: Unexpected fields: {}",
                    unexpected.join(", ")
                ),
                8,
                3,
                json!([]),
            ));
        }
    }
    if kind == "CreateCommand" {
        return Ok(Cmd::Create { template, args });
    }
    let choice = c["choice"].as_str().unwrap_or("").to_string();
    let arg = c.get("choiceArgument").cloned().unwrap_or(json!({}));
    let Some(params) = service.v2_choice_fields(&template, &choice) else {
        return Err(canton_error(
            Kind::Request,
            400,
            "INVALID_ARGUMENT",
            format!(
                "The submitted request has invalid arguments: Invalid template:{template} or choice:{choice}"
            ),
            8,
            3,
            json!([]),
        ));
    };
    let missing = absent(&params, &arg);
    if !missing.is_empty() {
        return Err(missing_fields("Set", &missing));
    }
    if kind == "ExerciseByKeyCommand" {
        let key = c.get("contractKey").cloned().unwrap_or(Json::Null);
        return Ok(Cmd::ExerciseByKey {
            template,
            key,
            choice,
            arg,
        });
    }
    if kind == "ExerciseCommand" {
        let cid = c["contractId"].as_str().unwrap_or("").to_string();
        if !parseable_contract_id(&cid) && service.v2_contract(&cid).is_none() {
            // [CANTON-NOTE: SEMANTICS] A string that is not a contract id at all is a request error, found before the
            // ledger is asked (measured on the node, AT-U04): 400 INVALID_FIELD.
            return Err(canton_error(
                Kind::RequestCorrelated,
                400,
                "INVALID_FIELD",
                format!("The submitted command has a field with invalid value: Invalid field contract_id: cannot parse ContractId \"{cid}\""),
                8,
                3,
                json!([]),
            ));
        }
        Ok(Cmd::Exercise {
            template,
            cid,
            choice,
            arg,
        })
    } else {
        Ok(Cmd::CreateAndExercise {
            template,
            args,
            choice,
            arg,
        })
    }
}

/// What an `ExercisedEvent` of the LEDGER_EFFECTS shape needs besides the exercised contract.
#[derive(Clone)]
pub(crate) struct ExInfo {
    pub(crate) choice: String,
    pub(crate) argument: Json,
    /// The argument and the result as Daml values, for the gRPC encoding (`value_proto`).
    pub(crate) argument_value: Option<Value>,
    pub(crate) acting: Vec<String>,
    pub(crate) consuming: bool,
    pub(crate) result: Json,
    pub(crate) result_value: Option<Value>,
    pub(crate) last_descendant: u64,
    /// The interface the choice was exercised through (`package:Module:Entity`), if any.
    pub(crate) interface_id: Option<String>,
    /// The choice's evaluated observers (`observer` clause), propagated into `witnessParties` and informees.
    pub(crate) choice_observers: Vec<String>,
}

/// An event of the transaction a submission produced, with its node id in the transaction (pre-order, exercise nodes
/// included). A created contract is one node; an exercise is one node (`exercise` is set, `created` is false) whose
/// contract is the exercised one.
#[derive(Clone)]
pub(crate) struct Ev {
    pub(crate) contract: GenericContract,
    pub(crate) created: bool,
    pub(crate) node: u64,
    pub(crate) exercise: Option<ExInfo>,
}

/// The transaction shapes the reads produce.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    AcsDelta,
    LedgerEffects,
}

impl Shape {
    pub(crate) fn parse(text: Option<&str>) -> Option<Shape> {
        match text {
            Some("TRANSACTION_SHAPE_ACS_DELTA") => Some(Shape::AcsDelta),
            Some("TRANSACTION_SHAPE_LEDGER_EFFECTS") => Some(Shape::LedgerEffects),
            _ => None,
        }
    }
}

/// [CANTON-NOTE: SEMANTICS] The default shape (ACS_DELTA) shows only what changes the active contract set: creations and
/// archivals. A contract created and archived inside the same transaction is left out together with its archival, and a
/// non-consuming exercise has no event (measured with a CreateAndExerciseCommand).
pub(crate) fn acs_delta_events(events: &[Ev]) -> Vec<Ev> {
    let archived: std::collections::HashSet<&String> = events
        .iter()
        .filter(|e| !e.created && e.exercise.as_ref().is_none_or(|x| x.consuming))
        .map(|e| &e.contract.contract_id)
        .collect();
    let created: std::collections::HashSet<&String> = events
        .iter()
        .filter(|e| e.created)
        .map(|e| &e.contract.contract_id)
        .collect();
    events
        .iter()
        .filter(|e| {
            let id = &e.contract.contract_id;
            if e.created {
                !archived.contains(id)
            } else if e.exercise.as_ref().is_some_and(|x| !x.consuming) {
                false
            } else {
                !created.contains(id)
            }
        })
        .cloned()
        .collect()
}

/// Resolves `ExerciseByKeyCommand` inside `execute` according to Canton 3.7.2 NUCK 3-tier priority:
/// 1. Created earlier in this submission (`in_tx_created`), newest first.
/// 2. Explicitly disclosed contracts (`current_disclosed_contracts`), in caller-supplied order.
/// 3. Active contracts visible to `act_as ∪ read_as`, newest first.
pub(super) fn resolve_exercise_by_key(
    service: &ExecutionService,
    template: &TemplateId,
    wanted_key: &Json,
    act_as: &[String],
    in_tx_created: &std::collections::HashSet<String>,
    consumed: &std::collections::HashMap<String, u64>,
) -> Result<String, Fail> {
    let all_holders: Vec<GenericContract> = service
        .contracts_with_key(template)
        .into_iter()
        .filter(|g| g.key_value.as_ref().map(value_json).as_ref() == Some(wanted_key))
        .collect();

    // Tier 1: locally created in this transaction, newest first (visible regardless of stakeholders).
    if let Some(hit) = all_holders
        .iter()
        .filter(|g| {
            g.active
                && !consumed.contains_key(&g.contract_id)
                && in_tx_created.contains(&g.contract_id)
        })
        .max_by(|a, b| {
            a.creation_seq
                .cmp(&b.creation_seq)
                .then_with(|| a.contract_id.cmp(&b.contract_id))
        })
    {
        return Ok(hit.contract_id.clone());
    }

    // Tier 2: explicitly disclosed contracts, preserving caller order.
    let cmd_pkg_name = service.v2_package_name(&template.package_id);
    for disc in crate::service::current_disclosed_contracts() {
        if consumed.contains_key(&disc.contract_id) {
            continue;
        }
        if disc.template_id.module_name != template.module_name
            || disc.template_id.entity_name != template.entity_name
        {
            continue;
        }
        let same_pkg = disc.template_id.package_id == template.package_id
            || (cmd_pkg_name.is_some()
                && service.v2_package_name(&disc.package_id) == cmd_pkg_name);
        if !same_pkg {
            continue;
        }
        if disc.key_value.as_ref().map(value_json).as_ref() != Some(wanted_key) {
            continue;
        }
        if service
            .v2_contract(&disc.contract_id)
            .is_some_and(|c| !c.active)
        {
            continue;
        }
        return Ok(disc.contract_id);
    }

    // Tier 3: participant-known active contracts visible to act_as U read_as, newest first.
    let read_as = crate::service::current_read_as();
    let is_reader = |p: &String| act_as.iter().any(|a| a == p) || read_as.iter().any(|r| r == p);
    if let Some(hit) = all_holders
        .iter()
        .filter(|g| {
            g.active
                && !consumed.contains_key(&g.contract_id)
                && !in_tx_created.contains(&g.contract_id)
                && g.signatories.iter().chain(&g.observers).any(is_reader)
        })
        .max_by(|a, b| {
            a.creation_seq
                .cmp(&b.creation_seq)
                .then_with(|| a.contract_id.cmp(&b.contract_id))
        })
    {
        return Ok(hit.contract_id.clone());
    }

    if let Some(gone) = all_holders
        .iter()
        .find(|g| service.consumed_during(&g.contract_id, crate::service::arrival()))
    {
        return Err(Fail::Resp(map_error(
            ApiError::ContractNotActive(gone.contract_id.clone()),
            None,
            service,
        )));
    }
    Err(Fail::Resp(canton_error(
        Kind::Interpretation { failure: false },
        404,
        "CONTRACT_KEY_NOT_FOUND",
        format!("Interpretation error: Error: dependency error: couldn't find key: {template}"),
        11,
        5,
        json!([]),
    )))
}

/// Runs the commands of a submission as one transaction (P-8): all of them take effect or none does. With a synchronizer behind the
/// service, a submission of several roots (a command each, two for a `CreateAndExerciseCommand`) is judged in one confirmation request.
pub(super) fn execute(
    service: &ExecutionService,
    act_as: &[String],
    commands: Vec<Cmd>,
) -> Result<Vec<Ev>, Fail> {
    let roots = commands
        .iter()
        .map(|c| match c {
            Cmd::CreateAndExercise { .. } => 2,
            _ => 1,
        })
        .sum();
    let mut events: Vec<Ev> = Vec::new();
    let mut consumed: std::collections::HashMap<String, u64> = Default::default();
    let mut in_tx_created: std::collections::HashSet<String> = Default::default();
    let mut node = 0u64;
    service.v2_atomic(|| -> Result<(), Fail> {
        let batch = service.begin_protocol_batch(roots)?;
        for cmd in commands {
            let (exercise, create, is_by_key) = match cmd {
                Cmd::Create { template, args } => (None, Some((template, args)), false),
                Cmd::Exercise {
                    template,
                    cid,
                    choice,
                    arg,
                } => (Some((template, Some(cid), choice, arg)), None, false),
                Cmd::ExerciseByKey {
                    template,
                    key,
                    choice,
                    arg,
                } => {
                    let cid = resolve_exercise_by_key(
                        service,
                        &template,
                        &key,
                        act_as,
                        &in_tx_created,
                        &consumed,
                    )?;
                    (Some((template, Some(cid), choice, arg)), None, true)
                }
                Cmd::CreateAndExercise {
                    template,
                    args,
                    choice,
                    arg,
                } => (
                    Some((template.clone(), None, choice, arg)),
                    Some((template, args)),
                    false,
                ),
            };
            let mut created_id = None;
            if let Some((template, args)) = create {
                let r = service.json_create(
                    act_as,
                    CreateRequest {
                        template_id: template,
                        payload: args,
                        meta: None,
                    },
                )?;
                in_tx_created.insert(r.result.contract_id.clone());
                if let Some(c) = service.v2_contract(&r.result.contract_id) {
                    events.push(Ev {
                        contract: c,
                        created: true,
                        node,
                        exercise: None,
                    });
                }
                node += 1;
                created_id = Some(r.result.contract_id);
            }
            if let Some((template, cid, choice, arg)) = exercise {
                let cid = cid.or(created_id).unwrap_or_default();
                if let Some(at) = consumed.get(&cid) {
                    return Err(Fail::Resp(consumed_in_transaction(&cid, &template, *at)));
                }
                let event_template = template.clone();
                let arg_value = service.v2_choice_arg_value(&template, &choice, &arg);
                let arg_json = arg_value.as_ref().map_or(arg.clone(), value_json);
                let controllers = service.v2_choice_controllers(&template, &choice);
                let exec_req = ExerciseRequest {
                    template_id: template,
                    contract_id: cid.clone(),
                    choice: choice.clone(),
                    argument: arg,
                    meta: None,
                };
                let (r, journal) = crate::service::capture_engine_events(|| {
                    if is_by_key {
                        crate::service::with_exercise_by_key(|| {
                            service.json_exercise(act_as, exec_req)
                        })
                    } else {
                        service.json_exercise(act_as, exec_req)
                    }
                });
                let r = r.map_err(|e| Fail::Api(e, Some(cid.clone())))?;
                // a command whose choice exercises, fetches or nests below the root: the tree the engine ran, node by node
                if let Some(tree) = nested_events(service, &journal, node, &event_template) {
                    for ev in &tree.events {
                        if ev.created {
                            in_tx_created.insert(ev.contract.contract_id.clone());
                        }
                        if ev.exercise.as_ref().is_some_and(|x| x.consuming) {
                            consumed.insert(ev.contract.contract_id.clone(), ev.node);
                        }
                    }
                    node = tree.next_node;
                    events.extend(tree.events);
                    continue;
                }
                let exercise_node = node;
                node += 1;
                let consuming = r
                    .result
                    .events
                    .iter()
                    .any(|e| matches!(e, JsonEvent::Archived(a) if a.contract_id == cid));
                let children = r
                    .result
                    .events
                    .iter()
                    .filter(|e| matches!(e, JsonEvent::Created(_)))
                    .count() as u64;
                if let Some(mut c) = service
                    .v2_contract(&cid)
                    .or_else(|| crate::service::disclosed_contract_by_id(&cid))
                {
                    // an upgraded exercise reports the template of the package version that ran
                    // (never overwrite with an interface id when exercised via an interface)
                    if c.template_id.module_name == event_template.module_name
                        && c.template_id.entity_name == event_template.entity_name
                        && !service.v2_interface_exists(&event_template)
                    {
                        c.template_id = event_template.clone();
                    }
                    // the acting parties are the choice's controllers, read off the contract's fields
                    let fields = value_json(&c.payload_value);
                    let mut acting: Vec<String> = controllers
                        .iter()
                        .filter_map(|f| fields.get(f.as_str())?.as_str().map(String::from))
                        .collect();
                    if acting.is_empty() {
                        acting = act_as.to_vec();
                    }
                    let (typed_arg, typed_res) = encode_choice_values(
                        service,
                        &c.template_id,
                        None,
                        &choice,
                        arg_value.as_ref(),
                        Some(arg_json),
                        r.result.result_value.as_ref().map(|b| &b.0),
                        r.result.exercise_result.clone(),
                    );
                    events.push(Ev {
                        contract: c,
                        created: false,
                        node: exercise_node,
                        exercise: Some(ExInfo {
                            choice,
                            argument: typed_arg,
                            argument_value: arg_value,
                            acting,
                            consuming,
                            result: typed_res,
                            result_value: r.result.result_value.as_ref().map(|b| b.0.clone()),
                            last_descendant: exercise_node + children,
                            interface_id: None,
                            choice_observers: Vec::new(),
                        }),
                    });
                }
                for ev in r.result.events {
                    match ev {
                        JsonEvent::Archived(a) => {
                            consumed.insert(a.contract_id.clone(), exercise_node);
                            // the exercised contract's archival is the exercise event itself
                            if a.contract_id != cid {
                                if let Some(c) = service.v2_contract(&a.contract_id).or_else(|| {
                                    crate::service::disclosed_contract_by_id(&a.contract_id)
                                }) {
                                    events.push(Ev {
                                        contract: c,
                                        created: false,
                                        node: exercise_node,
                                        exercise: None,
                                    });
                                }
                            }
                        }
                        JsonEvent::Created(c) => {
                            in_tx_created.insert(c.contract_id.clone());
                            if let Some(c) = service.v2_contract(&c.contract_id) {
                                events.push(Ev {
                                    contract: c,
                                    created: true,
                                    node,
                                    exercise: None,
                                });
                            }
                            node += 1;
                        }
                    }
                }
            }
        }
        if let Some(batch) = batch {
            service.finish_protocol_batch(batch)?;
        }
        Ok(())
    })?;
    Ok(events)
}

/// The events of a command's tree and the node number after it.
pub(super) struct NestedEvents {
    events: Vec<Ev>,
    next_node: u64,
}

pub(super) fn contract_from_journal(
    service: &ExecutionService,
    cid: &str,
    contracts: &std::collections::HashMap<String, lf_eval::Contract>,
) -> Option<GenericContract> {
    service
        .v2_contract(cid)
        .or_else(|| crate::service::disclosed_contract_by_id(cid))
        .or_else(|| {
            let hc = contracts.get(cid)?;
            let (mod_n, ent_n) = hc
                .template_id
                .split_once(':')
                .unwrap_or(("", &hc.template_id));
            let template_id = TemplateId::new(&hc.package_id, mod_n, ent_n);
            let json_payload =
                crate::payload_schema::typed_only_contract_json(service, &template_id, &hc.payload)
                    .unwrap_or_else(|| value_json(&hc.payload));
            let mut gc = GenericContract {
                contract_id: hc.contract_id.clone(),
                package_id: hc.package_id.clone(),
                template_id,
                payload_value: hc.payload.clone(),
                json_payload,
                signatories: hc.signatories.clone(),
                observers: hc.observers.clone(),
                witness_parties: hc.signatories.clone(),
                active: hc.active,
                key_value: None,
                created_at_micros: crate::clock::now_micros(),
                created_event_blob: String::new(),
                contract_key_hash: String::new(),
                key_maintainers: Vec::new(),
                creation_seq: 0,
            };
            gc.created_event_blob = blob_for(service, &gc);
            Some(gc)
        })
}

/// Encodes a choice's `choiceArgument` and `exerciseResult` with Daml-LF type awareness
/// (`Time` RFC 3339, `Numeric` fixed scale, `TextMap` objects, explicit `null` for `None` fields matching Canton 3.7.2).
#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
pub(crate) fn encode_choice_values(
    service: &ExecutionService,
    contract_tpl: &TemplateId,
    interface_id: Option<&str>,
    choice: &str,
    arg_val: Option<&Value>,
    fallback_arg: Option<Json>,
    res_val: Option<&Value>,
    fallback_res: Option<Json>,
) -> (Json, Json) {
    let encode_with = |types: &lf_eval::typed_json::Types<'_>,
                       ct: &lf_eval::typed_json::ChoiceTypes| {
        // [CANTON-NOTE: SEMANTICS] Canton 3.7.2 emits explicit JSON `null` for `Optional(None)`
        // fields in `choiceArgument` and `exerciseResult`.
        let _ = service;
        (
            arg_val.and_then(|v| types.encode_ledger_api(&ct.argument, v).ok()),
            res_val.and_then(|v| types.encode_ledger_api(&ct.result, v).ok()),
        )
    };
    let typed = if let Some(iface) = interface_id {
        let mut parts = iface.splitn(3, ':');
        let (ipkg, imod, ient) = (
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
        );
        if !ipkg.is_empty() && !imod.is_empty() && !ient.is_empty() {
            let ilocal = format!("{imod}:{ient}");
            service
                .with_world(ipkg, |w| {
                    let types = lf_eval::typed_json::Types::new(w);
                    let ct = types.interface_choice(ipkg, &ilocal, choice).ok()?;
                    Some(encode_with(&types, &ct))
                })
                .flatten()
        } else {
            None
        }
    } else {
        let local_tpl = format!("{}:{}", contract_tpl.module_name, contract_tpl.entity_name);
        service
            .with_world(&contract_tpl.package_id, |w| {
                let types = lf_eval::typed_json::Types::new(w);
                let ct = types
                    .choice(&contract_tpl.package_id, &local_tpl, choice)
                    .ok()?;
                Some(encode_with(&types, &ct))
            })
            .flatten()
    };
    let (arg_opt, res_opt) = typed.unwrap_or((None, None));
    let arg_json = arg_opt
        .or(fallback_arg)
        .unwrap_or_else(|| arg_val.map_or_else(|| json!({}), value_json));
    let res_json = res_opt
        .or(fallback_res)
        .unwrap_or_else(|| res_val.map_or_else(|| json!({}), value_json));
    (arg_json, res_json)
}

/// The update events of one command whose tree has more than the root exercise and the contracts it creates: a nested exercise, a fetch (which takes a
/// node number too), an interface exercise, or choice observers. `journal` is the engine's record and transient contracts of the command;
/// `start` the node number of its root; `root_template` the template the root exercise names (an upgraded exercise reports the version that ran).
/// `None` for a command that is the flat tree, and when a contract the tree names is unknown.
///
/// [CANTON-NOTE: SEMANTICS] Measured on an official Canton 3.7.2 (a consuming choice that fetches a contract, exercises a non-consuming and a consuming
/// choice of it and creates another contract): the nodes are numbered in pre-order, the fetch takes a number and has no event, every exercise has its own
/// event with the last node below it, and the creates below a consuming exercise are its children (`scripts/verify-official-events.sh`).
pub(super) fn nested_events(
    service: &ExecutionService,
    journal: &crate::service::CapturedJournal,
    start: u64,
    root_template: &TemplateId,
) -> Option<NestedEvents> {
    use lf_eval::EngineEvent as E;
    let nested = journal.events.iter().any(|e| {
        matches!(e, E::Fetch { .. })
            || matches!(
                e,
                E::Exercise {
                    depth,
                    interface_id,
                    observers,
                    ..
                } if *depth > 0 || interface_id.is_some() || !observers.is_empty()
            )
    });
    if !nested {
        return None;
    }
    let mut events: Vec<Ev> = Vec::new();
    // the exercises still open: (depth, index in `events`)
    let mut open: Vec<(usize, usize)> = Vec::new();
    let mut node = start;
    for ev in &journal.events {
        let depth = match ev {
            E::Create { depth, .. } | E::Exercise { depth, .. } | E::Fetch { depth, .. } => *depth,
        };
        while let Some((d, i)) = open.last().copied() {
            if d < depth {
                break;
            }
            open.pop();
            if let Some(x) = events[i].exercise.as_mut() {
                x.last_descendant = node - 1;
            }
        }
        let this = node;
        node += 1;
        match ev {
            E::Fetch { .. } => {}
            E::Create { contract_id, .. } => {
                let contract = contract_from_journal(service, contract_id, &journal.contracts)?;
                events.push(Ev {
                    contract,
                    created: true,
                    node: this,
                    exercise: None,
                });
            }
            E::Exercise {
                contract_id,
                choice,
                consuming,
                actors,
                argument,
                result,
                interface_id,
                observers,
                ..
            } => {
                let mut contract = contract_from_journal(service, contract_id, &journal.contracts)?;
                if this == start
                    && interface_id.is_none()
                    && contract.template_id.module_name == root_template.module_name
                    && contract.template_id.entity_name == root_template.entity_name
                {
                    contract.template_id = root_template.clone();
                }
                let (arg_json, res_json) = encode_choice_values(
                    service,
                    &contract.template_id,
                    interface_id.as_deref(),
                    choice,
                    Some(argument),
                    None,
                    result.as_ref(),
                    None,
                );
                open.push((depth, events.len()));
                events.push(Ev {
                    contract,
                    created: false,
                    node: this,
                    exercise: Some(ExInfo {
                        choice: choice.clone(),
                        argument: arg_json,
                        argument_value: Some(argument.clone()),
                        acting: actors.clone(),
                        consuming: *consuming,
                        result: res_json,
                        result_value: result.clone(),
                        last_descendant: this,
                        interface_id: interface_id.clone(),
                        choice_observers: observers.clone(),
                    }),
                });
            }
        }
    }
    while let Some((_, i)) = open.pop() {
        if let Some(x) = events[i].exercise.as_mut() {
            x.last_descendant = node - 1;
        }
    }
    Some(NestedEvents {
        events,
        next_node: node,
    })
}

/// A contract an earlier command of the same submission consumed (Canton: `CONTRACT_NOT_ACTIVE`, 404).
pub(super) fn consumed_in_transaction(cid: &str, template: &TemplateId, node: u64) -> HttpResponse {
    canton_error(
        Kind::Interpretation { failure: false },
        404,
        "CONTRACT_NOT_ACTIVE",
        format!(
            "CONTRACT_NOT_ACTIVE(11,00000000): Interpretation error: Error: Update failed due to fetch of an inactive contract {cid} ({}:{}@{}).\nThe contract had been consumed in sub-transaction #NodeId({node}):",
            template.module_name,
            template.entity_name,
            template.package_id.chars().take(8).collect::<String>()
        ),
        11,
        5,
        json!([
            ["TEMPLATE_ID", template.to_string()],
            ["CONTRACT_ID", cid]
        ]),
    )
}
