//! Party-scoped ledger projection normalization (`norm`), structural tree diff, and `V-A2`
//! witness invariant verification (`S-DX-005`).
//!
//! [CANTON-NOTE: SEMANTICS] Mirrors the formal normalization spec in `doc/devkit-feature-adoption/README.md`:
//! deletes implementation-volatile fields (`offset`, `updateId`, `recordTime`, `commandId`,
//! `workflowId`, `synchronizerId`, `traceContext`, node numbers), α-renames contract IDs scenario-wide
//! as `c0, c1, ...`, maps party fingerprints `<hint>::<fp>` to logical party names, preserves `packageId`
//! verbatim, and reconstructs parent-child event trees for deterministic semantic comparison.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Raw multi-step scenario capture recorded from either `canton-rs` or the JVM Canton oracle.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioCapture {
    /// Scenario identifier (e.g. `"V-01"`).
    pub scenario: String,
    /// Map from logical scenario party name (e.g. `"Alice"`) to raw ledger party ID (`"Alice::1220..."`).
    #[serde(default)]
    pub parties: BTreeMap<String, String>,
    /// Ordered scenario steps (`0, 1, ...`).
    pub steps: Vec<StepCapture>,
}

/// One scenario step holding `tx replay --format json` output per logical party.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepCapture {
    /// Zero-based scenario step index `k`.
    pub step: usize,
    /// Logical party name -> raw `tx replay --format json` payload (or `{"events": []}`).
    pub projections: BTreeMap<String, Value>,
}

/// Normalized projection for an entire scenario across all steps and parties.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormCapture {
    pub steps: Vec<NormStep>,
}

/// Normalized per-party event trees at scenario step `k`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormStep {
    pub step: usize,
    pub projections: BTreeMap<String, Vec<NormEventNode>>,
}

/// Canonical Ledger API v2 event tree node after `norm`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormEventNode {
    pub kind: String,
    pub contract_id: String,
    pub template_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choice: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choice_argument: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exercise_result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_argument: Option<Value>,
    pub signatories: BTreeSet<String>,
    pub observers: BTreeSet<String>,
    pub acting_parties: BTreeSet<String>,
    pub witness_parties: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consuming: Option<bool>,
    #[serde(default)]
    pub interface_views: Vec<NormInterfaceView>,
    #[serde(default)]
    pub children: Vec<NormEventNode>,
}

/// Canonical evaluated interface view attached to a `CreatedEvent`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormInterfaceView {
    pub interface_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_status_code: Option<i64>,
    pub view_value: Value,
}

/// One concrete discrepancy found between two normalized scenario projections.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffEntry {
    pub step: usize,
    pub party: String,
    pub path: String,
    pub left: Value,
    pub right: Value,
}

struct AlphaEnv {
    cids: BTreeMap<String, String>,
    raw_to_logical_party: BTreeMap<String, String>,
    embedded_party_replacements: Vec<(String, String)>,
}

impl AlphaEnv {
    fn new(parties: &BTreeMap<String, String>) -> Self {
        let mut raw_to_logical_party = BTreeMap::new();
        let mut embedded_party_replacements = Vec::new();
        for (logical, raw) in parties {
            raw_to_logical_party.insert(raw.clone(), logical.clone());
            raw_to_logical_party.insert(logical.clone(), logical.clone());
            if raw != logical && raw.contains("::") {
                embedded_party_replacements.push((raw.clone(), logical.clone()));
            }
        }
        embedded_party_replacements
            .sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        Self {
            cids: BTreeMap::new(),
            raw_to_logical_party,
            embedded_party_replacements,
        }
    }

    fn intern_cid(&mut self, raw: &str) -> String {
        if let Some(existing) = self.cids.get(raw) {
            return existing.clone();
        }
        let next = format!("c{}", self.cids.len());
        self.cids.insert(raw.to_string(), next.clone());
        next
    }

    fn normalize_party(&self, raw: &str) -> String {
        if let Some(logical) = self.raw_to_logical_party.get(raw) {
            return logical.clone();
        }
        if let Some((hint, fp)) = raw.split_once("::") {
            if !hint.is_empty() && fp.len() >= 16 && fp.bytes().all(|b| b.is_ascii_hexdigit()) {
                return hint.to_string();
            }
        }
        raw.to_string()
    }

    fn normalize_string(&mut self, raw: &str) -> String {
        if is_contract_id_literal(raw) {
            return self.intern_cid(raw);
        }
        if let Some(logical) = self.raw_to_logical_party.get(raw) {
            return logical.clone();
        }
        if let Some((hint, fp)) = raw.split_once("::") {
            if !hint.is_empty() && fp.len() >= 16 && fp.bytes().all(|b| b.is_ascii_hexdigit()) {
                return hint.to_string();
            }
            let mut out = raw.to_string();
            for (raw_party, logical) in &self.embedded_party_replacements {
                if out.contains(raw_party.as_str()) {
                    out = out.replace(raw_party.as_str(), logical);
                }
            }
            return out;
        }
        raw.to_string()
    }

    fn normalize_value(&mut self, val: &Value) -> Value {
        match val {
            Value::Null | Value::Bool(_) | Value::Number(_) => val.clone(),
            Value::String(s) => Value::String(self.normalize_string(s)),
            Value::Array(items) => {
                Value::Array(items.iter().map(|v| self.normalize_value(v)).collect())
            }
            Value::Object(map) => {
                // Sort keys in a BTreeMap so α-interning traversal and serialized keys are 100% deterministic.
                let mut sorted = BTreeMap::new();
                for (k, v) in map {
                    sorted.insert(k.clone(), v);
                }
                let mut out = serde_json::Map::new();
                for (k, v) in sorted {
                    let norm_k = self.normalize_string(&k);
                    let norm_v = self.normalize_value(v);
                    out.insert(norm_k, norm_v);
                }
                Value::Object(out)
            }
        }
    }
}

fn is_contract_id_literal(s: &str) -> bool {
    s.len() >= 68 && s.starts_with("00") && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn canonical_identifier(val: Option<&Value>) -> Result<String, String> {
    let Some(v) = val else {
        return Ok(String::new());
    };
    if let Some(s) = v.as_str() {
        return Ok(s.to_string());
    }
    let Some(obj) = v.as_object() else {
        return Err(format!("expected identifier string or object, got {v}"));
    };
    let pkg = obj
        .get("packageId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let module = obj
        .get("moduleName")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let entity = obj
        .get("entityName")
        .and_then(Value::as_str)
        .unwrap_or_default();
    Ok(format!("{pkg}:{module}:{entity}"))
}

fn extract_events_slice(projection: &Value) -> Result<Vec<Value>, String> {
    if projection.is_null() {
        return Ok(Vec::new());
    }
    if let Some(arr) = projection.as_array() {
        return Ok(arr.clone());
    }
    if let Some(arr) = projection.get("events").and_then(Value::as_array) {
        return Ok(arr.clone());
    }
    if let Some(arr) = projection
        .pointer("/update/Transaction/value/events")
        .and_then(Value::as_array)
    {
        return Ok(arr.clone());
    }
    if let Some(arr) = projection
        .pointer("/transaction/events")
        .and_then(Value::as_array)
    {
        return Ok(arr.clone());
    }
    if projection.get("visible").and_then(Value::as_bool) == Some(false)
        || projection.get("update").is_some_and(Value::is_null)
    {
        return Ok(Vec::new());
    }
    Err(format!(
        "unrecognized replay JSON shape (missing `events` array): {projection}"
    ))
}

fn parse_u64_field(obj: &serde_json::Map<String, Value>, key: &str) -> Option<u64> {
    obj.get(key)
        .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse::<u64>().ok()))
}

fn normalize_party_set(
    env: &AlphaEnv,
    body: &serde_json::Map<String, Value>,
    key: &str,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(arr) = body.get(key).and_then(Value::as_array) {
        for item in arr {
            if let Some(s) = item.as_str() {
                out.insert(env.normalize_party(s));
            }
        }
    }
    out
}

fn normalize_interface_views(
    env: &mut AlphaEnv,
    body: &serde_json::Map<String, Value>,
) -> Result<Vec<NormInterfaceView>, String> {
    let mut out = Vec::new();
    let Some(arr) = body.get("interfaceViews").and_then(Value::as_array) else {
        return Ok(out);
    };
    for item in arr {
        let Some(obj) = item.as_object() else {
            return Err(format!("expected interfaceView object, got {item}"));
        };
        let interface_id = canonical_identifier(obj.get("interfaceId"))?;
        let view_status_code = obj
            .get("viewStatus")
            .and_then(Value::as_object)
            .and_then(|st| {
                st.get("code")
                    .and_then(Value::as_i64)
                    .or_else(|| st.get("code").and_then(Value::as_str)?.parse::<i64>().ok())
            });
        let raw_view = obj.get("viewValue").unwrap_or(&Value::Null);
        let view_value = env.normalize_value(raw_view);
        out.push(NormInterfaceView {
            interface_id,
            view_status_code,
            view_value,
        });
    }
    out.sort_by(|a, b| a.interface_id.cmp(&b.interface_id));
    Ok(out)
}

fn normalize_raw_event(
    env: &mut AlphaEnv,
    ev: &Value,
) -> Result<(u64, u64, NormEventNode), String> {
    let Some(outer) = ev.as_object() else {
        return Err(format!("expected event object, got {ev}"));
    };
    let (kind, body_val) = if let Some(b) = outer.get("CreatedEvent") {
        ("Created", b)
    } else if let Some(b) = outer.get("ExercisedEvent") {
        ("Exercised", b)
    } else if let Some(b) = outer.get("ArchivedEvent") {
        ("Archived", b)
    } else {
        return Err(format!(
            "unsupported event variant (expected CreatedEvent/ExercisedEvent/ArchivedEvent): {ev}"
        ));
    };
    let Some(body) = body_val.as_object() else {
        return Err(format!("expected {kind}Event body object, got {body_val}"));
    };

    let node_id = parse_u64_field(body, "nodeId").unwrap_or(0);
    let last_descendant = parse_u64_field(body, "lastDescendantNodeId").unwrap_or(node_id);

    let raw_cid = body
        .get("contractId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let contract_id = if raw_cid.is_empty() {
        String::new()
    } else {
        env.intern_cid(raw_cid)
    };
    let template_id = canonical_identifier(body.get("templateId"))?;
    let interface_id = match body.get("interfaceId").filter(|v| !v.is_null()) {
        Some(v) => {
            let cid = canonical_identifier(Some(v))?;
            (!cid.is_empty()).then_some(cid)
        }
        None => None,
    };
    let choice = body
        .get("choice")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let create_argument = body.get("createArgument").map(|v| env.normalize_value(v));
    let choice_argument = body.get("choiceArgument").map(|v| env.normalize_value(v));
    let exercise_result = body.get("exerciseResult").map(|v| env.normalize_value(v));
    let signatories = normalize_party_set(env, body, "signatories");
    let observers = normalize_party_set(env, body, "observers");
    let acting_parties = normalize_party_set(env, body, "actingParties");
    let witness_parties = normalize_party_set(env, body, "witnessParties");
    let consuming = body.get("consuming").and_then(Value::as_bool);
    let interface_views = normalize_interface_views(env, body)?;

    Ok((
        node_id,
        last_descendant,
        NormEventNode {
            kind: kind.to_string(),
            contract_id,
            template_id,
            interface_id,
            choice,
            choice_argument,
            exercise_result,
            create_argument,
            signatories,
            observers,
            acting_parties,
            witness_parties,
            consuming,
            interface_views,
            children: Vec::new(),
        },
    ))
}

fn attach_frame(
    stack: &mut [(u64, NormEventNode)],
    roots: &mut Vec<NormEventNode>,
    node: NormEventNode,
) {
    if let Some((_, parent)) = stack.last_mut() {
        parent.children.push(node);
    } else {
        roots.push(node);
    }
}

fn build_event_tree(
    env: &mut AlphaEnv,
    raw_events: &[Value],
) -> Result<Vec<NormEventNode>, String> {
    let mut roots: Vec<NormEventNode> = Vec::new();
    let mut stack: Vec<(u64, NormEventNode)> = Vec::new();
    for ev in raw_events {
        let (node_id, last_desc, norm_node) = normalize_raw_event(env, ev)?;
        while let Some(&(parent_last_desc, _)) = stack.last() {
            if node_id <= parent_last_desc {
                break;
            }
            if let Some((_, finished)) = stack.pop() {
                attach_frame(&mut stack, &mut roots, finished);
            }
        }
        if norm_node.kind == "Exercised" && last_desc > node_id {
            stack.push((last_desc, norm_node));
        } else {
            attach_frame(&mut stack, &mut roots, norm_node);
        }
    }
    while let Some((_, finished)) = stack.pop() {
        attach_frame(&mut stack, &mut roots, finished);
    }
    Ok(roots)
}

/// Applies `norm` deterministically across a full [`ScenarioCapture`].
pub fn normalize_capture(cap: &ScenarioCapture) -> Result<NormCapture, String> {
    let mut env = AlphaEnv::new(&cap.parties);
    let mut ordered_steps: Vec<&StepCapture> = cap.steps.iter().collect();
    ordered_steps.sort_by_key(|s| s.step);

    let mut steps = Vec::with_capacity(ordered_steps.len());
    for step_cap in ordered_steps {
        let mut projections = BTreeMap::new();
        for (party, raw_proj) in &step_cap.projections {
            let logical_party = env.normalize_party(party);
            let raw_events = extract_events_slice(raw_proj)?;
            let tree = build_event_tree(&mut env, &raw_events)?;
            projections.insert(logical_party, tree);
        }
        steps.push(NormStep {
            step: step_cap.step,
            projections,
        });
    }
    Ok(NormCapture { steps })
}

fn check_node_witnesses(
    step: usize,
    party: &str,
    path: &str,
    node: &NormEventNode,
    violations: &mut Vec<String>,
) {
    if !node.witness_parties.contains(party) {
        violations.push(format!(
            "V-A2 violation at step {step} party {party} path {path}: witness_parties {:?} lacks queried party",
            node.witness_parties
        ));
    }
    for (idx, child) in node.children.iter().enumerate() {
        check_node_witnesses(
            step,
            party,
            &format!("{path}.children[{idx}]"),
            child,
            violations,
        );
    }
}

/// Checks `V-A2`: every event in party `p`'s projection includes `p` in `witnessParties`.
pub fn check_witness_invariants(norm: &NormCapture) -> Vec<String> {
    let mut violations = Vec::new();
    for step in &norm.steps {
        for (party, nodes) in &step.projections {
            for (idx, node) in nodes.iter().enumerate() {
                check_node_witnesses(
                    step.step,
                    party,
                    &format!("events[{idx}]"),
                    node,
                    &mut violations,
                );
            }
        }
    }
    violations
}

fn push_diff(
    diffs: &mut Vec<DiffEntry>,
    step: usize,
    party: &str,
    path: &str,
    left: impl Serialize,
    right: impl Serialize,
) {
    diffs.push(DiffEntry {
        step,
        party: party.to_string(),
        path: path.to_string(),
        left: serde_json::to_value(left).unwrap_or(Value::Null),
        right: serde_json::to_value(right).unwrap_or(Value::Null),
    });
}

fn diff_nodes(
    diffs: &mut Vec<DiffEntry>,
    step: usize,
    party: &str,
    path: &str,
    left: &NormEventNode,
    right: &NormEventNode,
) {
    if left.kind != right.kind {
        push_diff(
            diffs,
            step,
            party,
            &format!("{path}.kind"),
            &left.kind,
            &right.kind,
        );
    }
    if left.contract_id != right.contract_id {
        push_diff(
            diffs,
            step,
            party,
            &format!("{path}.contractId"),
            &left.contract_id,
            &right.contract_id,
        );
    }
    if left.template_id != right.template_id {
        push_diff(
            diffs,
            step,
            party,
            &format!("{path}.templateId"),
            &left.template_id,
            &right.template_id,
        );
    }
    if left.interface_id != right.interface_id {
        push_diff(
            diffs,
            step,
            party,
            &format!("{path}.interfaceId"),
            &left.interface_id,
            &right.interface_id,
        );
    }
    if left.choice != right.choice {
        push_diff(
            diffs,
            step,
            party,
            &format!("{path}.choice"),
            &left.choice,
            &right.choice,
        );
    }
    if left.choice_argument != right.choice_argument {
        push_diff(
            diffs,
            step,
            party,
            &format!("{path}.choiceArgument"),
            &left.choice_argument,
            &right.choice_argument,
        );
    }
    if left.exercise_result != right.exercise_result {
        push_diff(
            diffs,
            step,
            party,
            &format!("{path}.exerciseResult"),
            &left.exercise_result,
            &right.exercise_result,
        );
    }
    if left.create_argument != right.create_argument {
        push_diff(
            diffs,
            step,
            party,
            &format!("{path}.createArgument"),
            &left.create_argument,
            &right.create_argument,
        );
    }
    if left.signatories != right.signatories {
        push_diff(
            diffs,
            step,
            party,
            &format!("{path}.signatories"),
            &left.signatories,
            &right.signatories,
        );
    }
    if left.observers != right.observers {
        push_diff(
            diffs,
            step,
            party,
            &format!("{path}.observers"),
            &left.observers,
            &right.observers,
        );
    }
    if left.acting_parties != right.acting_parties {
        push_diff(
            diffs,
            step,
            party,
            &format!("{path}.actingParties"),
            &left.acting_parties,
            &right.acting_parties,
        );
    }
    if left.witness_parties != right.witness_parties {
        push_diff(
            diffs,
            step,
            party,
            &format!("{path}.witnessParties"),
            &left.witness_parties,
            &right.witness_parties,
        );
    }
    if left.consuming != right.consuming {
        push_diff(
            diffs,
            step,
            party,
            &format!("{path}.consuming"),
            left.consuming,
            right.consuming,
        );
    }
    if left.interface_views != right.interface_views {
        push_diff(
            diffs,
            step,
            party,
            &format!("{path}.interfaceViews"),
            &left.interface_views,
            &right.interface_views,
        );
    }
    diff_event_lists(
        diffs,
        step,
        party,
        &format!("{path}.children"),
        &left.children,
        &right.children,
    );
}

fn diff_event_lists(
    diffs: &mut Vec<DiffEntry>,
    step: usize,
    party: &str,
    prefix: &str,
    left: &[NormEventNode],
    right: &[NormEventNode],
) {
    if left.len() != right.len() {
        push_diff(
            diffs,
            step,
            party,
            &format!("{prefix}.len"),
            left.len(),
            right.len(),
        );
    }
    for (idx, (l_node, r_node)) in left.iter().zip(right.iter()).enumerate() {
        diff_nodes(
            diffs,
            step,
            party,
            &format!("{prefix}[{idx}]"),
            l_node,
            r_node,
        );
    }
}

/// Normalizes two [`ScenarioCapture`] values independently and returns all semantic differences.
pub fn diff_captures(
    left: &ScenarioCapture,
    right: &ScenarioCapture,
) -> Result<Vec<DiffEntry>, String> {
    let l_norm = normalize_capture(left)?;
    let r_norm = normalize_capture(right)?;

    let mut l_steps: BTreeMap<usize, &NormStep> = BTreeMap::new();
    for s in &l_norm.steps {
        l_steps.insert(s.step, s);
    }
    let mut r_steps: BTreeMap<usize, &NormStep> = BTreeMap::new();
    for s in &r_norm.steps {
        r_steps.insert(s.step, s);
    }

    let mut all_steps = BTreeSet::new();
    all_steps.extend(l_steps.keys().copied());
    all_steps.extend(r_steps.keys().copied());

    let mut diffs = Vec::new();
    for step_idx in all_steps {
        match (l_steps.get(&step_idx), r_steps.get(&step_idx)) {
            (Some(l_step), Some(r_step)) => {
                let mut all_parties = BTreeSet::new();
                all_parties.extend(l_step.projections.keys().cloned());
                all_parties.extend(r_step.projections.keys().cloned());
                for party in all_parties {
                    let l_events = l_step
                        .projections
                        .get(&party)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]);
                    let r_events = r_step
                        .projections
                        .get(&party)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]);
                    diff_event_lists(&mut diffs, step_idx, &party, "events", l_events, r_events);
                }
            }
            (Some(l_step), None) => {
                push_diff(&mut diffs, step_idx, "*", "step", l_step, Value::Null);
            }
            (None, Some(r_step)) => {
                push_diff(&mut diffs, step_idx, "*", "step", Value::Null, r_step);
            }
            (None, None) => {}
        }
    }
    Ok(diffs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_cid(tag: char) -> String {
        format!("00{}", tag.to_string().repeat(66))
    }

    fn base_created_event(cid: &str, tpl: &str) -> Value {
        json!({
            "CreatedEvent": {
                "offset": 1,
                "nodeId": 0,
                "contractId": cid,
                "templateId": tpl,
                "signatories": ["Alice::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "observers": ["Bob::1220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
                "witnessParties": ["Alice::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Bob::1220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
                "createArgument": { "owner": "Alice::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "refCid": cid },
                "interfaceViews": [
                    {
                        "interfaceId": "11111111:Mod:Iface",
                        "viewStatus": { "code": 0 },
                        "viewValue": { "holder": "Alice::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
                    }
                ]
            }
        })
    }

    fn wrap_capture(events: Vec<Value>) -> ScenarioCapture {
        let mut parties = BTreeMap::new();
        parties.insert(
            "Alice".into(),
            "Alice::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        );
        parties.insert(
            "Bob".into(),
            "Bob::1220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        );
        let mut projections = BTreeMap::new();
        projections.insert("Alice".into(), json!({ "events": events }));
        ScenarioCapture {
            scenario: "unit".into(),
            parties,
            steps: vec![StepCapture {
                step: 0,
                projections,
            }],
        }
    }

    #[test]
    fn sdx005_vu01_witness_parties_diff() {
        let cid = sample_cid('a');
        let left = wrap_capture(vec![base_created_event(&cid, "pkg1:Events:Box")]);
        let mut ev = base_created_event(&cid, "pkg1:Events:Box");
        ev["CreatedEvent"]["witnessParties"] =
            json!(["Alice::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
        let right = wrap_capture(vec![ev]);

        let diffs = diff_captures(&left, &right).expect("diff");
        assert!(
            diffs.iter().any(|d| d.path.ends_with(".witnessParties")),
            "expected witnessParties diff, got {diffs:?}"
        );
    }

    #[test]
    fn sdx005_vu02_template_pkg_id_diff() {
        let cid = sample_cid('a');
        let left = wrap_capture(vec![base_created_event(&cid, "pkgA:Events:Box")]);
        let right = wrap_capture(vec![base_created_event(&cid, "pkgB:Events:Box")]);
        let diffs = diff_captures(&left, &right).expect("diff");
        assert!(diffs.iter().any(|d| d.path.ends_with(".templateId")));
    }

    #[test]
    fn sdx005_vu03_choice_diff() {
        let cid = sample_cid('a');
        let ex1 = json!({
            "ExercisedEvent": {
                "nodeId": 0, "lastDescendantNodeId": 0, "contractId": cid, "templateId": "pkg1:Events:Box",
                "choice": "RunA", "choiceArgument": {}, "exerciseResult": {}, "actingParties": ["Alice"],
                "witnessParties": ["Alice"], "consuming": true
            }
        });
        let mut ex2 = ex1.clone();
        ex2["ExercisedEvent"]["choice"] = json!("RunB");
        let diffs =
            diff_captures(&wrap_capture(vec![ex1]), &wrap_capture(vec![ex2])).expect("diff");
        assert!(diffs.iter().any(|d| d.path.ends_with(".choice")));
    }

    #[test]
    fn sdx005_vu04_choice_argument_diff() {
        let cid = sample_cid('a');
        let ex1 = json!({
            "ExercisedEvent": {
                "nodeId": 0, "lastDescendantNodeId": 0, "contractId": cid, "templateId": "pkg1:Events:Box",
                "choice": "Run", "choiceArgument": { "amount": "10" }, "exerciseResult": {},
                "actingParties": ["Alice"], "witnessParties": ["Alice"], "consuming": false
            }
        });
        let mut ex2 = ex1.clone();
        ex2["ExercisedEvent"]["choiceArgument"] = json!({ "amount": "20" });
        let diffs =
            diff_captures(&wrap_capture(vec![ex1]), &wrap_capture(vec![ex2])).expect("diff");
        assert!(diffs.iter().any(|d| d.path.ends_with(".choiceArgument")));
    }

    #[test]
    fn sdx005_vu05_exercise_result_diff() {
        let cid = sample_cid('a');
        let ex1 = json!({
            "ExercisedEvent": {
                "nodeId": 0, "lastDescendantNodeId": 0, "contractId": cid, "templateId": "pkg1:Events:Box",
                "choice": "Run", "choiceArgument": {}, "exerciseResult": "ok",
                "actingParties": ["Alice"], "witnessParties": ["Alice"], "consuming": false
            }
        });
        let mut ex2 = ex1.clone();
        ex2["ExercisedEvent"]["exerciseResult"] = json!("changed");
        let diffs =
            diff_captures(&wrap_capture(vec![ex1]), &wrap_capture(vec![ex2])).expect("diff");
        assert!(diffs.iter().any(|d| d.path.ends_with(".exerciseResult")));
    }

    #[test]
    fn sdx005_vu06_create_argument_diff() {
        let cid = sample_cid('a');
        let left = wrap_capture(vec![base_created_event(&cid, "pkg1:Events:Box")]);
        let mut ev = base_created_event(&cid, "pkg1:Events:Box");
        ev["CreatedEvent"]["createArgument"]["label"] = json!("extra");
        let right = wrap_capture(vec![ev]);
        let diffs = diff_captures(&left, &right).expect("diff");
        assert!(diffs.iter().any(|d| d.path.ends_with(".createArgument")));
    }

    #[test]
    fn sdx005_vu07_signatories_diff() {
        let cid = sample_cid('a');
        let left = wrap_capture(vec![base_created_event(&cid, "pkg1:Events:Box")]);
        let mut ev = base_created_event(&cid, "pkg1:Events:Box");
        ev["CreatedEvent"]["signatories"] = json!([
            "Alice::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Bob::1220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ]);
        let right = wrap_capture(vec![ev]);
        let diffs = diff_captures(&left, &right).expect("diff");
        assert!(diffs.iter().any(|d| d.path.ends_with(".signatories")));
    }

    #[test]
    fn sdx005_vu08_observers_diff() {
        let cid = sample_cid('a');
        let left = wrap_capture(vec![base_created_event(&cid, "pkg1:Events:Box")]);
        let mut ev = base_created_event(&cid, "pkg1:Events:Box");
        ev["CreatedEvent"]["observers"] = json!([]);
        let right = wrap_capture(vec![ev]);
        let diffs = diff_captures(&left, &right).expect("diff");
        assert!(diffs.iter().any(|d| d.path.ends_with(".observers")));
    }

    #[test]
    fn sdx005_vu09_consuming_diff() {
        let cid = sample_cid('a');
        let ex1 = json!({
            "ExercisedEvent": {
                "nodeId": 0, "lastDescendantNodeId": 0, "contractId": cid, "templateId": "pkg1:Events:Box",
                "choice": "Run", "choiceArgument": {}, "exerciseResult": {},
                "actingParties": ["Alice"], "witnessParties": ["Alice"], "consuming": true
            }
        });
        let mut ex2 = ex1.clone();
        ex2["ExercisedEvent"]["consuming"] = json!(false);
        let diffs =
            diff_captures(&wrap_capture(vec![ex1]), &wrap_capture(vec![ex2])).expect("diff");
        assert!(diffs.iter().any(|d| d.path.ends_with(".consuming")));
    }

    #[test]
    fn sdx005_vu10_interface_views_diff() {
        let cid = sample_cid('a');
        let left = wrap_capture(vec![base_created_event(&cid, "pkg1:Events:Box")]);
        let mut ev = base_created_event(&cid, "pkg1:Events:Box");
        ev["CreatedEvent"]["interfaceViews"][0]["viewValue"]["extra"] = json!(1);
        let right = wrap_capture(vec![ev]);
        let diffs = diff_captures(&left, &right).expect("diff");
        assert!(diffs.iter().any(|d| d.path.ends_with(".interfaceViews")));
    }

    #[test]
    fn sdx005_vu11_tree_shape_diff() {
        let cid_a = sample_cid('a');
        let cid_b = sample_cid('b');
        let nested = vec![
            json!({
                "ExercisedEvent": {
                    "nodeId": 0, "lastDescendantNodeId": 1, "contractId": cid_a,
                    "templateId": "pkg1:Events:Box", "choice": "Spawn",
                    "choiceArgument": {}, "exerciseResult": {},
                    "actingParties": ["Alice"], "witnessParties": ["Alice"], "consuming": false
                }
            }),
            base_created_event(&cid_b, "pkg1:Events:Child"),
        ];
        let mut child_b = base_created_event(&cid_b, "pkg1:Events:Child");
        child_b["CreatedEvent"]["nodeId"] = json!(1);
        let flat = vec![
            json!({
                "ExercisedEvent": {
                    "nodeId": 0, "lastDescendantNodeId": 0, "contractId": cid_a,
                    "templateId": "pkg1:Events:Box", "choice": "Spawn",
                    "choiceArgument": {}, "exerciseResult": {},
                    "actingParties": ["Alice"], "witnessParties": ["Alice"], "consuming": false
                }
            }),
            child_b,
        ];
        let mut nested_events = nested;
        nested_events[1]["CreatedEvent"]["nodeId"] = json!(1);
        let diffs = diff_captures(&wrap_capture(nested_events), &wrap_capture(flat)).expect("diff");
        assert!(!diffs.is_empty(), "expected tree shape diff");
    }

    #[test]
    fn sdx005_vu12_sibling_order_diff() {
        let cid_a = sample_cid('a');
        let cid_b = sample_cid('b');
        let mut ev_t1 = base_created_event(&cid_a, "pkg1:Events:Box");
        let mut ev_t2 = base_created_event(&cid_b, "pkg1:Events:Gift");
        ev_t1["CreatedEvent"]["nodeId"] = json!(0);
        ev_t2["CreatedEvent"]["nodeId"] = json!(1);
        let left = wrap_capture(vec![ev_t1.clone(), ev_t2.clone()]);

        let mut ev_t2_first = ev_t2;
        let mut ev_t1_second = ev_t1;
        ev_t2_first["CreatedEvent"]["nodeId"] = json!(0);
        ev_t1_second["CreatedEvent"]["nodeId"] = json!(1);
        let right = wrap_capture(vec![ev_t2_first, ev_t1_second]);

        let diffs = diff_captures(&left, &right).expect("diff");
        assert!(diffs.iter().any(|d| d.path.contains(".templateId")));
    }

    #[test]
    fn sdx005_vu13_volatile_fields_invariance() {
        let cid_left = sample_cid('1');
        let cid_right = sample_cid('2');
        let left = ScenarioCapture {
            scenario: "S".into(),
            parties: BTreeMap::from([
                (
                    "Alice".into(),
                    "Alice::12201111111111111111111111111111".into(),
                ),
                ("Bob".into(), "Bob::12202222222222222222222222222222".into()),
            ]),
            steps: vec![StepCapture {
                step: 0,
                projections: BTreeMap::from([(
                    "Alice".into(),
                    json!({
                        "update": {
                            "Transaction": {
                                "value": {
                                    "updateId": "aaaa",
                                    "offset": 12,
                                    "commandId": "cmd-left",
                                    "workflowId": "wf-left",
                                    "synchronizerId": "sync::12209999999999999999",
                                    "recordTime": "2026-01-01T00:00:00Z",
                                    "traceContext": { "traceparent": "00-1111" },
                                    "events": [
                                        {
                                            "CreatedEvent": {
                                                "offset": 12,
                                                "nodeId": 5,
                                                "contractId": cid_left,
                                                "templateId": "pkg1:Events:Box",
                                                "signatories": ["Alice::12201111111111111111111111111111"],
                                                "observers": ["Bob::12202222222222222222222222222222"],
                                                "witnessParties": [
                                                    "Bob::12202222222222222222222222222222",
                                                    "Alice::12201111111111111111111111111111"
                                                ],
                                                "createdAt": "2026-01-01T00:00:00Z",
                                                "createdEventBlob": "AAAA",
                                                "createArgument": { "owner": "Alice::12201111111111111111111111111111", "selfRef": cid_left },
                                                "interfaceViews": [
                                                    { "interfaceId": "pkg1:I:B", "viewStatus": { "code": 0 }, "viewValue": { "b": 2 } },
                                                    { "interfaceId": "pkg1:I:A", "viewStatus": { "code": 0 }, "viewValue": { "a": 1 } }
                                                ]
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    }),
                )]),
            }],
        };

        let right = ScenarioCapture {
            scenario: "S".into(),
            parties: BTreeMap::from([
                (
                    "Alice".into(),
                    "Alice::12203333333333333333333333333333".into(),
                ),
                ("Bob".into(), "Bob::12204444444444444444444444444444".into()),
            ]),
            steps: vec![StepCapture {
                step: 0,
                projections: BTreeMap::from([(
                    "Alice".into(),
                    json!({
                        "events": [
                            {
                                "CreatedEvent": {
                                    "offset": 999,
                                    "nodeId": 0,
                                    "contractId": cid_right,
                                    "templateId": { "packageId": "pkg1", "moduleName": "Events", "entityName": "Box" },
                                    "signatories": ["Alice::12203333333333333333333333333333"],
                                    "observers": ["Bob::12204444444444444444444444444444"],
                                    "witnessParties": [
                                        "Alice::12203333333333333333333333333333",
                                        "Bob::12204444444444444444444444444444"
                                    ],
                                    "createdAt": "2026-12-31T23:59:59Z",
                                    "createdEventBlob": "BBBB",
                                    "createArgument": { "selfRef": cid_right, "owner": "Alice::12203333333333333333333333333333" },
                                    "interfaceViews": [
                                        { "interfaceId": { "packageId": "pkg1", "moduleName": "I", "entityName": "A" }, "viewStatus": { "code": 0 }, "viewValue": { "a": 1 } },
                                        { "interfaceId": { "packageId": "pkg1", "moduleName": "I", "entityName": "B" }, "viewStatus": { "code": 0 }, "viewValue": { "b": 2 } }
                                    ]
                                }
                            }
                        ]
                    }),
                )]),
            }],
        };

        let diffs = diff_captures(&left, &right).expect("diff");
        assert!(diffs.is_empty(), "expected zero diff, got {diffs:?}");
        let norm_left = normalize_capture(&left).expect("norm left");
        assert!(check_witness_invariants(&norm_left).is_empty());
    }

    #[test]
    fn sdx005_vu14_embedded_party_fingerprint_normalized_but_different_party_fails() {
        let bob_l = "Bob::1220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let carol_l = "Carol::1220cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let alice_r = "Alice::12201111111111111111111111111111111111111111111111111111111111111111";
        let bob_r = "Bob::1220dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let carol_r = "Carol::1220eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

        let mut left_ev = base_created_event(&sample_cid('a'), "pkg1:Events:Box");
        left_ev["CreatedEvent"]["createArgument"]["optContext"] =
            json!(format!("transfer to '{bob_l}'"));
        let mut left = wrap_capture(vec![left_ev]);
        left.parties.insert("Carol".into(), carol_l.into());

        let mut right_ev = json!({
            "CreatedEvent": {
                "offset": 9,
                "nodeId": 0,
                "contractId": sample_cid('b'),
                "templateId": "pkg1:Events:Box",
                "signatories": [alice_r],
                "observers": [bob_r],
                "witnessParties": [alice_r, bob_r],
                "createArgument": {
                    "owner": alice_r,
                    "refCid": sample_cid('b'),
                    "optContext": format!("transfer to '{bob_r}'")
                },
                "interfaceViews": [
                    {
                        "interfaceId": "11111111:Mod:Iface",
                        "viewStatus": { "code": 0 },
                        "viewValue": { "holder": alice_r }
                    }
                ]
            }
        });
        let mut right = wrap_capture(vec![right_ev.clone()]);
        right.parties.insert("Alice".into(), alice_r.into());
        right.parties.insert("Bob".into(), bob_r.into());
        right.parties.insert("Carol".into(), carol_r.into());

        let diffs_same = diff_captures(&left, &right).expect("diff");
        assert!(
            diffs_same.is_empty(),
            "same logical party in text must match, got {diffs_same:?}"
        );

        right_ev["CreatedEvent"]["createArgument"]["optContext"] =
            json!(format!("transfer to '{carol_r}'"));
        right.steps[0]
            .projections
            .insert("Alice".into(), json!({ "events": [right_ev] }));
        let diffs_diff = diff_captures(&left, &right).expect("diff");
        assert!(
            !diffs_diff.is_empty(),
            "different logical party in text must fail"
        );
        assert!(diffs_diff.iter().any(|d| {
            d.path.contains("createArgument")
                && d.left.get("optContext").and_then(Value::as_str) == Some("transfer to 'Bob'")
                && d.right.get("optContext").and_then(Value::as_str) == Some("transfer to 'Carol'")
        }));
    }
}
