use serde::{Deserialize, Serialize};

use super::ledger_api::TemplateId;

/// Meta object optionally provided in JSON API requests.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act_as: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_as: Option<Vec<String>>,
}

/// JSON API POST /v1/create request body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    pub template_id: TemplateId,
    pub payload: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<RequestMeta>,
}

/// Result object for JSON API POST /v1/create.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResult {
    pub contract_id: String,
    pub template_id: TemplateId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<serde_json::Value>,
    pub payload: serde_json::Value,
    pub signatories: Vec<String>,
    pub observers: Vec<String>,
    #[serde(default)]
    pub agreement_text: String,
}

/// JSON API POST /v1/exercise request body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExerciseRequest {
    pub template_id: TemplateId,
    pub contract_id: String,
    pub choice: String,
    pub argument: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<RequestMeta>,
}

/// Archived contract payload in JSON API choice exercise event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivedContract {
    pub contract_id: String,
    pub template_id: TemplateId,
    pub witness_parties: Vec<String>,
}

/// Created contract payload in JSON API choice exercise event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedContract {
    pub contract_id: String,
    pub template_id: TemplateId,
    pub payload: serde_json::Value,
    pub signatories: Vec<String>,
    pub observers: Vec<String>,
    pub witness_parties: Vec<String>,
}

/// Event returned in JSON API exercise result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JsonEvent {
    Archived(ArchivedContract),
    Created(CreatedContract),
}

/// Result object for JSON API POST /v1/exercise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExerciseResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exercise_result: Option<serde_json::Value>,
    pub events: Vec<JsonEvent>,
    /// The choice result as a Daml value, for the v2 `ExercisedEvent` (not part of the v1 response).
    #[serde(skip)]
    pub result_value: Option<ValueBox>,
}

/// A Daml value carried through a type that must be `Eq` (equality is the value's own; the engine's values hold no floats).
#[derive(Clone, Debug, PartialEq)]
pub struct ValueBox(pub lf_eval::Value);

impl Eq for ValueBox {}

/// Active contract representation in JSON API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractView {
    pub contract_id: String,
    pub template_id: TemplateId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<serde_json::Value>,
    pub payload: serde_json::Value,
    pub signatories: Vec<String>,
    pub observers: Vec<String>,
}

/// Query body for POST /v1/query or POST /v1/contracts.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryContractsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_ids: Option<Vec<TemplateId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<serde_json::Value>,
}

/// Standard Daml JSON API envelope response for successful operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonApiResponse<T> {
    pub status: u16,
    pub result: T,
}

impl<T> JsonApiResponse<T> {
    pub fn ok(result: T) -> Self {
        Self {
            status: 200,
            result,
        }
    }
}

/// Standard Daml JSON API error envelope response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonApiErrorResponse {
    pub status: u16,
    pub errors: Vec<String>,
}

impl JsonApiErrorResponse {
    pub fn new(status: u16, error: impl Into<String>) -> Self {
        Self {
            status,
            errors: vec![error.into()],
        }
    }
}

/// Strongly typed payload for AssetHolding contracts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetHoldingPayload {
    pub bank: String,
    pub owner: String,
    pub auditor: String,
    pub asset_symbol: String,
    pub amount: String,
}
