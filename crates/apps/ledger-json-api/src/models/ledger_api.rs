use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const DEFAULT_MODULE_NAME: &str = "AssetHolding";
pub const DEFAULT_ENTITY_NAME: &str = "AssetHolding";

/// Qualified template identifier: `<package_id>:<module_name>:<entity_name>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemplateId {
    pub package_id: String,
    pub module_name: String,
    pub entity_name: String,
}

impl TemplateId {
    pub fn new(
        package_id: impl Into<String>,
        module_name: impl Into<String>,
        entity_name: impl Into<String>,
    ) -> Self {
        Self {
            package_id: package_id.into(),
            module_name: module_name.into(),
            entity_name: entity_name.into(),
        }
    }

    pub fn asset_holding() -> Self {
        Self::new(
            lf_eval::ledger::sample_package_id(),
            DEFAULT_MODULE_NAME,
            DEFAULT_ENTITY_NAME,
        )
    }
}

impl fmt::Display for TemplateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.package_id.is_empty(), self.module_name.is_empty()) {
            (true, true) => write!(f, "{}", self.entity_name),
            (true, false) => write!(f, "{}:{}", self.module_name, self.entity_name),
            (false, _) => write!(
                f,
                "{}:{}:{}",
                self.package_id, self.module_name, self.entity_name
            ),
        }
    }
}

impl FromStr for TemplateId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 3 {
            Ok(Self::new(parts[0], parts[1], parts[2]))
        } else if parts.len() == 2 {
            // module:entity with unspecified package id resolved dynamically against loaded DARs
            Ok(Self::new("", parts[0], parts[1]))
        } else if parts.len() == 1 && !parts[0].is_empty() {
            // entity-only shorthand with unspecified package and module resolved dynamically
            Ok(Self::new("", "", parts[0]))
        } else {
            Err(format!(
                "invalid template identifier '{s}', expected '<package_id>:<module>:<entity>'"
            ))
        }
    }
}

impl Serialize for TemplateId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for TemplateId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Str(String),
            Obj {
                #[serde(alias = "packageId")]
                package_id: String,
                #[serde(alias = "moduleName")]
                module_name: String,
                #[serde(alias = "entityName")]
                entity_name: String,
            },
        }

        match Repr::deserialize(deserializer)? {
            Repr::Str(s) => TemplateId::from_str(&s).map_err(serde::de::Error::custom),
            Repr::Obj {
                package_id,
                module_name,
                entity_name,
            } => Ok(TemplateId::new(package_id, module_name, entity_name)),
        }
    }
}

/// Deduplication period specification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeduplicationPeriod {
    DurationInSeconds(u64),
    Offset(u64),
}

/// Command to create a contract instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCommand {
    pub template_id: TemplateId,
    pub create_arguments: serde_json::Value,
}

/// Command to exercise a choice on an existing contract instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExerciseCommand {
    pub template_id: TemplateId,
    pub contract_id: String,
    pub choice: String,
    pub choice_argument: serde_json::Value,
}

/// Individual ledger command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Command {
    Create(CreateCommand),
    Exercise(ExerciseCommand),
}

/// Batch of commands submitted for execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Commands {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    pub application_id: String,
    pub command_id: String,
    pub act_as: Vec<String>,
    #[serde(default)]
    pub read_as: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deduplication_period: Option<DeduplicationPeriod>,
    pub commands: Vec<Command>,
}

/// Request to submit commands and await execution result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitAndWaitRequest {
    pub commands: Commands,
}

/// Created event in a transaction tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedEvent {
    pub event_id: String,
    pub contract_id: String,
    pub template_id: TemplateId,
    pub create_arguments: serde_json::Value,
    pub signatories: Vec<String>,
    pub observers: Vec<String>,
    pub witness_parties: Vec<String>,
}

/// Exercised event in a transaction tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExercisedEvent {
    pub event_id: String,
    pub contract_id: String,
    pub template_id: TemplateId,
    pub choice: String,
    pub choice_argument: serde_json::Value,
    pub acting_parties: Vec<String>,
    pub consuming: bool,
    pub witness_parties: Vec<String>,
    pub child_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exercise_result: Option<serde_json::Value>,
}

/// Event within a transaction tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TreeEvent {
    Created(CreatedEvent),
    Exercised(ExercisedEvent),
}

/// Complete transaction tree resulting from command execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionTree {
    pub update_id: String,
    pub command_id: String,
    pub workflow_id: String,
    pub effective_at: u64,
    pub offset: u64,
    pub events_by_id: HashMap<String, TreeEvent>,
    pub root_event_ids: Vec<String>,
}

/// An active contract in the Active Contract Set (ACS).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveContract {
    pub contract_id: String,
    pub template_id: TemplateId,
    pub create_arguments: serde_json::Value,
    pub signatories: Vec<String>,
    pub observers: Vec<String>,
    pub witness_parties: Vec<String>,
}

/// Response returned from an ACS query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetActiveContractsResponse {
    pub offset: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    pub active_contracts: Vec<ActiveContract>,
}
