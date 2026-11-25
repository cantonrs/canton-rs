//! The JSON <-> value codec of a template payload or a choice argument, with a fall-back for the types the surface codec cannot show.
//!
//! [CANTON-NOTE: WHY] `lf_eval::codec::RecordSchema` reads the field types of a template from the package's *surface* (`ModuleSurface`),
//! which names a record or variant field only as an opaque type constructor, so a template with a record inside a record, a variant or a
//! `Map` (every template of the official Splice DARs: `DsoBootstrap`, `AmuletRules`, ...) fails with `UnsupportedType`. The typed codec
//! (`lf_eval::typed_json::Types`) resolves every type from the package itself. The surface codec stays the first choice, so what the
//! simulation tests measured against the JVM node (field order, error texts) does not change for the templates it already handles; only
//! the types it refuses are read and written by the typed codec.
//! [CANTON-NOTE: SEMANTICS] A payload the typed codec writes is the Ledger API JSON's contract encoding (`encode_ledger_api`: numerics as plain
//! decimals at their scale, `Time` as RFC 3339, `Map` as an array of pairs).
use std::sync::Arc;

use lf_eval::codec::{CodecError, RecordSchema};
use lf_eval::typed_json::{LfType, Types};
use lf_eval::Value;
use serde_json::Value as Json;

use crate::service::LfPackage;

/// A schema of one record type (a template payload or a choice argument) that reads and writes JSON.
pub struct PayloadSchema {
    surface: Option<RecordSchema>,
    typed: Option<(Arc<LfPackage>, LfType)>,
}

fn typed_error(e: String) -> CodecError {
    CodecError::Typed(e)
}

impl PayloadSchema {
    fn from_parts(
        surface: Result<RecordSchema, CodecError>,
        typed: Option<(Arc<LfPackage>, LfType)>,
    ) -> Result<Self, CodecError> {
        match (surface, typed) {
            (Ok(surface), typed) => Ok(Self {
                surface: Some(surface),
                typed,
            }),
            (Err(_), Some(typed)) => Ok(Self {
                surface: None,
                typed: Some(typed),
            }),
            (Err(e), None) => Err(e),
        }
    }

    /// The payload schema of `local_id` (`Module:Entity`) of the package `package_id` (a package `pkg` holds).
    pub fn template(
        pkg: &Arc<LfPackage>,
        package_id: &str,
        local_id: &str,
    ) -> Result<Self, CodecError> {
        let typed = Types::new(&pkg.world)
            .template(package_id, local_id)
            .ok()
            .map(|ty| (Arc::clone(pkg), ty));
        // [CANTON-NOTE: WHY] The surfaces are those of the DAR's main package: a template of another package of the DAR (an older version of the
        // same package, a dependency) may have other fields, so only the typed codec, which reads the package by its id, is right for it.
        let surface = if pkg.main_package_id == package_id {
            RecordSchema::template(&pkg.surfaces, local_id)
        } else {
            Err(CodecError::Typed(
                "the surface is that of another package".to_string(),
            ))
        };
        Self::from_parts(surface, typed)
    }

    /// The argument schema of `choice` of the template `local_id` of the package `package_id`.
    pub fn choice_arg(
        pkg: &Arc<LfPackage>,
        package_id: &str,
        local_id: &str,
        choice: &str,
    ) -> Result<Self, CodecError> {
        let typed = Types::new(&pkg.world)
            .choice(package_id, local_id, choice)
            .ok()
            .map(|c| (Arc::clone(pkg), c.argument));
        Self::from_parts(
            RecordSchema::choice_arg(&pkg.surfaces, local_id, choice),
            typed,
        )
    }

    pub fn from_json(&self, json: &Json) -> Result<Value, CodecError> {
        if let Some(surface) = &self.surface {
            match surface.from_json(json) {
                Err(CodecError::UnsupportedType { .. }) if self.typed.is_some() => {}
                other => return other,
            }
        }
        let (pkg, ty) = self
            .typed
            .as_ref()
            .ok_or_else(|| CodecError::Typed("no type information for the record".to_string()))?;
        Types::new(&pkg.world).decode(ty, json).map_err(typed_error)
    }

    pub fn to_json(&self, value: &Value) -> Result<Json, CodecError> {
        if let Some(surface) = &self.surface {
            match surface.to_json(value) {
                // [CANTON-NOTE: WHY] Any refusal, not only an unsupported type: the value may be of another version of the package than the
                // surface (a contract of an official database, whose template exists in several versions), which the surface reads with the
                // wrong fields. Writing a value out has no client-visible error text to keep, the typed codec reads the package by its id.
                Err(_) if self.typed.is_some() => {}
                other => return other,
            }
        }
        let (pkg, ty) = self
            .typed
            .as_ref()
            .ok_or_else(|| CodecError::Typed("no type information for the record".to_string()))?;
        Types::new(&pkg.world)
            .encode_ledger_api(ty, value)
            .map_err(typed_error)
    }
}

/// [CANTON-NOTE: SEMANTICS] Matches Canton 3.7.2 `SchemaProcessorsImpl.scala:251` (`removeTrailingNonesInRecords = true`) and
/// `JsonCodec.scala:66-68`: drops only trailing `None` record fields while preserving non-trailing `None` fields as `null`.
pub fn typed_only_contract_json(
    service: &crate::service::ExecutionService,
    template: &crate::models::ledger_api::TemplateId,
    value: &Value,
) -> Option<Json> {
    let pkg = service.v2_lf_package(&template.package_id)?;
    let local_id = format!("{}:{}", template.module_name, template.entity_name);
    let schema = PayloadSchema::template(&pkg, &template.package_id, &local_id).ok()?;
    if let Some(surface) = &schema.surface {
        if surface.to_json(value).is_ok() {
            return None;
        }
    }
    schema.typed_json(value)
}

impl PayloadSchema {
    fn typed_json(&self, value: &Value) -> Option<Json> {
        let (pkg, ty) = self.typed.as_ref()?;
        Types::new(&pkg.world).encode_ledger_api(ty, value).ok()
    }
}
