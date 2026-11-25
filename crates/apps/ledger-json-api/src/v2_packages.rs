//! S-API-006: DAR upload and validation, package contents and status, and the vetted-packages list of the JSON API v2,
//! checked against the Canton 3.7.2 sandbox by `scripts/verify-json-api.sh`.
//!
//! [CANTON-NOTE: SEMANTICS] A package is served as the payload of its DALF envelope (the bytes whose SHA-256 is the
//! package id), with the id in the `Canton-Package-Hash` header. The participant vets every package of an uploaded DAR on
//! its one synchronizer; the vetting topology (serial, `package-vetting/update`) is not modeled.
use std::collections::BTreeMap;

use serde_json::{json, Map, Value as Json};

use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;
use crate::v2_commands::{canton_error, Kind, SYNCHRONIZER};

mod admin_dars;
mod admin_inspect;
mod vetting;

pub use admin_dars::{
    admin_get_dar, admin_remove_dar, admin_upload_dars, admin_vet_dar, load_builtin_ping_dar,
};
pub use admin_inspect::{
    admin_get_dar_contents, admin_get_package_contents, admin_get_package_references,
    admin_remove_package, admin_unvet_dar, admin_validate_dar, AdminDarContents,
    AdminPackageContents, AdminPackageSummary,
};
pub use vetting::{
    preferred_package_version, preferred_packages, vetting_list, vetting_root, vetting_update,
};

use admin_inspect::find_dalf_archive_bytes;

#[cfg(feature = "protocol")]
pub(crate) use vetting::adopt_dar_packages;

/// A package this participant knows: the payload it serves and the metadata of the vetting list.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct PackageRec {
    pub(crate) payload: Vec<u8>,
    name: String,
    version: String,
    /// Vetted on the participant's synchronizer, with the optional validity window (RFC 3339 texts).
    pub(crate) vetted: bool,
    pub(crate) valid_from: Option<String>,
    pub(crate) valid_until: Option<String>,
}

pub(crate) type Packages = BTreeMap<String, PackageRec>;

fn corrupt_dar(dar_name: &str) -> HttpResponse {
    // Canton reports any archive it cannot open this way (the same text for garbage and for an empty body, measured)
    let mut resp = canton_error(
        Kind::Request,
        400,
        "INVALID_DAR",
        "Dar file is corrupt".into(),
        8,
        3,
        json!([]),
    );
    // the context of this error is its own: participant, entries, category, tid, throwable
    if let Ok(mut body) = serde_json::from_slice::<Json>(&resp.body) {
        let mut ctx = Map::new();
        ctx.insert("participant".into(), json!("rust"));
        ctx.insert("entries".into(), json!("List()"));
        ctx.insert("category".into(), json!("8"));
        ctx.insert("tid".into(), json!("0000000000000000"));
        ctx.insert(
            "throwable".into(),
            json!(format!("com.digitalasset.daml.lf.archive.Error$InvalidZipEntry: Invalid zip entryName: META-INF/MANIFEST.MF, DAR: {dar_name}, content: [}}]")),
        );
        body["context"] = Json::Object(ctx);
        resp.body = body.to_string().into_bytes();
        resp.headers
            .insert("Content-Length".into(), resp.body.len().to_string());
    }
    resp
}

/// A refused upload: the node's code, cause text and context keys for that code (the values are ours).
fn upload_refused(e: &lf_archive::DarError, dar_name: &str) -> HttpResponse {
    let code = e.node_code();
    let why = e.to_string();
    let (cause, extra): (&str, Vec<(&str, Json)>) = match code {
        "INVALID_DAR" => return corrupt_dar(dar_name),
        "DAR_PARSE_ERROR" => (
            "Failed to parse the dar file content.",
            vec![("reason", json!(why))],
        ),
        "INVALID_ZIP_ENTRY" => (
            "Dar zip file is corrupt",
            vec![("entries", json!("List()")), ("throwable", json!(why))],
        ),
        "DAR_DEPENDENCIES_NOT_VALID" => (
            "The set of packages in the dar is not self-consistent and is missing dependencies or has extra dependencies",
            vec![
                ("extraDependencies", json!("Set()")),
                ("missingDependencies", json!(format!("Set({})", why.split_whitespace().nth(2).unwrap_or("")))),
                ("mainPackageId", json!("")),
            ],
        ),
        "ALLOWED_LANGUAGE_VERSIONS" => (
            "Disallowed language version in package: Expected version range is List(2.1, 2.2, 2.3, 2.4)",
            vec![
                ("allowedLanguageVersions", json!("List(2.1, 2.2, 2.3, 2.4)")),
                ("packageId", json!("")),
                ("languageVersion", json!(why)),
            ],
        ),
        _ => (
            "Package validation failed.",
            vec![("validationError", json!(why))],
        ),
    };
    let mut resp = canton_error(Kind::Request, 400, code, cause.into(), 8, 3, json!([]));
    if let Ok(mut body) = serde_json::from_slice::<Json>(&resp.body) {
        let mut ctx = Map::new();
        ctx.insert("participant".into(), json!("rust"));
        for (k, v) in extra {
            ctx.insert(k.into(), v);
        }
        ctx.insert("tid".into(), json!("0000000000000000"));
        ctx.insert("category".into(), json!("8"));
        body["context"] = Json::Object(ctx);
        resp.body = body.to_string().into_bytes();
        resp.headers
            .insert("Content-Length".into(), resp.body.len().to_string());
    }
    resp
}

/// Why an upload may not vet its packages: an upgrade check refused it, or a package could not be read for the check.
enum UpgradeRefusal {
    Check(lf_archive::UpgradeCheckError),
    Unreadable(String),
}

impl UpgradeRefusal {
    fn code(&self) -> &'static str {
        match self {
            Self::Check(e) => e.code(),
            Self::Unreadable(_) => "DAR_VALIDATION_ERROR",
        }
    }
}

impl std::fmt::Display for UpgradeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Check(e) => e.fmt(f),
            Self::Unreadable(why) => f.write_str(why),
        }
    }
}

/// The upgrade checks Canton runs when an upload vets the packages of a DAR (`PackageUpgradeValidator.validateUpgrade`):
/// each package name of the DAR, with the vetted packages of that name, must form a lineage of valid upgrades.
///
/// [CANTON-NOTE: LIMITATION] The DARs of one multi-DAR admin upload are each checked against the participant's
/// packages, not against one another.
fn check_upgrades(
    service: &ExecutionService,
    dar: &lf_archive::LoadedDar,
) -> Result<(), UpgradeRefusal> {
    let unreadable =
        |e: lf_archive::typecheck::TypeError| UpgradeRefusal::Unreadable(e.to_string());
    let mut vetted = lf_archive::PackageSignature::of_dar(dar).map_err(unreadable)?;
    let new: std::collections::BTreeSet<String> = vetted.keys().cloned().collect();
    let names: std::collections::BTreeSet<String> =
        vetted.values().map(|sig| sig.name.clone()).collect();
    let mut known = BTreeMap::new();
    let mut lineage_members = Vec::new();
    {
        let packages = service
            .v2_state()
            .packages
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for (id, rec) in packages.iter() {
            if let Some(version) = lf_archive::PackageVersion::parse(&rec.version) {
                let meta = lf_archive::PackageMeta {
                    name: rec.name.clone(),
                    version,
                };
                known.insert(id.clone(), meta);
            }
            if rec.vetted
                && names.contains(&rec.name)
                && !new.contains(id)
                && !rec.payload.is_empty()
            {
                lineage_members.push((id.clone(), rec.payload.clone()));
            }
        }
    }
    for (id, payload) in lineage_members {
        let loaded = lf_archive::load_dalf_payload(&id, &payload)
            .map_err(|e| UpgradeRefusal::Unreadable(e.to_string()))?;
        let sig =
            lf_archive::PackageSignature::from_package(&id, &loaded.package, &loaded.lf_version)
                .map_err(unreadable)?;
        vetted.insert(id, sig);
    }
    lf_archive::validate_upgrade(&new, &vetted, &known).map_err(UpgradeRefusal::Check)
}

/// `POST /v2/dars` and `POST /v2/packages` (upload) and `POST /v2/dars/validate` (`validate_only`: nothing is kept).
pub fn upload(service: &ExecutionService, req: &HttpRequest, validate_only: bool) -> HttpResponse {
    let dar_name = if validate_only {
        "defaultDarName"
    } else {
        "uploaded-via-ledger-api"
    };
    // [CANTON-NOTE: ORACLE] the node's answers to a DAR it does not accept (S-LF-014): `DAR_PARSE_ERROR` for a package that
    // does not decode, `ALLOWED_LANGUAGE_VERSIONS`, `INVALID_ZIP_ENTRY` for a manifest naming a missing file or no DALFs,
    // `DAR_DEPENDENCIES_NOT_VALID` for a package whose dependency is not in the DAR (the participant's earlier uploads do not
    // count: measured), `DAR_VALIDATION_ERROR` for a package that does not pass `lf_archive::typecheck` (U-11, S-LF-016), and
    // `INVALID_DAR` for an archive that cannot be opened.
    let loaded = match lf_archive::parse_loaded_dar(std::io::Cursor::new(&req.body)) {
        Ok(l) => l,
        Err(e) => return upload_refused(&e, dar_name),
    };
    if let Err(e) = lf_archive::check_dar_for_upload(&loaded, &std::collections::HashSet::new()) {
        return upload_refused(&e, dar_name);
    }
    let Ok(payloads) = lf_archive::dalf_payloads(&req.body) else {
        return corrupt_dar(dar_name);
    };
    // [CANTON-NOTE: SEMANTICS] `PackageService.validateDar` (`PackageService.scala:595-626`),
    // `PackageOps.scala:464, 487-499`, `ParticipantTopologyValidation.scala:45-89`,
    // `PackageUpgradeValidator.scala:66-170`, and `VettingIT.scala:939-963`: dry-run DAR
    // validation runs upgrade validation against currently vetted packages before returning 200.
    // [CANTON-NOTE: LIMITATION] `validateDamlPrimOrStdLib` (`DAML_PRIM_NOT_UTILITY_PACKAGE`),
    // PV <= 34 dependency vetting, and synchronizer auto-detection on HTTP `/v2/dars/validate`
    // are not modeled here.
    if let Err(e) = check_upgrades(service, &loaded) {
        return canton_error(Kind::Request, 400, e.code(), e.to_string(), 8, 3, json!([]));
    }
    if validate_only {
        // Canton answers 200 with an empty body
        let mut resp = HttpResponse::json(200, &Json::Null);
        resp.body.clear();
        resp.headers.insert("Content-Length".into(), "0".into());
        return resp;
    }
    match service
        .load_loaded_dar(req.body.clone(), &loaded)
        .map_err(|e| e.to_string())
    {
        Ok(info) => {
            if let Err(err) = service.vet_loaded_dar(&loaded) {
                return canton_error(
                    Kind::Request,
                    400,
                    "DAR_VALIDATION_ERROR",
                    err.to_string(),
                    8,
                    3,
                    json!([]),
                );
            }
            let mut known = service.v2_state().packages.lock().expect("packages lock");
            let mut added = false;
            for (id, payload) in payloads {
                if known.contains_key(&id) {
                    continue;
                }
                added = true;
                let meta = info.dalfs.iter().find(|d| d.package_id == id);
                known.insert(
                    id,
                    PackageRec {
                        vetted: true,
                        valid_from: None,
                        valid_until: None,
                        payload,
                        name: meta
                            .and_then(|d| d.package_name.clone())
                            .unwrap_or_default(),
                        version: meta
                            .and_then(|d| d.package_version.clone())
                            .unwrap_or_default(),
                    },
                );
            }
            if added {
                // uploading new packages vets them: one topology transaction, the serial moves on (measured: 1 -> 2)
                *service
                    .v2_state()
                    .vetting_serial
                    .lock()
                    .expect("serial lock") += 1;
            }
            // the participant keeps the DARs it was given (see `ExecutionService::restore_admin_state`)
            service
                .v2_state()
                .journal("dars.journal", || Ok(crate::v2::base64(&req.body)));
            let dar_sink = service
                .v2_state()
                .official_dar_sink
                .lock()
                .ok()
                .and_then(|s| s.clone());
            if let Some(sink) = dar_sink {
                sink(&req.body);
            }
            HttpResponse::json(200, &json!({}))
        }
        Err(_) => corrupt_dar(dar_name),
    }
}

/// The main package ID of Canton's built-in admin ping workflow DAR (`canton-builtin-admin-workflow-ping.dar`).
pub const ADMIN_PING_PACKAGE_ID: &str =
    "de2cc2f90eb523414ff54e899951dadd8789a4c07e0f71f6d6c9eaf57d412a54";

/// One DAR entry passed to [`admin_upload_dars`].
pub struct UploadDarItem<'a> {
    pub bytes: &'a [u8],
    pub description: Option<&'a str>,
    pub expected_main_package_id: Option<&'a str>,
}

fn logical_sync_id(s: &str) -> String {
    match s.split_once("::") {
        Some((name, rest)) => match rest.split_once("::") {
            Some((fp, _)) => format!("{name}::{fp}"),
            None => s.to_string(),
        },
        None => s.to_string(),
    }
}

fn is_valid_package_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 255
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

fn package_not_found(id: &str) -> HttpResponse {
    let mut resp = canton_error(
        Kind::Request,
        404,
        "PACKAGE_NOT_FOUND",
        "Could not find package.".into(),
        11,
        5,
        json!([["PACKAGE", id]]),
    );
    if let Ok(mut body) = serde_json::from_slice::<Json>(&resp.body) {
        body["context"]["packageId"] = json!(format!("'{id}'"));
        resp.body = body.to_string().into_bytes();
        resp.headers
            .insert("Content-Length".into(), resp.body.len().to_string());
    }
    resp
}

/// `GET /v2/packages/{id}`: the package payload with the `Canton-Package-Hash` header.
pub fn get_package(service: &ExecutionService, id: &str) -> HttpResponse {
    let stored = service
        .v2_state()
        .packages
        .lock()
        .expect("packages lock")
        .get(id)
        .map(|rec| rec.payload.clone())
        .filter(|p| !p.is_empty());
    let body = stored.or_else(|| find_dalf_archive_bytes(service, id).map(|(_, p)| p));
    let Some(body) = body else {
        return package_not_found(id);
    };
    let mut resp = HttpResponse::json(200, &Json::Null);
    resp.body = body;
    resp.headers
        .insert("Content-Type".into(), "application/octet-stream".into());
    resp.headers
        .insert("Content-Length".into(), resp.body.len().to_string());
    resp.headers
        .insert("Canton-Package-Hash".into(), id.to_string());
    resp
}

/// `GET /v2/packages/{id}/status`: an unknown id is not an error, it is `PACKAGE_STATUS_UNSPECIFIED`.
pub fn package_status(service: &ExecutionService, id: &str) -> HttpResponse {
    let in_pkgs = service
        .v2_state()
        .packages
        .lock()
        .expect("packages lock")
        .contains_key(id);
    let in_dars = in_pkgs || find_dalf_archive_bytes(service, id).is_some();
    let status = if in_dars {
        "PACKAGE_STATUS_REGISTERED"
    } else {
        "PACKAGE_STATUS_UNSPECIFIED"
    };
    HttpResponse::json(200, &json!({ "packageStatus": status }))
}

fn vetted_json(id: &str, rec: &PackageRec) -> Json {
    json!({
        "packageId": id,
        "validFromInclusive": rec.valid_from,
        "validUntilExclusive": rec.valid_until,
        "packageName": rec.name,
        "packageVersion": rec.version
    })
}

fn vetted_packages(service: &ExecutionService, known: &Packages, serial: u64) -> Json {
    json!({
        "packages": known.iter().filter(|(_, r)| r.vetted).map(|(id, r)| vetted_json(id, r)).collect::<Vec<_>>(),
        "participantId": service.v2_state().participant_id(),
        "synchronizerId": SYNCHRONIZER,
        "topologySerial": serial
    })
}
