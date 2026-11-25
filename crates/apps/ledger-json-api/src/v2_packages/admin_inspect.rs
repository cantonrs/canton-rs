//! Admin API inspection and removal of DARs and packages (contents, references, validation, unvetting).

use std::collections::BTreeMap;

use crate::service::ExecutionService;

use super::admin_dars::check_vetting_synchronizer;
use super::{check_upgrades, is_valid_package_id, ADMIN_PING_PACKAGE_ID};

/// Package summary entry returned by Admin DAR/Package inspection calls:
/// `(package_id, name, version, payload_size_bytes)`.
pub type AdminPackageSummary = (String, String, String, usize);

/// Contents of a loaded DAR returned by Admin `PackageService/GetDarContents`.
#[derive(Clone, Debug)]
pub struct AdminDarContents {
    pub main: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub packages: Vec<AdminPackageSummary>,
}

/// Contents of a loaded DALF package returned by Admin `PackageService/GetPackageContents`.
#[derive(Clone, Debug)]
pub struct AdminPackageContents {
    pub package_id: String,
    pub name: String,
    pub version: String,
    pub size: usize,
    pub modules: Vec<String>,
    pub is_utility_package: bool,
    pub language_version: String,
}

pub(super) fn find_dalf_archive_bytes(
    service: &ExecutionService,
    package_id: &str,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let dars = service
        .v2_state()
        .loaded_dars
        .lock()
        .ok()
        .map(|d| d.clone())
        .unwrap_or_default();
    for dar in &dars {
        if let Ok(entries) = lf_archive::dalf_entries(&dar.bytes) {
            if let Some((_, archive_bytes, payload)) =
                entries.into_iter().find(|(id, _, _)| id == package_id)
            {
                return Some((archive_bytes, payload));
            }
        }
    }
    None
}

/// Returns the packages inside a loaded DAR (`PackageService/GetDarContents`).
pub fn admin_get_dar_contents(
    service: &ExecutionService,
    main_package_id: &str,
) -> Result<AdminDarContents, (i32, String)> {
    if !is_valid_package_id(main_package_id) {
        return Err((3, format!("Invalid DAR main package-id: {main_package_id}")));
    }
    let entry = {
        let dars = service
            .v2_state()
            .loaded_dars
            .lock()
            .map_err(|_| (13, "loaded_dars lock poisoned".to_string()))?;
        dars.iter()
            .find(|d| d.main_package_id == main_package_id)
            .cloned()
            .ok_or_else(|| {
                (
                    5,
                    format!(
                        "DAR_NOT_FOUND(11,00000000): getDarContents operation failed due to non-existent DAR archive with main package-id {main_package_id}"
                    ),
                )
            })?
    };
    let known_sizes: BTreeMap<String, (String, String, usize)> = service
        .v2_state()
        .packages
        .lock()
        .ok()
        .map(|k| {
            k.iter()
                .map(|(id, r)| {
                    (
                        id.clone(),
                        (r.name.clone(), r.version.clone(), r.payload.len()),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let dalf_sizes: BTreeMap<String, usize> = lf_archive::dalf_payloads(&entry.bytes)
        .unwrap_or_default()
        .into_iter()
        .map(|(id, p)| (id, p.len()))
        .collect();
    let packages = entry
        .package_ids
        .iter()
        .map(|id| {
            let (name, version) = known_sizes
                .get(id)
                .filter(|(n, _, _)| !n.is_empty())
                .map(|(n, v, _)| (n.clone(), v.clone()))
                .or_else(|| service.package_name_and_version(id))
                .unwrap_or_default();
            let size = known_sizes
                .get(id)
                .map(|(_, _, sz)| *sz)
                .filter(|&sz| sz > 0)
                .or_else(|| dalf_sizes.get(id).copied())
                .unwrap_or(0);
            (id.clone(), name, version, size)
        })
        .collect();
    Ok(AdminDarContents {
        main: entry.main_package_id,
        name: entry.name,
        version: entry.version,
        description: entry.description,
        packages,
    })
}

/// Returns decoded module list, utility flag, and LF version for `package_id` (`PackageService/GetPackageContents`).
pub fn admin_get_package_contents(
    service: &ExecutionService,
    package_id: &str,
) -> Result<AdminPackageContents, (i32, String)> {
    if !is_valid_package_id(package_id) {
        return Err((3, format!("Invalid package ID: {package_id}")));
    }
    let stored = service
        .v2_state()
        .packages
        .lock()
        .ok()
        .and_then(|k| k.get(package_id).cloned());
    let found_dalf = find_dalf_archive_bytes(service, package_id);
    if stored.is_none() && found_dalf.is_none() {
        return Err((
            5,
            format!("PACKAGE_NOT_FOUND(11,00000000): Could not find package {package_id}"),
        ));
    }

    let (mut name, mut version) = stored
        .as_ref()
        .map(|r| (r.name.clone(), r.version.clone()))
        .unwrap_or_default();
    if name.is_empty() {
        if let Some((n, v)) = service.package_name_and_version(package_id) {
            name = n;
            version = v;
        }
    }
    let size = stored
        .as_ref()
        .map(|r| r.payload.len())
        .filter(|&n| n > 0)
        .or_else(|| found_dalf.as_ref().map(|(_, p)| p.len()))
        .unwrap_or(0);

    if let Some((archive_bytes, _)) = found_dalf {
        if let Ok(loaded) = lf_archive::load_dalf(&archive_bytes) {
            let decoded = lf_archive::decode_dalf(&archive_bytes).ok();
            let modules = decoded
                .as_ref()
                .map(|d| d.modules.clone())
                .unwrap_or_default();
            if name.is_empty() {
                if let Some(d) = decoded.as_ref() {
                    if let Some(n) = &d.package_name {
                        name = n.clone();
                    }
                    if let Some(v) = &d.package_version {
                        version = v.clone();
                    }
                }
            }
            let is_utility_package = loaded
                .package
                .modules
                .iter()
                .all(|m| m.templates.is_empty() && m.interfaces.is_empty());
            return Ok(AdminPackageContents {
                package_id: package_id.to_string(),
                name,
                version,
                size,
                modules,
                is_utility_package,
                language_version: loaded.lf_version,
            });
        }
    }

    // Fallback: inspect stored payload wrapped inside a `daml_lf.Archive` envelope.
    let (modules, language_version, is_utility_package) = stored
        .and_then(|rec| {
            use prost::Message as _;
            let env = lf_archive::proto::daml_lf::Archive {
                hash_function: lf_archive::proto::daml_lf::HashFunction::Sha256 as i32,
                hash: package_id.to_string(),
                payload: rec.payload,
            }
            .encode_to_vec();
            let loaded = lf_archive::load_dalf(&env).ok()?;
            let decoded = lf_archive::decode_dalf(&env).ok()?;
            let is_util = loaded
                .package
                .modules
                .iter()
                .all(|m| m.templates.is_empty() && m.interfaces.is_empty());
            Some((decoded.modules, loaded.lf_version, is_util))
        })
        .unwrap_or_else(|| (Vec::new(), "2.1".to_string(), true));

    Ok(AdminPackageContents {
        package_id: package_id.to_string(),
        name,
        version,
        size,
        modules,
        is_utility_package,
        language_version,
    })
}

/// Returns all loaded DAR descriptions referencing `package_id` (`PackageService/GetPackageReferences`).
pub fn admin_get_package_references(
    service: &ExecutionService,
    package_id: &str,
) -> Result<Vec<(String, String, String, String)>, (i32, String)> {
    if !is_valid_package_id(package_id) {
        return Err((3, format!("Invalid package ID: {package_id}")));
    }
    let dars = service
        .v2_state()
        .loaded_dars
        .lock()
        .map_err(|_| (13, "loaded_dars lock poisoned".to_string()))?;
    let refs = dars
        .iter()
        .filter(|d| {
            d.main_package_id == package_id || d.package_ids.iter().any(|p| p == package_id)
        })
        .map(|d| {
            (
                d.main_package_id.clone(),
                d.name.clone(),
                d.version.clone(),
                d.description.clone(),
            )
        })
        .collect();
    Ok(refs)
}

/// Validates DAR bytes without mutating participant package/DAR state (`PackageService/ValidateDar`).
pub fn admin_validate_dar(
    service: &ExecutionService,
    bytes: &[u8],
    synchronizer_id: Option<&str>,
) -> Result<String, (i32, String)> {
    if let Some(sync) = synchronizer_id.filter(|s| !s.is_empty()) {
        check_vetting_synchronizer(service, Some(sync))?;
    }
    let loaded = lf_archive::parse_loaded_dar(std::io::Cursor::new(bytes))
        .map_err(|e| (3, format!("{}(8,00000000): {e}", e.node_code())))?;
    if let Err(e) = lf_archive::check_dar_for_upload(&loaded, &std::collections::HashSet::new()) {
        return Err((3, format!("{}(8,00000000): {e}", e.node_code())));
    }
    let _ = lf_archive::dalf_payloads(bytes).map_err(|_| {
        (
            3,
            "INVALID_DAR(8,00000000): Dar file is corrupt".to_string(),
        )
    })?;
    // [CANTON-NOTE: SEMANTICS] `GrpcPackageService.validateDar` (`GrpcPackageService.scala:77-92`)
    // delegates to `PackageService.validateDar`, so gRPC Admin `ValidateDar` runs the same upgrade check.
    if let Err(e) = check_upgrades(service, &loaded) {
        return Err((3, format!("{}(8,00000000): {e}", e.code())));
    }
    Ok(loaded.archive.main_package_id)
}

/// Revokes vetting for all exclusive packages (and main package) of `main_package_id` (`PackageService/UnvetDar`).
pub fn admin_unvet_dar(
    service: &ExecutionService,
    main_package_id: &str,
    synchronizer_id: Option<&str>,
) -> Result<(), (i32, String)> {
    check_vetting_synchronizer(service, synchronizer_id)?;
    if !is_valid_package_id(main_package_id) {
        return Err((3, format!("Invalid DAR main package-id: {main_package_id}")));
    }
    let (entry, remaining) = {
        let dars = service
            .v2_state()
            .loaded_dars
            .lock()
            .map_err(|_| (13, "loaded_dars lock poisoned".to_string()))?;
        let Some(entry) = dars
            .iter()
            .find(|d| d.main_package_id == main_package_id)
            .cloned()
        else {
            return Err((
                5,
                format!(
                    "DAR_NOT_FOUND(11,00000000): DAR archive unvetting failed due to non-existent DAR archive with main package-id {main_package_id}"
                ),
            ));
        };
        let remaining: Vec<_> = dars
            .iter()
            .filter(|d| d.main_package_id != main_package_id)
            .cloned()
            .collect();
        (entry, remaining)
    };

    let unvet_targets: Vec<String> = entry
        .package_ids
        .iter()
        .filter(|id| {
            *id == main_package_id || !remaining.iter().any(|r| r.package_ids.contains(id))
        })
        .cloned()
        .collect();
    let mut changed = false;
    let remaining_vetted: Vec<String> = {
        let mut known = service.v2_state().packages.lock().expect("packages lock");
        for id in &unvet_targets {
            if let Some(rec) = known.get_mut(id) {
                if rec.vetted {
                    rec.vetted = false;
                    changed = true;
                }
            }
        }
        known
            .iter()
            .filter(|(_, rec)| rec.vetted)
            .map(|(id, _)| id.clone())
            .collect()
    };
    if changed {
        *service
            .v2_state()
            .vetting_serial
            .lock()
            .expect("serial lock") += 1;
        service
            .sync_vetted_packages(synchronizer_id, &remaining_vetted)
            .map_err(|e| (9, format!("PACKAGE_VETTING_FAILED(9,00000000): {e}")))?;
    }
    Ok(())
}

/// Removes an individual unvetted, unused package (`PackageService/RemovePackage`).
pub fn admin_remove_package(
    service: &ExecutionService,
    package_id: &str,
    force: bool,
) -> Result<(), (i32, String)> {
    if !is_valid_package_id(package_id) {
        return Err((3, format!("Invalid package ID: {package_id}")));
    }
    let exists_in_pkgs = service
        .v2_state()
        .packages
        .lock()
        .ok()
        .is_some_and(|k| k.contains_key(package_id));
    let referenced_dars = admin_get_package_references(service, package_id)?;
    if !exists_in_pkgs && referenced_dars.is_empty() {
        return Err((
            5,
            format!("PACKAGE_NOT_FOUND(11,00000000): Could not find package {package_id}"),
        ));
    }
    if package_id == ADMIN_PING_PACKAGE_ID {
        return Err((
            9,
            format!(
                "PACKAGE_OR_DAR_REMOVAL_ERROR(9,00000000): Removal of package {package_id} failed as packages needed for admin workflows cannot be removed."
            ),
        ));
    }
    if !force {
        if !referenced_dars.is_empty() {
            return Err((
                9,
                format!(
                    "PACKAGE_OR_DAR_REMOVAL_ERROR(9,00000000): Package {package_id} is still referenced by DAR {}.",
                    referenced_dars[0].0
                ),
            ));
        }
        let is_vetted = service
            .v2_state()
            .packages
            .lock()
            .ok()
            .and_then(|k| k.get(package_id).map(|r| r.vetted))
            .unwrap_or(false);
        if is_vetted {
            return Err((
                9,
                format!(
                    "PACKAGE_OR_DAR_REMOVAL_ERROR(9,00000000): Package {package_id} is currently vetted and cannot be removed without force."
                ),
            ));
        }
        if let Ok(contracts) = service.generic_contracts.read() {
            if let Some(c) = contracts.values().find(|c| {
                c.active && (c.package_id == package_id || c.template_id.package_id == package_id)
            }) {
                return Err((
                    9,
                    format!(
                        "PACKAGE_OR_DAR_REMOVAL_ERROR(9,00000000): Package {package_id} is in-use by contract {}.",
                        c.contract_id
                    ),
                ));
            }
        }
    }
    if let Ok(mut known) = service.v2_state().packages.lock() {
        known.remove(package_id);
    }
    if let Ok(mut known) = service.v2_state().known_packages.lock() {
        known.retain(|id| id != package_id);
    }
    if let Ok(mut names) = service.package_names.write() {
        names.retain(|(_, id, _)| id != package_id);
    }
    if let Ok(mut pkgs) = service.lf_packages.write() {
        pkgs.retain(|p| p.main_package_id != package_id);
    }
    Ok(())
}
