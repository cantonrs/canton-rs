//! Admin API DAR upload, download, vetting and removal.

use std::collections::BTreeMap;

use crate::service::ExecutionService;

use super::{
    check_upgrades, is_valid_package_id, logical_sync_id, PackageRec, UploadDarItem,
    ADMIN_PING_PACKAGE_ID,
};

pub(super) fn check_vetting_synchronizer(
    service: &ExecutionService,
    synchronizer_id: Option<&str>,
) -> Result<(), (i32, String)> {
    let connected = service.connected_synchronizers();
    if let Some(req) = synchronizer_id.filter(|s| !s.is_empty()) {
        let req_logical = logical_sync_id(req);
        let matches = connected
            .iter()
            .any(|(_, id)| id == req || logical_sync_id(id) == req_logical);
        if !matches {
            return Err((
                9,
                format!(
                    "PACKAGE_SERVICE_NOT_CONNECTED_TO_SYNCHRONIZER(9,00000000): Cannot upload a dar because the participant is not connected to synchronizer '{req}'."
                ),
            ));
        }
        return Ok(());
    }
    match connected.len() {
        0 => Err((
            9,
            "PACKAGE_SERVICE_CANNOT_AUTODETECT_SYNCHRONIZER(9,00000000): Cannot autodetect a synchronizer because no synchronizer is connected.".into(),
        )),
        1 => Ok(()),
        _ => Err((
            9,
            "PACKAGE_SERVICE_CANNOT_AUTODETECT_SYNCHRONIZER(9,00000000): Cannot autodetect a synchronizer because multiple synchronizers are connected.".into(),
        )),
    }
}

/// Uploads one or more DARs through the Admin `PackageService/UploadDar` path.
///
/// [CANTON-NOTE: SEMANTICS] Validates all DAR payloads and `expected_main_package_id` constraints before committing any DAR,
/// vets packages on the target synchronizer only when `vet_all_packages` is true, and optionally keeps the upload out of
/// `dars.journal` / `official_dar_sink` when loading internal built-in workflows (`record_external = false`).
pub fn admin_upload_dars(
    service: &ExecutionService,
    dars: &[UploadDarItem<'_>],
    vet_all_packages: bool,
    synchronizer_id: Option<&str>,
    record_external: bool,
) -> Result<Vec<String>, (i32, String)> {
    if vet_all_packages {
        check_vetting_synchronizer(service, synchronizer_id)?;
    }
    let mut validated = Vec::with_capacity(dars.len());
    for item in dars {
        if let Some(desc) = item.description {
            if desc.len() > 255 {
                return Err((
                    3,
                    format!(
                        "INVALID_DAR_FILE_NAME(8,00000000): Invalid DAR description length ({} > 255)",
                        desc.len()
                    ),
                ));
            }
        }
        let loaded = lf_archive::parse_loaded_dar(std::io::Cursor::new(item.bytes))
            .map_err(|e| (3, format!("{}(8,00000000): {e}", e.node_code())))?;
        if let Err(e) = lf_archive::check_dar_for_upload(&loaded, &std::collections::HashSet::new())
        {
            return Err((3, format!("{}(8,00000000): {e}", e.node_code())));
        }
        let payloads = lf_archive::dalf_payloads(item.bytes).map_err(|_| {
            (
                3,
                "INVALID_DAR(8,00000000): Dar file is corrupt".to_string(),
            )
        })?;
        if let Some(expected) = item.expected_main_package_id.filter(|s| !s.is_empty()) {
            if loaded.archive.main_package_id != expected {
                return Err((
                    3,
                    format!(
                        "MAIN_PACKAGE_IN_DAR_DOES_NOT_MATCH_EXPECTED(8,00000000): The main package '{}' in the uploaded DAR does not match the expected main package '{}'.",
                        loaded.archive.main_package_id, expected
                    ),
                ));
            }
        }
        if vet_all_packages {
            check_upgrades(service, &loaded)
                .map_err(|e| (3, format!("{}(8,00000000): {e}", e.code())))?;
        }
        validated.push((item, loaded.archive.main_package_id, payloads));
    }

    let mut dar_ids = Vec::with_capacity(validated.len());
    for (item, main_id, payloads) in validated {
        let info = crate::v2_commands::load_dar_bytes(service, item.bytes)
            .map_err(|e| (3, format!("INVALID_DAR(8,00000000): {e}")))?;
        if let Some(desc) = item.description {
            if let Ok(mut entries) = service.v2_state().loaded_dars.lock() {
                if let Some(entry) = entries.iter_mut().find(|d| d.main_package_id == main_id) {
                    entry.description = desc.to_string();
                }
            }
        }
        if vet_all_packages {
            service
                .vet_dar(item.bytes)
                .map_err(|e| (3, format!("DAR_VALIDATION_ERROR(8,00000000): {e}")))?;
        }
        let mut known = service.v2_state().packages.lock().expect("packages lock");
        let mut vetting_changed = false;
        for (id, payload) in payloads {
            if let Some(rec) = known.get_mut(&id) {
                if rec.payload.is_empty() {
                    rec.payload = payload;
                }
                if vet_all_packages && !rec.vetted {
                    rec.vetted = true;
                    vetting_changed = true;
                }
                continue;
            }
            if vet_all_packages {
                vetting_changed = true;
            }
            let meta = info.dalfs.iter().find(|d| d.package_id == id);
            known.insert(
                id,
                PackageRec {
                    vetted: vet_all_packages,
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
        drop(known);
        if vetting_changed {
            *service
                .v2_state()
                .vetting_serial
                .lock()
                .expect("serial lock") += 1;
        }
        if record_external {
            service
                .v2_state()
                .journal("dars.journal", || Ok(crate::v2::base64(item.bytes)));
            let dar_sink = service
                .v2_state()
                .official_dar_sink
                .lock()
                .ok()
                .and_then(|s| s.clone());
            if let Some(sink) = dar_sink {
                sink(item.bytes);
            }
        }
        dar_ids.push(main_id);
    }
    Ok(dar_ids)
}

/// Loads `canton-builtin-admin-workflow-ping.dar` internally without requiring a connected synchronizer or polluting
/// `dars.journal`, marking its packages vetted in the Ledger API state so Admin `PingService/Ping` can create/exercise `Ping`.
pub fn load_builtin_ping_dar(
    service: &ExecutionService,
    bytes: &[u8],
) -> Result<(), (i32, String)> {
    let loaded = service
        .loaded_dar_descriptions()
        .into_iter()
        .any(|(main, _, _, _)| main == ADMIN_PING_PACKAGE_ID);
    if !loaded {
        admin_upload_dars(
            service,
            &[UploadDarItem {
                bytes,
                description: Some("canton-builtin-admin-workflow-ping"),
                expected_main_package_id: Some(ADMIN_PING_PACKAGE_ID),
            }],
            false,
            None,
            false,
        )?;
    }
    if let Ok(mut known) = service.v2_state().packages.lock() {
        if let Some(rec) = known.get_mut(ADMIN_PING_PACKAGE_ID) {
            rec.vetted = true;
        }
        let dars = service
            .v2_state()
            .loaded_dars
            .lock()
            .ok()
            .and_then(|v| {
                v.iter()
                    .find(|d| d.main_package_id == ADMIN_PING_PACKAGE_ID)
                    .map(|d| d.package_ids.clone())
            })
            .unwrap_or_default();
        for pkg in dars {
            if let Some(rec) = known.get_mut(&pkg) {
                rec.vetted = true;
            }
        }
    }
    Ok(())
}

/// Returns `(bytes, name, version, description)` of a loaded DAR for Admin `PackageService/GetDar`.
pub fn admin_get_dar(
    service: &ExecutionService,
    main_package_id: &str,
) -> Result<(Vec<u8>, String, String, String), (i32, String)> {
    if !is_valid_package_id(main_package_id) {
        return Err((3, format!("Invalid DAR main package-id: {main_package_id}")));
    }
    let dars = service
        .v2_state()
        .loaded_dars
        .lock()
        .map_err(|_| (13, "loaded_dars lock poisoned".to_string()))?;
    dars.iter()
        .find(|d| d.main_package_id == main_package_id)
        .map(|d| {
            (
                d.bytes.clone(),
                d.name.clone(),
                d.version.clone(),
                d.description.clone(),
            )
        })
        .ok_or_else(|| {
            (
                5,
                format!(
                    "DAR_NOT_FOUND(11,00000000): getDar operation failed due to non-existent DAR archive with main package-id {main_package_id}"
                ),
            )
        })
}

/// Enables vetting for all packages belonging to `main_package_id` (`PackageService/VetDar`).
pub fn admin_vet_dar(
    service: &ExecutionService,
    main_package_id: &str,
    synchronizer_id: Option<&str>,
) -> Result<(), (i32, String)> {
    check_vetting_synchronizer(service, synchronizer_id)?;
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
                        "DAR_NOT_FOUND(11,00000000): DAR archive vetting operation failed due to non-existent DAR archive with main package-id {main_package_id}"
                    ),
                )
            })?
    };
    service
        .vet_dar(&entry.bytes)
        .map_err(|e| (9, format!("PACKAGE_VETTING_FAILED(9,00000000): {e}")))?;
    let payloads = lf_archive::dalf_payloads(&entry.bytes).unwrap_or_default();
    let payload_map: BTreeMap<String, Vec<u8>> = payloads.into_iter().collect();
    let mut known = service.v2_state().packages.lock().expect("packages lock");
    let mut changed = false;
    for id in &entry.package_ids {
        if let Some(rec) = known.get_mut(id) {
            if !rec.vetted {
                rec.vetted = true;
                changed = true;
            }
        } else {
            let (name, version) = service.package_name_and_version(id).unwrap_or_default();
            known.insert(
                id.clone(),
                PackageRec {
                    payload: payload_map.get(id).cloned().unwrap_or_default(),
                    name,
                    version,
                    vetted: true,
                    valid_from: None,
                    valid_until: None,
                },
            );
            changed = true;
        }
    }
    drop(known);
    if changed {
        *service
            .v2_state()
            .vetting_serial
            .lock()
            .expect("serial lock") += 1;
    }
    let dar_sink = service
        .v2_state()
        .official_dar_sink
        .lock()
        .ok()
        .and_then(|s| s.clone());
    if let Some(sink) = dar_sink {
        sink(&entry.bytes);
    }
    Ok(())
}

/// Removes a loaded DAR and its exclusive packages (`PackageService/RemoveDar`).
///
/// [CANTON-NOTE: LIMITATION] When a backing protocol `Node` is attached, this updates the participant's local package/DAR
/// registries and vetting table, but does not broadcast a `VettedPackages` revocation topology transaction to the synchronizer.
pub fn admin_remove_dar(
    service: &ExecutionService,
    main_package_id: &str,
) -> Result<(), (i32, String)> {
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
                    "DAR_NOT_FOUND(11,00000000): DAR archive removal operation failed due to non-existent DAR archive with main package-id {main_package_id}"
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
    if main_package_id == ADMIN_PING_PACKAGE_ID {
        return Err((
            9,
            format!(
                "PACKAGE_OR_DAR_REMOVAL_ERROR(9,00000000): Removal of package {main_package_id} failed as packages needed for admin workflows cannot be removed."
            ),
        ));
    }
    let exclusive: std::collections::HashSet<String> = entry
        .package_ids
        .iter()
        .filter(|id| !remaining.iter().any(|r| r.package_ids.contains(id)))
        .cloned()
        .collect();
    let sync_id = service.v2_state().synchronizer_id();
    if let Ok(contracts) = service.generic_contracts.read() {
        for c in contracts.values().filter(|c| c.active) {
            let pkg = if c.package_id.is_empty() {
                &c.template_id.package_id
            } else {
                &c.package_id
            };
            if pkg == main_package_id || c.template_id.package_id == main_package_id {
                return Err((
                    9,
                    format!(
                        "PACKAGE_OR_DAR_REMOVAL_ERROR(9,00000000): The DAR {} cannot be removed because its main package {main_package_id} is in-use by contract {} on synchronizer {sync_id}.",
                        entry.main_package_id, c.contract_id
                    ),
                ));
            }
            if exclusive.contains(pkg) || exclusive.contains(&c.template_id.package_id) {
                let used = if exclusive.contains(pkg) {
                    pkg
                } else {
                    &c.template_id.package_id
                };
                return Err((
                    9,
                    format!(
                        "PACKAGE_OR_DAR_REMOVAL_ERROR(9,00000000): The DAR {} cannot be removed because it is the only DAR containing the used package {used}, but there are contracts using it.",
                        entry.main_package_id
                    ),
                ));
            }
        }
    }
    if main_package_id == lf_eval::ledger::PACKAGE_ID {
        if let Ok(ledger) = service.ledger.read() {
            if let Some((idx, _)) = ledger
                .contracts
                .iter()
                .enumerate()
                .find(|(_, c)| c.is_some())
            {
                return Err((
                    9,
                    format!(
                        "PACKAGE_OR_DAR_REMOVAL_ERROR(9,00000000): The DAR {} cannot be removed because its main package {main_package_id} is in-use by contract #{idx}:0 on synchronizer {sync_id}.",
                        entry.main_package_id
                    ),
                ));
            }
        }
    }

    if let Ok(mut dars) = service.v2_state().loaded_dars.lock() {
        dars.retain(|d| d.main_package_id != main_package_id);
    }
    if let Ok(mut pkgs) = service.lf_packages.write() {
        pkgs.retain(|p| p.main_package_id != main_package_id);
    }
    if let Ok(mut blobs) = service.dar_blobs.write() {
        *blobs = remaining.iter().map(|d| d.bytes.clone()).collect();
    }
    if let Ok(mut names) = service.package_names.write() {
        names.retain(|(_, id, _)| !exclusive.contains(id));
    }
    if let Ok(mut known) = service.v2_state().known_packages.lock() {
        known.retain(|id| !exclusive.contains(id));
    }
    let mut unvetted_any = false;
    let mut remaining_vetted: Vec<String> = Vec::new();
    if let Ok(mut known) = service.v2_state().packages.lock() {
        for id in &exclusive {
            if let Some(removed) = known.remove(id) {
                if removed.vetted {
                    unvetted_any = true;
                }
            }
        }
        remaining_vetted = known
            .iter()
            .filter(|(_, rec)| rec.vetted)
            .map(|(id, _)| id.clone())
            .collect();
    }
    if unvetted_any {
        *service
            .v2_state()
            .vetting_serial
            .lock()
            .expect("serial lock") += 1;
        service
            .sync_vetted_packages(None, &remaining_vetted)
            .map_err(|e| (9, format!("PACKAGE_VETTING_FAILED(9,00000000): {e}")))?;
    }
    if let Ok(mut info_lock) = service.dar_info.write() {
        let replace_info = info_lock
            .as_ref()
            .is_some_and(|i| i.main_package_id == main_package_id);
        if replace_info {
            *info_lock = remaining.last().and_then(|last| {
                lf_archive::parse_loaded_dar(std::io::Cursor::new(&last.bytes))
                    .ok()
                    .map(|loaded| crate::DarPackageInfo {
                        main_package_id: loaded.archive.main_package_id,
                        package_name: loaded.archive.package_name,
                        package_version: loaded.archive.package_version,
                        lf_version: loaded.archive.lf_version,
                        modules: loaded.archive.modules,
                        dalfs: loaded.archive.dalfs,
                        module_surfaces: loaded.archive.module_surfaces,
                    })
            });
        }
    }
    Ok(())
}
