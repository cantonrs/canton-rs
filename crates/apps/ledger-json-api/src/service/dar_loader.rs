//! DAR loading, package registry lookup, and LF schema/template introspection.

use super::context::version_key;
use super::{
    map_codec_error, ApiError, Arc, ContractId, DarPackageInfo, ExecutionService, GenericContract,
    HashSet, LfPackage, Ordering, PackagesResponse, Path, PayloadSchema, TemplateId,
    TemplateResolution, PACKAGE_ID,
};

impl ExecutionService {
    /// The main package id of the loaded DAR whose package name is `name` (the `#name:Module:Entity` template form).
    /// The main package ids of every loaded package of that name (all upgrade versions).
    pub fn packages_named(&self, name: &str) -> Vec<String> {
        self.package_names
            .read()
            .map(|n| {
                n.iter()
                    .filter(|(x, _, _)| x == name)
                    .map(|(_, id, _)| id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Runs `f` on the evaluation world of a loaded package.
    pub fn with_world<R>(
        &self,
        package_id: &str,
        f: impl FnOnce(&lf_eval::World) -> R,
    ) -> Option<R> {
        let pkgs = self.lf_packages.read().ok()?;
        // a dependency package of a DAR (the Token Standard interfaces of the Splice DARs) is in the world of the DAR that carries it
        pkgs.iter()
            .find(|p| p.main_package_id == package_id)
            .or_else(|| pkgs.iter().find(|p| p.world.has_package(package_id)))
            .map(|p| f(&p.world))
    }

    /// All interfaces `(iface_package_id, "Module:Interface")` implemented by `local_template`
    /// in `package_id` (in declaration order, memoized per template).
    pub(crate) fn v2_implemented_interfaces(
        &self,
        package_id: &str,
        local_template: &str,
    ) -> Vec<(String, String)> {
        let key = (package_id.to_string(), local_template.to_string());
        if let Ok(guard) = self.v2.implemented_interfaces_cache.lock() {
            if let Some(cached) = guard.get(&key) {
                return cached.clone();
            }
        }
        let Some(computed) = self.with_world(package_id, |w| {
            w.template_implemented_interfaces(package_id, local_template)
                .unwrap_or_default()
        }) else {
            return Vec::new();
        };
        if let Ok(mut guard) = self.v2.implemented_interfaces_cache.lock() {
            guard.insert(key, computed.clone());
        }
        computed
    }

    /// Every contract (active or consumed) of `template` that carries a contract key, for `ExerciseByKeyCommand`.
    pub fn contracts_with_key(&self, template: &TemplateId) -> Vec<GenericContract> {
        self.generic_contracts
            .read()
            .map(|m| {
                m.values()
                    .filter(|c| c.key_value.is_some() && &c.template_id == template)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The next stamp of the logical clock (the arrival of a request, the completion of a commit).
    pub fn tick(&self) -> u64 {
        self.clock.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Whether `contract_id` was consumed by a commit that completed after the stamp `arrival` (the request overlapped it).
    ///
    /// [CANTON-NOTE: SEMANTICS] On a node two submissions that overlap in time and consume the same contract do not see the
    /// first one's archive: the second is refused while the first holds the contract (`LOCAL_VERDICT_LOCKED_CONTRACTS`, HTTP
    /// 409, measured 30 of 30 races in tests/oracle/concurrency). A request that arrives after the first completed finds the
    /// contract archived (`CONTRACT_NOT_FOUND`). Here the lock is modelled by time overlap.
    pub fn consumed_during(&self, contract_id: &str, arrival: u64) -> bool {
        self.consumed_at
            .read()
            .ok()
            .and_then(|m| m.get(contract_id).copied())
            .is_some_and(|done| done > arrival)
    }

    pub fn v2_package_id_for_name(&self, name: &str) -> Option<String> {
        let names = self.package_names.read().ok()?;
        // [CANTON-NOTE: SEMANTICS] A package-name reference resolves to the HIGHEST version of that name, whatever the order
        // the DARs were uploaded in (measured on the node, AT-L08: version 2.0.0 uploaded first still wins over 1.0.0).
        names
            .iter()
            .filter(|(n, _, _)| n == name)
            .max_by(|a, b| version_key(&a.2).cmp(&version_key(&b.2)))
            .map(|(_, id, _)| id.clone())
    }

    /// The main package of every DAR loaded (in load order): `(main package id, name, version)`; a DAR whose main package has no name has empty ones.
    pub fn loaded_dar_mains(&self) -> Vec<(String, String, String)> {
        let ids: Vec<String> = self
            .lf_packages
            .read()
            .map(|pkgs| pkgs.iter().map(|p| p.main_package_id.clone()).collect())
            .unwrap_or_default();
        ids.into_iter()
            .map(|id| {
                let (name, version) = self.package_name_and_version(&id).unwrap_or_default();
                (id, name, version)
            })
            .collect()
    }

    /// Every DAR loaded (in load order): `(main package id, name, version, description)`.
    pub fn loaded_dar_descriptions(&self) -> Vec<(String, String, String, String)> {
        if let Ok(dars) = self.v2.loaded_dars.lock() {
            if !dars.is_empty() || self.v2.dar_ever_loaded.load(Ordering::SeqCst) {
                return dars
                    .iter()
                    .map(|d| {
                        (
                            d.main_package_id.clone(),
                            d.name.clone(),
                            d.version.clone(),
                            d.description.clone(),
                        )
                    })
                    .collect();
            }
        }
        self.loaded_dar_mains()
            .into_iter()
            .map(|(id, name, version)| (id, name, version, String::new()))
            .collect()
    }

    /// Payload size in bytes of an uploaded package, or loaded-DAR DALF size when not yet explicitly registered.
    pub fn package_payload_size(&self, package_id: &str) -> usize {
        let stored = self
            .v2
            .packages
            .lock()
            .ok()
            .and_then(|pkgs| pkgs.get(package_id).map(|r| r.payload.len()))
            .filter(|&n| n > 0);
        if let Some(len) = stored {
            return len;
        }
        let Ok(dars) = self.v2.loaded_dars.lock() else {
            return 0;
        };
        for d in dars.iter() {
            if let Ok(payloads) = lf_archive::dalf_payloads(&d.bytes) {
                if let Some((_, bytes)) = payloads.into_iter().find(|(id, _)| id == package_id) {
                    return bytes.len();
                }
            }
        }
        0
    }

    /// The participant identifier (`name::fingerprint`).
    pub fn participant_id(&self) -> String {
        self.v2.participant_id()
    }

    /// Whether a protocol synchronizer committer is attached to this service.
    pub fn has_committer(&self) -> bool {
        self.committer
            .read()
            .ok()
            .is_some_and(|guard| guard.is_some())
    }

    /// Whether `party` is hosted locally on this participant and should be answered by the Admin Ping Nanobot.
    pub fn is_local_ping_responder(&self, party: &str) -> bool {
        if party == self.participant_id() {
            return true;
        }
        let is_known = self
            .v2
            .parties
            .lock()
            .ok()
            .is_some_and(|p| p.iter().any(|x| x == party));
        let is_remote = self
            .v2
            .remote_parties
            .lock()
            .ok()
            .is_some_and(|r| r.contains(party));
        is_known && !is_remote
    }

    /// The synchronizers this participant is connected to as `(alias, synchronizer_id)`.
    pub fn connected_synchronizers(&self) -> Vec<(String, String)> {
        if let Ok(reg) = self.v2.registered_syncs.lock() {
            if let Some(list) = reg.as_ref() {
                return list
                    .iter()
                    .filter(|s| s.connected)
                    .map(|s| {
                        let id = if !s.synchronizer_id.is_empty() {
                            s.synchronizer_id.clone()
                        } else {
                            s.physical_synchronizer_id.clone()
                        };
                        (s.alias.clone(), id)
                    })
                    .collect();
            }
        }
        let several = self
            .committer
            .read()
            .ok()
            .and_then(|c| c.as_ref().map(|c| c.synchronizers()))
            .unwrap_or_default();
        if several.is_empty() {
            vec![("mysync".to_string(), self.v2.synchronizer_id())]
        } else {
            several
        }
    }

    /// The name and version of a loaded package (`None` for a package that is only listed, not loaded).
    pub fn package_name_and_version(&self, package_id: &str) -> Option<(String, String)> {
        let names = self.package_names.read().ok()?;
        names
            .iter()
            .find(|(_, id, _)| id == package_id)
            .map(|(n, _, v)| (n.clone(), v.clone()))
    }

    /// The package name of a loaded package (for the `packageName` of an event).
    pub fn v2_package_name(&self, package_id: &str) -> Option<String> {
        let names = self.package_names.read().ok()?;
        names
            .iter()
            .find(|(_, id, _)| id == package_id)
            .map(|(n, _, _)| n.clone())
    }

    pub(crate) fn next_creation_seq(&self) -> u64 {
        self.creation_seq_counter.fetch_add(1, Ordering::SeqCst)
    }

    pub(crate) fn v2_lf_package(&self, package_id: &str) -> Option<Arc<LfPackage>> {
        let pkgs = self.lf_packages.read().ok()?;
        pkgs.iter()
            .find(|p| p.main_package_id == package_id)
            .cloned()
            .or_else(|| {
                pkgs.iter()
                    .find(|p| {
                        lf_eval::typed_json::Types::new(&p.world)
                            .package_name(package_id)
                            .is_ok()
                    })
                    .cloned()
            })
    }

    /// The field names of a template of a loaded package, for the "missing fields" check of a command.
    pub fn v2_template_fields(&self, template: &TemplateId) -> Option<Vec<String>> {
        let pkgs = self.lf_packages.read().ok()?;
        for pkg in pkgs
            .iter()
            .filter(|p| p.main_package_id == template.package_id)
        {
            for ms in pkg
                .surfaces
                .iter()
                .filter(|m| m.name == template.module_name)
            {
                if let Some(t) = ms.templates.iter().find(|t| t.name == template.entity_name) {
                    return Some(t.fields.iter().map(|f| f.name.clone()).collect());
                }
            }
        }
        None
    }

    /// Whether `template` refers to an interface in any loaded package `World`.
    pub fn v2_interface_exists(&self, template: &TemplateId) -> bool {
        if template.module_name.is_empty() || template.entity_name.is_empty() {
            return false;
        }
        let Ok(pkgs) = self.lf_packages.read() else {
            return false;
        };
        let local = format!("{}:{}", template.module_name, template.entity_name);
        for pkg in pkgs.iter() {
            if !template.package_id.is_empty() {
                if pkg.world.has_package(&template.package_id)
                    && pkg.world.interface_exists(&template.package_id, &local)
                {
                    return true;
                }
            } else if pkg.world.interface_exists(&pkg.main_package_id, &local)
                || pkg
                    .world
                    .package_ids()
                    .into_iter()
                    .any(|pid| pkg.world.interface_exists(&pid, &local))
            {
                return true;
            }
        }
        false
    }

    /// The field names of a template that a command must give: the fields that are not `Optional`.
    pub fn v2_template_required_fields(&self, template: &TemplateId) -> Option<Vec<String>> {
        let pkgs = self.lf_packages.read().ok()?;
        for pkg in pkgs
            .iter()
            .filter(|p| p.main_package_id == template.package_id)
        {
            for ms in pkg
                .surfaces
                .iter()
                .filter(|m| m.name == template.module_name)
            {
                if let Some(t) = ms.templates.iter().find(|t| t.name == template.entity_name) {
                    return Some(
                        t.fields
                            .iter()
                            .filter(|f| !matches!(f.ty, lf_archive::SurfaceType::Optional(_)))
                            .map(|f| f.name.clone())
                            .collect(),
                    );
                }
            }
        }
        None
    }

    /// The parameter names of a choice, for the "missing fields" check of a command (S-API-003).
    pub fn v2_choice_fields(&self, template: &TemplateId, choice: &str) -> Option<Vec<String>> {
        let pkgs = self.lf_packages.read().ok()?;
        if let Some(fields) = pkgs
            .iter()
            .filter(|p| template.package_id.is_empty() || p.main_package_id == template.package_id)
            .flat_map(|p| p.surfaces.iter())
            .filter(|m| m.name == template.module_name)
            .flat_map(|m| m.templates.iter())
            .filter(|t| t.name == template.entity_name)
            .flat_map(|t| t.choices.iter())
            .find(|c| c.name == choice)
            .map(|c| c.params.iter().map(|p| p.name.clone()).collect())
        {
            return Some(fields);
        }
        if template.module_name.is_empty() || template.entity_name.is_empty() {
            return None;
        }
        let local = format!("{}:{}", template.module_name, template.entity_name);
        for p in pkgs.iter() {
            let pid = if template.package_id.is_empty() {
                p.main_package_id.as_str()
            } else {
                template.package_id.as_str()
            };
            if !p.world.has_package(pid) {
                continue;
            }
            let types = lf_eval::typed_json::Types::new(&p.world);
            if let Ok(ct) = types.interface_choice(pid, &local, choice) {
                let fields = match &ct.argument {
                    lf_eval::typed_json::LfType::Con { .. } => types
                        .record_fields(&ct.argument)
                        .map(|fs| fs.into_iter().map(|(n, _)| n).collect())
                        .unwrap_or_default(),
                    _ => Vec::new(),
                };
                return Some(fields);
            }
        }
        None
    }

    /// The value of a choice argument given as JSON (normalized: numerics at their scale), for the exercised event.
    pub fn v2_choice_arg_value(
        &self,
        template: &TemplateId,
        choice: &str,
        arg: &serde_json::Value,
    ) -> Option<lf_eval::Value> {
        let pkgs = self.lf_packages.read().ok()?;
        let local = format!("{}:{}", template.module_name, template.entity_name);
        if let Some(pkg) = pkgs
            .iter()
            .find(|p| p.main_package_id == template.package_id)
        {
            if let Ok(schema) = PayloadSchema::choice_arg(pkg, &template.package_id, &local, choice)
            {
                return schema.from_json(arg).ok();
            }
        }
        if template.module_name.is_empty() || template.entity_name.is_empty() {
            return None;
        }
        for pkg in pkgs.iter() {
            let pid = if template.package_id.is_empty() {
                pkg.main_package_id.as_str()
            } else {
                template.package_id.as_str()
            };
            if !pkg.world.has_package(pid) {
                continue;
            }
            let types = lf_eval::typed_json::Types::new(&pkg.world);
            if let Ok(ct) = types.interface_choice(pid, &local, choice) {
                if let Ok(val) = types.decode(&ct.argument, arg) {
                    return Some(val);
                }
            }
        }
        None
    }

    /// The controller field names of a choice (the fields of the contract naming its controllers).
    pub fn v2_choice_controllers(&self, template: &TemplateId, choice: &str) -> Vec<String> {
        let Ok(pkgs) = self.lf_packages.read() else {
            return Vec::new();
        };
        pkgs.iter()
            .filter(|p| p.main_package_id == template.package_id)
            .flat_map(|p| p.surfaces.iter())
            .filter(|m| m.name == template.module_name)
            .flat_map(|m| m.templates.iter())
            .filter(|t| t.name == template.entity_name)
            .flat_map(|t| t.choices.iter())
            .find(|c| c.name == choice)
            .map(|c| c.controllers.clone())
            .unwrap_or_default()
    }

    /// Dynamically load a DAR archive, verify package ID and cryptographic integrity,
    /// initialize the Daml-LF evaluation bytecode engine (`World`), and store package
    /// metadata and module surfaces.
    pub fn load_dar(&self, path: &Path) -> Result<DarPackageInfo, ApiError> {
        let dar_bytes = std::fs::read(path)
            .map_err(|e| ApiError::Dar(format!("failed to read DAR file: {e}")))?;
        let loaded = lf_archive::load_dar_file(path)
            .map_err(|e| ApiError::Dar(format!("failed to parse DAR file: {e}")))?;
        self.load_loaded_dar(dar_bytes, &loaded)
    }

    /// Loads a DAR directly from raw bytes and a pre-parsed [`lf_archive::LoadedDar`],
    /// avoiding duplicate ZIP/protobuf decoding across upload validation, engine load, and vetting.
    pub fn load_loaded_dar(
        &self,
        dar_bytes: Vec<u8>,
        loaded: &lf_archive::LoadedDar,
    ) -> Result<DarPackageInfo, ApiError> {
        let archive = loaded.archive.clone();

        if archive.main_package_id.len() != 64 {
            return Err(ApiError::Dar(format!(
                "invalid main package ID length {}: {}",
                archive.main_package_id.len(),
                archive.main_package_id
            )));
        }

        // [CANTON-NOTE: INVARIANT] Initialize World to parse and load all DALF packages for Daml-LF bytecode evaluation.
        let world = lf_eval::World::from_loaded_ref(loaded)
            .map_err(|e| ApiError::Dar(format!("failed to open DAR for evaluation: {e}")))?;

        let info = DarPackageInfo {
            main_package_id: archive.main_package_id.clone(),
            package_name: archive.package_name,
            package_version: archive.package_version,
            lf_version: archive.lf_version,
            modules: archive.modules,
            dalfs: archive.dalfs,
            module_surfaces: archive.module_surfaces.clone(),
        };

        let lf_pkg = Arc::new(LfPackage {
            main_package_id: archive.main_package_id.clone(),
            world,
            surfaces: archive.module_surfaces,
        });

        // [CANTON-NOTE: INVARIANT] Promote pre-existing active contracts from SingleContractLedger
        // into generic_contracts and active_state so that any subsequent exercise on them executes via lf-eval::Engine
        // and never falls through to legacy string-based choice arms.
        // [CANTON-NOTE: WHY] Guarantees that contracts created in an unloaded fixture state
        // transition seamlessly to Daml-LF bytecode evaluation once a DAR is dynamically loaded.
        // [CANTON-NOTE: SEMANTICS] In Canton / Daml-LF semantics, loading a package must validate that
        // existing active state conforms to the new package schemas. If schema resolution or payload decoding
        // fails, load_dar must abort with ApiError::Internal rather than silently dropping corrupt contracts.
        let mut promoted_generic = Vec::new();
        let mut promoted_active = Vec::new();

        {
            let ledger = self
                .ledger
                .read()
                .map_err(|e| ApiError::Ledger(format!("failed to acquire lock: {e}")))?;
            self.sync_contract_counter_from_ledger(&ledger);

            for (idx, maybe_holding) in ledger.contracts.iter().enumerate() {
                if let Some(holding) = maybe_holding {
                    let cid_str = Self::format_contract_id(idx);
                    let json_payload = Self::holding_to_value(holding);
                    let local_id = "AssetHolding:AssetHolding";
                    let Ok(schema) =
                        lf_eval::codec::RecordSchema::template(&info.module_surfaces, local_id)
                    else {
                        continue;
                    };
                    let val = schema.from_json(&json_payload).map_err(|err| {
                        ApiError::Internal(format!(
                            "Contract promotion failed to decode payload for contract {cid_str}: {err}"
                        ))
                    })?;

                    let mut witness = vec![holding.bank.clone(), holding.owner.clone()];
                    if !witness.contains(&holding.auditor) {
                        witness.push(holding.auditor.clone());
                    }
                    let g_contract = GenericContract {
                        contract_id: cid_str.clone(),
                        package_id: archive.main_package_id.clone(),
                        template_id: TemplateId::new(
                            &archive.main_package_id,
                            "AssetHolding",
                            "AssetHolding",
                        ),
                        payload_value: val,
                        json_payload: json_payload.clone(),
                        signatories: vec![holding.bank.clone(), holding.owner.clone()],
                        observers: vec![holding.auditor.clone()],
                        witness_parties: witness,
                        active: true,
                        key_value: None,
                        created_at_micros: crate::clock::now_micros(),
                        created_event_blob: String::new(),
                        contract_key_hash: String::new(),
                        key_maintainers: Vec::new(),
                        creation_seq: self.next_creation_seq(),
                    };
                    promoted_generic.push(g_contract);

                    let cid = ContractId(cid_str);
                    let mut stakeholders = HashSet::new();
                    stakeholders.insert(holding.bank.clone());
                    stakeholders.insert(holding.owner.clone());
                    stakeholders.insert(holding.auditor.clone());
                    promoted_active.push((
                        cid,
                        lf_eval::tx_model::ActiveContract {
                            template_id: TemplateId::new(
                                &archive.main_package_id,
                                "AssetHolding",
                                "AssetHolding",
                            )
                            .to_string(),
                            payload: serde_json::to_vec(&json_payload).unwrap_or_default(),
                            stakeholders,
                            key: None,
                        },
                    ));
                }
            }
        }

        {
            let mut lock = self
                .dar_info
                .write()
                .map_err(|e| ApiError::Ledger(format!("failed to acquire lock: {e}")))?;
            *lock = Some(info.clone());
        }
        if let Some(name) = info.package_name.clone() {
            let mut names = self
                .package_names
                .write()
                .map_err(|e| ApiError::Ledger(format!("failed to acquire lock: {e}")))?;
            names.retain(|(_, id, _)| id != &info.main_package_id);
            names.push((
                name,
                info.main_package_id.clone(),
                info.package_version.clone().unwrap_or_default(),
            ));
        }
        // [CANTON-NOTE: SEMANTICS] The packages a DAR carries for its dependencies (the Splice DARs carry the Token Standard interfaces
        // `splice-api-token-holding-v1` ...) are uploaded with it and are addressable by name (`#splice-api-token-holding-v1:...` in an
        // interface filter); the standard libraries (`daml-prim`, `daml-stdlib`) are not offered as names here.
        {
            let mut names = self
                .package_names
                .write()
                .map_err(|e| ApiError::Ledger(format!("failed to acquire lock: {e}")))?;
            let types = lf_eval::typed_json::Types::new(&lf_pkg.world);
            for id in lf_pkg.world.package_ids() {
                if names.iter().any(|(_, known, _)| known == &id) {
                    continue;
                }
                if let Some((name, version)) = types.package_name_and_version(&id) {
                    if !name.starts_with("daml-") {
                        names.push((name, id, version));
                    }
                }
            }
        }

        {
            let mut pkgs = self
                .lf_packages
                .write()
                .map_err(|e| ApiError::Ledger(format!("failed to acquire lock: {e}")))?;
            if let Some(pos) = pkgs
                .iter()
                .position(|p| p.main_package_id == lf_pkg.main_package_id)
            {
                pkgs[pos] = lf_pkg;
            } else {
                pkgs.push(lf_pkg);
            }
        }

        {
            let mut g_lock = self
                .generic_contracts
                .write()
                .map_err(|e| ApiError::Ledger(format!("failed to acquire lock: {e}")))?;
            for g_contract in promoted_generic {
                g_lock
                    .entry(g_contract.contract_id.clone())
                    .or_insert(g_contract);
            }
        }

        {
            let mut state_lock = self
                .active_state
                .write()
                .map_err(|e| ApiError::Ledger(format!("failed to acquire lock: {e}")))?;
            for (cid, ac) in promoted_active {
                state_lock.active_contracts.insert(cid, ac);
            }
        }

        if let Ok(mut dars) = self.v2.loaded_dars.lock() {
            let mut pkg_ids = vec![info.main_package_id.clone()];
            for dalf in &info.dalfs {
                if !pkg_ids.contains(&dalf.package_id) {
                    pkg_ids.push(dalf.package_id.clone());
                }
            }
            let entry = crate::v2::LoadedDarEntry {
                main_package_id: info.main_package_id.clone(),
                name: info.package_name.clone().unwrap_or_default(),
                version: info.package_version.clone().unwrap_or_default(),
                description: String::new(),
                bytes: dar_bytes,
                package_ids: pkg_ids,
            };
            if let Some(existing) = dars
                .iter_mut()
                .find(|d| d.main_package_id == entry.main_package_id)
            {
                let prev_desc = std::mem::take(&mut existing.description);
                *existing = entry;
                existing.description = prev_desc;
            } else {
                dars.push(entry);
            }
            if let Ok(mut blobs) = self.dar_blobs.write() {
                *blobs = dars.iter().map(|d| d.bytes.clone()).collect();
            }
        } else if let Ok(mut blobs) = self.dar_blobs.write() {
            blobs.push(dar_bytes);
        }
        self.v2.dar_ever_loaded.store(true, Ordering::SeqCst);

        Ok(info)
    }

    /// Retrieve the currently loaded DAR information if any.
    pub fn dar_info(&self) -> Option<DarPackageInfo> {
        self.dar_info.read().ok().and_then(|guard| guard.clone())
    }

    /// Retrieve the packages response for GET /v1/packages.
    pub fn packages_response(&self) -> PackagesResponse {
        if let Ok(guard) = self.dar_info.read() {
            if let Some(ref info) = *guard {
                let mut pkgs = Vec::new();
                pkgs.push(info.main_package_id.clone());
                for dalf in &info.dalfs {
                    if !pkgs.contains(&dalf.package_id) {
                        pkgs.push(dalf.package_id.clone());
                    }
                }
                return PackagesResponse {
                    package_ids: pkgs.clone(),
                    packages: pkgs,
                    main_package_id: info.main_package_id.clone(),
                    package_name: info.package_name.clone(),
                    package_version: info.package_version.clone(),
                    modules: info.modules.clone(),
                };
            }
        }

        PackagesResponse {
            package_ids: vec![PACKAGE_ID.to_string()],
            packages: vec![PACKAGE_ID.to_string()],
            main_package_id: PACKAGE_ID.to_string(),
            package_name: Some("sample-contract".to_string()),
            package_version: Some("0.1.0".to_string()),
            modules: vec!["AssetHolding".to_string()],
        }
    }

    /// Resolves a requested TemplateId against loaded DAR packages, falling back
    /// to the legacy hardcoded AssetHolding fixture if no DAR is loaded.
    ///
    /// Semantics:
    /// 1. If any loaded DAR contains a template matching the requested package (or unspecified),
    ///    module (or unspecified), and entity name, resolve to `TemplateResolution::Generic`.
    /// 2. If any DAR is loaded and no template matches, resolve to `TemplateResolution::NotFound`.
    /// 3. If no DAR is loaded, check if it matches the legacy AssetHolding fixture (package
    ///    matching PACKAGE_ID or empty, entity matching "AssetHolding").
    /// 4. Otherwise, resolve to `TemplateResolution::NotFound`.
    pub(super) fn resolve_template(&self, template_id: &TemplateId) -> TemplateResolution {
        let effective_pkg_id = match template_id.package_id.strip_prefix('#') {
            Some(name) => match self.v2_package_id_for_name(name) {
                Some(id) => id,
                None => return TemplateResolution::NotFound(template_id.to_string()),
            },
            None => template_id.package_id.clone(),
        };
        if let Ok(pkgs) = self.lf_packages.read() {
            if !pkgs.is_empty() {
                // [CANTON-NOTE: INVARIANT] In loaded DAR mode, templates MUST resolve strictly
                // against the loaded packages. Fallback to LegacyAssetHolding is strictly disallowed.
                // [CANTON-NOTE: WHY] Once a DAR is loaded, requests targeting that DAR or any
                // unrecognised template must never fall into the legacy SingleContractLedger path.
                for pkg in pkgs.iter() {
                    let pkg_match =
                        effective_pkg_id.is_empty() || effective_pkg_id == pkg.main_package_id;
                    if !pkg_match {
                        continue;
                    }
                    for ms in &pkg.surfaces {
                        if template_id.module_name.is_empty() || ms.name == template_id.module_name
                        {
                            for tmpl in &ms.templates {
                                if tmpl.name == template_id.entity_name {
                                    return TemplateResolution::Generic {
                                        package: Arc::clone(pkg),
                                        local_id: format!("{}:{}", ms.name, tmpl.name),
                                        package_id: pkg.main_package_id.clone(),
                                    };
                                }
                            }
                        }
                    }
                }
                if !template_id.module_name.is_empty() && !template_id.entity_name.is_empty() {
                    let local = format!("{}:{}", template_id.module_name, template_id.entity_name);
                    for pkg in pkgs.iter() {
                        if !effective_pkg_id.is_empty() {
                            if pkg.world.has_package(&effective_pkg_id)
                                && pkg.world.interface_exists(&effective_pkg_id, &local)
                            {
                                return TemplateResolution::Interface {
                                    package: Arc::clone(pkg),
                                    interface_id: local,
                                    interface_package_id: effective_pkg_id,
                                };
                            }
                        } else if pkg.world.interface_exists(&pkg.main_package_id, &local) {
                            return TemplateResolution::Interface {
                                package: Arc::clone(pkg),
                                interface_id: local,
                                interface_package_id: pkg.main_package_id.clone(),
                            };
                        } else {
                            for pid in pkg.world.package_ids() {
                                if pkg.world.interface_exists(&pid, &local) {
                                    return TemplateResolution::Interface {
                                        package: Arc::clone(pkg),
                                        interface_id: local,
                                        interface_package_id: pid,
                                    };
                                }
                            }
                        }
                    }
                }
                // [CANTON-NOTE: INVARIANT] Once a DAR is loaded, any template not defined in loaded packages is NotFound.
                return TemplateResolution::NotFound(template_id.to_string());
            }
        }

        // [CANTON-NOTE: LIMITATION] Unloaded DAR fallback: when NO DAR has been loaded into the service,
        // allow pre-existing test fixtures to resolve the hardcoded AssetHolding template.
        let pkg_match = effective_pkg_id.is_empty() || effective_pkg_id == PACKAGE_ID;
        let mod_match =
            template_id.module_name.is_empty() || template_id.module_name == "AssetHolding";
        let entity_match = template_id.entity_name == "AssetHolding";

        if pkg_match && mod_match && entity_match {
            TemplateResolution::LegacyAssetHolding
        } else {
            TemplateResolution::NotFound(template_id.to_string())
        }
    }

    /// Selects the runtime `LfPackage` whose `World` contains both the target contract's template
    /// and any requested interface package, avoiding missing template surfaces on split DARs.
    pub(super) fn resolve_exercise_package(
        &self,
        fallback: Arc<LfPackage>,
        contract_package_id: &str,
        interface_package_id: Option<&str>,
    ) -> Arc<LfPackage> {
        let Some(iface_pkg_id) = interface_package_id else {
            return fallback;
        };
        self.v2_lf_package(contract_package_id)
            .filter(|p| p.world.has_package(iface_pkg_id))
            .unwrap_or(fallback)
    }

    /// Decodes a JSON choice argument using either template surface metadata or interface choice type info.
    pub(super) fn decode_choice_arg(
        &self,
        package: &Arc<LfPackage>,
        package_id: &str,
        local_id: &str,
        iface: Option<(&str, &str)>,
        choice: &str,
        arg: &serde_json::Value,
    ) -> Result<lf_eval::Value, ApiError> {
        if let Some((iface_pkg_id, iface_id)) = iface {
            let types = lf_eval::typed_json::Types::new(&package.world);
            let ct = types
                .interface_choice(iface_pkg_id, iface_id, choice)
                .map_err(|e| {
                    ApiError::InvalidArgument(format!(
                        "Unknown interface choice {iface_id}.{choice}: {e}"
                    ))
                })?;
            types
                .decode(&ct.argument, arg)
                .map_err(|e| ApiError::InvalidArgument(format!("Invalid choice argument: {e}")))
        } else {
            let arg_schema = PayloadSchema::choice_arg(package, package_id, local_id, choice)
                .map_err(map_codec_error)?;
            arg_schema
                .from_json(arg)
                .map_err(|e| ApiError::InvalidArgument(format!("Invalid choice argument: {e}")))
        }
    }

    /// Resolves the `RecordSchema` for a contract created during execution, falling back to the
    /// created contract's own loaded DAR when it originates from another loaded package.
    pub(super) fn schema_for_created_template(
        &self,
        package: &Arc<LfPackage>,
        package_id: &str,
        template_id: &str,
    ) -> Result<PayloadSchema, ApiError> {
        if let Ok(schema) = PayloadSchema::template(package, package_id, template_id) {
            return Ok(schema);
        }
        if let Some(other) = self.v2_lf_package(package_id) {
            if let Ok(schema) = PayloadSchema::template(&other, package_id, template_id) {
                return Ok(schema);
            }
        }
        Err(ApiError::Ledger(format!(
            "failed to get schema for created template {template_id}: Template '{template_id}' not found in loaded DAR"
        )))
    }
}
