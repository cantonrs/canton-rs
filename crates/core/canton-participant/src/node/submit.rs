use super::{
    multi_root, CreateSpec, CreatedByExercise, Described, LiveTopologyCheck, Node, PreparedCreate,
    TreeEntry, TreeNode, Verdict,
};
use crate::submit::{plan_created, Built, Create, ExercisePlan, Os, Randomness, StoredContract};
use crate::value_forms::forms;
use crate::view_conformance::open_instance;
use lf_eval::typed_json::Types;
use lf_eval::Value;
use std::collections::BTreeMap;
use std::time::Duration;

impl Node {
    /// What the protocol needs to know of a contract of `template` with `payload`: its two argument forms, its signatories and its
    /// stakeholders (sorted, without duplicates).
    pub fn describe(&self, template: &str, payload: &Value) -> Result<Described, String> {
        let (package_id, module, name) = self.resolve_template(template)?;
        let local = format!("{module}:{name}");
        let (arg, hash_arg) = {
            let types = Types::new(&self.world);
            let ty = types.template(&package_id, &local)?;
            forms(&types, &ty, payload)?
        };
        let mut signatories = self
            .world
            .eval_template_signatories_in(&package_id, module, name, payload)
            .map_err(|e| e.to_string())?;
        let observers = self
            .world
            .eval_template_observers_in(&package_id, module, name, payload)
            .map_err(|e| e.to_string())?;
        let mut stakeholders = signatories.clone();
        stakeholders.extend(observers);
        stakeholders.sort();
        stakeholders.dedup();
        signatories.sort();
        signatories.dedup();
        let key = match self
            .world
            .eval_template_key_in(&package_id, module, name, payload)
            .map_err(|e| e.to_string())?
        {
            Some((key_val, mut maintainers)) => {
                maintainers.sort();
                maintainers.dedup();
                let types = Types::new(&self.world);
                let key_ty = types
                    .template_key_type(&package_id, &local)?
                    .ok_or_else(|| {
                        format!("template {local} has a key value without a key type")
                    })?;
                let (lf_key, hash_key) = forms(&types, &key_ty, &key_val)?;
                Some(crate::submit::NewKey {
                    value: lf_key,
                    hash_value: hash_key,
                    maintainers,
                })
            }
            None => None,
        };
        Ok(Described {
            package_id,
            module: module.split('.').map(String::from).collect(),
            name: name.split('.').map(String::from).collect(),
            arg,
            hash_arg,
            signatories,
            stakeholders,
            key,
        })
    }

    pub(super) fn describe_key(
        &self,
        template: &str,
        key_val: &Value,
        contract_id: Option<String>,
        fallback_pkg_name: &str,
    ) -> Result<crate::view_tree::KeyUse, String> {
        let (package_id, module, name) = self.resolve_template(template)?;
        let local = format!("{module}:{name}");
        let types = Types::new(&self.world);
        let key_ty = types
            .template_key_type(&package_id, &local)?
            .ok_or_else(|| format!("template {local} declares no key"))?;
        let (lf_key, hash_key) = forms(&types, &key_ty, key_val)?;
        let mut maintainers = self
            .world
            .eval_key_maintainers_in(&package_id, module, name, key_val)
            .map_err(|e| e.to_string())?;
        maintainers.sort();
        maintainers.dedup();
        let pkg_name = self
            .package_name_of(&package_id)
            .unwrap_or(fallback_pkg_name)
            .to_string();
        Ok(crate::view_tree::KeyUse {
            package_name: pkg_name,
            package_id,
            module: module.split('.').map(String::from).collect(),
            name: name.split('.').map(String::from).collect(),
            value: lf_key,
            hash_value: hash_key,
            maintainers,
            contract_id,
        })
    }

    pub(super) fn contract_key_use(
        &self,
        contract: &StoredContract,
        fallback_pkg_name: &str,
    ) -> Result<Option<crate::view_tree::KeyUse>, String> {
        let module = contract.module.join(".");
        let name = contract.name.join(".");
        // [CANTON-NOTE: SEMANTICS] A template without a key has no key use, so its arguments are not decoded here: the instance may be of an
        // older package version than the one the engine's surfaces describe (smart contract upgrade, ug06: a 2-field contract of a 3-field
        // template), and decoding it with the newer record shape fails with an arity error before the exercise is even built.
        if !self
            .world
            .template_has_key(&contract.package_id, &module, &name)
            .map_err(|e| e.to_string())?
        {
            return Ok(None);
        }
        let opened = open_instance(&self.runtime.engine, &contract.instance)?;
        let Some((key_val, _)) = self
            .world
            .eval_template_key_in(&contract.package_id, &module, &name, &opened.arg)
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        let template = format!("{}:{module}:{name}", contract.package_id);
        self.describe_key(
            &template,
            &key_val,
            Some(contract.contract_id_hex.clone()),
            fallback_pkg_name,
        )
        .map(Some)
    }

    /// The id of the contract that will be the `index`-th child (a create) of the exercise `plan` describes: promised to the engine before the
    /// exercise's request is built.
    pub fn promise_created(
        &self,
        package_name: &str,
        plan: &ExercisePlan,
        index: usize,
        template: &str,
        payload: &Value,
    ) -> Result<String, String> {
        self.promise_created_at(package_name, plan, index, &[], template, payload)
    }

    /// Like [`Node::promise_created`] for a create that is not a direct child of the root exercise: `path` is its position in the view's tree
    /// ([`submit::NewInView::path`]; empty means a direct child whose position is `index`).
    pub fn promise_created_at(
        &self,
        package_name: &str,
        plan: &ExercisePlan,
        index: usize,
        path: &[i32],
        template: &str,
        payload: &Value,
    ) -> Result<String, String> {
        let d = self.describe(template, payload)?;
        let pkg_name = self.package_name_of(&d.package_id).unwrap_or(package_name);
        Ok(
            plan_created(&self.context(), plan, index, &d.in_view_at(pkg_name, path))?
                .contract_id_hex,
        )
    }

    /// Builds the request for a create without sending it. With `now` and a replaying [`Randomness`] the same inputs give the same contract id,
    /// which is how an id is promised to the engine first and the request built and sent later (`prepare` and `submit_prepared`).
    pub fn prepare_create(
        &mut self,
        package_name: &str,
        template: &str,
        payload: &Value,
        command_id: &str,
        now: Option<i64>,
        random: &mut dyn Randomness,
    ) -> Result<PreparedCreate, String> {
        self.prepare_create_inner(
            CreateSpec {
                package_name,
                template,
                payload,
                command_id,
                now,
                topology_check: LiveTopologyCheck::Enforce,
                submission: crate::submit::Submission::default(),
            },
            random,
        )
    }

    /// The confirmation request of a create as a sequencer prices it, built and never sent (S-SIM-001 `build_without_send`): the same
    /// request [`Self::prepare_create`] builds for the submission, with fresh randomness. `None` inside: no followed topology to price by.
    pub fn priced_create_request(
        &mut self,
        package_name: &str,
        template: &str,
        payload: &Value,
        command_id: &str,
        submission: &crate::submit::Submission,
    ) -> Result<Option<Vec<crate::participant_runtime::PricedEnvelope>>, String> {
        let prepared = self.prepare_create_inner(
            CreateSpec {
                package_name,
                template,
                payload,
                command_id,
                now: None,
                topology_check: LiveTopologyCheck::Enforce,
                submission: submission.clone(),
            },
            &mut crate::submit::Os,
        )?;
        Ok(self.runtime.priced_envelopes(&prepared.built.envelopes))
    }

    /// The confirmation request of an exercise as a sequencer prices it, built and never sent (S-SIM-001 `build_without_send`): the
    /// request [`Self::prepare_exercise_with_remap`] builds for the submission, with fresh randomness and fresh ids for the contracts it
    /// creates. `None` inside: no followed topology to price by.
    ///
    /// [CANTON-NOTE: WHY] The ids of created contracts are not checked against the engine's: they are derived from randomness the
    /// estimate does not replay, and an id has the same size whatever it is.
    pub fn priced_exercise_request(
        &mut self,
        package_name: &str,
        root: &multi_root::ExerciseRoot<'_>,
        command_id: &str,
        disclosed_instances: &[(String, Vec<u8>)],
        submission: &crate::submit::Submission,
    ) -> Result<Option<Vec<crate::participant_runtime::PricedEnvelope>>, String> {
        if submission.external_authorization.is_none() {
            self.check_submitters(root.actors)?;
        }
        let extra = self.disclosed_contracts(disclosed_instances)?;
        let mut assembly = multi_root::Assembly::default();
        self.add_exercise_root(&mut assembly, package_name, root, &extra)?;
        let (built, _, _) =
            self.build_assembly_unchecked(assembly, root.actors, command_id, &[], submission)?;
        Ok(self.runtime.priced_envelopes(&built.envelopes))
    }

    /// Like [`Self::prepare_create`], for a create its external parties authorized (U-56): the submitter metadata carries
    /// `submission`'s external authorization and this participant need not host the parties to submit for them.
    pub fn prepare_create_as(
        &mut self,
        package_name: &str,
        template: &str,
        payload: &Value,
        command_id: &str,
        now: i64,
        random: &mut dyn Randomness,
        submission: crate::submit::Submission,
    ) -> Result<PreparedCreate, String> {
        self.prepare_create_inner(
            CreateSpec {
                package_name,
                template,
                payload,
                command_id,
                now: Some(now),
                topology_check: LiveTopologyCheck::Enforce,
                submission,
            },
            random,
        )
    }

    /// Allocates a deterministic contract ID before the submission is built (`ProtocolCommitter::allocate_contract_id`), skipping
    /// live submitter/vetting checks that run when the command itself is prepared for submission.
    pub fn prepare_create_for_allocation(
        &mut self,
        package_name: &str,
        template: &str,
        payload: &Value,
        now: Option<i64>,
        random: &mut dyn Randomness,
    ) -> Result<PreparedCreate, String> {
        self.prepare_create_inner(
            CreateSpec {
                package_name,
                template,
                payload,
                command_id: "allocation",
                now,
                topology_check: LiveTopologyCheck::SkipForAllocation,
                submission: crate::submit::Submission::default(),
            },
            random,
        )
    }

    pub(super) fn prepare_create_inner(
        &mut self,
        spec: CreateSpec<'_>,
        random: &mut dyn Randomness,
    ) -> Result<PreparedCreate, String> {
        let d = self.describe(spec.template, spec.payload)?;
        // [CANTON-NOTE: SEMANTICS] an externally signed submission is authorized by its parties' signatures, not by this participant's
        // permission to submit for them (`AuthorizationValidator`: the submission-permission check applies to classic submissions only)
        if spec.topology_check == LiveTopologyCheck::Enforce
            && spec.submission.external_authorization.is_none()
        {
            self.check_submitters(&d.signatories)?;
        }
        let hosts = self.hosts_of(&d.stakeholders)?;
        if spec.topology_check == LiveTopologyCheck::Enforce {
            self.check_peers_vetted(&d.package_id, &hosts)?;
        }
        let pkg_name = self
            .package_name_of(&d.package_id)
            .unwrap_or(spec.package_name)
            .to_string();
        let now = match spec.now {
            Some(now) => now,
            None => self.now()?,
        };
        let built = crate::submit::build_create_as(
            &self.context(),
            &Create {
                package_name: &pkg_name,
                package_id: &d.package_id,
                module: d.module.clone(),
                name: d.name.clone(),
                arg: d.arg.clone(),
                hash_arg: d.hash_arg.clone(),
                signatories: d.signatories.clone(),
                stakeholders: d.stakeholders.clone(),
                hosts,
                command_id: spec.command_id.to_string(),
                key: d.key,
            },
            now,
            random,
            &spec.submission,
        )?;
        let stored = StoredContract {
            contract_id_hex: built.contract_id_hex.clone(),
            instance: built.instance.clone(),
            package_id: d.package_id,
            module: d.module,
            name: d.name,
            signatories: d.signatories,
            stakeholders: d.stakeholders,
        };
        Ok(PreparedCreate {
            built,
            stored,
            command_id: spec.command_id.to_string(),
        })
    }

    /// Sends a prepared create and waits for the verdict; an approved contract becomes one this node can exercise.
    pub fn submit_prepared(
        &mut self,
        prepared: PreparedCreate,
        timeout: Duration,
    ) -> Result<Verdict, String> {
        let verdict = self.send_and_wait(&prepared.built, timeout)?;
        if verdict == Verdict::Approved {
            self.remember(prepared.stored);
        }
        Ok(verdict)
    }

    /// Creates a contract of `template` (`Module:Name`) with `payload`; returns its id and the verdict.
    pub fn submit_create(
        &mut self,
        package_name: &str,
        template: &str,
        payload: &Value,
        command_id: &str,
        timeout: Duration,
    ) -> Result<(String, Verdict), String> {
        let prepared =
            self.prepare_create(package_name, template, payload, command_id, None, &mut Os)?;
        let id = prepared.built.contract_id_hex.clone();
        let verdict = self.submit_prepared(prepared, timeout)?;
        Ok((id, verdict))
    }

    /// Builds the request for `choice` on a contract this node created, without sending it. Returns it with whether the choice consumes.
    ///
    /// An exercise that creates contracts (`created`, in the order the engine created them) needs the `plan` their ids were promised with
    /// ([`Node::promise_created`]); the request is refused if the contracts it would create do not have those ids.
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn prepare_exercise(
        &mut self,
        package_name: &str,
        contract_id_hex: &str,
        choice: &str,
        argument: &Value,
        actors: &[String],
        command_id: &str,
        plan: Option<ExercisePlan>,
        created: &[CreatedByExercise],
    ) -> Result<(Built, bool), String> {
        let entries: Vec<TreeEntry> = created
            .iter()
            .map(|c| TreeEntry {
                depth: 1,
                node: TreeNode::Create(CreatedByExercise {
                    template: c.template,
                    payload: c.payload,
                    expected_id: c.expected_id,
                }),
            })
            .collect();
        self.prepare_exercise_tree(
            package_name,
            contract_id_hex,
            choice,
            argument,
            actors,
            command_id,
            plan,
            &entries,
        )
    }

    /// Like [`Node::prepare_exercise`] for an exercise with a subtree (G8 P0): `entries` are the nodes below the root exercise in the order the
    /// engine ran them. The request is built by [`crate::view_tree`], a port of Canton's view decomposition: which nodes share a view, who
    /// confirms, and how the nodes are numbered all follow from the tree and from who hosts whom.
    ///
    /// [CANTON-NOTE: LIMITATION] Every contract a node uses must be one this node knows. A subtree that does not stay in one view needs the
    /// chosen value of the exercise that roots the subview, which the engine's journal does not carry: such a request is refused.
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn prepare_exercise_tree(
        &mut self,
        package_name: &str,
        contract_id_hex: &str,
        choice: &str,
        argument: &Value,
        actors: &[String],
        command_id: &str,
        plan: Option<ExercisePlan>,
        entries: &[TreeEntry],
    ) -> Result<(Built, bool), String> {
        self.prepare_exercise_full(
            package_name,
            contract_id_hex,
            choice,
            argument,
            actors,
            command_id,
            plan,
            entries,
            None,
            false,
        )
    }

    /// Full protocol exercise builder supporting interface choices (`root_interface_id`), by-key root (`root_by_key`),
    /// keyed descendants (`TreeNode::Lookup`, `by_key`), nested interface calls, and `Rollback` scopes (G8 P4/P5/P6).
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn prepare_exercise_full(
        &mut self,
        package_name: &str,
        contract_id_hex: &str,
        choice: &str,
        argument: &Value,
        actors: &[String],
        command_id: &str,
        plan: Option<ExercisePlan>,
        entries: &[TreeEntry],
        root_interface_id: Option<&str>,
        root_by_key: bool,
    ) -> Result<(Built, bool), String> {
        self.prepare_exercise_with_options(
            package_name,
            contract_id_hex,
            choice,
            argument,
            actors,
            command_id,
            plan,
            entries,
            root_interface_id,
            root_by_key,
            None,
            &[],
        )
    }

    /// Full protocol exercise builder with optional smart-contract upgrade `root_package_id` and explicitly disclosed foreign contracts.
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn prepare_exercise_with_options(
        &mut self,
        package_name: &str,
        contract_id_hex: &str,
        choice: &str,
        argument: &Value,
        actors: &[String],
        command_id: &str,
        plan: Option<ExercisePlan>,
        entries: &[TreeEntry],
        root_interface_id: Option<&str>,
        root_by_key: bool,
        root_package_id: Option<&str>,
        disclosed_instances: &[(String, Vec<u8>)],
    ) -> Result<(Built, bool), String> {
        // [CANTON-NOTE: LIMITATION] This entry point takes no choice observers; a choice with an `observer` clause must go
        // through `SharedNode::submit_exercise_command` (`ExerciseCommand::observers`), as the JSON API does.
        let (built, consuming, _) = self.prepare_exercise_with_remap(
            package_name,
            &multi_root::ExerciseRoot {
                contract_id_hex,
                choice,
                argument,
                actors,
                observers: &[],
                entries,
                root_interface_id,
                root_by_key,
                root_package_id,
            },
            command_id,
            plan,
            disclosed_instances,
            &crate::submit::Submission::default(),
        )?;
        Ok((built, consuming))
    }

    pub(super) fn prepare_exercise_with_remap(
        &mut self,
        package_name: &str,
        root: &multi_root::ExerciseRoot<'_>,
        command_id: &str,
        plan: Option<ExercisePlan>,
        disclosed_instances: &[(String, Vec<u8>)],
        submission: &crate::submit::Submission,
    ) -> Result<(Built, bool, BTreeMap<String, String>), String> {
        // [CANTON-NOTE: SEMANTICS] an externally signed submission is authorized by its parties' signatures (U-56)
        if submission.external_authorization.is_none() {
            self.check_submitters(root.actors)?;
        }
        let extra = self.disclosed_contracts(disclosed_instances)?;
        let mut assembly = multi_root::Assembly::default();
        let consuming = self.add_exercise_root(&mut assembly, package_name, root, &extra)?;
        let plans: Vec<ExercisePlan> = plan.into_iter().collect();
        let (built, remapped) =
            self.build_assembly_with_remap(assembly, root.actors, command_id, &plans, submission)?;
        Ok((built, consuming, remapped))
    }

    /// Builds the request of an exercise its external parties authorized without sending it (U-56): with the `plan` its ids (if any) were
    /// promised under, its submitter metadata carrying `submission`'s authorization. The node's state is not changed.
    pub fn prepare_exercise_as(
        &mut self,
        package_name: &str,
        root: &multi_root::ExerciseRoot<'_>,
        command_id: &str,
        plan: Option<ExercisePlan>,
        disclosed_instances: &[(String, Vec<u8>)],
        submission: &crate::submit::Submission,
    ) -> Result<Built, String> {
        self.prepare_exercise_with_remap(
            package_name,
            root,
            command_id,
            plan,
            disclosed_instances,
            submission,
        )
        .map(|(built, _, _)| built)
    }

    /// Exercises `choice` on a contract this node created.
    pub fn submit_exercise(
        &mut self,
        contract_id_hex: &str,
        choice: &str,
        argument: &Value,
        actors: &[String],
        command_id: &str,
        timeout: Duration,
    ) -> Result<Verdict, String> {
        let (built, consuming) = self.prepare_exercise(
            "",
            contract_id_hex,
            choice,
            argument,
            actors,
            command_id,
            None,
            &[],
        )?;
        let verdict = self.send_and_wait(&built, timeout)?;
        if verdict == Verdict::Approved {
            self.apply_exercise(contract_id_hex, consuming, built.created);
        }
        Ok(verdict)
    }

    /// What an approved exercise changes in the contracts this node can exercise: the input goes when consumed, what it created comes.
    pub(super) fn apply_exercise(
        &mut self,
        contract_id_hex: &str,
        consuming: bool,
        created: Vec<StoredContract>,
    ) {
        if consuming {
            self.forget(contract_id_hex);
        }
        for c in created {
            self.remember(c);
        }
    }

    /// Sends the request and registers it as waiting for its verdict.
    pub(super) fn send(&mut self, built: &Built) -> Result<(), String> {
        self.send_tagged(&built.message_id, built.request.clone(), "")
    }

    /// Sends a signed submission request and keeps its message id in flight until its fate is known (see [`Node::send_tagged`]).
    pub(super) fn send_raw(&mut self, message_id: &str, request: Vec<u8>) -> Result<(), String> {
        self.send_tagged(message_id, request, "")
    }

    /// Sends the request and reads events until the verdict about it.
    pub(super) fn send_and_wait(
        &mut self,
        built: &Built,
        timeout: Duration,
    ) -> Result<Verdict, String> {
        self.send(built)?;
        self.wait_for(&built.message_id, timeout)
    }
}
