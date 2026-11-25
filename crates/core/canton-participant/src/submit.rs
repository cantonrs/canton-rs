//! The submitting side of a participant (F1 of `doc/performance/EQUAL-CONDITIONS.md`): a create command turned into the request the
//! sequencer carries, for any template whose argument [`crate::value_forms`] can write.
//!
//! Until now the submitting side existed only as the hand-written sample-contract code of `tests/sequencer_connect.rs`
//! (`rust_creates_sample`), which the official mediator approved. This module is that code with the template-specific parts replaced by
//! inputs, and with the randomness injected so that a test can fix it.
//!
//! [CANTON-NOTE: SEMANTICS] What a request for a create consists of (measured against the official mediator in `rust_creates_sample`):
//! - a contract id derived from the contract's salt, the stakeholders and the creation time (`contract_id`), and an instance carrying it;
//! - one root view whose informees are the stakeholders **plus the submitting participant's admin party**, which must confirm too: the
//!   quorum is {every signatory: 1, admin party: 1} with threshold equal to the number of confirmers. Informees and confirmers are sorted;
//! - the informee tree (the view without its data) to the mediator, a root hash message to the mediator and each participant that hosts an
//!   informee, and the encrypted view to every such participant, the submitter included when it hosts one.
//!
//! [CANTON-NOTE: LIMITATION] [`build_create`] builds one create (a template with or without a key) as one root view with no sub-views, for
//! one mediator group. Exercises, transactions with children and commands touching several views are built by [`crate::view_tree`] from
//! the parts this module exports.
use crate::confirmation_wire as cw;
use crate::contract_id as ci;
use crate::contract_wire::{authentication_data, ContractInstance, LfValue};
use crate::merkle_wire as mw;
use crate::sequencing_wire as sw;
use crate::topology_wire::ParticipantIdentity;
use crate::view_message as vm;
use std::collections::BTreeSet;

/// A participant that hosts an informee and so receives the request.
#[derive(Clone, Debug)]
pub struct Peer {
    pub member: String,
    /// DER SubjectPublicKeyInfo of its P-256 encryption key, and the key's fingerprint.
    pub encryption_spki: Vec<u8>,
    pub fingerprint: String,
}

/// The source of the request's randomness: salts, seeds, the view's encryption randomness and IV. `fresh(label)` is 32 fresh bytes.
pub trait Randomness {
    fn fresh(&mut self, label: &str) -> [u8; 32];
}

/// Operating-system randomness (`/dev/urandom`).
pub struct Os;

impl Randomness for Os {
    fn fresh(&mut self, _label: &str) -> [u8; 32] {
        use std::io::Read;
        let mut bytes = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .expect("the operating system has randomness");
        bytes
    }
}

/// What the participant is and where it submits.
pub struct Context<'a> {
    pub identity: &'a ParticipantIdentity,
    /// The physical synchronizer id the request is for.
    pub synchronizer: &'a str,
    pub mediator_group: u32,
    pub user_id: &'a str,
}

/// A create command with its argument in both protocol forms (see [`crate::value_forms::forms`]).
/// The key of a contract of a template with one: its value as the protocol writes it, as the typed value the key hash is made of, and the
/// maintainers the template computes (`contract_id::lf_contract_key_hash`, the instance's `contract_key_with_maintainers`, a view's `resolved_keys`).
#[derive(Clone)]
pub struct NewKey {
    pub value: LfValue,
    pub hash_value: ci::HashValue,
    pub maintainers: Vec<String>,
}

pub struct Create<'a> {
    pub package_name: &'a str,
    pub package_id: &'a str,
    pub module: Vec<String>,
    pub name: Vec<String>,
    pub arg: LfValue,
    pub hash_arg: ci::HashValue,
    /// The signatories as the template computes them (the evaluator's `signatories`), and all stakeholders (signatories and observers).
    pub signatories: Vec<String>,
    pub stakeholders: Vec<String>,
    /// The participants that host a stakeholder (the submitter included, when it hosts one).
    pub hosts: Vec<Peer>,
    pub command_id: String,
    /// `None` for a template without a key.
    pub key: Option<NewKey>,
}

/// The request, and what a later request needs of the contract it creates.
pub struct Built {
    /// The signed submission request, as the sequencer accepts it.
    pub request: Vec<u8>,
    pub message_id: String,
    /// The envelopes of the request, each with the members it is addressed to (what the sequencer delivers to a recipient).
    pub envelopes: Vec<(Vec<String>, Vec<u8>)>,
    pub root_hash: Vec<u8>,
    pub contract_id_hex: String,
    /// The contract instance exactly as the create view carries it.
    pub instance: Vec<u8>,
    /// What an exercise's view creates, in the order of the view's created contracts (empty for a create and for a plain exercise).
    pub created: Vec<StoredContract>,
    /// The index (in `Transaction::nodes`) of the node that created each entry of `created`.
    pub created_nodes: Vec<usize>,
    /// The whole transaction tree, nothing blinded: what an externally signed submission's prepared transaction is read from
    /// (`crate::external_hash::prepared_transaction`, the same reading its confirmers make).
    pub tree: canton_proto::com::digitalasset::canton::protocol::v30::GenTransactionTree,
}

/// How a request is submitted: by this participant for parties it hosts to submit (the default), or for external parties that
/// authorized the transaction with their own signatures (U-56).
#[derive(Default, Clone, Debug)]
pub struct Submission {
    /// The external parties' authorization the submitter metadata carries (`None`: a classic submission).
    pub external_authorization:
        Option<canton_proto::com::digitalasset::canton::protocol::v32::ExternalAuthorization>,
}

pub(crate) fn uuid(bytes: &[u8; 32]) -> String {
    format!(
        "{}-{}-4{}-8{}-{}",
        hex::encode(&bytes[0..4]),
        hex::encode(&bytes[4..6]),
        &hex::encode(&bytes[6..8])[1..],
        &hex::encode(&bytes[8..10])[1..],
        hex::encode(&bytes[10..16])
    )
}

pub(crate) fn sorted(mut parties: Vec<String>) -> Vec<String> {
    parties.sort();
    parties.dedup();
    parties
}

/// A contract created by a view, as its instance is derived.
pub struct NewInView<'a> {
    pub package_name: &'a str,
    pub package_id: &'a str,
    pub module: &'a [String],
    pub name: &'a [String],
    pub arg: &'a LfValue,
    pub hash_arg: &'a ci::HashValue,
    /// Sorted, without duplicates.
    pub signatories: &'a [String],
    pub stakeholders: &'a [String],
    pub key: Option<&'a NewKey>,
    /// The indices of the create's ancestors below the view's root node and of the create itself, each the position among the siblings that
    /// have a seed (G8 P0). Empty means a direct child of the root exercise, whose position is its index among the view's creates.
    pub path: &'a [i32],
}

/// What a created contract's id depends on besides the contract: the time, the view's salt, the index of the create in the view, the
/// transaction's uuid and the create node's seed.
pub(crate) struct Derivation<'a> {
    pub(crate) now: i64,
    pub(crate) vpd_salt: &'a [u8; 32],
    pub(crate) create_index: i32,
    pub(crate) transaction_uuid: &'a str,
    pub(crate) node_seed: &'a [u8; 32],
    /// The position of the view the create is in, innermost index first (`[[]]` for the only root view).
    pub(crate) view_position: &'a [Vec<bool>],
}

/// The id and the instance of a contract created in a root view (`view_position` `[[]]`).
///
/// [CANTON-NOTE: SEMANTICS] The same derivation serves a root create (index 0, a seed of its own) and a create under an exercise (the index of
/// the create among the exercise's children, the seed derived from the exercise's by that index): what the receiver re-derives in
/// `view_conformance::authenticate_created` and `check_discriminators`.
pub(crate) fn derive_created(
    ctx: &Context,
    c: &NewInView,
    d: &Derivation,
) -> Result<(String, ContractInstance), String> {
    let mediator = cw::mediator_group(ctx.mediator_group);
    let salt = ci::contract_salt(&ci::SaltInputs {
        view_participant_data_salt: d.vpd_salt,
        create_index: d.create_index,
        view_position: d.view_position,
        transaction_uuid: d.transaction_uuid,
        synchronizer_id: ctx.synchronizer,
        mediator: &mediator,
    });
    let contract_hash = ci::lf_contract_hash(c.package_name, c.module, c.name, c.hash_arg);
    let key_hash = c
        .key
        .map(|k| ci::lf_contract_key_hash(c.package_name, c.module, c.name, &k.hash_value));
    let unicum = ci::unicum(
        &salt,
        &ci::UnicumInputs {
            created_at_micros: d.now,
            signatories: c.signatories,
            stakeholders: c.stakeholders,
            key: c.key.zip(key_hash.as_ref()).map(|(k, hash)| ci::KeyInputs {
                hash,
                maintainers: &k.maintainers,
            }),
            contract_hash: &contract_hash,
        },
    );
    let discriminator = ci::derive_contract_discriminator(d.node_seed, d.now, c.stakeholders);
    let contract_id_hex = ci::contract_id(&discriminator, &unicum);
    let instance = ContractInstance {
        contract_id: hex::decode(&contract_id_hex).map_err(|e| e.to_string())?,
        package_name: c.package_name.to_string(),
        package_id: c.package_id.to_string(),
        module: c.module.to_vec(),
        name: c.name.to_vec(),
        arg: c.arg.clone(),
        signatories: c.signatories.iter().cloned().collect::<BTreeSet<_>>(),
        stakeholders: c.stakeholders.iter().cloned().collect::<BTreeSet<_>>(),
        created_at_micros: d.now,
        authentication_data: authentication_data(&salt),
        key: c
            .key
            .zip(key_hash)
            .map(|(k, hash)| crate::contract_wire::ContractKey {
                value: k.value.clone(),
                maintainers: k.maintainers.clone(),
                hash,
            }),
    };
    Ok((contract_id_hex, instance))
}

/// Builds the request for `command` at the sequencer's time `now` (microseconds), valid for 60 seconds.
pub fn build_create(
    ctx: &Context,
    command: &Create,
    now: i64,
    random: &mut dyn Randomness,
) -> Result<Built, String> {
    build_create_as(ctx, command, now, random, &Submission::default())
}

/// Like [`build_create`], submitted as `submission` says (an externally signed submission carries its parties' authorization).
pub fn build_create_as(
    ctx: &Context,
    command: &Create,
    now: i64,
    random: &mut dyn Randomness,
    submission: &Submission,
) -> Result<Built, String> {
    if command.signatories.is_empty() {
        return Err("a contract needs a signatory".into());
    }
    if command.hosts.is_empty() {
        return Err("a request needs at least one participant that hosts a stakeholder".into());
    }
    let identity = ctx.identity;
    let signatories = sorted(command.signatories.clone());
    let stakeholders = sorted(command.stakeholders.clone());
    if let Some(missing) = signatories.iter().find(|s| !stakeholders.contains(s)) {
        return Err(format!(
            "the signatory {missing} is not among the stakeholders"
        ));
    }
    let transaction_uuid = uuid(&random.fresh("uuid"));
    let view_participant_data_salt = random.fresh("vpd-salt");
    let node_seed = random.fresh("node-seed");
    let (contract_id_hex, instance) = derive_created(
        ctx,
        &NewInView {
            package_name: command.package_name,
            package_id: command.package_id,
            module: &command.module,
            name: &command.name,
            arg: &command.arg,
            hash_arg: &command.hash_arg,
            signatories: &signatories,
            stakeholders: &stakeholders,
            key: command.key.as_ref(),
            path: &[],
        },
        &Derivation {
            now,
            vpd_salt: &view_participant_data_salt,
            create_index: 0,
            transaction_uuid: &transaction_uuid,
            node_seed: &node_seed,
            view_position: &[vec![]],
        },
    )?;
    let instance_bytes = instance.encode();
    // a keyed contract's view states the key it creates: the template, the value (a `Versioned` value, "2" as p1 writes it), the package name
    // and the hash, with the maintainers and no contract id (nothing held the key; measured on views p1 made, S-NET-034)
    let resolved_keys = command
        .key
        .iter()
        .map(|k| {
            use canton_proto::com::digitalasset::canton::protocol::v31::{
                view_participant_data::KeyResolutionWithMaintainers, GlobalKey,
            };
            use canton_proto::com::digitalasset::daml::lf::{
                transaction::Versioned, value::Identifier,
            };
            use prost::Message;
            let mut maintainers = k.maintainers.clone();
            maintainers.sort();
            KeyResolutionWithMaintainers {
                key: Some(GlobalKey {
                    template_id: Identifier {
                        package_id: command.package_id.to_string(),
                        module_name: command.module.clone(),
                        name: command.name.clone(),
                    }
                    .encode_to_vec(),
                    key: Versioned {
                        version: "2".into(),
                        payload: k.value.encode(),
                    }
                    .encode_to_vec(),
                    package_name: command.package_name.to_string(),
                    hash: ci::lf_contract_key_hash(
                        command.package_name,
                        &command.module,
                        &command.name,
                        &k.hash_value,
                    )
                    .to_vec(),
                }),
                maintainers,
                contract_ids: Vec::new(),
            }
        })
        .collect();
    let view_participant_data = mw::view_participant_data_create_with_keys(
        &instance_bytes,
        &contract_id_hex,
        &node_seed,
        &view_participant_data_salt,
        resolved_keys,
    );
    let admin = identity.uid();
    let informees = sorted(
        stakeholders
            .iter()
            .cloned()
            .chain(std::iter::once(admin.clone()))
            .collect(),
    );
    let mut confirmers: Vec<(String, i32)> = signatories.iter().map(|s| (s.clone(), 1)).collect();
    confirmers.push((admin, 1));
    let assembled = assemble(
        ctx,
        &RootView {
            participant_data: &view_participant_data,
            informees,
            quorums: vec![confirmers],
            act_as: signatories,
            command_id: &command.command_id,
            transaction_uuid: &transaction_uuid,
            hosts: &command.hosts,
            now,
            external_authorization: submission.external_authorization.as_ref(),
        },
        random,
    )?;
    Ok(Built {
        request: assembled.request,
        message_id: assembled.message_id,
        envelopes: assembled.envelopes,
        root_hash: assembled.root_hash,
        contract_id_hex,
        instance: instance_bytes,
        created: Vec::new(),
        created_nodes: Vec::new(),
        tree: assembled.tree,
    })
}

/// One root view and who is told about it.
struct RootView<'a> {
    participant_data: &'a mw::LeafNode,
    informees: Vec<String>,
    /// The quorums: each a list of confirmers with weight, and the threshold is the number of confirmers.
    quorums: Vec<Vec<(String, i32)>>,
    act_as: Vec<String>,
    command_id: &'a str,
    transaction_uuid: &'a str,
    hosts: &'a [Peer],
    now: i64,
    external_authorization:
        Option<&'a canton_proto::com::digitalasset::canton::protocol::v32::ExternalAuthorization>,
}

struct Assembled {
    request: Vec<u8>,
    message_id: String,
    envelopes: Vec<(Vec<String>, Vec<u8>)>,
    root_hash: Vec<u8>,
    tree: canton_proto::com::digitalasset::canton::protocol::v30::GenTransactionTree,
}

/// The transaction tree around one root view, the informee tree, the encrypted view and the signed submission request.
fn assemble(
    ctx: &Context,
    rv: &RootView,
    random: &mut dyn Randomness,
) -> Result<Assembled, String> {
    let identity = ctx.identity;
    let now = rv.now;
    let mediator = cw::mediator_group(ctx.mediator_group);
    let uid = identity.member();
    let uid = uid.trim_start_matches("PAR::").to_string();
    let common = mw::common_metadata(
        ctx.synchronizer,
        ctx.mediator_group as i32,
        &random.fresh("cm"),
        rv.transaction_uuid,
    );
    let participant = mw::participant_metadata(now, now, None, &random.fresh("pm"));
    let submitter = mw::submitter_metadata_with(
        &mw::SubmitterInfo {
            act_as: rv.act_as.iter().map(String::as_str).collect(),
            user_id: ctx.user_id,
            command_id: rv.command_id,
            submitting_participant_uid: &uid,
            submission_id: None,
            dedup_duration: (300, 0),
            max_sequencing_time_micros: now + 60_000_000,
        },
        &random.fresh("sm"),
        rv.external_authorization,
    );
    let informees = sorted(rv.informees.clone());
    let informee_refs: Vec<&str> = informees.iter().map(String::as_str).collect();
    let quorums: Vec<mw::QuorumSpec> = rv
        .quorums
        .iter()
        .map(|members| {
            let mut confirmers: Vec<(&str, i32)> =
                members.iter().map(|(p, w)| (p.as_str(), *w)).collect();
            confirmers.sort();
            confirmers.dedup();
            let threshold = confirmers.len() as i32;
            mw::QuorumSpec {
                confirmers,
                threshold,
            }
        })
        .collect();
    let view_common_data = mw::view_common_data(&informee_refs, &quorums, &random.fresh("vcd"));
    let view = |participant_data: &mw::Tree| {
        mw::view_node(
            &mw::Tree::leaf(&view_common_data),
            participant_data,
            &mw::merkle_seq(&[]),
        )
    };
    let full_view = view(&mw::Tree::leaf(rv.participant_data));
    let full = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::leaf(&participant),
        &mw::merkle_seq(std::slice::from_ref(&full_view)),
    );
    let informee_tree = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::blinded(participant.root_hash()),
        &mw::merkle_seq(&[view(&mw::Tree::blinded(rv.participant_data.root_hash()))]),
    );
    if full.root_hash != informee_tree.root_hash {
        return Err("the full and the informee tree must have one root hash".into());
    }
    let recipients: Vec<vm::Recipient> = rv
        .hosts
        .iter()
        .map(|peer| {
            let iv: [u8; 16] = random.fresh("ecies-iv")[..16]
                .try_into()
                .expect("SeededRandom::fresh always yields 32 bytes");
            vm::Recipient {
                encryption_spki: &peer.encryption_spki,
                fingerprint: &peer.fingerprint,
                ecies_iv: iv,
                ecies_ephemeral_scalar: random.fresh("ecies-eph"),
            }
        })
        .collect();
    let randomness: [u8; 16] = random.fresh("randomness")[..16]
        .try_into()
        .expect("SeededRandom::fresh always yields 32 bytes");
    let gcm_iv: [u8; 12] = random.fresh("gcm-iv")[..12]
        .try_into()
        .expect("SeededRandom::fresh always yields 32 bytes");
    let encrypted = vm::encrypted_view_message(
        &vm::light_view_tree(&full),
        &full_view.hash,
        &randomness,
        &gcm_iv,
        &recipients,
        ctx.synchronizer,
        identity.signing_key.sign_bytes(&full.root_hash),
    );
    let message_id = format!("submit-{}", hex::encode(&random.fresh("message-id")[..12]));
    let mut envelopes: Vec<(Vec<String>, Vec<u8>)> = vec![(
        vec![mediator.clone()],
        cw::informee_message(&informee_tree, &identity.signing_key),
    )];
    // [CANTON-NOTE: SEMANTICS] one root hash message envelope to every informee participant, one recipient group `{participant, mediator
    // group}` each (`TransactionConfirmationRequest.asBatch`, `Recipients.recipientGroups`; U-57: it used to be one envelope per participant)
    let root_hash_message = cw::root_hash_message(&full.root_hash, ctx.synchronizer, now);
    let root_hash_groups: Vec<Vec<String>> = rv
        .hosts
        .iter()
        .map(|peer| vec![mediator.clone(), peer.member.clone()])
        .collect();
    let mut every_recipient: Vec<String> = std::iter::once(mediator)
        .chain(rv.hosts.iter().map(|p| p.member.clone()))
        .collect();
    every_recipient.dedup();
    envelopes.push((every_recipient, root_hash_message));
    envelopes.push((
        rv.hosts.iter().map(|p| p.member.clone()).collect(),
        encrypted,
    ));
    let trees: Vec<(
        Vec<canton_proto::com::digitalasset::canton::protocol::v30::RecipientsTree>,
        Vec<u8>,
    )> = envelopes
        .iter()
        .enumerate()
        .map(|(i, (group, content))| {
            let trees = if i == 1 {
                root_hash_groups
                    .iter()
                    .map(|g| sw::path_tree(std::slice::from_ref(g)))
                    .collect()
            } else {
                vec![sw::path_tree(std::slice::from_ref(group))]
            };
            (trees, content.clone())
        })
        .collect();
    let request = sw::submission_request_with_trees(
        &identity.member(),
        &message_id,
        &trees,
        now + 60_000_000,
    );
    Ok(Assembled {
        request: sw::signed_submission_request(request, &identity.signing_key),
        message_id,
        envelopes,
        root_hash: full.root_hash,
        tree: full.proto,
    })
}

/// A contract the participant knows the instance of exactly as it was created (an exercise's input carries it).
#[derive(Clone, Debug)]
pub struct StoredContract {
    pub contract_id_hex: String,
    pub instance: Vec<u8>,
    pub package_id: String,
    pub module: Vec<String>,
    pub name: Vec<String>,
    pub signatories: Vec<String>,
    pub stakeholders: Vec<String>,
}

/// The randomness of an exercise's request that the ids of the contracts it creates depend on: the transaction's uuid, the view's salt, the
/// exercise node's seed and the time. Drawing it first lets the ids be promised before the request is built ([`plan_created`]).
#[derive(Clone, Debug)]
pub struct ExercisePlan {
    pub transaction_uuid: String,
    pub vpd_salt: [u8; 32],
    pub node_seed: [u8; 32],
    pub now: i64,
    /// The position of the root view the plan is for (`[[]]`: the only root view of its request).
    pub view_position: Vec<Vec<bool>>,
}

impl ExercisePlan {
    /// Draws in the order [`build_exercise`] draws when it has no plan.
    pub fn draw(random: &mut dyn Randomness, now: i64) -> Self {
        let transaction_uuid = uuid(&random.fresh("uuid"));
        let node_seed = random.fresh("exercise-node-seed");
        let vpd_salt = random.fresh("vpd-salt");
        Self {
            transaction_uuid,
            vpd_salt,
            node_seed,
            now,
            view_position: vec![vec![]],
        }
    }

    /// The plans of a request with `roots` root views, one per root in order: one uuid and time, each root's seed derived from one transaction
    /// seed, a salt per root view.
    ///
    /// [CANTON-NOTE: SEMANTICS] Speedy seeds the `i`-th root node with `deriveNodeSeed(transactionSeed, i)` (`SeededTransactionRootContext`),
    /// and `NextGenTransactionTreeFactory.createRootViews` places root view `i` at `MerkleSeq.indicesFromSeq(n)(i)`, which is why every id of
    /// a multi-root request depends on the number of roots.
    pub fn draw_roots(random: &mut dyn Randomness, now: i64, roots: usize) -> Vec<Self> {
        let transaction_uuid = uuid(&random.fresh("uuid"));
        let transaction_seed = random.fresh("transaction-seed");
        crate::view_tree::seq_indices(roots)
            .into_iter()
            .enumerate()
            .map(|(i, position)| Self {
                transaction_uuid: transaction_uuid.clone(),
                vpd_salt: random.fresh("vpd-salt"),
                node_seed: ci::derive_node_seed(
                    &transaction_seed,
                    i32::try_from(i).unwrap_or(i32::MAX),
                ),
                now,
                view_position: vec![position],
            })
            .collect()
    }
}

/// The id and the stored form of the contract a root create of `plan`'s root view creates (its node seed is the root's, its index 0).
pub fn plan_root_created(
    ctx: &Context,
    plan: &ExercisePlan,
    contract: &NewInView,
) -> Result<StoredContract, String> {
    stored_created(ctx, plan, 0, &plan.node_seed, contract)
}

/// The seed of the node at `path` below the root node whose seed is `root`: `deriveNodeSeed` once per level. An empty path is the direct child
/// at `index`.
fn node_seed_at(root: &[u8; 32], path: &[i32], index: i32) -> [u8; 32] {
    if path.is_empty() {
        return ci::derive_node_seed(root, index);
    }
    path.iter()
        .fold(*root, |seed, i| ci::derive_node_seed(&seed, *i))
}

/// The id and the stored form of the contract that is the `index`-th child (a create) of the exercise `plan` describes.
pub fn plan_created(
    ctx: &Context,
    plan: &ExercisePlan,
    index: usize,
    contract: &NewInView,
) -> Result<StoredContract, String> {
    let seed = node_seed_at(&plan.node_seed, contract.path, index as i32);
    stored_created(ctx, plan, index, &seed, contract)
}

fn stored_created(
    ctx: &Context,
    plan: &ExercisePlan,
    index: usize,
    node_seed: &[u8; 32],
    contract: &NewInView,
) -> Result<StoredContract, String> {
    let (contract_id_hex, instance) = derive_created(
        ctx,
        contract,
        &Derivation {
            now: plan.now,
            vpd_salt: &plan.vpd_salt,
            create_index: index as i32,
            transaction_uuid: &plan.transaction_uuid,
            node_seed,
            view_position: &plan.view_position,
        },
    )?;
    Ok(StoredContract {
        contract_id_hex,
        instance: instance.encode(),
        package_id: contract.package_id.to_string(),
        module: contract.module.to_vec(),
        name: contract.name.to_vec(),
        signatories: contract.signatories.to_vec(),
        stakeholders: contract.stakeholders.to_vec(),
    })
}

/// A `Versioned { version = "2.1", payload }` around a value's bytes (the form a chosen value has in an exercise view).
pub fn versioned(value: &LfValue) -> Vec<u8> {
    versioned_as("2.1", value)
}

/// Like [`versioned`] with the serialization version of the value's package: `"2.1"` for a Daml-LF 2.1 package, `"2"` for a 2.3 one (measured:
/// the official participant rebuilds the chosen value of a `Keyed` exercise as `V2`, S-SPL-014).
pub fn versioned_as(version: &str, value: &LfValue) -> Vec<u8> {
    fn varint(mut n: usize, out: &mut Vec<u8>) {
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    }
    let payload = value.encode();
    let mut out = vec![10];
    varint(version.len(), &mut out);
    out.extend_from_slice(version.as_bytes());
    out.push(18);
    varint(payload.len(), &mut out);
    out.extend_from_slice(&payload);
    out
}

/// The common data of a view: informees (sorted) and one quorum per list, the threshold being the number of members.
pub(crate) fn common_data_of(
    informees: &[String],
    quorums: &[Vec<(String, i32)>],
    salt: &[u8],
) -> mw::LeafNode {
    let informees = sorted(informees.to_vec());
    let refs: Vec<&str> = informees.iter().map(String::as_str).collect();
    let specs: Vec<mw::QuorumSpec> = quorums
        .iter()
        .map(|members| {
            let mut confirmers: Vec<(&str, i32)> =
                members.iter().map(|(p, w)| (p.as_str(), *w)).collect();
            confirmers.sort();
            confirmers.dedup();
            let threshold = confirmers.len() as i32;
            mw::QuorumSpec {
                confirmers,
                threshold,
            }
        })
        .collect();
    mw::view_common_data(&refs, &specs, salt)
}
