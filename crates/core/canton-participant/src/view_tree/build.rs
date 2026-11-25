//! Building a transaction's view tree with recorded or replayed randomness (`build_transaction`, `build_planned`).

use std::collections::{BTreeMap, BTreeSet};

use crate::submit::{uuid, Built, Context, Peer, Randomness, StoredContract};
use crate::{
    confirmation_wire as cw, merkle_wire as mw, sequencing_wire as sw, view_message as vm,
};

use super::run::{light_node, node_seeds, with_ids};
use super::{decompose, seq_indices, Action, BuiltView, Run, Transaction};

/// Records what a [`Randomness`] hands out.
struct Recording<'r> {
    inner: &'r mut dyn Randomness,
    draws: Vec<[u8; 32]>,
}

impl Randomness for Recording<'_> {
    fn fresh(&mut self, label: &str) -> [u8; 32] {
        let bytes = self.inner.fresh(label);
        self.draws.push(bytes);
        bytes
    }
}

/// Hands out recorded draws in order.
struct Replay {
    draws: Vec<[u8; 32]>,
    at: usize,
}

impl Randomness for Replay {
    fn fresh(&mut self, _label: &str) -> [u8; 32] {
        let bytes = self.draws[self.at];
        self.at += 1;
        bytes
    }
}

/// Builds the request of `tx` (see [`Transaction::temp_ids`] for a transaction whose exercises name contracts it creates).
///
/// [CANTON-NOTE: SEMANTICS] The id of a created contract comes from its node seed, its view's salt and its position, never from the arguments
/// of the exercises around it, so the first build's ids are the final ones; the second build replays the same randomness with them stated.
pub fn build_transaction(
    ctx: &Context,
    tx: &Transaction,
    peers: &[Peer],
    hosting: &dyn Fn(&str) -> BTreeSet<String>,
    act_as: &[String],
    command_id: &str,
    now: i64,
    plan: Option<&crate::submit::ExercisePlan>,
    random: &mut dyn Randomness,
) -> Result<Built, String> {
    let plans = plan.map_or(&[][..], std::slice::from_ref);
    build_planned(
        ctx, tx, peers, hosting, act_as, command_id, now, plans, random,
    )
}

/// Who submits a transaction and how: the submitting parties, the command, the sequencer's time, the plans of a request whose ids were
/// promised before it was built, and whether its external parties authorized it (U-56).
#[derive(Clone, Copy)]
pub struct RequestSpec<'a> {
    pub act_as: &'a [String],
    pub command_id: &'a str,
    pub now: i64,
    pub plan: &'a [crate::submit::ExercisePlan],
    pub submission: &'a crate::submit::Submission,
}

/// Like [`build_transaction`] with one plan per root view (`submit::ExercisePlan::draw_roots`), for a request whose ids were promised
/// before it was built. No plan draws everything; a single plan is the plan of the only root, as in [`build_transaction`].
#[expect(
    clippy::too_many_arguments,
    reason = "the arguments of build_transaction with the plans in place of one plan"
)]
pub fn build_planned(
    ctx: &Context,
    tx: &Transaction,
    peers: &[Peer],
    hosting: &dyn Fn(&str) -> BTreeSet<String>,
    act_as: &[String],
    command_id: &str,
    now: i64,
    plan: &[crate::submit::ExercisePlan],
    random: &mut dyn Randomness,
) -> Result<Built, String> {
    build_planned_as(
        ctx,
        tx,
        peers,
        hosting,
        &RequestSpec {
            act_as,
            command_id,
            now,
            plan,
            submission: &crate::submit::Submission::default(),
        },
        random,
    )
}

/// Like [`build_planned`], with who submits and how in one [`RequestSpec`].
pub fn build_planned_as(
    ctx: &Context,
    tx: &Transaction,
    peers: &[Peer],
    hosting: &dyn Fn(&str) -> BTreeSet<String>,
    spec: &RequestSpec<'_>,
    random: &mut dyn Randomness,
) -> Result<Built, String> {
    if tx.temp_ids.is_empty() {
        return build_transaction_once(ctx, tx, peers, hosting, spec, random);
    }
    let dummy: BTreeMap<String, String> = tx
        .temp_ids
        .keys()
        .map(|k| (k.clone(), "00".repeat(34)))
        .collect();
    let mut recording = Recording {
        inner: random,
        draws: Vec::new(),
    };
    let first = build_transaction_once(
        ctx,
        &with_ids(tx, &dummy, &BTreeMap::new()),
        peers,
        hosting,
        spec,
        &mut recording,
    )?;
    let collect_resolved = |built: &Built| -> Result<
        (BTreeMap<String, String>, BTreeMap<String, StoredContract>),
        String,
    > {
        let mut next_real = BTreeMap::new();
        let mut next_made = BTreeMap::new();
        for (temp, node) in &tx.temp_ids {
            let at = built
                .created_nodes
                .iter()
                .position(|n| n == node)
                .ok_or_else(|| format!("node {node} created no contract"))?;
            next_real.insert(temp.clone(), built.created[at].contract_id_hex.clone());
            next_made.insert(temp.clone(), built.created[at].clone());
        }
        Ok((next_real, next_made))
    };
    let (mut real, mut made) = collect_resolved(&first)?;
    // Iterate fixed point up to `temp_ids.len() + 1` passes so chained `Create A -> Create B(ref A)`
    // across subviews converges onto the exact hashes of the derived contracts.
    let mut built = first;
    for _ in 0..=tx.temp_ids.len() {
        let mut replay = Replay {
            draws: recording.draws.clone(),
            at: 0,
        };
        let next = build_transaction_once(
            ctx,
            &with_ids(tx, &real, &made),
            peers,
            hosting,
            spec,
            &mut replay,
        )?;
        let (next_real, next_made) = collect_resolved(&next)?;
        let converged = next_real == real;
        real = next_real;
        made = next_made;
        built = next;
        if converged {
            break;
        }
    }
    Ok(built)
}

/// Builds the confirmation request for `tx` submitted by `ctx.identity`'s participant, valid for 60 seconds from `now`.
///
/// `plan` fixes the transaction's uuid, the root node's seed, the root view's salt and the time when the ids of the contracts it creates were
/// promised before this call (`submit::ExercisePlan`).
///
/// `peers` are the participants the request may be sent to (with their encryption keys) and `hosting` says which members host a party.
/// `act_as` are the submitting parties, `command_id` the command.
fn build_transaction_once(
    ctx: &Context,
    tx: &Transaction,
    peers: &[Peer],
    hosting: &dyn Fn(&str) -> BTreeSet<String>,
    spec: &RequestSpec<'_>,
    random: &mut dyn Randomness,
) -> Result<Built, String> {
    let RequestSpec {
        act_as,
        command_id,
        now,
        plan,
        submission,
    } = *spec;
    let sequencer_now = plan.first().map_or(now, |p| p.now);
    let now = tx.ledger_time.unwrap_or(sequencer_now);
    if tx.roots.is_empty() {
        return Err("a transaction has at least one root".into());
    }
    let identity = ctx.identity;
    let admin = identity.uid();
    let decomposition = decompose(tx, &admin, hosting);
    if plan.len() > 1 && plan.len() != decomposition.len() {
        return Err(format!(
            "{} root views and {} plans",
            decomposition.len(),
            plan.len()
        ));
    }
    let transaction_uuid = match plan.first() {
        Some(plan) => plan.transaction_uuid.clone(),
        None => uuid(&random.fresh("uuid")),
    };
    let root_seeds: Vec<[u8; 32]> = plan.iter().map(|p| p.node_seed).collect();
    let seeds = node_seeds(tx, &root_seeds, random);
    let mut run = Run {
        ctx,
        tx,
        now,
        uuid: transaction_uuid.clone(),
        seeds,
        hosting,
        created: Vec::new(),
        created_nodes: Vec::new(),
        root_salt: None,
    };
    let root_positions = seq_indices(decomposition.len());
    let mut roots: Vec<BuiltView> = Vec::new();
    for (i, (nv, p)) in decomposition.iter().zip(root_positions).enumerate() {
        run.root_salt = match plan {
            [only] => Some(only.vpd_salt),
            many => many.get(i).map(|p| p.vpd_salt),
        };
        roots.push(run.view(nv, vec![p], random)?);
    }
    let mediator = cw::mediator_group(ctx.mediator_group);
    let common = mw::common_metadata(
        ctx.synchronizer,
        ctx.mediator_group as i32,
        &random.fresh("cm"),
        &transaction_uuid,
    );
    let participant = mw::participant_metadata(now, now, None, &random.fresh("pm"));
    let uid = identity.member().trim_start_matches("PAR::").to_string();
    let submitter = mw::submitter_metadata_with(
        &mw::SubmitterInfo {
            act_as: act_as.iter().map(String::as_str).collect(),
            user_id: ctx.user_id,
            command_id,
            submitting_participant_uid: &uid,
            submission_id: None,
            dedup_duration: (300, 0),
            max_sequencing_time_micros: sequencer_now + 60_000_000,
        },
        &random.fresh("sm"),
        submission.external_authorization.as_ref(),
    );
    let gen = |submitter: mw::Tree, participant: mw::Tree, views: Vec<mw::Tree>| {
        mw::gen_transaction_tree(
            &submitter,
            &mw::Tree::leaf(&common),
            &participant,
            &mw::merkle_seq(&views),
        )
    };
    let full = gen(
        mw::Tree::leaf(&submitter),
        mw::Tree::leaf(&participant),
        roots.iter().map(|r| r.full.clone()).collect(),
    );
    let informee_tree = gen(
        mw::Tree::leaf(&submitter),
        mw::Tree::blinded(participant.root_hash()),
        roots.iter().map(|r| r.informee.clone()).collect(),
    );
    // every view, with its chain from its root
    fn collect<'v>(
        view: &'v BuiltView,
        chain: &mut Vec<&'v BuiltView>,
        out: &mut Vec<Vec<&'v BuiltView>>,
    ) {
        chain.push(view);
        out.push(chain.clone());
        for c in &view.children {
            collect(c, chain, out);
        }
        chain.pop();
    }
    let mut chains: Vec<Vec<&BuiltView>> = Vec::new();
    for r in &roots {
        collect(r, &mut Vec::new(), &mut chains);
    }
    let mut envelopes: Vec<(Vec<String>, Vec<u8>)> = vec![(
        vec![mediator.clone()],
        cw::informee_message(&informee_tree, &identity.signing_key),
    )];
    let peer_of = |member: &str| -> Result<&Peer, String> {
        peers
            .iter()
            .find(|p| p.member == member)
            .ok_or_else(|| format!("no encryption key is known for {member}"))
    };
    let mut everyone: BTreeSet<String> = BTreeSet::new();
    // the recipients of each view message as a path of groups from the root view down to it (see `sw::compressed_batch_paths`)
    let mut view_paths: Vec<Vec<Vec<String>>> = Vec::new();
    for chain in &chains {
        let target = chain[chain.len() - 1];
        everyone.extend(target.members.iter().cloned());
        let is_root = chain.len() == 1;
        let light = gen(
            if is_root {
                mw::Tree::leaf(&submitter)
            } else {
                mw::Tree::blinded(submitter.root_hash())
            },
            mw::Tree::leaf(&participant),
            roots
                .iter()
                .map(|r| {
                    if std::ptr::eq(r, chain[0]) {
                        light_node(chain)
                    } else {
                        mw::Tree::blinded(r.full.hash.clone())
                    }
                })
                .collect(),
        );
        if light.root_hash != full.root_hash {
            return Err("the light tree of a view must have the root hash of the request".into());
        }
        let drawn: Vec<(Peer, [u8; 16], [u8; 32])> = target
            .members
            .iter()
            .map(|m| {
                let peer = peer_of(m)?.clone();
                let iv: [u8; 16] = random.fresh("ecies-iv")[..16]
                    .try_into()
                    .expect("SeededRandom::fresh always yields 32 bytes");
                Ok((peer, iv, random.fresh("ecies-eph")))
            })
            .collect::<Result<_, String>>()?;
        let recipients: Vec<vm::Recipient> = drawn
            .iter()
            .map(|(peer, iv, eph)| vm::Recipient {
                encryption_spki: &peer.encryption_spki,
                fingerprint: &peer.fingerprint,
                ecies_iv: *iv,
                ecies_ephemeral_scalar: *eph,
            })
            .collect();
        let subviews: Vec<(Vec<u8>, [u8; 16])> = target
            .children
            .iter()
            .map(|c| (c.full.hash.clone(), c.key))
            .collect();
        let gcm_iv: [u8; 12] = random.fresh("gcm-iv")[..12]
            .try_into()
            .expect("SeededRandom::fresh always yields 32 bytes");
        let message = vm::encrypted_view_message_signed(
            &vm::light_view_tree_with_subviews(&light, &subviews),
            &target.full.hash,
            &target.key,
            &gcm_iv,
            &recipients,
            ctx.synchronizer,
            is_root.then(|| identity.signing_key.sign_bytes(&full.root_hash)),
        );
        envelopes.push((target.members.iter().cloned().collect(), message));
        view_paths.push(
            chain
                .iter()
                .map(|v| v.members.iter().cloned().collect())
                .collect(),
        );
    }
    // [CANTON-NOTE: SEMANTICS] one root hash message envelope to every informee participant, one recipient group `{mediator group,
    // participant}` each (`TransactionConfirmationRequest.asBatch`, `Recipients.recipientGroups`; U-57: it used to be one envelope per
    // participant)
    let root_hash_message = cw::root_hash_message(&full.root_hash, ctx.synchronizer, sequencer_now);
    let root_hash_groups: Vec<Vec<String>> = everyone
        .iter()
        .map(|m| vec![mediator.clone(), m.clone()])
        .collect();
    let every_recipient: Vec<String> = std::iter::once(mediator)
        .chain(everyone.iter().cloned())
        .collect();
    let views = envelopes.split_off(1);
    envelopes.push((every_recipient, root_hash_message));
    envelopes.extend(views);
    let message_id = format!("submit-{}", hex::encode(&random.fresh("message-id")[..12]));
    // the same envelopes, in the same order, each addressed to its recipient trees: the informee message to its group, the root hash
    // message to the group of each participant, the view messages to the groups of their chain (a path)
    let trees: Vec<(
        Vec<canton_proto::com::digitalasset::canton::protocol::v30::RecipientsTree>,
        Vec<u8>,
    )> = envelopes
        .iter()
        .enumerate()
        .map(|(i, (group, content))| {
            let trees = match i {
                0 => vec![sw::path_tree(std::slice::from_ref(group))],
                1 => root_hash_groups
                    .iter()
                    .map(|g| sw::path_tree(std::slice::from_ref(g)))
                    .collect(),
                _ => vec![sw::path_tree(&view_paths[i - 2])],
            };
            (trees, content.clone())
        })
        .collect();
    let request = sw::submission_request_with_trees(
        &identity.member(),
        &message_id,
        &trees,
        sequencer_now + 60_000_000,
    );
    let created = run.created;
    let created_nodes = run.created_nodes;
    let root_contract_id = match &tx.nodes[tx.roots[0]] {
        Action::Create(_) => created
            .first()
            .map(|c| c.contract_id_hex.clone())
            .unwrap_or_default(),
        Action::Exercise { contract, .. } | Action::Fetch { contract, .. } => {
            contract.contract_id_hex.clone()
        }
        Action::Lookup(..) | Action::Rollback { .. } => String::new(),
    };
    Ok(Built {
        request: sw::signed_submission_request(request, &identity.signing_key),
        message_id,
        envelopes,
        root_hash: full.root_hash,
        tree: full.proto,
        contract_id_hex: root_contract_id,
        instance: Vec::new(),
        created,
        created_nodes,
    })
}
