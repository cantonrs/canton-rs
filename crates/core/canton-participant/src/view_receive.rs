//! What a participant does with the encrypted view message it receives (G5 5.6h, S-NET-016): decrypt it, parse the light view
//! tree, and check that the tree is what the submitting participant signed for.
//!
//! [CANTON-NOTE: SEMANTICS] The reverse of `view_message`/`merkle_wire`:
//! - The session key randomness is the entry of `session_key_lookup` that names the fingerprint of this participant's encryption
//!   key, ECIES-decrypted with its private key; the view trees are AES-128-GCM-decrypted with it and Zstd-decompressed into an
//!   `UncompressedViewTrees` whose elements are versioned `LightTransactionViewTree`s.
//! - The **root hash** of a tree is recomputed from its nodes (a leaf is hashed from its *salt* and its versioned bytes, an inner
//!   node from the hashes of its children, a blinded node is its hash) and must equal the root hash of the `RootHashMessage` the
//!   participant got from the same sequenced event; the unblinded view's own hash must be one of the message's `view_hashes`.
//! - The submitting participant's signature covers the root hash (the multihash bytes themselves).
//!
//! [CANTON-NOTE: LIMITATION] No model conformance in this module: replaying the action in an engine and re-deriving contract ids is
//! `view_conformance`, called by `view_decision` on the views this module reveals.
use crate::merkle_wire::inner_hash;
use crate::topology_wire::unversioned;
use crate::view_crypto::{aes_gcm_decrypt, ecies_decrypt};
use canton_algo::hash::PurposeHash;
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    blindable_node::BlindedOrNot, BlindableNode, CommonMetadata, GenTransactionTree,
    LightTransactionViewTree, MerkleSeq, MerkleSeqElement, ParticipantMetadata, RootHashMessage,
    ViewCommonData, ViewNode,
};
use canton_proto::com::digitalasset::canton::protocol::v32::{
    encrypted_multiple_views_message::UncompressedViewTrees, envelope_content::SomeEnvelopeContent,
    EncryptedMultipleViewsMessage, EnvelopeContent, SubmitterMetadata, ViewParticipantData,
};
use prost::Message;

/// Why a received view is not accepted.
#[derive(Debug, PartialEq, Eq)]
pub enum ReceiveError {
    NotAnEncryptedViewMessage,
    NoSessionKeyForThisParticipant,
    SessionKeyDoesNotDecrypt,
    ViewsDoNotDecrypt,
    NotDecompressible,
    Malformed(String),
    /// A hash the message states is not the one recomputed from the tree.
    HashMismatch(String),
    BadSignature,
}

/// The decrypted, parsed content of an encrypted view message.
#[derive(Debug, Clone)]
pub struct DecryptedViews {
    pub view_trees: Vec<LightTransactionViewTree>,
    pub view_hashes: Vec<Vec<u8>>,
    pub submitting_participant_signature: Option<Signature>,
    pub physical_synchronizer_id: String,
}

/// Decrypts the content of an envelope that holds an `EncryptedMultipleViewsMessage`.
pub fn decrypt_views(
    envelope_content: &[u8],
    encryption_fingerprint: &str,
    encryption_secret: &[u8; 32],
) -> Result<DecryptedViews, ReceiveError> {
    let (inner, _version) =
        unversioned(envelope_content).ok_or(ReceiveError::NotAnEncryptedViewMessage)?;
    let content = canton_proto::depth::decode::<EnvelopeContent>(inner.as_slice())
        .map_err(|_| ReceiveError::NotAnEncryptedViewMessage)?;
    let Some(SomeEnvelopeContent::EncryptedMultipleViewsMessage(message)) =
        content.some_envelope_content
    else {
        return Err(ReceiveError::NotAnEncryptedViewMessage);
    };
    let EncryptedMultipleViewsMessage {
        compressed_view_trees,
        view_hashes,
        submitting_participant_signature,
        session_key_lookup,
        physical_synchronizer_id,
        ..
    } = message;
    let entry = session_key_lookup
        .iter()
        .find(|e| e.fingerprint == encryption_fingerprint)
        .ok_or(ReceiveError::NoSessionKeyForThisParticipant)?;
    let randomness: [u8; 16] = ecies_decrypt(encryption_secret, &entry.ciphertext)
        .and_then(|r| r.try_into().ok())
        .ok_or(ReceiveError::SessionKeyDoesNotDecrypt)?;
    let compressed = aes_gcm_decrypt(&randomness, &compressed_view_trees)
        .ok_or(ReceiveError::ViewsDoNotDecrypt)?;
    // [CANTON-NOTE: SEMANTICS] Bounded as Canton bounds it (`EncryptedViewMessage.decryptWithRandomness`: `MaxBytesToDecompress` of the
    // synchronizer's `maxRequestSize`), with the envelope readers' fixed bound (`sequencing_wire::MAX_DECOMPRESSED_BYTES`).
    let uncompressed =
        crate::sequencing_wire::decompress(&compressed).ok_or(ReceiveError::NotDecompressible)?;
    let trees = canton_proto::depth::decode::<UncompressedViewTrees>(uncompressed.as_slice())
        .map_err(|e| ReceiveError::Malformed(format!("UncompressedViewTrees: {e}")))?;
    let view_trees = trees
        .view_trees
        .iter()
        .map(|bytes| {
            let (data, _) = unversioned(bytes)
                .ok_or_else(|| ReceiveError::Malformed("an unversioned light view tree".into()))?;
            canton_proto::depth::decode::<LightTransactionViewTree>(data.as_slice())
                .map_err(|e| ReceiveError::Malformed(format!("LightTransactionViewTree: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DecryptedViews {
        view_trees,
        view_hashes,
        submitting_participant_signature,
        physical_synchronizer_id,
    })
}

/// The root hash a `RootHashMessage` envelope announces.
pub fn root_hash_of_message(envelope_content: &[u8]) -> Option<Vec<u8>> {
    let (inner, _) = unversioned(envelope_content)?;
    match canton_proto::depth::decode::<EnvelopeContent>(inner.as_slice())
        .ok()?
        .some_envelope_content?
    {
        SomeEnvelopeContent::RootHashMessage(RootHashMessage { root_hash, .. }) => Some(root_hash),
        _ => None,
    }
}

fn multihash(digest: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0x12, 0x20];
    out.extend_from_slice(&digest);
    out
}

/// The hash of a leaf node from its salt and its versioned bytes.
fn leaf_hash(purpose: i32, salt: &[u8], versioned_bytes: &[u8]) -> Vec<u8> {
    let mut h = PurposeHash::new(purpose);
    h.add_byte_string(salt).expect("open");
    h.add_byte_string(versioned_bytes).expect("open");
    multihash(h.finish().expect("open"))
}

/// What a node is, which decides how its bytes are hashed.
#[derive(Clone, Copy)]
enum Kind {
    SubmitterMetadata,
    CommonMetadata,
    ParticipantMetadata,
    ViewCommonData,
    ViewParticipantData,
    View,
    SeqElement,
}

fn salt_of(salt: Option<canton_proto::com::digitalasset::canton::crypto::v30::Salt>) -> Vec<u8> {
    salt.map(|s| s.salt).unwrap_or_default()
}

/// The hash of a node as the tree states it (`None` for an absent node).
fn node_hash(node: &BlindableNode, kind: Kind) -> Result<Vec<u8>, ReceiveError> {
    let malformed = |what: &str| ReceiveError::Malformed(what.to_string());
    match node
        .blinded_or_not
        .as_ref()
        .ok_or_else(|| malformed("an empty node"))?
    {
        BlindedOrNot::BlindedHash(hash) => Ok(hash.clone()),
        BlindedOrNot::Unblinded(bytes) => {
            let (data, _) = unversioned(bytes).ok_or_else(|| malformed("an unversioned node"))?;
            let decode_err = |e: prost::DecodeError| ReceiveError::Malformed(e.to_string());
            Ok(match kind {
                Kind::SubmitterMetadata => leaf_hash(
                    5,
                    &salt_of(
                        SubmitterMetadata::decode(data.as_slice())
                            .map_err(decode_err)?
                            .salt,
                    ),
                    bytes,
                ),
                Kind::CommonMetadata => leaf_hash(
                    6,
                    &salt_of(
                        CommonMetadata::decode(data.as_slice())
                            .map_err(decode_err)?
                            .salt,
                    ),
                    bytes,
                ),
                Kind::ParticipantMetadata => leaf_hash(
                    7,
                    &salt_of(
                        ParticipantMetadata::decode(data.as_slice())
                            .map_err(decode_err)?
                            .salt,
                    ),
                    bytes,
                ),
                Kind::ViewCommonData => leaf_hash(
                    8,
                    &salt_of(
                        ViewCommonData::decode(data.as_slice())
                            .map_err(decode_err)?
                            .salt,
                    ),
                    bytes,
                ),
                Kind::ViewParticipantData => leaf_hash(
                    9,
                    &salt_of(
                        ViewParticipantData::decode(data.as_slice())
                            .map_err(decode_err)?
                            .salt,
                    ),
                    bytes,
                ),
                Kind::View => {
                    let view = ViewNode::decode(data.as_slice()).map_err(decode_err)?;
                    let mut children = vec![
                        node_hash(
                            view.view_common_data
                                .as_ref()
                                .ok_or_else(|| malformed("a view without common data"))?,
                            Kind::ViewCommonData,
                        )?,
                        node_hash(
                            view.view_participant_data
                                .as_ref()
                                .ok_or_else(|| malformed("a view without participant data"))?,
                            Kind::ViewParticipantData,
                        )?,
                    ];
                    if let Some(h) = seq_hash(view.subviews.as_ref())? {
                        children.push(h);
                    }
                    let refs: Vec<&[u8]> = children.iter().map(Vec::as_slice).collect();
                    inner_hash(&refs)
                }
                Kind::SeqElement => {
                    let e = MerkleSeqElement::decode(data.as_slice()).map_err(decode_err)?;
                    let mut children = Vec::new();
                    for (child, k) in [
                        (e.first.as_ref(), Kind::SeqElement),
                        (e.second.as_ref(), Kind::SeqElement),
                        (e.data.as_ref(), Kind::View),
                    ] {
                        if let Some(c) = child {
                            children.push(node_hash(c, k)?);
                        }
                    }
                    let refs: Vec<&[u8]> = children.iter().map(Vec::as_slice).collect();
                    inner_hash(&refs)
                }
            })
        }
    }
}

fn seq_hash(seq: Option<&MerkleSeq>) -> Result<Option<Vec<u8>>, ReceiveError> {
    match seq.and_then(|s| s.root_or_empty.as_ref()) {
        None => Ok(None),
        Some(root) => node_hash(root, Kind::SeqElement).map(Some),
    }
}

/// The root hash of a transaction tree, recomputed from its nodes.
pub fn recompute_root_hash(tree: &GenTransactionTree) -> Result<Vec<u8>, ReceiveError> {
    let missing = |what: &str| ReceiveError::Malformed(format!("a tree without {what}"));
    let mut children = vec![
        node_hash(
            tree.submitter_metadata
                .as_ref()
                .ok_or_else(|| missing("submitter metadata"))?,
            Kind::SubmitterMetadata,
        )?,
        node_hash(
            tree.common_metadata
                .as_ref()
                .ok_or_else(|| missing("common metadata"))?,
            Kind::CommonMetadata,
        )?,
        node_hash(
            tree.participant_metadata
                .as_ref()
                .ok_or_else(|| missing("participant metadata"))?,
            Kind::ParticipantMetadata,
        )?,
    ];
    if let Some(h) = seq_hash(tree.root_views.as_ref())? {
        children.push(h);
    }
    let refs: Vec<&[u8]> = children.iter().map(Vec::as_slice).collect();
    Ok(inner_hash(&refs))
}

/// A view whose common and participant data are revealed.
#[derive(Debug, Clone)]
pub struct RevealedView {
    /// The view's own hash (what `view_hashes` lists).
    pub view_hash: Vec<u8>,
    pub common_data: ViewCommonData,
    pub participant_data: ViewParticipantData,
    /// The view's position (`ViewPosition`): one element per level of nesting, **innermost first**; each element is the path from
    /// the view up to the root of its `MerkleSeq` (`true` = right). A root view has one element, a subview of it two.
    pub position: Vec<Vec<bool>>,
    /// `true` if the view has subviews in the tree (revealed or blinded).
    pub has_subviews: bool,
}

/// The revealed views of a tree, at any depth: the roots, and the subviews of a revealed view. A participant that is an informee
/// only of a subview receives a tree in which the views above it are blinded.
pub fn revealed_views(tree: &GenTransactionTree) -> Result<Vec<RevealedView>, ReceiveError> {
    fn walk_seq(
        seq: Option<&MerkleSeq>,
        ancestors: &[Vec<bool>],
        out: &mut Vec<RevealedView>,
    ) -> Result<(), ReceiveError> {
        if let Some(root) = seq.and_then(|s| s.root_or_empty.as_ref()) {
            walk_element(root, &mut Vec::new(), ancestors, out)?;
        }
        Ok(())
    }
    fn walk_element(
        node: &BlindableNode,
        path_from_root: &mut Vec<bool>,
        ancestors: &[Vec<bool>],
        out: &mut Vec<RevealedView>,
    ) -> Result<(), ReceiveError> {
        let Some(BlindedOrNot::Unblinded(bytes)) = node.blinded_or_not.as_ref() else {
            return Ok(());
        };
        let (data, _) = unversioned(bytes)
            .ok_or_else(|| ReceiveError::Malformed("an unversioned sequence element".into()))?;
        let e = MerkleSeqElement::decode(data.as_slice())
            .map_err(|e| ReceiveError::Malformed(e.to_string()))?;
        if let Some(first) = &e.first {
            path_from_root.push(false);
            walk_element(first, path_from_root, ancestors, out)?;
            path_from_root.pop();
        }
        if let Some(second) = &e.second {
            path_from_root.push(true);
            walk_element(second, path_from_root, ancestors, out)?;
            path_from_root.pop();
        }
        let Some(view_node) = e.data.as_ref() else {
            return Ok(());
        };
        let Some(BlindedOrNot::Unblinded(view_bytes)) = view_node.blinded_or_not.as_ref() else {
            return Ok(());
        };
        let (vdata, _) = unversioned(view_bytes)
            .ok_or_else(|| ReceiveError::Malformed("an unversioned view".into()))?;
        let view = ViewNode::decode(vdata.as_slice())
            .map_err(|e| ReceiveError::Malformed(e.to_string()))?;
        // the position is the path from the view to the root of its sequence, then the parents' (innermost first)
        let mut position = vec![path_from_root.iter().rev().copied().collect::<Vec<bool>>()];
        position.extend_from_slice(ancestors);
        if let (
            Some(BlindableNode {
                blinded_or_not: Some(BlindedOrNot::Unblinded(vcd)),
            }),
            Some(BlindableNode {
                blinded_or_not: Some(BlindedOrNot::Unblinded(vpd)),
            }),
        ) = (&view.view_common_data, &view.view_participant_data)
        {
            let (vcd_data, _) =
                unversioned(vcd).ok_or_else(|| ReceiveError::Malformed("common data".into()))?;
            let (vpd_data, _) = unversioned(vpd)
                .ok_or_else(|| ReceiveError::Malformed("participant data".into()))?;
            out.push(RevealedView {
                view_hash: node_hash(view_node, Kind::View)?,
                common_data: ViewCommonData::decode(vcd_data.as_slice())
                    .map_err(|e| ReceiveError::Malformed(e.to_string()))?,
                participant_data: ViewParticipantData::decode(vpd_data.as_slice())
                    .map_err(|e| ReceiveError::Malformed(e.to_string()))?,
                position: position.clone(),
                has_subviews: view
                    .subviews
                    .as_ref()
                    .is_some_and(|s| s.root_or_empty.is_some()),
            });
        }
        // views below this one (revealed or not, the walk only reports the revealed ones)
        walk_seq(view.subviews.as_ref(), &position, out)
    }
    let mut out = Vec::new();
    walk_seq(tree.root_views.as_ref(), &[], &mut out)?;
    Ok(out)
}

/// A view of an informee tree: its position and its common data (the informees and the quorums).
pub type InformeeView = (Vec<Vec<bool>>, ViewCommonData);

/// The views of an **informee tree** (what the mediator receives): every view whose common data is revealed, with its position. The
/// participant data of such a tree is blinded, which is why [`revealed_views`] does not report them.
pub fn informee_views(tree: &GenTransactionTree) -> Result<Vec<InformeeView>, ReceiveError> {
    fn walk_seq(
        seq: Option<&MerkleSeq>,
        ancestors: &[Vec<bool>],
        out: &mut Vec<InformeeView>,
    ) -> Result<(), ReceiveError> {
        if let Some(root) = seq.and_then(|s| s.root_or_empty.as_ref()) {
            walk_element(root, &mut Vec::new(), ancestors, out)?;
        }
        Ok(())
    }
    fn walk_element(
        node: &BlindableNode,
        path_from_root: &mut Vec<bool>,
        ancestors: &[Vec<bool>],
        out: &mut Vec<InformeeView>,
    ) -> Result<(), ReceiveError> {
        let Some(BlindedOrNot::Unblinded(bytes)) = node.blinded_or_not.as_ref() else {
            return Ok(());
        };
        let (data, _) = unversioned(bytes)
            .ok_or_else(|| ReceiveError::Malformed("an unversioned sequence element".into()))?;
        let e = MerkleSeqElement::decode(data.as_slice())
            .map_err(|e| ReceiveError::Malformed(e.to_string()))?;
        if let Some(first) = &e.first {
            path_from_root.push(false);
            walk_element(first, path_from_root, ancestors, out)?;
            path_from_root.pop();
        }
        if let Some(second) = &e.second {
            path_from_root.push(true);
            walk_element(second, path_from_root, ancestors, out)?;
            path_from_root.pop();
        }
        let Some(view_node) = e.data.as_ref() else {
            return Ok(());
        };
        let Some(BlindedOrNot::Unblinded(view_bytes)) = view_node.blinded_or_not.as_ref() else {
            return Ok(());
        };
        let (vdata, _) = unversioned(view_bytes)
            .ok_or_else(|| ReceiveError::Malformed("an unversioned view".into()))?;
        let view = ViewNode::decode(vdata.as_slice())
            .map_err(|e| ReceiveError::Malformed(e.to_string()))?;
        let mut position = vec![path_from_root.iter().rev().copied().collect::<Vec<bool>>()];
        position.extend_from_slice(ancestors);
        if let Some(BlindableNode {
            blinded_or_not: Some(BlindedOrNot::Unblinded(vcd)),
        }) = &view.view_common_data
        {
            let (vcd_data, _) =
                unversioned(vcd).ok_or_else(|| ReceiveError::Malformed("common data".into()))?;
            out.push((
                position.clone(),
                ViewCommonData::decode(vcd_data.as_slice())
                    .map_err(|e| ReceiveError::Malformed(e.to_string()))?,
            ));
        }
        walk_seq(view.subviews.as_ref(), &position, out)
    }
    let mut out = Vec::new();
    walk_seq(tree.root_views.as_ref(), &[], &mut out)?;
    Ok(out)
}

/// The revealed views among the root views only (kept for the callers that have just a root view).
pub fn revealed_root_views(tree: &GenTransactionTree) -> Result<Vec<RevealedView>, ReceiveError> {
    Ok(revealed_views(tree)?
        .into_iter()
        .filter(|v| v.position.len() == 1)
        .collect())
}

/// The checks that need no engine, on a decrypted message and the root hash the same event announced.
///
/// Returns the revealed views of the (single) light view tree on success.
pub fn check_views(
    views: &DecryptedViews,
    announced_root_hash: &[u8],
    verify_signature: impl Fn(&Signature, &[u8]) -> bool,
) -> Result<Vec<RevealedView>, ReceiveError> {
    let mut revealed = Vec::new();
    for light in &views.view_trees {
        let tree = light
            .tree
            .as_ref()
            .ok_or_else(|| ReceiveError::Malformed("a light view tree without a tree".into()))?;
        let root = recompute_root_hash(tree)?;
        if root != announced_root_hash {
            return Err(ReceiveError::HashMismatch(
                "the tree's root hash is not the one the root hash message announced".into(),
            ));
        }
        let mut top_level = false;
        for view in revealed_views(tree)? {
            if !views.view_hashes.contains(&view.view_hash) {
                return Err(ReceiveError::HashMismatch(
                    "a revealed view is not among the view hashes of the message".into(),
                ));
            }
            top_level |= view.position.len() == 1;
            revealed.push(view);
        }
        // [CANTON-NOTE: SEMANTICS] The submitting participant signs only the message of a **top-level** view (the factory sets the
        // signature `viewTree.toBeSigned`, which only a root view has). A subview's message carries none: what ties it to the request
        // is that its tree has the root hash the (sequenced, sender-authenticated) root hash message announced. A signature that is
        // present is verified all the same.
        match (&views.submitting_participant_signature, top_level) {
            (Some(sig), _) if !verify_signature(sig, &root) => {
                return Err(ReceiveError::BadSignature)
            }
            (None, true) => return Err(ReceiveError::BadSignature),
            _ => {}
        }
    }
    if revealed.is_empty() {
        return Err(ReceiveError::Malformed("no revealed view".into()));
    }
    Ok(revealed)
}

/// The submitter metadata the tree reveals (who submitted: the acting parties and the **submitting participant**, whose admin party
/// confirms every root view it submits).
pub fn revealed_submitter_metadata(
    tree: &GenTransactionTree,
) -> Result<SubmitterMetadata, ReceiveError> {
    let Some(BlindableNode {
        blinded_or_not: Some(BlindedOrNot::Unblinded(bytes)),
    }) = tree.submitter_metadata.as_ref()
    else {
        return Err(ReceiveError::Malformed("blinded submitter metadata".into()));
    };
    let (data, _) = unversioned(bytes)
        .ok_or_else(|| ReceiveError::Malformed("unversioned submitter metadata".into()))?;
    SubmitterMetadata::decode(data.as_slice()).map_err(|e| ReceiveError::Malformed(e.to_string()))
}

/// The participant metadata the tree reveals (the ledger time and the **preparation time**, which the contract discriminators of
/// the transaction are derived with). It is blinded in the informee tree and revealed to the participants that get the view.
pub fn revealed_participant_metadata(
    tree: &GenTransactionTree,
) -> Result<ParticipantMetadata, ReceiveError> {
    let Some(BlindableNode {
        blinded_or_not: Some(BlindedOrNot::Unblinded(bytes)),
    }) = tree.participant_metadata.as_ref()
    else {
        return Err(ReceiveError::Malformed(
            "blinded participant metadata".into(),
        ));
    };
    let (data, _) = unversioned(bytes)
        .ok_or_else(|| ReceiveError::Malformed("unversioned participant metadata".into()))?;
    ParticipantMetadata::decode(data.as_slice()).map_err(|e| ReceiveError::Malformed(e.to_string()))
}

/// The common metadata the tree reveals (the uuid, synchronizer and mediator group of the request).
pub fn revealed_common_metadata(tree: &GenTransactionTree) -> Result<CommonMetadata, ReceiveError> {
    let Some(BlindableNode {
        blinded_or_not: Some(BlindedOrNot::Unblinded(bytes)),
    }) = tree.common_metadata.as_ref()
    else {
        return Err(ReceiveError::Malformed("blinded common metadata".into()));
    };
    let (data, _) = unversioned(bytes)
        .ok_or_else(|| ReceiveError::Malformed("unversioned common metadata".into()))?;
    CommonMetadata::decode(data.as_slice()).map_err(|e| ReceiveError::Malformed(e.to_string()))
}
