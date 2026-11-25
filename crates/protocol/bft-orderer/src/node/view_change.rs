//! View changes of a consensus node: segments, leaders, new views and their validation.

use std::collections::BTreeMap;

use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30 as bft;

use crate::consensus::pre_prepare_message;

use super::{ConsensusNode, Event};

impl ConsensusNode {
    pub(super) fn segment_index_of_block(&self, block: i64) -> Option<usize> {
        self.epoch
            .segments
            .iter()
            .position(|s| s.slots.contains(&block))
    }

    /// The leader of a segment in a view (`SegmentState.computeLeaderOfView`): the leader list, from the original leader on, by the view number.
    pub(super) fn leader_in_view(&self, segment: usize, view: i64) -> Option<String> {
        let leaders = &self.epoch.leaders;
        if leaders.is_empty() {
            return None;
        }
        let original = leaders
            .iter()
            .position(|l| *l == self.epoch.segments[segment].original_leader)?;
        let n = leaders.len() as i64;
        Some(leaders[((original as i64 + view.rem_euclid(n)) % n) as usize].clone())
    }

    fn weak(&self) -> usize {
        crate::topology::weak_quorum_size(self.nodes.len())
    }

    pub(super) fn segment_complete(&self, segment: usize) -> bool {
        self.epoch.segments[segment]
            .slots
            .iter()
            .all(|b| self.is_ordered(*b))
    }

    /// The consensus certificates a `ViewChange` carries: for every block of the segment the commit certificate if it was ordered, otherwise the prepare
    /// certificate of the highest view it was prepared in (`SegmentBlockState.consensusCertificate`).
    fn certificates_of_segment(&self, segment: usize) -> Vec<bft::ConsensusCertificate> {
        let mut certs = Vec::new();
        for block in &self.epoch.segments[segment].slots {
            let Some(state) = self.blocks.get(block) else {
                continue;
            };
            if let (Some(commits), Some(pp)) = (&state.ordered, &state.pre_prepare) {
                certs.push(bft::ConsensusCertificate {
                    certificate: Some(bft::consensus_certificate::Certificate::CommitCertificate(
                        bft::CommitCertificate {
                            pre_prepare: Some(pp.signed.clone()),
                            commits: commits.clone(),
                        },
                    )),
                });
            } else if let Some(prepared) = &state.prepare_cert {
                certs.push(bft::ConsensusCertificate {
                    certificate: Some(bft::consensus_certificate::Certificate::PrepareCertificate(
                        prepared.clone(),
                    )),
                });
            }
        }
        certs
    }

    fn view_change_metadata(&self, segment: usize) -> bft::BlockMetadata {
        bft::BlockMetadata {
            epoch_number: self.epoch.info.number,
            block_number: self.epoch.segments[segment].slots[0],
        }
    }

    pub(super) fn decode_consensus(signed: &bft::SignedMessage) -> Option<bft::ConsensusMessage> {
        crate::verify::decode_consensus(signed)
    }

    /// A node moves its segment to a new view (`startViewChangeAction`): it makes its own `ViewChange` and sends it (`sendViewChangeAction`).
    pub(super) fn start_view_change(
        &mut self,
        segment: usize,
        view: i64,
        now_ms: u64,
        out: &mut Vec<bft::SignedMessage>,
    ) {
        if self.segments[segment].view >= view {
            return;
        }
        self.events.push(Event::ViewChangeStarted {
            epoch: self.epoch.info.number,
            first_block: self.epoch.segments[segment].slots[0],
            view,
            leader: self.leader_in_view(segment, view).unwrap_or_default(),
        });
        let certs = self.certificates_of_segment(segment);
        let seg = &mut self.segments[segment];
        seg.view = view;
        seg.in_view_change = true;
        seg.strong_quorum_seen = false;
        seg.timer_deadline_ms = None;
        let already = seg
            .view_changes
            .get(&view)
            .is_some_and(|v| v.new_view.is_some() || v.view_changes.contains_key(&self.me));
        if !already {
            let message = bft::ConsensusMessage {
                block_metadata: Some(self.view_change_metadata(segment)),
                view_number: view,
                from: self.me.clone(),
                message: Some(bft::consensus_message::Message::ViewChange(
                    bft::ViewChange {
                        consensus_certs: certs,
                    },
                )),
            };
            let signed = self.sign(&message);
            self.segments[segment]
                .view_changes
                .entry(view)
                .or_default()
                .view_changes
                .insert(self.me.clone(), signed.clone());
            out.push(signed);
        }
        self.advance_view_change(segment, view, now_ms, out);
    }

    /// What the state of a view change allows, once each (`SegmentState.advanceViewChange`): start it on a weak quorum of view changes, start the nested timer on a
    /// strong quorum, make the `NewView` when this node leads the view, and finish with a `NewView`.
    fn advance_view_change(
        &mut self,
        segment: usize,
        view: i64,
        now_ms: u64,
        out: &mut Vec<bft::SignedMessage>,
    ) {
        let weak = self.weak();
        let strong = self.strong();
        let (count, has_new_view) = match self.segments[segment].view_changes.get(&view) {
            Some(v) => (v.view_changes.len(), v.new_view.is_some()),
            None => return,
        };
        if self.segments[segment].view < view && (count >= weak || has_new_view) {
            self.start_view_change(segment, view, now_ms, out);
            return;
        }
        if self.segments[segment].view != view || !self.segments[segment].in_view_change {
            return;
        }
        if count >= strong && !self.segments[segment].strong_quorum_seen {
            self.segments[segment].strong_quorum_seen = true;
            // the nested timer: a view change that has its quorum must finish in time, or the next view is tried
            self.segments[segment].timer_deadline_ms = Some(now_ms + self.timeout_for_view(view));
        }
        let leads = self.leader_in_view(segment, view).as_deref() == Some(self.me.as_str());
        let made = self.segments[segment]
            .view_changes
            .get(&view)
            .is_some_and(|v| v.new_view_made);
        if leads && count >= strong && !has_new_view && !made {
            if let Some(signed) = self.make_new_view(segment, view) {
                let state = self.segments[segment].view_changes.entry(view).or_default();
                state.new_view_made = true;
                state.new_view = Some(signed.clone());
                out.push(signed);
            }
        }
        let new_view = self.segments[segment]
            .view_changes
            .get(&view)
            .and_then(|v| v.new_view.clone());
        if let Some(new_view) = new_view {
            self.complete_view_change(segment, view, &new_view, now_ms, out);
        }
    }

    /// `ViewChange.consensusCerts` of a strong quorum, one per block: the commit certificate of the highest view if any, otherwise the prepare certificate of the
    /// highest view (`NewView.computeCertificatePerBlock`).
    fn certificate_per_block(
        view_changes: &[bft::ViewChange],
    ) -> BTreeMap<i64, bft::ConsensusCertificate> {
        let mut best: BTreeMap<i64, (bool, i64, bft::ConsensusCertificate)> = BTreeMap::new();
        for vc in view_changes {
            for cert in &vc.consensus_certs {
                let (is_commit, pre_prepare) = match &cert.certificate {
                    Some(bft::consensus_certificate::Certificate::CommitCertificate(c)) => {
                        (true, c.pre_prepare.as_ref())
                    }
                    Some(bft::consensus_certificate::Certificate::PrepareCertificate(c)) => {
                        (false, c.pre_prepare.as_ref())
                    }
                    None => continue,
                };
                let Some(pp) = pre_prepare.and_then(Self::decode_consensus) else {
                    continue;
                };
                let block = pp.block_metadata.map(|m| m.block_number).unwrap_or(-1);
                let rank = (is_commit, pp.view_number);
                let better = match best.get(&block) {
                    None => true,
                    Some((c, v, _)) => rank > (*c, *v),
                };
                if better {
                    best.insert(block, (is_commit, pp.view_number, cert.clone()));
                }
            }
        }
        best.into_iter().map(|(b, (_, _, c))| (b, c)).collect()
    }

    fn pre_prepare_of(cert: &bft::ConsensusCertificate) -> Option<bft::SignedMessage> {
        match &cert.certificate {
            Some(bft::consensus_certificate::Certificate::CommitCertificate(c)) => {
                c.pre_prepare.clone()
            }
            Some(bft::consensus_certificate::Certificate::PrepareCertificate(c)) => {
                c.pre_prepare.clone()
            }
            None => None,
        }
    }

    /// The `NewView` of the leader of a view (`constructPrePreparesForNewView`, `createNewViewMessage`): the view changes of a strong quorum (by sender), and a
    /// pre-prepare for every block of the segment: the certified one where the quorum has a certificate, otherwise an empty block of the new view.
    fn make_new_view(&mut self, segment: usize, view: i64) -> Option<bft::SignedMessage> {
        let strong = self.strong();
        let set: Vec<bft::SignedMessage> = self.segments[segment]
            .view_changes
            .get(&view)?
            .view_changes
            .values()
            .take(strong)
            .cloned()
            .collect();
        let decoded: Vec<bft::ViewChange> = set
            .iter()
            .filter_map(|m| match Self::decode_consensus(m)?.message {
                Some(bft::consensus_message::Message::ViewChange(v)) => Some(v),
                _ => None,
            })
            .collect();
        let certs = Self::certificate_per_block(&decoded);
        let epoch = self.epoch.info.number;
        let slots = self.epoch.segments[segment].slots.clone();
        let mut pre_prepares = Vec::new();
        for block in slots {
            match certs.get(&block).and_then(Self::pre_prepare_of) {
                Some(signed) => pre_prepares.push(signed),
                None => {
                    let message = pre_prepare_message(
                        epoch,
                        block,
                        view,
                        &self.me,
                        bft::OrderingBlock { proofs: vec![] },
                        bft::CanonicalCommitSet {
                            canonical_commits: vec![],
                        },
                    );
                    pre_prepares.push(self.sign(&message));
                }
            }
        }
        let message = bft::ConsensusMessage {
            block_metadata: Some(self.view_change_metadata(segment)),
            view_number: view,
            from: self.me.clone(),
            message: Some(bft::consensus_message::Message::NewView(bft::NewView {
                view_changes: set,
                pre_prepares,
            })),
        };
        Some(self.sign(&message))
    }

    /// A `ViewChange` or `NewView` of another node (its signature checked by the caller).
    pub(super) fn on_view_change_message(
        &mut self,
        signed: bft::SignedMessage,
        message: bft::ConsensusMessage,
        now_ms: u64,
        _now_micros: i64,
        out: &mut Vec<bft::SignedMessage>,
    ) {
        let Some(meta) = message.block_metadata else {
            return;
        };
        let Some(segment) = self
            .epoch
            .segments
            .iter()
            .position(|s| s.slots.first() == Some(&meta.block_number))
        else {
            return;
        };
        let view = message.view_number;
        if view < self.segments[segment].view
            || (view == self.segments[segment].view && !self.segments[segment].in_view_change)
        {
            return;
        }
        match message.message {
            Some(bft::consensus_message::Message::ViewChange(_)) => {
                self.segments[segment]
                    .view_changes
                    .entry(view)
                    .or_default()
                    .view_changes
                    .entry(message.from)
                    .or_insert(signed);
            }
            Some(bft::consensus_message::Message::NewView(_)) => {
                if self.leader_in_view(segment, view).as_deref() != Some(message.from.as_str()) {
                    self.events.push(Event::Dropped(format!(
                        "a new view of {} for view {view}, which it does not lead",
                        message.from
                    )));
                    return;
                }
                if let Err(why) = self.validate_new_view(segment, view, &message) {
                    self.events.push(Event::Dropped(format!(
                        "a new view that does not hold: {why}"
                    )));
                    return;
                }
                self.segments[segment]
                    .view_changes
                    .entry(view)
                    .or_default()
                    .new_view
                    .get_or_insert(signed);
            }
            _ => return,
        }
        self.advance_view_change(segment, view, now_ms, out);
    }

    /// `ViewChangeMessageValidator.validateNewViewMessage`: the view changes are of this segment and view, from distinct nodes and enough of them, and the
    /// pre-prepares are exactly what the view changes call for. Signatures of what a `NewView` embeds are checked when the node has the keys.
    fn validate_new_view(
        &self,
        segment: usize,
        view: i64,
        message: &bft::ConsensusMessage,
    ) -> Result<(), String> {
        let Some(bft::consensus_message::Message::NewView(nv)) = &message.message else {
            return Err("not a new view".into());
        };
        let slots = &self.epoch.segments[segment].slots;
        let first = slots[0];
        let epoch = self.epoch.info.number;
        let mut senders = std::collections::BTreeSet::new();
        let mut decoded = Vec::new();
        for m in &nv.view_changes {
            self.verify_embedded(m)?;
            let Some(vc) = Self::decode_consensus(m) else {
                return Err("an undecodable view change".into());
            };
            let meta = vc.block_metadata.unwrap_or_default();
            if meta.epoch_number != epoch || meta.block_number != first || vc.view_number != view {
                return Err("a view change of another epoch, segment or view".into());
            }
            if !senders.insert(vc.from.clone()) || !self.nodes.contains(&vc.from) {
                return Err("a view change from a repeated or unknown sender".into());
            }
            if let Some(bft::consensus_message::Message::ViewChange(v)) = vc.message {
                decoded.push(v);
            }
        }
        if senders.len() < self.strong() {
            return Err(format!(
                "{} view changes, a strong quorum is {}",
                senders.len(),
                self.strong()
            ));
        }
        for vc in &decoded {
            for cert in &vc.consensus_certs {
                self.verify_certificate(cert, view)?;
            }
        }
        let certs = Self::certificate_per_block(&decoded);
        if nv.pre_prepares.len() != slots.len() {
            return Err("not a pre-prepare for every block of the segment".into());
        }
        for (block, signed) in slots.iter().zip(&nv.pre_prepares) {
            let Some(pp) = Self::decode_consensus(signed) else {
                return Err("an undecodable pre-prepare".into());
            };
            if pp.block_metadata.as_ref().map(|m| m.block_number) != Some(*block) {
                return Err("pre-prepares out of order".into());
            }
            match certs.get(block).and_then(Self::pre_prepare_of) {
                Some(expected) => {
                    if expected.message != signed.message {
                        return Err(format!(
                            "the pre-prepare for block {block} is not the certified one"
                        ));
                    }
                }
                None => {
                    let empty = matches!(&pp.message, Some(bft::consensus_message::Message::PrePrepare(p))
                        if p.block.as_ref().is_some_and(|b| b.proofs.is_empty())
                            && p.bft_time_canonical_commit_set.as_ref().is_some_and(|c| c.canonical_commits.is_empty()));
                    if pp.view_number != view || pp.from != message.from || !empty {
                        return Err(format!("the pre-prepare for block {block} should be an empty block of view {view}"));
                    }
                }
            }
        }
        Ok(())
    }

    fn verify_embedded(&self, signed: &bft::SignedMessage) -> Result<(), String> {
        crate::verify::verify_embedded(&self.keys, signed)
    }

    /// [`crate::verify::verify_certificate`] against this epoch's topology, for a view change to `current_view`.
    pub(super) fn verify_certificate(
        &self,
        cert: &bft::ConsensusCertificate,
        current_view: i64,
    ) -> Result<(), String> {
        crate::verify::verify_certificate(
            cert,
            &crate::verify::Membership::of(&self.nodes),
            &self.keys,
            Some(current_view),
        )
    }

    /// The view change finished with a `NewView` (`SegmentState.completeViewChange`): blocks the new view's certificates have completed are ordered, the others
    /// start over in the new view with the pre-prepare the new view carries.
    fn complete_view_change(
        &mut self,
        segment: usize,
        view: i64,
        new_view: &bft::SignedMessage,
        now_ms: u64,
        out: &mut Vec<bft::SignedMessage>,
    ) {
        let Some(message) = Self::decode_consensus(new_view) else {
            return;
        };
        let Some(bft::consensus_message::Message::NewView(nv)) = message.message else {
            return;
        };
        let decoded: Vec<bft::ViewChange> = nv
            .view_changes
            .iter()
            .filter_map(|m| match Self::decode_consensus(m)?.message {
                Some(bft::consensus_message::Message::ViewChange(v)) => Some(v),
                _ => None,
            })
            .collect();
        let certs = Self::certificate_per_block(&decoded);
        let slots = self.epoch.segments[segment].slots.clone();
        // a block that is complete stays; the others begin the new view
        for block in &slots {
            if self.is_ordered(*block) {
                continue;
            }
            if let Some(bft::consensus_certificate::Certificate::CommitCertificate(c)) =
                certs.get(block).and_then(|c| c.certificate.clone())
            {
                self.order_with_commit_certificate(*block, c, now_ms, 0, out);
                continue;
            }
            let state = self.blocks.entry(*block).or_default();
            state.view = view;
            state.pre_prepare = None;
            state.prepares.clear();
            state.commits.clear();
            state.commit_sent = false;
        }
        let timeout = self.timeout_for_view(view);
        let seg = &mut self.segments[segment];
        seg.in_view_change = false;
        seg.strong_quorum_seen = false;
        seg.timer_deadline_ms = Some(now_ms + timeout);
        self.events.push(Event::ViewChangeCompleted {
            epoch: self.epoch.info.number,
            first_block: slots[0],
            view,
        });
        // the proposals the new view carries, as pre-prepares of the blocks that are not complete
        for (block, signed) in slots.iter().zip(&nv.pre_prepares) {
            if self.is_ordered(*block) {
                continue;
            }
            if let Some(bft::consensus_message::Message::PrePrepare(pp)) =
                Self::decode_consensus(signed).and_then(|c| c.message)
            {
                self.take_pre_prepare(*block, signed.clone(), pp);
            }
        }
        for block in &slots {
            self.advance(*block, now_ms, now_ms as i64 * 1000, out);
        }
        // the votes of this view that came while it was being installed
        let queued = self.segments[segment].future.drain();
        for message in queued {
            self.accept(message, now_ms, now_ms as i64 * 1000, out);
        }
    }
}
