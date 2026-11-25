//! P-13: what this node applied, and the fates of its awaited submissions, stay kept until whoever shows them (the JSON API) recorded them.
//!
//! [CANTON-NOTE: WHY] The node applies an approval, and decides a fate, before the API records them; a crash in between lost the update or
//! the completion. Held ([`SharedNode::hold_until_shown`]), they are handed over again after a restart until marked shown: an approval of
//! another participant as a [`RemoteTransaction`] ([`SharedNode::take_unshown`]), a fate of this node's own submission as a late fate with
//! its transaction.
use super::{RemoteTransaction, SharedNode};
use std::cell::RefCell;
use std::collections::BTreeSet;

/// The awaited submissions this thread got the fate of and whose recording is still to be confirmed: the node (by address), the caller's
/// `command_id` (used to scope confirmations so a succeeding command never sweeps an unrecorded peer), the `message_id`, and the request
/// id when it was sequenced.
type Awaited = (usize, String, String, Option<i64>);

/// How many awaited fates a thread keeps unconfirmed (a caller that never confirms does not grow it without bound).
const MAX_AWAITED: usize = 1024;

thread_local! {
    static AWAITED: RefCell<Vec<Awaited>> = const { RefCell::new(Vec::new()) };
    static LAST_APPROVED_ROOT_HASH: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
    static LAST_REMAPPED_CIDS: RefCell<std::collections::BTreeMap<String, String>> =
        const { RefCell::new(std::collections::BTreeMap::new()) };
}

impl SharedNode {
    fn key(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    /// Keeps the applied transactions and the awaited fates until they are marked shown (see the module documentation).
    pub fn hold_until_shown(&self) -> Result<(), String> {
        self.with(|n| {
            n.runtime.keep_applied_until_shown();
            n.runtime.in_flight.keep_awaited_until_taken();
        })
    }

    fn ensure_awaited_capacity(message_id: &str) -> Result<(), String> {
        AWAITED.with(|a| {
            if a.borrow().len() >= MAX_AWAITED {
                let err = format!(
                    "thread awaited fate queue overflow (limit {MAX_AWAITED}) while queueing {message_id}"
                );
                crate::diag::diag_eprintln!("{err}");
                return Err(err);
            }
            Ok(())
        })
    }

    /// Records one awaited fate on this thread, returning an error (instead of silently evicting old entries) if
    /// `MAX_AWAITED` unconfirmed entries are already queued.
    fn push_awaited(
        key: usize,
        command_id: &str,
        message_id: &str,
        request: Option<i64>,
    ) -> Result<(), String> {
        AWAITED.with(|a| {
            let mut a = a.borrow_mut();
            if a.len() >= MAX_AWAITED {
                let err = format!(
                    "thread awaited fate queue overflow (limit {MAX_AWAITED}) while queueing {message_id}"
                );
                crate::diag::diag_eprintln!("{err}");
                return Err(err);
            }
            a.push((key, command_id.to_string(), message_id.to_string(), request));
            Ok(())
        })
    }

    /// The caller of this thread got the fate of `message_id` for `command_id`: it is marked shown when the caller says it recorded it
    /// ([`SharedNode::awaited_recorded_for`]). Capacity is checked BEFORE popping `board.requests` so overflow never drops request linkage.
    pub(super) fn note_awaited(&self, command_id: &str, message_id: &str) -> Result<(), String> {
        Self::ensure_awaited_capacity(message_id)?;
        let request = self.board.take_request(message_id);
        let key = self.key();
        Self::push_awaited(key, command_id, message_id, request)
    }

    /// Whoever waited on this thread recorded the fates it got for `command_id` (or all for this node when `command_id` is empty): they
    /// are not handed over again, while any unrecorded peer command on this thread stays queued.
    pub fn awaited_recorded_for(&self, command_id: &str) -> Result<(), String> {
        let key = self.key();
        let mine: Vec<Awaited> = AWAITED.with(|a| {
            let mut a = a.borrow_mut();
            let (mine, others) = std::mem::take(&mut *a)
                .into_iter()
                .partition(|(k, cmd, _, _)| {
                    *k == key && (command_id.is_empty() || cmd == command_id)
                });
            *a = others;
            mine
        });
        if mine.is_empty() {
            return Ok(());
        }
        self.with(|n| {
            for (_, _, message_id, request) in &mine {
                n.fate_handed_over(message_id)?;
                if let Some(request) = request {
                    n.runtime.applied_shown(*request)?;
                }
            }
            Ok(())
        })?
    }

    /// Whoever waited on this thread recorded all fates it got for this node (legacy unscoped helper; prefer [`SharedNode::awaited_recorded_for`]).
    pub fn awaited_recorded(&self) -> Result<(), String> {
        self.awaited_recorded_for("")
    }

    /// The approvals applied and not shown before a restart, as transactions of others, except those a late fate hands over with its
    /// transaction. Each is marked shown with [`SharedNode::applied_shown`] once recorded.
    pub fn take_unshown(&self) -> Result<Vec<RemoteTransaction>, String> {
        self.with(|n| {
            let late: BTreeSet<i64> = n.late.iter().filter_map(|f| f.settled.request_id).collect();
            let unshown: Vec<_> = n
                .runtime
                .unshown_applied()
                .into_iter()
                .filter(|a| !late.contains(&a.request_id))
                .collect();
            unshown.into_iter().map(|a| n.show(a)).collect()
        })
    }

    /// The transaction of `request_id` was recorded by whoever shows it.
    pub fn applied_shown(&self, request_id: i64) -> Result<(), String> {
        self.with(|n| n.runtime.applied_shown(request_id))?
    }

    pub(super) fn clear_approved_root_hash() {
        LAST_APPROVED_ROOT_HASH.with(|h| *h.borrow_mut() = None);
    }

    pub(super) fn note_approved_root_hash(hash: Vec<u8>) {
        LAST_APPROVED_ROOT_HASH.with(|h| *h.borrow_mut() = Some(hash));
    }

    /// Takes the transaction tree root hash (`1220...` multihash) approved for this thread's last submission.
    pub fn take_last_approved_root_hash() -> Option<Vec<u8>> {
        LAST_APPROVED_ROOT_HASH.with(|h| h.borrow_mut().take())
    }

    pub(super) fn clear_remapped_cids() {
        LAST_REMAPPED_CIDS.with(|m| m.borrow_mut().clear());
    }

    pub(super) fn note_remapped_cids(map: std::collections::BTreeMap<String, String>) {
        LAST_REMAPPED_CIDS.with(|m| *m.borrow_mut() = map);
    }

    /// Takes temporary->derived contract ID remappings emitted when a subview changed final ContractIds (`S-DX-005`).
    pub fn take_last_remapped_cids() -> std::collections::BTreeMap<String, String> {
        LAST_REMAPPED_CIDS.with(|m| std::mem::take(&mut *m.borrow_mut()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r13a_awaited_cap_overflow_returns_err_and_keeps_existing() {
        AWAITED.with(|a| a.borrow_mut().clear());
        for i in 0..MAX_AWAITED {
            assert!(
                SharedNode::push_awaited(
                    42,
                    &format!("cmd-{i}"),
                    &format!("msg-{i}"),
                    Some(i as i64)
                )
                .is_ok(),
                "push {i} within MAX_AWAITED must succeed"
            );
        }
        let err = SharedNode::push_awaited(42, "cmd-overflow", "msg-overflow", Some(9999))
            .expect_err("pushing past MAX_AWAITED must return Err instead of silent eviction");
        assert!(err.contains("overflow"), "{err}");
        AWAITED.with(|a| {
            let a = a.borrow();
            assert_eq!(a.len(), MAX_AWAITED);
            assert_eq!(a[0].2, "msg-0");
            assert_eq!(a[MAX_AWAITED - 1].2, format!("msg-{}", MAX_AWAITED - 1));
        });
        AWAITED.with(|a| a.borrow_mut().clear());
    }

    #[test]
    fn r13a_awaited_recorded_scopes_by_command_id_and_preserves_unrecorded_peer() {
        AWAITED.with(|a| a.borrow_mut().clear());
        SharedNode::push_awaited(77, "cmd-fail", "msg-fail", Some(100)).unwrap();
        SharedNode::push_awaited(77, "cmd-ok", "msg-ok", Some(101)).unwrap();
        let taken: Vec<Awaited> = AWAITED.with(|a| {
            let mut a = a.borrow_mut();
            let (mine, others) = std::mem::take(&mut *a)
                .into_iter()
                .partition(|(k, cmd, _, _)| *k == 77 && cmd == "cmd-ok");
            *a = others;
            mine
        });
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].2, "msg-ok");
        AWAITED.with(|a| {
            let rem = a.borrow();
            assert_eq!(rem.len(), 1);
            assert_eq!(rem[0].1, "cmd-fail");
            assert_eq!(rem[0].2, "msg-fail");
            assert_eq!(rem[0].3, Some(100));
        });
        AWAITED.with(|a| a.borrow_mut().clear());
    }
}
