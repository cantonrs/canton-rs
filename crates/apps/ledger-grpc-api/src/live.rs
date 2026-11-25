//! The live part of server-streaming calls: `CommandCompletionService/CompletionStream` tails the ledger with `OffsetCheckpoint`s,
//! and every open stream re-checks its token and its user's rights (`ledger_json_api::auth_stream`).
//!
//! [CANTON-NOTE: SEMANTICS] `IndexServiceImpl.getCompletions` never ends a completion stream (`endInclusive = None`) and runs it
//! through `checkpointFlow`: about 500 ms after the stream started and then whenever it idles, it sends the participant's cached
//! checkpoint when the stream stands exactly at that checkpoint's offset and has not sent it yet (`injectCheckpoints`, the `Timeout`
//! case). The cache holds the ledger end as of its last refresh, every `offsetCheckpointCacheUpdateInterval` (15 s by default).
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use ledger_json_api::auth_stream::StreamAuthorization;
use prost_reflect::{DynamicMessage, MethodDescriptor, Value as Field};
use tokio::sync::mpsc::Sender;
use tonic::Status;

use crate::server::{invoke_blocking, response_messages, status_of, State};

const POLL: Duration = Duration::from_millis(50);
const FIRST_CHECKPOINT: Duration = Duration::from_millis(500);
const CHECKPOINT_CACHE_REFRESH: Duration = Duration::from_secs(15);

/// The participant's `OffsetCheckpointCache`: the ledger end as of its last refresh.
pub(crate) struct CheckpointCache(Mutex<(i64, Instant)>);

impl CheckpointCache {
    pub(crate) fn new(ledger_end: u64) -> Self {
        Self(Mutex::new((
            i64::try_from(ledger_end).unwrap_or(i64::MAX),
            Instant::now(),
        )))
    }

    /// The cached offset, refreshed from `ledger_end` when the refresh interval has passed.
    fn offset(&self, ledger_end: i64) -> i64 {
        let mut cached = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if cached.1.elapsed() >= CHECKPOINT_CACHE_REFRESH {
            *cached = (ledger_end, Instant::now());
        }
        cached.0
    }
}

/// Sends `item` after the per-element check; `false` when the stream is over (the client left, or the check ended it).
pub(crate) async fn send_checked(
    tx: &Sender<Result<DynamicMessage, Status>>,
    auth: &StreamAuthorization,
    item: DynamicMessage,
) -> bool {
    match auth.before_element() {
        Ok(()) => tx.send(Ok(item)).await.is_ok(),
        Err(refusal) => {
            let _ = tx.send(Err(status_of(refusal.status, &refusal.body))).await;
            false
        }
    }
}

/// The status a stream ends with when a read for its next elements failed.
pub(crate) fn read_failure(
    auth: &mut StreamAuthorization,
    state: &State,
    status: Status,
) -> Status {
    match auth.refusal_of_next_read(&state.ledger) {
        Some(refusal) => status_of(refusal.status, &refusal.body),
        None => status,
    }
}

/// The periodic check of an open stream; `false` when it ended the stream.
pub(crate) async fn still_authorized(
    tx: &Sender<Result<DynamicMessage, Status>>,
    auth: &mut StreamAuthorization,
    state: &State,
) -> bool {
    match auth.periodic(&state.ledger) {
        Ok(()) => true,
        Err(refusal) => {
            let _ = tx.send(Err(status_of(refusal.status, &refusal.body))).await;
            false
        }
    }
}

fn completion_offset(item: &DynamicMessage) -> Option<i64> {
    if !item.has_field_by_name("completion") {
        return None;
    }
    let completion = item.get_field_by_name("completion")?;
    completion
        .as_message()?
        .get_field_by_name("offset")?
        .as_i64()
}

fn checkpoint_offset(item: &DynamicMessage) -> Option<i64> {
    if !item.has_field_by_name("offset_checkpoint") {
        return None;
    }
    let checkpoint = item.get_field_by_name("offset_checkpoint")?;
    checkpoint
        .as_message()?
        .get_field_by_name("offset")?
        .as_i64()
}

/// Serves `CompletionStream` after its first answer (`initial`, what the request asked for up to now) until the client leaves.
pub(crate) fn tail_completions(
    state: Arc<State>,
    method: MethodDescriptor,
    request: DynamicMessage,
    authorization: Option<String>,
    initial: Vec<DynamicMessage>,
    tx: Sender<Result<DynamicMessage, Status>>,
) {
    let mut auth = StreamAuthorization::capture(&state.ledger, authorization.as_deref());
    tokio::spawn(async move {
        let started = Instant::now();
        let mut cursor = request
            .get_field_by_name("begin_exclusive")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let mut last_checkpoint: Option<i64> = None;
        for item in initial {
            cursor = cursor.max(completion_offset(&item).unwrap_or(cursor));
            if let Some(offset) = checkpoint_offset(&item) {
                last_checkpoint = Some(offset);
            }
            if !send_checked(&tx, &auth, item).await {
                return;
            }
        }
        loop {
            tokio::select! {
                _ = tokio::time::sleep(POLL) => {}
                _ = tx.closed() => return,
            }
            if !still_authorized(&tx, &mut auth, &state).await {
                return;
            }
            let end = i64::try_from(state.ledger.v2_ledger_end()).unwrap_or(i64::MAX);
            if end > cursor {
                let mut next = request.clone();
                next.set_field_by_name("begin_exclusive", Field::I64(cursor));
                let items = match invoke_blocking(
                    Arc::clone(&state),
                    method.clone(),
                    next,
                    authorization.clone(),
                    None,
                )
                .await
                {
                    Ok(items) => items,
                    Err(status) => {
                        let _ = tx.send(Err(read_failure(&mut auth, &state, status))).await;
                        return;
                    }
                };
                for item in items {
                    // the checkpoints of this stream are this loop's to place
                    let Some(offset) = completion_offset(&item) else {
                        continue;
                    };
                    cursor = cursor.max(offset);
                    if !send_checked(&tx, &auth, item).await {
                        return;
                    }
                }
            }
            // the stream has sent every completion up to `end`: that is where it stands
            let scanned = end.max(cursor);
            if started.elapsed() < FIRST_CHECKPOINT {
                continue;
            }
            let cached = state.checkpoints.offset(end);
            if cached == scanned && cached > 0 && last_checkpoint.is_none_or(|last| cached > last) {
                let body = ledger_json_api::v2_completions::offset_checkpoint_body(
                    &state.ledger,
                    u64::try_from(cached).unwrap_or(0),
                );
                let checkpoint = match response_messages(&method, "", &body, &Default::default()) {
                    Ok(mut items) if !items.is_empty() => items.remove(0),
                    Ok(_) => continue,
                    Err(status) => {
                        let _ = tx.send(Err(status)).await;
                        return;
                    }
                };
                last_checkpoint = Some(cached);
                if !send_checked(&tx, &auth, checkpoint).await {
                    return;
                }
            }
        }
    });
}
