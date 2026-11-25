use super::errors::refuse;
use super::{ExerciseRecord, NodeCommitter, MAX_PROMISES};
use crate::service::ApiError;
use canton_participant::submit::{ExercisePlan, Os};
use lf_eval::engine::NewContract;
use lf_eval::{EngineEvent, Value};

impl NodeCommitter {
    /// The id of a contract created inside a choice: derived from the seed of the exercise it is a child of, so the exercise's plan is drawn
    /// when its first contract is allocated and kept until the transaction is committed.
    pub(super) fn allocate_created_by_exercise(
        &self,
        new: &NewContract<'_>,
        session: &mut Option<u64>,
    ) -> Option<String> {
        let key = *session.get_or_insert_with(|| {
            self.sessions
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        });
        let known = self
            .exercises
            .lock()
            .ok()?
            .get(&key)
            .map(|r| r.plan.clone());
        let plan = match known {
            Some(plan) => plan,
            None => {
                let now = self.node.with(|n| n.current_time()).ok()?.ok()?;
                ExercisePlan::draw(&mut Os, now)
            }
        };
        let path: Vec<i32> = new.path.iter().map(|i| *i as i32).collect();
        let qualified = if new.package_id.len() == 64 {
            format!("{}:{}", new.package_id, new.template_id)
        } else {
            new.template_id.to_string()
        };
        let id = self
            .node
            .promise_created_at(
                &self.package_name,
                &plan,
                new.creation_index,
                &path,
                &qualified,
                new.payload,
            )
            .ok()?;
        let mut exercises = self.exercises.lock().ok()?;
        if exercises.len() >= MAX_PROMISES {
            exercises.pop_first();
        }
        exercises
            .entry(key)
            .or_insert_with(|| ExerciseRecord {
                plan,
                ids: Vec::new(),
            })
            .ids
            .push((new.creation_index, id.clone()));
        let mut session_of = self.session_of.lock().ok()?;
        if session_of.len() >= MAX_PROMISES {
            session_of.pop_first();
        }
        session_of.insert(id.clone(), key);
        Some(id)
    }
}

/// A node below the root exercise, as the engine's journal gives it, with what the commit needs to build the view tree.
pub(super) enum Below {
    Exercise {
        contract_id: String,
        choice: String,
        argument: Option<Value>,
        consuming: bool,
        actors: Vec<String>,
        /// The choice's own observers.
        observers: Vec<String>,
        interface_id: Option<String>,
        by_key: bool,
    },
    Fetch {
        contract_id: String,
        actors: Vec<String>,
        by_key: bool,
    },
    Lookup {
        template: String,
        key: Value,
        /// Every contract the query found, in the order the engine found them (`lookupByKey` finds at most one,
        /// `lookupNByKey n` at most `n`).
        contract_ids: Vec<String>,
    },
    /// The `i`-th contract the transaction created.
    Create(usize),
    /// A caught exception: the nodes of the `try` body that follow it, one level deeper, are its children (S-SPL-028).
    Rollback,
}

/// The nodes below the root exercise of `contract_id` in the order the engine ran them, with their depth.
///
/// [CANTON-NOTE: SEMANTICS] A nested exercise's actors are the choice's controllers. A fetch's acting parties are the parties authorizing the
/// code that fetched (the signatories and controllers of the enclosing exercise): the node's confirming parties in Canton are its contract's
/// signatories and its acting parties (`TransactionViewDecompositionFactory.informeesParticipantsAndThreshold`).
///
/// [CANTON-NOTE: LIMITATION] The acting parties a Canton engine records for a fetch node were checked against the official participant on one
/// case only (`Tree.Driver.Run`, where they coincide with the controllers of the enclosing exercise and the `actAs` parties).
pub(super) fn below_root(
    events: &[EngineEvent],
    rolled_back: &[lf_eval::engine::RolledBack],
    key_lookups: &[lf_eval::engine::RecordedKeyLookup],
    contract_id: &str,
) -> Result<Vec<(usize, Below)>, ApiError> {
    match events.first() {
        Some(EngineEvent::Exercise {
            contract_id: root,
            depth: 0,
            ..
        }) if root == contract_id => {}
        _ => {
            return Err(refuse(
                "the engine's journal does not start with the root exercise",
            ))
        }
    }
    let mut created = 0;
    let mut out = Vec::new();
    // [CANTON-NOTE: SEMANTICS] A rolled-back `try` body is a `Rollback` node among the siblings at the depth of its direct nodes; what it
    // journaled is its children, one level deeper. Nested rollbacks are flattened (positions and `rolled_back` are the same). A rollback
    // holds no create: the engine refuses an effectful rollback (`EffectfulRollback`).
    let mut groups: Vec<&lf_eval::engine::RolledBack> = rolled_back.iter().collect();
    groups.sort_by_key(|g| g.at);
    let mut groups = groups.into_iter().peekable();
    let push_group = |group: &lf_eval::engine::RolledBack,
                      out: &mut Vec<(usize, Below)>|
     -> Result<(), ApiError> {
        let top = group
            .events
            .iter()
            .map(|e| match e {
                EngineEvent::Create { depth, .. }
                | EngineEvent::Exercise { depth, .. }
                | EngineEvent::Fetch { depth, .. } => *depth,
            })
            .min()
            .ok_or_else(|| refuse("an empty rollback"))?;
        out.push((top, Below::Rollback));
        for event in &group.events {
            out.push(match event {
                EngineEvent::Create { .. } => {
                    return Err(refuse(
                        "a create inside a rolled-back `try` is not supported",
                    ))
                }
                EngineEvent::Exercise {
                    contract_id,
                    choice,
                    consuming,
                    actors,
                    observers,
                    depth,
                    argument,
                    interface_id,
                    ..
                } => (
                    *depth + 1,
                    Below::Exercise {
                        contract_id: contract_id.clone(),
                        choice: choice.clone(),
                        argument: Some(argument.clone()),
                        consuming: *consuming,
                        actors: actors.clone(),
                        observers: observers.clone(),
                        interface_id: interface_id.clone(),
                        by_key: false,
                    },
                ),
                EngineEvent::Fetch {
                    contract_id,
                    depth,
                    authorizers,
                    ..
                } => (
                    *depth + 1,
                    Below::Fetch {
                        contract_id: contract_id.clone(),
                        actors: authorizers.clone(),
                        by_key: false,
                    },
                ),
            });
        }
        Ok(())
    };
    let push_lookup_at = |pos: usize, out: &mut Vec<(usize, Below)>| {
        for lk in key_lookups
            .iter()
            .filter(|lk| lk.is_query && lk.event_pos == pos)
        {
            out.push((
                lk.depth,
                Below::Lookup {
                    template: format!("{}:{}", lk.package_id, lk.lookup.template_id),
                    key: lk.lookup.key.clone(),
                    contract_ids: lk.lookup.contract_ids.clone(),
                },
            ));
        }
    };
    push_lookup_at(0, &mut out);
    for (i, event) in events.iter().enumerate().skip(1) {
        // `at` is relative to `events` and counts the root exercise at index 0
        while let Some(group) = groups.next_if(|g| g.at <= i) {
            push_group(group, &mut out)?;
        }
        push_lookup_at(i, &mut out);
        let is_by_key = key_lookups
            .iter()
            .any(|lk| !lk.is_query && lk.event_pos == i);
        out.push(match event {
            EngineEvent::Create { depth, .. } => {
                created += 1;
                (*depth, Below::Create(created - 1))
            }
            EngineEvent::Exercise {
                contract_id,
                choice,
                consuming,
                actors,
                observers,
                depth,
                argument,
                interface_id,
                ..
            } => (
                *depth,
                Below::Exercise {
                    contract_id: contract_id.clone(),
                    choice: choice.clone(),
                    argument: Some(argument.clone()),
                    consuming: *consuming,
                    actors: actors.clone(),
                    observers: observers.clone(),
                    interface_id: interface_id.clone(),
                    by_key: is_by_key,
                },
            ),
            EngineEvent::Fetch {
                contract_id,
                depth,
                authorizers,
                ..
            } => (
                *depth,
                Below::Fetch {
                    contract_id: contract_id.clone(),
                    actors: authorizers.clone(),
                    by_key: is_by_key,
                },
            ),
        });
    }
    for group in groups {
        push_group(group, &mut out)?;
    }
    for lk in key_lookups
        .iter()
        .filter(|lk| lk.is_query && lk.event_pos >= events.len())
    {
        out.push((
            lk.depth,
            Below::Lookup {
                template: format!("{}:{}", lk.package_id, lk.lookup.template_id),
                key: lk.lookup.key.clone(),
                contract_ids: lk.lookup.contract_ids.clone(),
            },
        ));
    }
    Ok(out)
}
