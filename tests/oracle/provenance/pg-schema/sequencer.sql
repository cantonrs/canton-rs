
CREATE SCHEMA debug;

CREATE TYPE public.change_type AS ENUM (
    'deactivation',
    'activation'
);

CREATE TYPE public.key_status AS ENUM (
    'unassigned',
    'assigned'
);

CREATE TYPE public.operation_type AS ENUM (
    'create',
    'add',
    'assign',
    'archive',
    'purge',
    'unassign'
);

CREATE TYPE public.pruning_phase AS ENUM (
    'started',
    'completed'
);

CREATE FUNCTION debug.canton_timestamp(bigint) RETURNS character varying
    LANGUAGE sql IMMUTABLE STRICT
    AS $_$
select to_char(to_timestamp($1/1000000.0) at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
$_$;

CREATE FUNCTION debug.checkpoint_type(integer) RETURNS character
    LANGUAGE sql IMMUTABLE STRICT
    AS $_$
select
  case
    when $1 = 1 then 'ReconciliationIntervalBoundary'
    when $1 = 2 then 'AffirmationIntervalBoundary'
    when $1 = 3 then 'MaxEventsWithoutCheckpoint'
    when $1 = 4 then 'PartyHostingChange'
    when $1 = 5 then 'Reinitialization'
    when $1 = 6 then 'ReceivedCommitmentCheckpoint'
    else $1::text
    end;
$_$;

CREATE FUNCTION debug.key_purpose(integer) RETURNS character varying
    LANGUAGE sql IMMUTABLE STRICT
    AS $_$
select
  case
    when $1 = 0 then 'Signing'
    when $1 = 1 then 'Encryption'
    else $1::text
  end;
$_$;

CREATE FUNCTION debug.key_usage(integer) RETURNS character varying
    LANGUAGE sql IMMUTABLE STRICT
    AS $_$
select
case
  when $1 = 0 then 'Namespace'
  -- 1 was IdentityDelegation
  when $1 = 2 then 'SequencerAuthentication'
  when $1 = 3 then 'Protocol'
  when $1 = 4 then 'ProofOfOwnership'
  else $1::text
end;
$_$;

CREATE FUNCTION debug.key_usages(integer[]) RETURNS character varying[]
    LANGUAGE sql STABLE STRICT
    AS $_$
select array_agg(debug.key_usage(m)) from unnest($1) as m;
$_$;

CREATE FUNCTION debug.lapi_compression(integer) RETURNS character varying
    LANGUAGE sql IMMUTABLE
    AS $_$
select
  case
    when $1 = 1 then 'GZIP'
    when $1 is null then 'None'
    else $1::text
  end;
$_$;

CREATE FUNCTION debug.lapi_event_type(smallint) RETURNS character varying
    LANGUAGE sql IMMUTABLE
    AS $_$
select
  case
    when $1 = 1 then 'Activate-Create'
    when $1 = 2 then 'Activate-Assign'
    when $1 = 3 then 'Deactivate-Consuming-Exercise'
    when $1 = 4 then 'Deactivate-Unassign'
    when $1 = 5 then 'Witnessed-Non-Consuming-Exercise'
    when $1 = 6 then 'Witnessed-Create'
    when $1 = 7 then 'Witnessed-Consuming-Exercise'
    when $1 = 8 then 'Topology-PartyToParticipant'
    when $1 = 9 then 'Topology-DynamicSynchronizerParameters'
    when $1 is null then 'None'
    else $1::text
  end;
$_$;

CREATE FUNCTION debug.lapi_rejection_status_code(integer) RETURNS character varying
    LANGUAGE sql IMMUTABLE STRICT
    AS $_$
select
  case
    when $1 = 0 then 'Ok'
    when $1 = 1 then 'Cancelled'
    when $1 = 2 then 'Unknown'
    when $1 = 3 then 'Invalid Argument'
    when $1 = 4 then 'Deadline Exceeded'
    when $1 = 5 then 'Not Found'
    when $1 = 6 then 'Already Exists'
    when $1 = 7 then 'Permission_Denied'
    when $1 = 8 then 'Resource Exhausted'
    when $1 = 9 then 'Failed Precondition'
    when $1 = 10 then 'Aborted'
    when $1 = 11 then 'Out of Range'
    when $1 = 12 then 'Unimplemented'
    when $1 = 13 then 'Internal'
    when $1 = 14 then 'Unavailable'
    when $1 = 15 then 'Data Loss'
    when $1 = 16 then 'Unauthenticated'
    else $1::text
  end;
$_$;

CREATE FUNCTION debug.lapi_user_right(integer) RETURNS character varying
    LANGUAGE sql IMMUTABLE STRICT
    AS $_$
select
  case
    when $1 = 1 then 'ParticipantAdmin'
    when $1 = 2 then 'CanActAs'
    when $1 = 3 then 'CanReadAs'
    when $1 = 4 then 'IdentityProviderAdmin'
    when $1 = 5 then 'CanReadAsAnyParty'
    else $1::text
  end;
$_$;

CREATE FUNCTION debug.resolve_common_static_string(integer) RETURNS character varying
    LANGUAGE sql STABLE STRICT
    AS $_$
select string from common_static_strings where id = $1;
$_$;

CREATE FUNCTION debug.resolve_lapi_interned_string(integer) RETURNS character varying
    LANGUAGE sql STABLE STRICT
    AS $_$
select substring(external_string, 3) from lapi_string_interning where internal_id = $1;
$_$;

CREATE FUNCTION debug.resolve_lapi_interned_strings(input bytea) RETURNS character varying[]
    LANGUAGE sql STABLE STRICT
    AS $$
select array_agg(debug.resolve_lapi_interned_string(
        get_byte(input, i)::int << 24 |
           get_byte(input, i + 1)::int << 16 |
           get_byte(input, i + 2)::int << 8 |
           get_byte(input, i + 3)::int
                 ))
from generate_series(1, length(input) - 1, 4) as s(i);
$$;

CREATE FUNCTION debug.resolve_lapi_user(integer) RETURNS character varying
    LANGUAGE sql STABLE STRICT
    AS $_$
select user_id from lapi_users where internal_id = $1;
$_$;

CREATE FUNCTION debug.resolve_sequencer_member(integer) RETURNS character varying
    LANGUAGE sql STABLE STRICT
    AS $_$
select member from sequencer_members where id = $1;
$_$;

CREATE FUNCTION debug.resolve_sequencer_members(integer[]) RETURNS character varying[]
    LANGUAGE sql STABLE STRICT
    AS $_$
select array_agg(debug.resolve_sequencer_member(m)) from unnest($1) as m;
$_$;

CREATE FUNCTION debug.to_canton_timestamp(text) RETURNS bigint
    LANGUAGE sql IMMUTABLE STRICT
    AS $_$
select (extract(epoch from $1::timestamptz) * 1000000)::bigint;
$_$;

CREATE FUNCTION debug.topology_change_op(integer) RETURNS character varying
    LANGUAGE sql IMMUTABLE STRICT
    AS $_$
select
  case
    when $1 = 1 then 'Replace'
    when $1 = 2 then 'Remove'
    else $1::text
  end;
$_$;

CREATE FUNCTION debug.topology_mapping(integer) RETURNS character
    LANGUAGE sql IMMUTABLE STRICT
    AS $_$
select
  case
    when $1 = 1 then 'NamespaceDelegation'
    -- 2 was IdentifierDelegation
    when $1 = 3 then 'DecentralizedNamespaceDefinition'
    when $1 = 4 then 'OwnerToKeyMapping'
    when $1 = 5 then 'SynchronizerTrustCertificate'
    when $1 = 6 then 'ParticipantSynchronizerPermission'
    when $1 = 7 then 'PartyHostingLimits'
    when $1 = 8 then 'VettedPackages'
    when $1 = 9 then 'PartyToParticipant'
    -- 10 was AuthorityOf
    when $1 = 11 then 'SynchronizerParameters'
    when $1 = 12 then 'MediatorSynchronizerState'
    when $1 = 13 then 'SequencerSynchronizerState'
    -- 14 was OffboardParticipant
    -- 15 was PurgeTopologyTransaction
    -- 16 was TrafficControlState
    when $1 = 17 then 'DynamicSequencingParametersState'
    when $1 = 18 then 'PartyToKeyMapping'
    else $1::text
  end;
$_$;

CREATE FUNCTION public.create_partitions_for_epoch_range(parent_table regclass, min_val bigint, max_val bigint) RETURNS void
    LANGUAGE plpgsql
    AS $$
declare
  partition_size bigint := 1500;
  current_val bigint;
  from_val bigint;
  next_val bigint;
  final_val bigint;
  partition_index bigint;
  partition_name text;
begin
  if partition_size <= 0 then
    raise exception 'partition_size must be positive';
  end if;

  current_val := floor(min_val::numeric / partition_size)::bigint * partition_size;

  -- creates one extra partition after the partition containing max_val
  final_val := max_val + partition_size;

  while current_val <= final_val loop
    next_val := current_val + partition_size;
    partition_index := current_val / partition_size;
    partition_name := format(
      '%s_p%s',
      replace(parent_table::text, '.', '_'),
      partition_index
    );

    -- the first partition will start at -1
    if current_val = 0 then
      from_val := -1;
    else
      from_val := current_val;
    end if;

    execute format(
      'create table if not exists %I partition of %s for values from (%L) to (%L)',
      partition_name,
      parent_table::text,
      from_val,
      next_val
    );

    current_val := next_val;
  end loop;
end;
$$;

CREATE TABLE public.acs_no_wait_counter_participants (
    synchronizer_id character varying NOT NULL COLLATE pg_catalog."C",
    participant_id character varying NOT NULL COLLATE pg_catalog."C"
);

CREATE VIEW debug.acs_no_wait_counter_participants AS
 SELECT synchronizer_id,
    participant_id
   FROM public.acs_no_wait_counter_participants;

CREATE TABLE public.acs_slow_counter_participants (
    synchronizer_id character varying NOT NULL COLLATE pg_catalog."C",
    participant_id character varying NOT NULL COLLATE pg_catalog."C",
    is_distinguished boolean NOT NULL,
    is_added_to_metrics boolean NOT NULL
);

CREATE VIEW debug.acs_slow_counter_participants AS
 SELECT synchronizer_id,
    participant_id,
    is_distinguished,
    is_added_to_metrics
   FROM public.acs_slow_counter_participants;

CREATE TABLE public.acs_slow_participant_config (
    synchronizer_id character varying NOT NULL COLLATE pg_catalog."C",
    threshold_distinguished integer NOT NULL,
    threshold_default integer NOT NULL
);

CREATE VIEW debug.acs_slow_participant_config AS
 SELECT synchronizer_id,
    threshold_distinguished,
    threshold_default
   FROM public.acs_slow_participant_config;

CREATE TABLE public.common_crypto_private_keys (
    key_id character varying NOT NULL COLLATE pg_catalog."C",
    wrapper_key_id character varying COLLATE pg_catalog."C",
    purpose smallint NOT NULL,
    data bytea NOT NULL,
    name character varying COLLATE pg_catalog."C"
);

CREATE VIEW debug.common_crypto_private_keys AS
 SELECT key_id,
    wrapper_key_id,
    debug.key_purpose((purpose)::integer) AS purpose,
    data,
    name
   FROM public.common_crypto_private_keys;

CREATE TABLE public.common_crypto_public_keys (
    key_id character varying NOT NULL COLLATE pg_catalog."C",
    purpose smallint NOT NULL,
    data bytea NOT NULL,
    name character varying COLLATE pg_catalog."C"
);

CREATE VIEW debug.common_crypto_public_keys AS
 SELECT key_id,
    debug.key_purpose((purpose)::integer) AS purpose,
    data,
    name
   FROM public.common_crypto_public_keys;

CREATE TABLE public.common_head_sequencer_counters (
    physical_synchronizer_idx integer NOT NULL,
    prehead_counter bigint NOT NULL,
    ts bigint NOT NULL
);

CREATE VIEW debug.common_head_sequencer_counters AS
 SELECT debug.resolve_common_static_string(physical_synchronizer_idx) AS physical_synchronizer_idx,
    prehead_counter,
    debug.canton_timestamp(ts) AS ts
   FROM public.common_head_sequencer_counters;

CREATE TABLE public.common_kms_metadata_store (
    fingerprint character varying NOT NULL COLLATE pg_catalog."C",
    kms_key_id character varying NOT NULL COLLATE pg_catalog."C",
    purpose smallint NOT NULL,
    key_usage integer[]
);

CREATE VIEW debug.common_kms_metadata_store AS
 SELECT fingerprint,
    kms_key_id,
    debug.key_purpose((purpose)::integer) AS purpose,
    debug.key_usages(key_usage) AS key_usage
   FROM public.common_kms_metadata_store;

CREATE TABLE public.common_node_id (
    identifier character varying NOT NULL COLLATE pg_catalog."C",
    namespace character varying NOT NULL COLLATE pg_catalog."C"
);

CREATE VIEW debug.common_node_id AS
 SELECT identifier,
    namespace
   FROM public.common_node_id;

CREATE TABLE public.common_pending_operations (
    operation_name character varying NOT NULL COLLATE pg_catalog."C",
    operation_key character varying NOT NULL COLLATE pg_catalog."C",
    operation bytea NOT NULL,
    synchronizer_id character varying NOT NULL COLLATE pg_catalog."C"
);

CREATE VIEW debug.common_pending_operations AS
 SELECT operation_name,
    operation_key,
    operation,
    synchronizer_id
   FROM public.common_pending_operations;

CREATE TABLE public.common_pruning_schedules (
    node_type character varying NOT NULL COLLATE pg_catalog."C",
    cron character varying NOT NULL COLLATE pg_catalog."C",
    max_duration bigint NOT NULL,
    retention bigint NOT NULL
);

CREATE VIEW debug.common_pruning_schedules AS
 SELECT node_type,
    cron,
    max_duration,
    retention
   FROM public.common_pruning_schedules;

CREATE TABLE public.common_sequenced_event_store_pruning (
    physical_synchronizer_idx integer NOT NULL,
    phase public.pruning_phase NOT NULL,
    ts bigint NOT NULL,
    succeeded bigint
);

CREATE VIEW debug.common_sequenced_event_store_pruning AS
 SELECT debug.resolve_common_static_string(physical_synchronizer_idx) AS physical_synchronizer_idx,
    phase,
    debug.canton_timestamp(ts) AS ts,
    debug.canton_timestamp(succeeded) AS succeeded
   FROM public.common_sequenced_event_store_pruning;

CREATE TABLE public.common_sequenced_events (
    physical_synchronizer_idx integer NOT NULL,
    sequenced_event bytea NOT NULL,
    type character varying NOT NULL COLLATE pg_catalog."C",
    ts bigint NOT NULL,
    sequencer_counter bigint NOT NULL,
    trace_context bytea NOT NULL,
    ignore boolean NOT NULL,
    CONSTRAINT common_sequenced_events_type_check CHECK (((type)::text = ANY ((ARRAY['del'::character varying, 'err'::character varying, 'ign'::character varying])::text[])))
);
ALTER TABLE ONLY public.common_sequenced_events ALTER COLUMN sequenced_event SET STORAGE EXTERNAL;

CREATE VIEW debug.common_sequenced_events AS
 SELECT debug.resolve_common_static_string(physical_synchronizer_idx) AS physical_synchronizer_idx,
    sequenced_event,
    type,
    debug.canton_timestamp(ts) AS ts,
    sequencer_counter,
    trace_context,
    ignore
   FROM public.common_sequenced_events;

CREATE TABLE public.common_static_strings (
    id integer NOT NULL,
    string character varying NOT NULL COLLATE pg_catalog."C",
    source integer NOT NULL
);

CREATE VIEW debug.common_static_strings AS
 SELECT id,
    string,
    source
   FROM public.common_static_strings;

CREATE TABLE public.common_topology_dispatching (
    store_id integer NOT NULL,
    watermark_ts bigint NOT NULL
);

CREATE VIEW debug.common_topology_dispatching AS
 SELECT store_id,
    debug.canton_timestamp(watermark_ts) AS watermark_ts
   FROM public.common_topology_dispatching;

CREATE TABLE public.common_topology_transactions (
    id bigint NOT NULL,
    store_id integer NOT NULL,
    sequenced bigint NOT NULL,
    transaction_type integer NOT NULL,
    namespace character varying NOT NULL COLLATE pg_catalog."C",
    identifier character varying NOT NULL COLLATE pg_catalog."C",
    mapping_key_hash bytea NOT NULL,
    serial_counter integer NOT NULL,
    valid_from bigint NOT NULL,
    batch_idx integer NOT NULL,
    valid_until bigint,
    operation integer NOT NULL,
    instance bytea NOT NULL,
    tx_hash bytea NOT NULL,
    rejection_reason character varying COLLATE pg_catalog."C",
    is_proposal boolean NOT NULL,
    representative_protocol_version integer NOT NULL,
    hash_of_signatures bytea NOT NULL
);

CREATE VIEW debug.common_topology_transactions AS
 SELECT id,
    store_id,
    debug.canton_timestamp(sequenced) AS sequenced,
    debug.topology_mapping(transaction_type) AS transaction_type,
    namespace,
    identifier,
    lower(encode(mapping_key_hash, 'hex'::text)) AS mapping_key_hash,
    serial_counter,
    debug.canton_timestamp(valid_from) AS valid_from,
    batch_idx,
    debug.canton_timestamp(valid_until) AS valid_until,
    debug.topology_change_op(operation) AS operation,
    instance,
    lower(encode(tx_hash, 'hex'::text)) AS tx_hash,
    rejection_reason,
    is_proposal,
    representative_protocol_version,
    lower(encode(hash_of_signatures, 'hex'::text)) AS hash_of_signatures
   FROM public.common_topology_transactions;

CREATE TABLE public.lapi_achs_state (
    valid_at bigint NOT NULL,
    last_removed bigint NOT NULL,
    last_populated bigint NOT NULL
);

CREATE VIEW debug.lapi_achs_state AS
 SELECT valid_at,
    last_removed,
    last_populated
   FROM public.lapi_achs_state;

CREATE TABLE public.lapi_command_completions (
    completion_offset bigint NOT NULL,
    record_time bigint NOT NULL,
    publication_time bigint NOT NULL,
    user_id integer NOT NULL,
    submitters bytea NOT NULL,
    command_id character varying NOT NULL COLLATE pg_catalog."C",
    update_id bytea,
    submission_id character varying COLLATE pg_catalog."C",
    deduplication_offset bigint,
    deduplication_duration_seconds bigint,
    deduplication_duration_nanos integer,
    rejection_status_code integer,
    rejection_status_message character varying COLLATE pg_catalog."C",
    rejection_status_details bytea,
    synchronizer_id integer NOT NULL,
    message_uuid character varying COLLATE pg_catalog."C",
    is_transaction boolean NOT NULL,
    trace_context bytea NOT NULL,
    traffic_cost bigint,
    transaction_hash bytea
);

CREATE VIEW debug.lapi_command_completions AS
 SELECT completion_offset,
    debug.canton_timestamp(record_time) AS record_time,
    debug.canton_timestamp(publication_time) AS publication_time,
    user_id,
    debug.resolve_lapi_interned_strings(submitters) AS submitters,
    command_id,
    lower(encode(update_id, 'hex'::text)) AS update_id,
    submission_id,
    deduplication_offset,
    deduplication_duration_seconds,
    deduplication_duration_nanos,
    debug.lapi_rejection_status_code(rejection_status_code) AS rejection_status_code,
    rejection_status_message,
    lower(encode(rejection_status_details, 'hex'::text)) AS rejection_status_details,
    debug.resolve_lapi_interned_string(synchronizer_id) AS synchronizer_id,
    message_uuid,
    is_transaction,
    lower(encode(trace_context, 'hex'::text)) AS trace_context,
    traffic_cost,
    lower(encode(transaction_hash, 'hex'::text)) AS transaction_hash
   FROM public.lapi_command_completions;

CREATE TABLE public.lapi_events_acs_commitments (
    event_sequential_id bigint NOT NULL,
    event_offset bigint NOT NULL,
    update_id bytea NOT NULL,
    synchronizer_id integer NOT NULL,
    record_time bigint NOT NULL,
    payload bytea NOT NULL,
    trace_context bytea NOT NULL
);

CREATE VIEW debug.lapi_events_acs_commitments AS
 SELECT event_sequential_id,
    event_offset,
    lower(encode(update_id, 'hex'::text)) AS update_id,
    debug.resolve_lapi_interned_string(synchronizer_id) AS synchronizer_id,
    debug.canton_timestamp(record_time) AS record_time,
    lower(encode(payload, 'hex'::text)) AS payload,
    lower(encode(trace_context, 'hex'::text)) AS trace_context
   FROM public.lapi_events_acs_commitments;

CREATE TABLE public.lapi_events_activate_contract (
    event_offset bigint NOT NULL,
    update_id bytea NOT NULL,
    workflow_id character varying COLLATE pg_catalog."C",
    command_id character varying COLLATE pg_catalog."C",
    submitters bytea,
    record_time bigint NOT NULL,
    synchronizer_id integer NOT NULL,
    trace_context bytea NOT NULL,
    external_transaction_hash bytea,
    event_type smallint NOT NULL,
    event_sequential_id bigint NOT NULL,
    node_id integer NOT NULL,
    additional_witnesses bytea,
    source_synchronizer_id integer,
    reassignment_counter bigint,
    reassignment_id bytea,
    representative_package_id integer NOT NULL,
    internal_contract_id bigint NOT NULL,
    create_key_hash character varying COLLATE pg_catalog."C",
    traffic_cost bigint
);

CREATE VIEW debug.lapi_events_activate_contract AS
 SELECT event_offset,
    lower(encode(update_id, 'hex'::text)) AS update_id,
    workflow_id,
    command_id,
    debug.resolve_lapi_interned_strings(submitters) AS submitters,
    debug.canton_timestamp(record_time) AS record_time,
    debug.resolve_lapi_interned_string(synchronizer_id) AS synchronizer_id,
    lower(encode(trace_context, 'hex'::text)) AS trace_context,
    lower(encode(external_transaction_hash, 'hex'::text)) AS external_transaction_hash,
    debug.lapi_event_type(event_type) AS event_type,
    event_sequential_id,
    node_id,
    debug.resolve_lapi_interned_strings(additional_witnesses) AS additional_witnesses,
    debug.resolve_lapi_interned_string(source_synchronizer_id) AS source_synchronizer_id,
    reassignment_counter,
    lower(encode(reassignment_id, 'hex'::text)) AS reassignment_id,
    debug.resolve_lapi_interned_string(representative_package_id) AS representative_package_id,
    internal_contract_id,
    create_key_hash,
    traffic_cost
   FROM public.lapi_events_activate_contract;

CREATE TABLE public.lapi_events_deactivate_contract (
    event_offset bigint NOT NULL,
    update_id bytea NOT NULL,
    workflow_id character varying COLLATE pg_catalog."C",
    command_id character varying COLLATE pg_catalog."C",
    submitters bytea,
    record_time bigint NOT NULL,
    synchronizer_id integer NOT NULL,
    trace_context bytea NOT NULL,
    external_transaction_hash bytea,
    event_type smallint NOT NULL,
    event_sequential_id bigint NOT NULL,
    node_id integer NOT NULL,
    deactivated_event_sequential_id bigint,
    additional_witnesses bytea,
    exercise_choice integer,
    exercise_choice_interface integer,
    exercise_argument bytea,
    exercise_result bytea,
    exercise_actors bytea,
    exercise_last_descendant_node_id integer,
    exercise_argument_compression smallint,
    exercise_result_compression smallint,
    reassignment_id bytea,
    assignment_exclusivity bigint,
    target_synchronizer_id integer,
    reassignment_counter bigint,
    contract_id bytea,
    internal_contract_id bigint,
    template_id integer NOT NULL,
    package_id integer NOT NULL,
    stakeholders bytea NOT NULL,
    ledger_effective_time bigint,
    traffic_cost bigint
);

CREATE VIEW debug.lapi_events_deactivate_contract AS
 SELECT event_offset,
    lower(encode(update_id, 'hex'::text)) AS update_id,
    workflow_id,
    command_id,
    debug.resolve_lapi_interned_strings(submitters) AS submitters,
    debug.canton_timestamp(record_time) AS record_time,
    debug.resolve_lapi_interned_string(synchronizer_id) AS synchronizer_id,
    lower(encode(trace_context, 'hex'::text)) AS trace_context,
    lower(encode(external_transaction_hash, 'hex'::text)) AS external_transaction_hash,
    debug.lapi_event_type(event_type) AS event_type,
    event_sequential_id,
    node_id,
    deactivated_event_sequential_id,
    debug.resolve_lapi_interned_strings(additional_witnesses) AS additional_witnesses,
    debug.resolve_lapi_interned_string(exercise_choice) AS exercise_choice,
    debug.resolve_lapi_interned_string(exercise_choice_interface) AS exercise_choice_interface,
    lower(encode(exercise_argument, 'hex'::text)) AS exercise_argument,
    lower(encode(exercise_result, 'hex'::text)) AS exercise_result,
    debug.resolve_lapi_interned_strings(exercise_actors) AS exercise_actors,
    exercise_last_descendant_node_id,
    debug.lapi_compression((exercise_argument_compression)::integer) AS exercise_argument_compression,
    debug.lapi_compression((exercise_result_compression)::integer) AS exercise_result_compression,
    lower(encode(reassignment_id, 'hex'::text)) AS reassignment_id,
    assignment_exclusivity,
    debug.resolve_lapi_interned_string(target_synchronizer_id) AS target_synchronizer_id,
    reassignment_counter,
    lower(encode(contract_id, 'hex'::text)) AS contract_id,
    internal_contract_id,
    debug.resolve_lapi_interned_string(template_id) AS template_id,
    debug.resolve_lapi_interned_string(package_id) AS package_id,
    debug.resolve_lapi_interned_strings(stakeholders) AS stakeholders,
    debug.canton_timestamp(ledger_effective_time) AS ledger_effective_time,
    traffic_cost
   FROM public.lapi_events_deactivate_contract;

CREATE TABLE public.lapi_events_generic_topology_events (
    event_sequential_id bigint NOT NULL,
    event_offset bigint NOT NULL,
    update_id bytea NOT NULL,
    synchronizer_id integer NOT NULL,
    record_time bigint NOT NULL,
    event_type smallint NOT NULL,
    payload bytea NOT NULL,
    trace_context bytea NOT NULL
);

CREATE VIEW debug.lapi_events_generic_topology_events AS
 SELECT event_sequential_id,
    event_offset,
    lower(encode(update_id, 'hex'::text)) AS update_id,
    debug.resolve_lapi_interned_string(synchronizer_id) AS synchronizer_id,
    debug.canton_timestamp(record_time) AS record_time,
    debug.lapi_event_type(event_type) AS event_type,
    lower(encode(payload, 'hex'::text)) AS payload,
    lower(encode(trace_context, 'hex'::text)) AS trace_context
   FROM public.lapi_events_generic_topology_events;

CREATE TABLE public.lapi_events_party_to_participant (
    event_sequential_id bigint NOT NULL,
    event_offset bigint NOT NULL,
    update_id bytea NOT NULL,
    party_id integer NOT NULL,
    participant_id integer NOT NULL,
    participant_permission integer NOT NULL,
    participant_authorization_event integer NOT NULL,
    synchronizer_id integer NOT NULL,
    record_time bigint NOT NULL,
    trace_context bytea NOT NULL,
    party character varying NOT NULL COLLATE pg_catalog."C"
);

CREATE VIEW debug.lapi_events_party_to_participant AS
 SELECT event_sequential_id,
    event_offset,
    lower(encode(update_id, 'hex'::text)) AS update_id,
    party_id,
    party,
    participant_id,
    participant_permission,
    participant_authorization_event,
    debug.resolve_lapi_interned_string(synchronizer_id) AS synchronizer_id,
    debug.canton_timestamp(record_time) AS record_time,
    lower(encode(trace_context, 'hex'::text)) AS trace_context
   FROM public.lapi_events_party_to_participant;

CREATE TABLE public.lapi_events_various_witnessed (
    event_offset bigint NOT NULL,
    update_id bytea NOT NULL,
    workflow_id character varying COLLATE pg_catalog."C",
    command_id character varying COLLATE pg_catalog."C",
    submitters bytea,
    record_time bigint NOT NULL,
    synchronizer_id integer NOT NULL,
    trace_context bytea NOT NULL,
    external_transaction_hash bytea,
    event_type smallint NOT NULL,
    event_sequential_id bigint NOT NULL,
    node_id integer NOT NULL,
    additional_witnesses bytea NOT NULL,
    consuming boolean,
    exercise_choice integer,
    exercise_choice_interface integer,
    exercise_argument bytea,
    exercise_result bytea,
    exercise_actors bytea,
    exercise_last_descendant_node_id integer,
    exercise_argument_compression smallint,
    exercise_result_compression smallint,
    representative_package_id integer,
    contract_id bytea,
    internal_contract_id bigint,
    template_id integer,
    package_id integer,
    ledger_effective_time bigint,
    traffic_cost bigint
);

CREATE VIEW debug.lapi_events_various_witnessed AS
 SELECT event_offset,
    lower(encode(update_id, 'hex'::text)) AS update_id,
    workflow_id,
    command_id,
    debug.resolve_lapi_interned_strings(submitters) AS submitters,
    debug.canton_timestamp(record_time) AS record_time,
    debug.resolve_lapi_interned_string(synchronizer_id) AS synchronizer_id,
    lower(encode(trace_context, 'hex'::text)) AS trace_context,
    lower(encode(external_transaction_hash, 'hex'::text)) AS external_transaction_hash,
    debug.lapi_event_type(event_type) AS event_type,
    event_sequential_id,
    node_id,
    debug.resolve_lapi_interned_strings(additional_witnesses) AS additional_witnesses,
    consuming,
    debug.resolve_lapi_interned_string(exercise_choice) AS exercise_choice,
    debug.resolve_lapi_interned_string(exercise_choice_interface) AS exercise_choice_interface,
    lower(encode(exercise_argument, 'hex'::text)) AS exercise_argument,
    lower(encode(exercise_result, 'hex'::text)) AS exercise_result,
    debug.resolve_lapi_interned_strings(exercise_actors) AS exercise_actors,
    exercise_last_descendant_node_id,
    debug.lapi_compression((exercise_argument_compression)::integer) AS exercise_argument_compression,
    debug.lapi_compression((exercise_result_compression)::integer) AS exercise_result_compression,
    debug.resolve_lapi_interned_string(representative_package_id) AS representative_package_id,
    lower(encode(contract_id, 'hex'::text)) AS contract_id,
    internal_contract_id,
    debug.resolve_lapi_interned_string(template_id) AS template_id,
    debug.resolve_lapi_interned_string(package_id) AS package_id,
    debug.canton_timestamp(ledger_effective_time) AS ledger_effective_time,
    traffic_cost
   FROM public.lapi_events_various_witnessed;

CREATE TABLE public.lapi_filter_achs_stakeholder (
    event_sequential_id bigint NOT NULL,
    template_id integer NOT NULL,
    party_id integer NOT NULL,
    first_per_sequential_id boolean
);

CREATE VIEW debug.lapi_filter_achs_stakeholder AS
 SELECT event_sequential_id,
    debug.resolve_lapi_interned_string(template_id) AS template_id,
    debug.resolve_lapi_interned_string(party_id) AS party_id,
    first_per_sequential_id
   FROM public.lapi_filter_achs_stakeholder;

CREATE TABLE public.lapi_filter_activate_stakeholder (
    event_sequential_id bigint NOT NULL,
    template_id integer NOT NULL,
    party_id integer NOT NULL,
    first_per_sequential_id boolean
);

CREATE VIEW debug.lapi_filter_activate_stakeholder AS
 SELECT event_sequential_id,
    debug.resolve_lapi_interned_string(template_id) AS template_id,
    debug.resolve_lapi_interned_string(party_id) AS party_id,
    first_per_sequential_id
   FROM public.lapi_filter_activate_stakeholder;

CREATE TABLE public.lapi_filter_activate_witness (
    event_sequential_id bigint NOT NULL,
    template_id integer NOT NULL,
    party_id integer NOT NULL,
    first_per_sequential_id boolean
);

CREATE VIEW debug.lapi_filter_activate_witness AS
 SELECT event_sequential_id,
    debug.resolve_lapi_interned_string(template_id) AS template_id,
    debug.resolve_lapi_interned_string(party_id) AS party_id,
    first_per_sequential_id
   FROM public.lapi_filter_activate_witness;

CREATE TABLE public.lapi_filter_deactivate_stakeholder (
    event_sequential_id bigint NOT NULL,
    template_id integer NOT NULL,
    party_id integer NOT NULL,
    first_per_sequential_id boolean
);

CREATE VIEW debug.lapi_filter_deactivate_stakeholder AS
 SELECT event_sequential_id,
    debug.resolve_lapi_interned_string(template_id) AS template_id,
    debug.resolve_lapi_interned_string(party_id) AS party_id,
    first_per_sequential_id
   FROM public.lapi_filter_deactivate_stakeholder;

CREATE TABLE public.lapi_filter_deactivate_witness (
    event_sequential_id bigint NOT NULL,
    template_id integer NOT NULL,
    party_id integer NOT NULL,
    first_per_sequential_id boolean
);

CREATE VIEW debug.lapi_filter_deactivate_witness AS
 SELECT event_sequential_id,
    debug.resolve_lapi_interned_string(template_id) AS template_id,
    debug.resolve_lapi_interned_string(party_id) AS party_id,
    first_per_sequential_id
   FROM public.lapi_filter_deactivate_witness;

CREATE TABLE public.lapi_filter_various_witness (
    event_sequential_id bigint NOT NULL,
    template_id integer NOT NULL,
    party_id integer NOT NULL,
    first_per_sequential_id boolean
);

CREATE VIEW debug.lapi_filter_various_witness AS
 SELECT event_sequential_id,
    debug.resolve_lapi_interned_string(template_id) AS template_id,
    debug.resolve_lapi_interned_string(party_id) AS party_id,
    first_per_sequential_id
   FROM public.lapi_filter_various_witness;

CREATE TABLE public.lapi_identity_provider_config (
    identity_provider_id character varying NOT NULL COLLATE pg_catalog."C",
    issuer character varying NOT NULL COLLATE pg_catalog."C",
    jwks_url character varying NOT NULL COLLATE pg_catalog."C",
    is_deactivated boolean NOT NULL,
    audience character varying COLLATE pg_catalog."C"
);

CREATE VIEW debug.lapi_identity_provider_config AS
 SELECT identity_provider_id,
    issuer,
    jwks_url,
    is_deactivated,
    audience
   FROM public.lapi_identity_provider_config;

CREATE TABLE public.lapi_ledger_end_synchronizer_index (
    synchronizer_id integer NOT NULL,
    sequencer_timestamp bigint,
    repair_timestamp bigint,
    repair_counter bigint,
    record_time bigint NOT NULL
);

CREATE VIEW debug.lapi_ledger_end_synchronizer_index AS
 SELECT debug.resolve_lapi_interned_string(synchronizer_id) AS synchronizer_id,
    debug.canton_timestamp(sequencer_timestamp) AS sequencer_timestamp,
    debug.canton_timestamp(repair_timestamp) AS repair_timestamp,
    repair_counter,
    debug.canton_timestamp(record_time) AS record_time
   FROM public.lapi_ledger_end_synchronizer_index;

CREATE TABLE public.lapi_parameters (
    ledger_end bigint,
    participant_id character varying NOT NULL COLLATE pg_catalog."C",
    participant_pruned_up_to_inclusive bigint,
    ledger_end_sequential_id bigint,
    ledger_end_string_interning_id integer,
    ledger_end_publication_time bigint
);

CREATE VIEW debug.lapi_parameters AS
 SELECT ledger_end,
    participant_id,
    participant_pruned_up_to_inclusive,
    ledger_end_sequential_id,
    ledger_end_string_interning_id,
    debug.canton_timestamp(ledger_end_publication_time) AS ledger_end_publication_time
   FROM public.lapi_parameters;

CREATE TABLE public.lapi_party_record_annotations (
    internal_id integer NOT NULL,
    name character varying NOT NULL COLLATE pg_catalog."C",
    val character varying COLLATE pg_catalog."C",
    updated_at bigint NOT NULL
);

CREATE VIEW debug.lapi_party_record_annotations AS
 SELECT internal_id,
    name,
    val,
    debug.canton_timestamp(updated_at) AS updated_at
   FROM public.lapi_party_record_annotations;

CREATE TABLE public.lapi_party_records (
    internal_id integer NOT NULL,
    party character varying NOT NULL COLLATE pg_catalog."C",
    resource_version bigint NOT NULL,
    created_at bigint NOT NULL,
    identity_provider_id character varying COLLATE pg_catalog."C"
);

CREATE VIEW debug.lapi_party_records AS
 SELECT internal_id,
    party,
    resource_version,
    debug.canton_timestamp(created_at) AS created_at,
    identity_provider_id
   FROM public.lapi_party_records;

CREATE TABLE public.lapi_post_processing_end (
    post_processing_end bigint
);

CREATE VIEW debug.lapi_post_processing_end AS
 SELECT post_processing_end
   FROM public.lapi_post_processing_end;

CREATE TABLE public.lapi_pruning_candidate_deactivated (
    deactivate_event_sequential_id bigint NOT NULL,
    activate_event_sequential_id bigint
);

CREATE VIEW debug.lapi_pruning_candidate_deactivated AS
 SELECT deactivate_event_sequential_id,
    activate_event_sequential_id
   FROM public.lapi_pruning_candidate_deactivated;

CREATE TABLE public.lapi_pruning_contract_candidate (
    internal_contract_id bigint NOT NULL
);

CREATE VIEW debug.lapi_pruning_contract_candidate AS
 SELECT internal_contract_id
   FROM public.lapi_pruning_contract_candidate;

CREATE TABLE public.lapi_string_interning (
    internal_id integer NOT NULL,
    external_string character varying NOT NULL COLLATE pg_catalog."C"
);

CREATE VIEW debug.lapi_string_interning AS
 SELECT internal_id,
    external_string
   FROM public.lapi_string_interning;

CREATE TABLE public.lapi_update_meta (
    update_id bytea NOT NULL,
    event_offset bigint NOT NULL,
    publication_time bigint NOT NULL,
    record_time bigint NOT NULL,
    synchronizer_id integer NOT NULL,
    event_sequential_id_first bigint NOT NULL,
    event_sequential_id_last bigint NOT NULL,
    transaction_hash bytea
);

CREATE VIEW debug.lapi_update_meta AS
 SELECT lower(encode(update_id, 'hex'::text)) AS update_id,
    event_offset,
    debug.canton_timestamp(publication_time) AS publication_time,
    debug.canton_timestamp(record_time) AS record_time,
    debug.resolve_lapi_interned_string(synchronizer_id) AS synchronizer_id,
    event_sequential_id_first,
    event_sequential_id_last,
    lower(encode(transaction_hash, 'hex'::text)) AS transaction_hash
   FROM public.lapi_update_meta;

CREATE TABLE public.lapi_user_annotations (
    internal_id integer NOT NULL,
    name character varying NOT NULL COLLATE pg_catalog."C",
    val character varying COLLATE pg_catalog."C",
    updated_at bigint NOT NULL
);

CREATE VIEW debug.lapi_user_annotations AS
 SELECT debug.resolve_lapi_user(internal_id) AS internal_id,
    name,
    val,
    debug.canton_timestamp(updated_at) AS updated_at
   FROM public.lapi_user_annotations;

CREATE TABLE public.lapi_user_rights (
    user_internal_id integer NOT NULL,
    user_right integer NOT NULL,
    for_party character varying COLLATE pg_catalog."C",
    granted_at bigint NOT NULL
);

CREATE VIEW debug.lapi_user_rights AS
 SELECT debug.resolve_lapi_user(user_internal_id) AS user_internal_id,
    debug.lapi_user_right(user_right) AS user_right,
    for_party,
    debug.canton_timestamp(granted_at) AS granted_at
   FROM public.lapi_user_rights;

CREATE TABLE public.lapi_users (
    internal_id integer NOT NULL,
    user_id character varying NOT NULL COLLATE pg_catalog."C",
    primary_party character varying COLLATE pg_catalog."C",
    created_at bigint NOT NULL,
    is_deactivated boolean DEFAULT false NOT NULL,
    resource_version bigint DEFAULT 0 NOT NULL,
    identity_provider_id character varying COLLATE pg_catalog."C",
    primary_party_authentication boolean DEFAULT false NOT NULL
);

CREATE VIEW debug.lapi_users AS
 SELECT internal_id,
    user_id,
    primary_party,
    debug.canton_timestamp(created_at) AS created_at,
    is_deactivated,
    resource_version,
    identity_provider_id,
    primary_party_authentication
   FROM public.lapi_users;

CREATE TABLE public.med_response_aggregations (
    request_id bigint NOT NULL,
    mediator_confirmation_request bytea NOT NULL,
    finalization_time bigint NOT NULL,
    verdict bytea NOT NULL,
    request_trace_context bytea NOT NULL
);

CREATE VIEW debug.med_response_aggregations AS
 SELECT debug.canton_timestamp(request_id) AS request_id,
    mediator_confirmation_request,
    debug.canton_timestamp(finalization_time) AS finalization_time,
    verdict,
    request_trace_context
   FROM public.med_response_aggregations;

CREATE TABLE public.mediator_deduplication_store (
    uuid character varying NOT NULL COLLATE pg_catalog."C",
    request_time bigint NOT NULL,
    expire_after bigint NOT NULL
);

CREATE VIEW debug.mediator_deduplication_store AS
 SELECT uuid,
    debug.canton_timestamp(request_time) AS request_time,
    debug.canton_timestamp(expire_after) AS expire_after
   FROM public.mediator_deduplication_store;

CREATE TABLE public.mediator_synchronizer_configuration (
    lock character(1) DEFAULT 'X'::bpchar NOT NULL,
    physical_synchronizer_id character varying NOT NULL COLLATE pg_catalog."C",
    static_synchronizer_parameters bytea NOT NULL,
    sequencer_connection bytea NOT NULL,
    is_topology_initialized boolean DEFAULT false NOT NULL,
    CONSTRAINT mediator_synchronizer_configuration_lock_check CHECK ((lock = 'X'::bpchar))
);

CREATE VIEW debug.mediator_synchronizer_configuration AS
 SELECT lock,
    physical_synchronizer_id,
    static_synchronizer_parameters,
    sequencer_connection,
    is_topology_initialized
   FROM public.mediator_synchronizer_configuration;

CREATE TABLE public.ord_availability_batch (
    id character varying NOT NULL COLLATE pg_catalog."C",
    batch bytea NOT NULL,
    epoch_number bigint NOT NULL
)
PARTITION BY RANGE (epoch_number);

CREATE VIEW debug.ord_availability_batch AS
 SELECT id,
    batch,
    epoch_number
   FROM public.ord_availability_batch;

CREATE TABLE public.ord_epochs (
    epoch_number bigint NOT NULL,
    start_block_number bigint NOT NULL,
    epoch_length bigint NOT NULL,
    topology_ts bigint NOT NULL,
    in_progress boolean NOT NULL
)
PARTITION BY RANGE (epoch_number);

CREATE VIEW debug.ord_epochs AS
 SELECT epoch_number,
    start_block_number,
    epoch_length,
    debug.canton_timestamp(topology_ts) AS topology_ts,
    in_progress
   FROM public.ord_epochs;

CREATE TABLE public.ord_leader_selection_state (
    epoch_number bigint NOT NULL,
    state bytea NOT NULL
)
PARTITION BY RANGE (epoch_number);

CREATE VIEW debug.ord_leader_selection_state AS
 SELECT epoch_number,
    state
   FROM public.ord_leader_selection_state;

CREATE TABLE public.ord_metadata_output_blocks (
    epoch_number bigint NOT NULL,
    block_number bigint NOT NULL,
    bft_ts bigint NOT NULL
)
PARTITION BY RANGE (epoch_number);

CREATE VIEW debug.ord_metadata_output_blocks AS
 SELECT epoch_number,
    block_number,
    debug.canton_timestamp(bft_ts) AS bft_ts
   FROM public.ord_metadata_output_blocks;

CREATE TABLE public.ord_metadata_output_epochs (
    epoch_number bigint NOT NULL,
    could_alter_ordering_topology boolean NOT NULL
)
PARTITION BY RANGE (epoch_number);

CREATE VIEW debug.ord_metadata_output_epochs AS
 SELECT epoch_number,
    could_alter_ordering_topology
   FROM public.ord_metadata_output_epochs;

CREATE TABLE public.ord_output_lower_bound (
    single_row_lock character(1) DEFAULT 'X'::bpchar NOT NULL,
    epoch_number bigint NOT NULL,
    block_number bigint NOT NULL,
    CONSTRAINT ord_output_lower_bound_single_row_lock_check CHECK ((single_row_lock = 'X'::bpchar))
);

CREATE VIEW debug.ord_output_lower_bound AS
 SELECT single_row_lock,
    epoch_number,
    block_number
   FROM public.ord_output_lower_bound;

CREATE TABLE public.ord_p2p_endpoints (
    address character varying NOT NULL COLLATE pg_catalog."C",
    port integer NOT NULL,
    transport_security boolean NOT NULL,
    custom_server_trust_certificates bytea,
    client_certificate_chain bytea,
    client_private_key_file character varying COLLATE pg_catalog."C",
    node_id character varying COLLATE pg_catalog."C"
);

CREATE VIEW debug.ord_p2p_endpoints AS
 SELECT address,
    port,
    transport_security,
    custom_server_trust_certificates,
    client_certificate_chain,
    client_private_key_file,
    node_id
   FROM public.ord_p2p_endpoints;

CREATE TABLE public.ord_partition_size_history (
    epoch_number bigint NOT NULL,
    partition_number bigint NOT NULL,
    partition_size integer NOT NULL
);

CREATE VIEW debug.ord_partition_size_history AS
 SELECT epoch_number,
    partition_number,
    partition_size
   FROM public.ord_partition_size_history;

CREATE TABLE public.ord_pbft_messages_completed (
    block_number bigint NOT NULL,
    epoch_number bigint NOT NULL,
    message bytea NOT NULL,
    discriminator smallint NOT NULL,
    from_sequencer_id character varying NOT NULL COLLATE pg_catalog."C"
)
PARTITION BY RANGE (epoch_number);

CREATE VIEW debug.ord_pbft_messages_completed AS
 SELECT block_number,
    epoch_number,
    message,
    discriminator,
    from_sequencer_id
   FROM public.ord_pbft_messages_completed;

CREATE TABLE public.ord_pbft_messages_in_progress (
    block_number bigint NOT NULL,
    epoch_number bigint NOT NULL,
    view_number bigint NOT NULL,
    message bytea NOT NULL,
    discriminator smallint NOT NULL,
    from_sequencer_id character varying NOT NULL COLLATE pg_catalog."C"
)
PARTITION BY RANGE (epoch_number);

CREATE VIEW debug.ord_pbft_messages_in_progress AS
 SELECT block_number,
    epoch_number,
    view_number,
    message,
    discriminator,
    from_sequencer_id
   FROM public.ord_pbft_messages_in_progress;

CREATE TABLE public.ord_pruning_schedules (
    lock character(1) DEFAULT 'X'::bpchar NOT NULL,
    cron character varying NOT NULL COLLATE pg_catalog."C",
    max_duration bigint NOT NULL,
    retention bigint NOT NULL,
    min_blocks_to_keep integer NOT NULL,
    CONSTRAINT ord_pruning_schedules_lock_check CHECK ((lock = 'X'::bpchar))
);

CREATE VIEW debug.ord_pruning_schedules AS
 SELECT lock,
    cron,
    max_duration,
    retention,
    min_blocks_to_keep
   FROM public.ord_pruning_schedules;

CREATE TABLE public.par_acs_commitment_period_match (
    synchronizer_idx integer NOT NULL,
    participant_id integer NOT NULL,
    from_exclusive bigint NOT NULL,
    to_inclusive bigint NOT NULL,
    update_offset bigint NOT NULL
);

CREATE VIEW debug.par_acs_commitment_period_match AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    debug.resolve_lapi_interned_string(participant_id) AS participant_id,
    debug.canton_timestamp(from_exclusive) AS from_exclusive,
    debug.canton_timestamp(to_inclusive) AS to_inclusive,
    update_offset
   FROM public.par_acs_commitment_period_match;

CREATE TABLE public.par_acs_commitment_period_mismatch (
    synchronizer_idx integer NOT NULL,
    participant_id integer NOT NULL,
    from_exclusive bigint NOT NULL,
    to_inclusive bigint NOT NULL,
    update_offset bigint NOT NULL,
    expected_hashed_digest bytea
);

CREATE VIEW debug.par_acs_commitment_period_mismatch AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    debug.resolve_lapi_interned_string(participant_id) AS participant_id,
    debug.canton_timestamp(from_exclusive) AS from_exclusive,
    debug.canton_timestamp(to_inclusive) AS to_inclusive,
    update_offset,
    lower(encode(expected_hashed_digest, 'hex'::text)) AS expected_hashed_digest
   FROM public.par_acs_commitment_period_mismatch;

CREATE TABLE public.par_acs_commitment_period_outstanding (
    synchronizer_idx integer NOT NULL,
    participant_id integer NOT NULL,
    from_exclusive bigint NOT NULL,
    to_inclusive bigint NOT NULL,
    expected_hashed_digest bytea NOT NULL
);

CREATE VIEW debug.par_acs_commitment_period_outstanding AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    debug.resolve_lapi_interned_string(participant_id) AS participant_id,
    debug.canton_timestamp(from_exclusive) AS from_exclusive,
    debug.canton_timestamp(to_inclusive) AS to_inclusive,
    lower(encode(expected_hashed_digest, 'hex'::text)) AS expected_hashed_digest
   FROM public.par_acs_commitment_period_outstanding;

CREATE TABLE public.par_acs_commitment_period_pruning (
    synchronizer_idx integer NOT NULL,
    phase public.pruning_phase NOT NULL,
    ts bigint NOT NULL,
    succeeded bigint
);

CREATE VIEW debug.par_acs_commitment_period_pruning AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    phase,
    debug.canton_timestamp(ts) AS ts,
    debug.canton_timestamp(succeeded) AS succeeded
   FROM public.par_acs_commitment_period_pruning;

CREATE TABLE public.par_acs_commitment_period_watermark (
    synchronizer_idx integer NOT NULL,
    watermark_matching bigint NOT NULL
);

CREATE VIEW debug.par_acs_commitment_period_watermark AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    watermark_matching
   FROM public.par_acs_commitment_period_watermark;

CREATE TABLE public.par_acs_commitment_sender_watermark (
    synchronizer_idx integer NOT NULL,
    watermark_offset bigint NOT NULL,
    watermark_timestamp bigint NOT NULL
);

CREATE VIEW debug.par_acs_commitment_sender_watermark AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    watermark_offset,
    debug.canton_timestamp(watermark_timestamp) AS watermark_timestamp
   FROM public.par_acs_commitment_sender_watermark;

CREATE TABLE public.par_acs_participant_running_digest (
    synchronizer_idx integer NOT NULL,
    participant_id integer NOT NULL,
    change_offset bigint NOT NULL,
    ts bigint NOT NULL,
    digest bytea,
    trace_data character varying COLLATE pg_catalog."C",
    replaces_offset bigint
);
ALTER TABLE ONLY public.par_acs_participant_running_digest ALTER COLUMN digest SET STORAGE PLAIN;

CREATE VIEW debug.par_acs_participant_running_digest AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    debug.resolve_lapi_interned_string(participant_id) AS participant_id,
    change_offset,
    debug.canton_timestamp(ts) AS ts,
    lower(encode(digest, 'hex'::text)) AS digest,
    (trace_data)::json AS trace_data,
    replaces_offset
   FROM public.par_acs_participant_running_digest;

CREATE TABLE public.par_acs_party_running_digest (
    synchronizer_idx integer NOT NULL,
    party_id integer NOT NULL,
    change_offset bigint NOT NULL,
    ts bigint NOT NULL,
    digest bytea,
    trace_data character varying COLLATE pg_catalog."C",
    replaces_offset bigint
);
ALTER TABLE ONLY public.par_acs_party_running_digest ALTER COLUMN digest SET STORAGE PLAIN;

CREATE VIEW debug.par_acs_party_running_digest AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    debug.resolve_lapi_interned_string(party_id) AS party_id,
    change_offset,
    debug.canton_timestamp(ts) AS ts,
    lower(encode(digest, 'hex'::text)) AS digest,
    (trace_data)::json AS trace_data,
    replaces_offset
   FROM public.par_acs_party_running_digest;

CREATE TABLE public.par_acs_running_digests_checkpoint (
    synchronizer_idx integer NOT NULL,
    change_offset bigint NOT NULL,
    ts bigint NOT NULL,
    checkpoint_type integer NOT NULL
);

CREATE VIEW debug.par_acs_running_digests_checkpoint AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    change_offset,
    debug.canton_timestamp(ts) AS ts,
    debug.checkpoint_type(checkpoint_type) AS checkpoint_type
   FROM public.par_acs_running_digests_checkpoint;

CREATE TABLE public.par_acs_running_digests_pruning (
    synchronizer_idx integer NOT NULL,
    latest_successful_prune_offset bigint NOT NULL
);

CREATE VIEW debug.par_acs_running_digests_pruning AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    latest_successful_prune_offset
   FROM public.par_acs_running_digests_pruning;

CREATE TABLE public.par_active_contract_pruning (
    synchronizer_idx integer NOT NULL,
    phase public.pruning_phase NOT NULL,
    ts bigint NOT NULL,
    succeeded bigint
);

CREATE VIEW debug.par_active_contract_pruning AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    phase,
    debug.canton_timestamp(ts) AS ts,
    debug.canton_timestamp(succeeded) AS succeeded
   FROM public.par_active_contract_pruning;

CREATE TABLE public.par_active_contracts (
    synchronizer_idx integer NOT NULL,
    contract_id bytea NOT NULL,
    change public.change_type NOT NULL,
    operation public.operation_type NOT NULL,
    ts bigint NOT NULL,
    repair_counter bigint NOT NULL,
    remote_synchronizer_idx integer,
    reassignment_counter bigint
);

CREATE VIEW debug.par_active_contracts AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    lower(encode(contract_id, 'hex'::text)) AS contract_id,
    change,
    operation,
    debug.canton_timestamp(ts) AS ts,
    repair_counter,
    debug.resolve_common_static_string(remote_synchronizer_idx) AS remote_synchronizer_idx,
    reassignment_counter
   FROM public.par_active_contracts;

CREATE TABLE public.par_command_deduplication (
    change_id_hash character varying NOT NULL COLLATE pg_catalog."C",
    user_id character varying NOT NULL COLLATE pg_catalog."C",
    command_id character varying NOT NULL COLLATE pg_catalog."C",
    act_as bytea NOT NULL,
    offset_definite_answer bigint NOT NULL,
    publication_time_definite_answer bigint NOT NULL,
    submission_id_definite_answer character varying COLLATE pg_catalog."C",
    trace_context_definite_answer bytea NOT NULL,
    offset_acceptance bigint,
    publication_time_acceptance bigint,
    submission_id_acceptance character varying COLLATE pg_catalog."C",
    trace_context_acceptance bytea
);

CREATE VIEW debug.par_command_deduplication AS
 SELECT change_id_hash,
    user_id,
    command_id,
    act_as,
    offset_definite_answer,
    debug.canton_timestamp(publication_time_definite_answer) AS publication_time_definite_answer,
    submission_id_definite_answer,
    trace_context_definite_answer,
    offset_acceptance,
    debug.canton_timestamp(publication_time_acceptance) AS publication_time_acceptance,
    submission_id_acceptance,
    trace_context_acceptance
   FROM public.par_command_deduplication;

CREATE TABLE public.par_command_deduplication_pruning (
    client integer NOT NULL,
    pruning_offset character varying NOT NULL COLLATE pg_catalog."C",
    publication_time bigint NOT NULL
);

CREATE VIEW debug.par_command_deduplication_pruning AS
 SELECT client,
    pruning_offset,
    debug.canton_timestamp(publication_time) AS publication_time
   FROM public.par_command_deduplication_pruning;

CREATE TABLE public.par_commitment_checkpoint_snapshot (
    synchronizer_idx integer NOT NULL,
    stakeholders_hash bytea NOT NULL,
    stakeholders integer[] NOT NULL,
    commitment bytea NOT NULL
);

CREATE VIEW debug.par_commitment_checkpoint_snapshot AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    lower(encode(stakeholders_hash, 'hex'::text)) AS stakeholders_hash,
    stakeholders,
    commitment
   FROM public.par_commitment_checkpoint_snapshot;

CREATE TABLE public.par_commitment_checkpoint_snapshot_time (
    synchronizer_idx integer NOT NULL,
    ts bigint NOT NULL,
    tie_breaker bigint NOT NULL
);

CREATE VIEW debug.par_commitment_checkpoint_snapshot_time AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    debug.canton_timestamp(ts) AS ts,
    tie_breaker
   FROM public.par_commitment_checkpoint_snapshot_time;

CREATE TABLE public.par_commitment_pruning (
    synchronizer_idx integer NOT NULL,
    phase public.pruning_phase NOT NULL,
    ts bigint NOT NULL,
    succeeded bigint
);

CREATE VIEW debug.par_commitment_pruning AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    phase,
    debug.canton_timestamp(ts) AS ts,
    debug.canton_timestamp(succeeded) AS succeeded
   FROM public.par_commitment_pruning;

CREATE TABLE public.par_commitment_queue (
    synchronizer_idx integer NOT NULL,
    sender character varying NOT NULL COLLATE pg_catalog."C",
    counter_participant character varying NOT NULL COLLATE pg_catalog."C",
    from_exclusive bigint NOT NULL,
    to_inclusive bigint NOT NULL,
    commitment bytea NOT NULL,
    CONSTRAINT check_nonempty_interval_queue CHECK ((to_inclusive > from_exclusive))
);

CREATE VIEW debug.par_commitment_queue AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    sender,
    counter_participant,
    debug.canton_timestamp(from_exclusive) AS from_exclusive,
    debug.canton_timestamp(to_inclusive) AS to_inclusive,
    commitment
   FROM public.par_commitment_queue;

CREATE TABLE public.par_commitment_reinitialization (
    synchronizer_idx integer NOT NULL,
    ts_reinit_ongoing bigint,
    ts_reinit_completed bigint
);

CREATE VIEW debug.par_commitment_reinitialization AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    debug.canton_timestamp(ts_reinit_ongoing) AS ts_reinit_ongoing,
    debug.canton_timestamp(ts_reinit_completed) AS ts_reinit_completed
   FROM public.par_commitment_reinitialization;

CREATE TABLE public.par_commitment_snapshot (
    synchronizer_idx integer NOT NULL,
    stakeholders_hash bytea NOT NULL,
    stakeholders integer[] NOT NULL,
    commitment bytea NOT NULL
);

CREATE VIEW debug.par_commitment_snapshot AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    lower(encode(stakeholders_hash, 'hex'::text)) AS stakeholders_hash,
    stakeholders,
    commitment
   FROM public.par_commitment_snapshot;

CREATE TABLE public.par_commitment_snapshot_time (
    synchronizer_idx integer NOT NULL,
    ts bigint NOT NULL,
    tie_breaker bigint NOT NULL
);

CREATE VIEW debug.par_commitment_snapshot_time AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    debug.canton_timestamp(ts) AS ts,
    tie_breaker
   FROM public.par_commitment_snapshot_time;

CREATE TABLE public.par_computed_acs_commitments (
    synchronizer_idx integer NOT NULL,
    counter_participant character varying NOT NULL COLLATE pg_catalog."C",
    from_exclusive bigint NOT NULL,
    to_inclusive bigint NOT NULL,
    commitment bytea NOT NULL,
    CONSTRAINT check_nonempty_interval_computed CHECK ((to_inclusive > from_exclusive))
);

CREATE VIEW debug.par_computed_acs_commitments AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    counter_participant,
    debug.canton_timestamp(from_exclusive) AS from_exclusive,
    debug.canton_timestamp(to_inclusive) AS to_inclusive,
    commitment
   FROM public.par_computed_acs_commitments;

CREATE TABLE public.par_contracts (
    internal_contract_id bigint NOT NULL,
    contract_id bytea NOT NULL,
    instance bytea NOT NULL,
    package_id character varying NOT NULL COLLATE pg_catalog."C",
    template_id character varying NOT NULL COLLATE pg_catalog."C"
);

CREATE VIEW debug.par_contracts AS
 SELECT internal_contract_id,
    lower(encode(contract_id, 'hex'::text)) AS contract_id,
    instance,
    package_id,
    template_id
   FROM public.par_contracts;

CREATE TABLE public.par_daml_packages (
    package_id character varying NOT NULL COLLATE pg_catalog."C",
    data bytea NOT NULL,
    name character varying NOT NULL COLLATE pg_catalog."C",
    version character varying NOT NULL COLLATE pg_catalog."C",
    uploaded_at bigint NOT NULL,
    package_size bigint NOT NULL
);

CREATE VIEW debug.par_daml_packages AS
 SELECT package_id,
    data,
    name,
    version,
    uploaded_at,
    package_size
   FROM public.par_daml_packages;

CREATE TABLE public.par_dar_packages (
    main_package_id character varying NOT NULL COLLATE pg_catalog."C",
    package_id character varying NOT NULL COLLATE pg_catalog."C"
);

CREATE VIEW debug.par_dar_packages AS
 SELECT main_package_id,
    package_id
   FROM public.par_dar_packages;

CREATE TABLE public.par_dars (
    main_package_id character varying NOT NULL COLLATE pg_catalog."C",
    data bytea NOT NULL,
    description character varying COLLATE pg_catalog."C",
    name character varying NOT NULL COLLATE pg_catalog."C",
    version character varying NOT NULL COLLATE pg_catalog."C"
);

CREATE VIEW debug.par_dars AS
 SELECT main_package_id,
    data,
    description,
    name,
    version
   FROM public.par_dars;

CREATE TABLE public.par_fresh_submitted_transaction (
    physical_synchronizer_idx integer NOT NULL,
    root_hash_hex character varying NOT NULL COLLATE pg_catalog."C",
    request_id bigint NOT NULL,
    max_sequencing_time bigint NOT NULL
);

CREATE VIEW debug.par_fresh_submitted_transaction AS
 SELECT debug.resolve_common_static_string(physical_synchronizer_idx) AS physical_synchronizer_idx,
    root_hash_hex,
    debug.canton_timestamp(request_id) AS request_id,
    debug.canton_timestamp(max_sequencing_time) AS max_sequencing_time
   FROM public.par_fresh_submitted_transaction;

CREATE TABLE public.par_fresh_submitted_transaction_pruning (
    physical_synchronizer_idx integer NOT NULL,
    phase public.pruning_phase NOT NULL,
    ts bigint NOT NULL,
    succeeded bigint
);

CREATE VIEW debug.par_fresh_submitted_transaction_pruning AS
 SELECT debug.resolve_common_static_string(physical_synchronizer_idx) AS physical_synchronizer_idx,
    phase,
    debug.canton_timestamp(ts) AS ts,
    debug.canton_timestamp(succeeded) AS succeeded
   FROM public.par_fresh_submitted_transaction_pruning;

CREATE TABLE public.par_in_flight_submission (
    change_id_hash character varying NOT NULL COLLATE pg_catalog."C",
    submission_id character varying COLLATE pg_catalog."C",
    submission_synchronizer_id character varying NOT NULL COLLATE pg_catalog."C",
    message_id character varying NOT NULL COLLATE pg_catalog."C",
    sequencing_timeout bigint,
    sequencing_time bigint,
    tracking_data bytea,
    root_hash_hex character varying COLLATE pg_catalog."C",
    trace_context bytea NOT NULL
);

CREATE VIEW debug.par_in_flight_submission AS
 SELECT change_id_hash,
    submission_id,
    submission_synchronizer_id,
    message_id,
    debug.canton_timestamp(sequencing_timeout) AS sequencing_timeout,
    debug.canton_timestamp(sequencing_time) AS sequencing_time,
    tracking_data,
    root_hash_hex,
    trace_context
   FROM public.par_in_flight_submission;

CREATE TABLE public.par_journal_requests (
    physical_synchronizer_idx integer NOT NULL,
    request_counter bigint NOT NULL,
    request_state_index smallint NOT NULL,
    request_timestamp bigint NOT NULL,
    commit_time bigint
);

CREATE VIEW debug.par_journal_requests AS
 SELECT debug.resolve_common_static_string(physical_synchronizer_idx) AS physical_synchronizer_idx,
    request_counter,
    request_state_index,
    debug.canton_timestamp(request_timestamp) AS request_timestamp,
    debug.canton_timestamp(commit_time) AS commit_time
   FROM public.par_journal_requests;

CREATE TABLE public.par_last_computed_acs_commitments (
    synchronizer_idx integer NOT NULL,
    ts bigint NOT NULL
);

CREATE VIEW debug.par_last_computed_acs_commitments AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    debug.canton_timestamp(ts) AS ts
   FROM public.par_last_computed_acs_commitments;

CREATE TABLE public.par_outstanding_acs_commitments (
    synchronizer_idx integer NOT NULL,
    from_exclusive bigint NOT NULL,
    to_inclusive bigint NOT NULL,
    counter_participant character varying NOT NULL COLLATE pg_catalog."C",
    matching_state smallint NOT NULL,
    multi_hosted_cleared boolean DEFAULT false NOT NULL,
    CONSTRAINT check_nonempty_interval_outstanding CHECK ((to_inclusive > from_exclusive))
);

CREATE VIEW debug.par_outstanding_acs_commitments AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    counter_participant,
    debug.canton_timestamp(from_exclusive) AS from_exclusive,
    debug.canton_timestamp(to_inclusive) AS to_inclusive,
    matching_state,
    multi_hosted_cleared
   FROM public.par_outstanding_acs_commitments;

CREATE TABLE public.par_pruning_operation (
    name character varying NOT NULL COLLATE pg_catalog."C",
    started_up_to_inclusive bigint,
    completed_up_to_inclusive bigint
);

CREATE VIEW debug.par_pruning_operation AS
 SELECT name,
    debug.canton_timestamp(started_up_to_inclusive) AS started_up_to_inclusive,
    debug.canton_timestamp(completed_up_to_inclusive) AS completed_up_to_inclusive
   FROM public.par_pruning_operation;

CREATE TABLE public.par_pruning_schedules (
    lock character(1) DEFAULT 'X'::bpchar NOT NULL,
    cron character varying NOT NULL COLLATE pg_catalog."C",
    max_duration bigint NOT NULL,
    retention bigint NOT NULL,
    prune_internally_only boolean DEFAULT false NOT NULL,
    CONSTRAINT par_pruning_schedules_lock_check CHECK ((lock = 'X'::bpchar))
);

CREATE VIEW debug.par_pruning_schedules AS
 SELECT lock,
    cron,
    max_duration,
    retention,
    prune_internally_only
   FROM public.par_pruning_schedules;

CREATE TABLE public.par_reassignments (
    target_synchronizer_idx integer NOT NULL,
    source_synchronizer_idx integer NOT NULL,
    reassignment_id character varying NOT NULL COLLATE pg_catalog."C",
    unassignment_global_offset bigint,
    assignment_global_offset bigint,
    unassignment_timestamp bigint NOT NULL,
    unassignment_data bytea,
    assignment_timestamp bigint,
    stakeholders character varying[] NOT NULL,
    incomplete_last_stakeholder_offboarded_target_offset bigint
);

CREATE VIEW debug.par_reassignments AS
 SELECT debug.resolve_common_static_string(target_synchronizer_idx) AS target_synchronizer_idx,
    debug.resolve_common_static_string(source_synchronizer_idx) AS source_synchronizer_idx,
    reassignment_id,
    unassignment_global_offset,
    assignment_global_offset,
    debug.canton_timestamp(unassignment_timestamp) AS unassignment_timestamp,
    unassignment_data,
    stakeholders,
    debug.canton_timestamp(assignment_timestamp) AS assignment_timestamp,
    incomplete_last_stakeholder_offboarded_target_offset
   FROM public.par_reassignments;

CREATE TABLE public.par_received_acs_commitments (
    synchronizer_idx integer NOT NULL,
    sender character varying NOT NULL COLLATE pg_catalog."C",
    from_exclusive bigint NOT NULL,
    to_inclusive bigint NOT NULL,
    signed_commitment bytea NOT NULL,
    CONSTRAINT check_to_after_from CHECK ((to_inclusive > from_exclusive))
);

CREATE VIEW debug.par_received_acs_commitments AS
 SELECT debug.resolve_common_static_string(synchronizer_idx) AS synchronizer_idx,
    sender,
    debug.canton_timestamp(from_exclusive) AS from_exclusive,
    debug.canton_timestamp(to_inclusive) AS to_inclusive,
    signed_commitment
   FROM public.par_received_acs_commitments;

CREATE TABLE public.par_registered_synchronizers (
    physical_synchronizer_id character varying NOT NULL COLLATE pg_catalog."C",
    synchronizer_alias character varying NOT NULL COLLATE pg_catalog."C"
);

CREATE VIEW debug.par_registered_synchronizers AS
 SELECT synchronizer_alias,
    physical_synchronizer_id
   FROM public.par_registered_synchronizers;

CREATE TABLE public.par_settings (
    client integer NOT NULL,
    max_infight_validation_requests integer,
    max_submission_rate integer,
    max_deduplication_duration bytea,
    max_submission_burst_factor double precision DEFAULT 0.5 NOT NULL
);

CREATE VIEW debug.par_settings AS
 SELECT client,
    max_infight_validation_requests,
    max_submission_rate,
    max_deduplication_duration,
    max_submission_burst_factor
   FROM public.par_settings;

CREATE TABLE public.par_synchronizer_connection_configs (
    synchronizer_alias character varying NOT NULL COLLATE pg_catalog."C",
    physical_synchronizer_id character varying COLLATE pg_catalog."C",
    empty_if_null_physical_synchronizer_id character varying GENERATED ALWAYS AS (
CASE
    WHEN (physical_synchronizer_id IS NULL) THEN ''::character varying
    ELSE physical_synchronizer_id
END) STORED NOT NULL COLLATE pg_catalog."C",
    config bytea NOT NULL,
    status character(1) DEFAULT 'A'::bpchar NOT NULL,
    synchronizer_predecessor bytea
);

CREATE VIEW debug.par_synchronizer_connection_configs AS
 SELECT synchronizer_alias,
    physical_synchronizer_id,
    empty_if_null_physical_synchronizer_id,
    config,
    status,
    synchronizer_predecessor
   FROM public.par_synchronizer_connection_configs;

CREATE TABLE public.par_synchronizer_connectivity_status (
    physical_synchronizer_id character varying NOT NULL COLLATE pg_catalog."C",
    params bytea NOT NULL,
    is_topology_initialized boolean DEFAULT false NOT NULL
);

CREATE VIEW debug.par_synchronizer_connectivity_status AS
 SELECT physical_synchronizer_id,
    params,
    is_topology_initialized
   FROM public.par_synchronizer_connectivity_status;

CREATE TABLE public.par_traffic_enforcement_balance (
    account_id character varying NOT NULL COLLATE pg_catalog."C",
    event_sequence_nb bigint NOT NULL,
    total_debits bigint NOT NULL,
    total_credits bigint NOT NULL,
    updated_at bigint NOT NULL
);

CREATE VIEW debug.par_traffic_enforcement_balance AS
 SELECT account_id,
    event_sequence_nb,
    total_debits,
    total_credits,
    debug.canton_timestamp(updated_at) AS updated_at
   FROM public.par_traffic_enforcement_balance;

CREATE TABLE public.par_traffic_enforcement_correlations (
    change_id_hash character varying NOT NULL COLLATE pg_catalog."C",
    submission_id character varying NOT NULL COLLATE pg_catalog."C",
    account_id character varying COLLATE pg_catalog."C",
    "timestamp" bigint NOT NULL
);

CREATE VIEW debug.par_traffic_enforcement_correlations AS
 SELECT change_id_hash,
    submission_id,
    account_id,
    debug.canton_timestamp("timestamp") AS "timestamp"
   FROM public.par_traffic_enforcement_correlations;

CREATE TABLE public.par_traffic_enforcement_event (
    sequence_nb bigint NOT NULL,
    event_source smallint NOT NULL,
    event_type smallint NOT NULL,
    event_id character varying NOT NULL COLLATE pg_catalog."C",
    account_id character varying NOT NULL COLLATE pg_catalog."C",
    amount bigint NOT NULL,
    "timestamp" bigint NOT NULL
);

CREATE VIEW debug.par_traffic_enforcement_event AS
 SELECT sequence_nb,
    event_source,
    event_type,
    event_id,
    account_id,
    amount,
    debug.canton_timestamp("timestamp") AS "timestamp"
   FROM public.par_traffic_enforcement_event;

CREATE TABLE public.pekko_projection_management (
    projection_name character varying NOT NULL COLLATE pg_catalog."C",
    projection_key character varying NOT NULL COLLATE pg_catalog."C",
    paused boolean NOT NULL,
    last_updated bigint NOT NULL
);

CREATE VIEW debug.pekko_projection_management AS
 SELECT projection_name,
    projection_key,
    paused,
    last_updated
   FROM public.pekko_projection_management;

CREATE TABLE public.pekko_projection_offset_store (
    projection_name character varying NOT NULL COLLATE pg_catalog."C",
    projection_key character varying NOT NULL COLLATE pg_catalog."C",
    current_offset character varying NOT NULL COLLATE pg_catalog."C",
    manifest character varying NOT NULL COLLATE pg_catalog."C",
    mergeable boolean NOT NULL,
    last_updated bigint NOT NULL
);

CREATE VIEW debug.pekko_projection_offset_store AS
 SELECT projection_name,
    projection_key,
    current_offset,
    manifest,
    mergeable,
    last_updated
   FROM public.pekko_projection_offset_store;

CREATE TABLE public.seq_block_height (
    height bigint NOT NULL,
    latest_event_ts bigint NOT NULL,
    latest_sequencer_event_ts bigint,
    latest_pending_topology_ts bigint,
    CONSTRAINT seq_block_height_height_check CHECK ((height >= '-1'::integer))
)
WITH (autovacuum_vacuum_scale_factor='0.0', autovacuum_vacuum_threshold='10000', autovacuum_vacuum_cost_limit='2000', autovacuum_vacuum_cost_delay='5', autovacuum_vacuum_insert_scale_factor='0.0', autovacuum_vacuum_insert_threshold='100000', autovacuum_analyze_scale_factor='0.0', autovacuum_analyze_threshold='1000000');

CREATE VIEW debug.seq_block_height AS
 SELECT height,
    debug.canton_timestamp(latest_event_ts) AS latest_event_ts,
    debug.canton_timestamp(latest_sequencer_event_ts) AS latest_sequencer_event_ts,
    debug.canton_timestamp(latest_pending_topology_ts) AS latest_pending_topology_ts
   FROM public.seq_block_height;

CREATE TABLE public.seq_in_flight_aggregated_sender (
    aggregation_id character varying NOT NULL COLLATE pg_catalog."C",
    sender_id integer NOT NULL,
    sequencing_timestamp bigint NOT NULL,
    signatures bytea NOT NULL
)
WITH (autovacuum_vacuum_scale_factor='0.0', autovacuum_vacuum_threshold='10000', autovacuum_vacuum_cost_limit='2000', autovacuum_vacuum_cost_delay='5', autovacuum_vacuum_insert_scale_factor='0.0', autovacuum_vacuum_insert_threshold='100000', autovacuum_analyze_scale_factor='0.0', autovacuum_analyze_threshold='1000000');

CREATE VIEW debug.seq_in_flight_aggregated_sender AS
 SELECT aggregation_id,
    sender_id,
    debug.canton_timestamp(sequencing_timestamp) AS sequencing_timestamp,
    signatures
   FROM public.seq_in_flight_aggregated_sender;

CREATE TABLE public.seq_in_flight_aggregation (
    aggregation_id character varying NOT NULL COLLATE pg_catalog."C",
    max_sequencing_time bigint NOT NULL,
    aggregation_rule bytea NOT NULL
)
WITH (autovacuum_vacuum_scale_factor='0.0', autovacuum_vacuum_threshold='10000', autovacuum_vacuum_cost_limit='2000', autovacuum_vacuum_cost_delay='5', autovacuum_vacuum_insert_scale_factor='0.0', autovacuum_vacuum_insert_threshold='100000', autovacuum_analyze_scale_factor='0.0', autovacuum_analyze_threshold='1000000');

CREATE VIEW debug.seq_in_flight_aggregation AS
 SELECT aggregation_id,
    debug.canton_timestamp(max_sequencing_time) AS max_sequencing_time,
    aggregation_rule
   FROM public.seq_in_flight_aggregation;

CREATE TABLE public.seq_traffic_control_balance_updates (
    member_id integer NOT NULL,
    sequencing_timestamp bigint NOT NULL,
    balance bigint NOT NULL,
    serial bigint NOT NULL
);

CREATE VIEW debug.seq_traffic_control_balance_updates AS
 SELECT member_id,
    debug.canton_timestamp(sequencing_timestamp) AS sequencing_timestamp,
    balance,
    serial
   FROM public.seq_traffic_control_balance_updates;

CREATE TABLE public.seq_traffic_control_consumed_journal (
    member_id integer NOT NULL,
    sequencing_timestamp bigint NOT NULL,
    extra_traffic_consumed bigint NOT NULL,
    base_traffic_remainder bigint NOT NULL,
    last_consumed_cost bigint NOT NULL
)
WITH (autovacuum_vacuum_scale_factor='0.0', autovacuum_vacuum_threshold='10000', autovacuum_vacuum_cost_limit='2000', autovacuum_vacuum_cost_delay='5', autovacuum_vacuum_insert_scale_factor='0.0', autovacuum_vacuum_insert_threshold='100000', autovacuum_analyze_scale_factor='0.0', autovacuum_analyze_threshold='1000000');

CREATE VIEW debug.seq_traffic_control_consumed_journal AS
 SELECT member_id,
    debug.canton_timestamp(sequencing_timestamp) AS sequencing_timestamp,
    extra_traffic_consumed,
    base_traffic_remainder,
    last_consumed_cost
   FROM public.seq_traffic_control_consumed_journal;

CREATE TABLE public.seq_traffic_control_initial_timestamp (
    initial_timestamp bigint NOT NULL
);

CREATE VIEW debug.seq_traffic_control_initial_timestamp AS
 SELECT debug.canton_timestamp(initial_timestamp) AS initial_timestamp
   FROM public.seq_traffic_control_initial_timestamp;

CREATE TABLE public.sequencer_acknowledgements (
    member integer NOT NULL,
    ts bigint NOT NULL
);

CREATE VIEW debug.sequencer_acknowledgements AS
 SELECT debug.resolve_sequencer_member(member) AS member,
    debug.canton_timestamp(ts) AS ts
   FROM public.sequencer_acknowledgements;

CREATE TABLE public.sequencer_event_recipients (
    ts bigint NOT NULL,
    recipient_id integer NOT NULL,
    node_index smallint NOT NULL,
    is_topology_event boolean NOT NULL
)
WITH (autovacuum_vacuum_scale_factor='0.0', autovacuum_vacuum_threshold='100000', autovacuum_vacuum_cost_limit='2000', autovacuum_vacuum_cost_delay='5', autovacuum_vacuum_insert_scale_factor='0.0', autovacuum_vacuum_insert_threshold='1000000', autovacuum_analyze_scale_factor='0.0', autovacuum_analyze_threshold='10000000');

CREATE VIEW debug.sequencer_event_recipients AS
 SELECT debug.canton_timestamp(ts) AS ts,
    debug.resolve_sequencer_member(recipient_id) AS recipient_id,
    node_index,
    is_topology_event
   FROM public.sequencer_event_recipients;

CREATE TABLE public.sequencer_events (
    ts bigint NOT NULL,
    node_index smallint NOT NULL,
    event_type character(1) NOT NULL,
    message_id character varying COLLATE pg_catalog."C",
    sender integer,
    recipients integer[],
    payload_id bigint,
    trace_context bytea NOT NULL,
    error bytea,
    consumed_cost bigint,
    extra_traffic_consumed bigint,
    base_traffic_remainder bigint,
    CONSTRAINT event_type_enum CHECK ((event_type = ANY (ARRAY['D'::bpchar, 'E'::bpchar, 'R'::bpchar])))
)
WITH (autovacuum_vacuum_scale_factor='0.0', autovacuum_vacuum_threshold='10000', autovacuum_vacuum_cost_limit='2000', autovacuum_vacuum_cost_delay='5', autovacuum_vacuum_insert_scale_factor='0.0', autovacuum_vacuum_insert_threshold='100000', autovacuum_analyze_scale_factor='0.0', autovacuum_analyze_threshold='1000000');

CREATE VIEW debug.sequencer_events AS
 SELECT debug.canton_timestamp(ts) AS ts,
    node_index,
    event_type,
    message_id,
    debug.resolve_sequencer_member(sender) AS sender,
    debug.resolve_sequencer_members(recipients) AS recipients,
    payload_id,
    trace_context,
    error,
    consumed_cost,
    extra_traffic_consumed,
    base_traffic_remainder
   FROM public.sequencer_events;

CREATE TABLE public.sequencer_lower_bound (
    single_row_lock character(1) DEFAULT 'X'::bpchar NOT NULL,
    ts bigint NOT NULL,
    latest_topology_client_timestamp bigint,
    CONSTRAINT sequencer_lower_bound_single_row_lock_check CHECK ((single_row_lock = 'X'::bpchar))
);

CREATE VIEW debug.sequencer_lower_bound AS
 SELECT single_row_lock,
    debug.canton_timestamp(ts) AS ts,
    debug.canton_timestamp(latest_topology_client_timestamp) AS latest_topology_client_timestamp
   FROM public.sequencer_lower_bound;

CREATE TABLE public.sequencer_members (
    member character varying NOT NULL COLLATE pg_catalog."C",
    id integer NOT NULL,
    registered_ts bigint,
    pruned_previous_event_timestamp bigint,
    status smallint DEFAULT 1 NOT NULL,
    onboarded_ts bigint
);

CREATE VIEW debug.sequencer_members AS
 SELECT member,
    id,
    debug.canton_timestamp(registered_ts) AS registered_ts,
    debug.canton_timestamp(pruned_previous_event_timestamp) AS pruned_previous_event_timestamp,
    status,
    debug.canton_timestamp(onboarded_ts) AS onboarded_ts
   FROM public.sequencer_members;

CREATE TABLE public.sequencer_payloads (
    id bigint NOT NULL,
    instance_discriminator character varying NOT NULL COLLATE pg_catalog."C",
    content bytea NOT NULL
)
WITH (autovacuum_vacuum_scale_factor='0.0', autovacuum_vacuum_threshold='10000', autovacuum_vacuum_cost_limit='2000', autovacuum_vacuum_cost_delay='5', autovacuum_vacuum_insert_scale_factor='0.0', autovacuum_vacuum_insert_threshold='100000', autovacuum_analyze_scale_factor='0.0', autovacuum_analyze_threshold='1000000');

CREATE VIEW debug.sequencer_payloads AS
 SELECT id,
    instance_discriminator,
    content
   FROM public.sequencer_payloads;

CREATE TABLE public.sequencer_synchronizer_configuration (
    lock character(1) DEFAULT 'X'::bpchar NOT NULL,
    physical_synchronizer_id character varying NOT NULL COLLATE pg_catalog."C",
    static_synchronizer_parameters bytea NOT NULL,
    CONSTRAINT sequencer_synchronizer_configuration_lock_check CHECK ((lock = 'X'::bpchar))
);

CREATE VIEW debug.sequencer_synchronizer_configuration AS
 SELECT lock,
    physical_synchronizer_id,
    static_synchronizer_parameters
   FROM public.sequencer_synchronizer_configuration;

CREATE TABLE public.sequencer_watermarks (
    node_index integer NOT NULL,
    watermark_ts bigint NOT NULL,
    sequencer_online boolean NOT NULL
);

CREATE VIEW debug.sequencer_watermarks AS
 SELECT node_index,
    debug.canton_timestamp(watermark_ts) AS watermark_ts,
    sequencer_online
   FROM public.sequencer_watermarks;

ALTER TABLE public.common_static_strings ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.common_static_strings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

ALTER TABLE public.common_topology_transactions ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.common_topology_transactions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.flyway_schema_history (
    installed_rank integer NOT NULL,
    version character varying(50),
    description character varying(200) NOT NULL,
    type character varying(20) NOT NULL,
    script character varying(1000) NOT NULL,
    checksum integer,
    installed_by character varying(100) NOT NULL,
    installed_on timestamp without time zone DEFAULT now() NOT NULL,
    execution_time integer NOT NULL,
    success boolean NOT NULL
);

ALTER TABLE public.lapi_party_records ALTER COLUMN internal_id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.lapi_party_records_internal_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

ALTER TABLE public.lapi_users ALTER COLUMN internal_id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.lapi_users_internal_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.ord_availability_batch_p0 (
    id character varying NOT NULL COLLATE pg_catalog."C",
    batch bytea NOT NULL,
    epoch_number bigint NOT NULL
);

CREATE TABLE public.ord_availability_batch_p1 (
    id character varying NOT NULL COLLATE pg_catalog."C",
    batch bytea NOT NULL,
    epoch_number bigint NOT NULL
);

CREATE TABLE public.ord_epochs_p0 (
    epoch_number bigint NOT NULL,
    start_block_number bigint NOT NULL,
    epoch_length bigint NOT NULL,
    topology_ts bigint NOT NULL,
    in_progress boolean NOT NULL
);

CREATE TABLE public.ord_epochs_p1 (
    epoch_number bigint NOT NULL,
    start_block_number bigint NOT NULL,
    epoch_length bigint NOT NULL,
    topology_ts bigint NOT NULL,
    in_progress boolean NOT NULL
);

CREATE TABLE public.ord_leader_selection_state_p0 (
    epoch_number bigint NOT NULL,
    state bytea NOT NULL
);

CREATE TABLE public.ord_leader_selection_state_p1 (
    epoch_number bigint NOT NULL,
    state bytea NOT NULL
);

CREATE TABLE public.ord_metadata_output_blocks_p0 (
    epoch_number bigint NOT NULL,
    block_number bigint NOT NULL,
    bft_ts bigint NOT NULL,
    CONSTRAINT ord_metadata_output_blocks_p0_lb CHECK (((bft_ts >= 1000) AND (block_number >= 0)))
);

CREATE TABLE public.ord_metadata_output_blocks_p1 (
    epoch_number bigint NOT NULL,
    block_number bigint NOT NULL,
    bft_ts bigint NOT NULL
);

CREATE TABLE public.ord_metadata_output_epochs_p0 (
    epoch_number bigint NOT NULL,
    could_alter_ordering_topology boolean NOT NULL
);

CREATE TABLE public.ord_metadata_output_epochs_p1 (
    epoch_number bigint NOT NULL,
    could_alter_ordering_topology boolean NOT NULL
);

CREATE TABLE public.ord_pbft_messages_completed_p0 (
    block_number bigint NOT NULL,
    epoch_number bigint NOT NULL,
    message bytea NOT NULL,
    discriminator smallint NOT NULL,
    from_sequencer_id character varying NOT NULL COLLATE pg_catalog."C"
);

CREATE TABLE public.ord_pbft_messages_completed_p1 (
    block_number bigint NOT NULL,
    epoch_number bigint NOT NULL,
    message bytea NOT NULL,
    discriminator smallint NOT NULL,
    from_sequencer_id character varying NOT NULL COLLATE pg_catalog."C"
);

CREATE TABLE public.ord_pbft_messages_in_progress_p0 (
    block_number bigint NOT NULL,
    epoch_number bigint NOT NULL,
    view_number bigint NOT NULL,
    message bytea NOT NULL,
    discriminator smallint NOT NULL,
    from_sequencer_id character varying NOT NULL COLLATE pg_catalog."C"
);

CREATE TABLE public.ord_pbft_messages_in_progress_p1 (
    block_number bigint NOT NULL,
    epoch_number bigint NOT NULL,
    view_number bigint NOT NULL,
    message bytea NOT NULL,
    discriminator smallint NOT NULL,
    from_sequencer_id character varying NOT NULL COLLATE pg_catalog."C"
);

ALTER TABLE public.par_contracts ALTER COLUMN internal_contract_id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.par_contracts_internal_contract_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

ALTER TABLE public.par_traffic_enforcement_event ALTER COLUMN sequence_nb ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.par_traffic_enforcement_event_sequence_nb_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE SEQUENCE public.participant_event_publisher_local_offsets
    START WITH 0
    INCREMENT BY 1
    MINVALUE 0
    NO MAXVALUE
    CACHE 1;

ALTER TABLE public.sequencer_members ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.sequencer_members_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

ALTER TABLE ONLY public.ord_availability_batch ATTACH PARTITION public.ord_availability_batch_p0 FOR VALUES FROM ('-1') TO ('1500');

ALTER TABLE ONLY public.ord_availability_batch ATTACH PARTITION public.ord_availability_batch_p1 FOR VALUES FROM ('1500') TO ('3000');

ALTER TABLE ONLY public.ord_epochs ATTACH PARTITION public.ord_epochs_p0 FOR VALUES FROM ('-1') TO ('1500');

ALTER TABLE ONLY public.ord_epochs ATTACH PARTITION public.ord_epochs_p1 FOR VALUES FROM ('1500') TO ('3000');

ALTER TABLE ONLY public.ord_leader_selection_state ATTACH PARTITION public.ord_leader_selection_state_p0 FOR VALUES FROM ('-1') TO ('1500');

ALTER TABLE ONLY public.ord_leader_selection_state ATTACH PARTITION public.ord_leader_selection_state_p1 FOR VALUES FROM ('1500') TO ('3000');

ALTER TABLE ONLY public.ord_metadata_output_blocks ATTACH PARTITION public.ord_metadata_output_blocks_p0 FOR VALUES FROM ('-1') TO ('1500');

ALTER TABLE ONLY public.ord_metadata_output_blocks ATTACH PARTITION public.ord_metadata_output_blocks_p1 FOR VALUES FROM ('1500') TO ('3000');

ALTER TABLE ONLY public.ord_metadata_output_epochs ATTACH PARTITION public.ord_metadata_output_epochs_p0 FOR VALUES FROM ('-1') TO ('1500');

ALTER TABLE ONLY public.ord_metadata_output_epochs ATTACH PARTITION public.ord_metadata_output_epochs_p1 FOR VALUES FROM ('1500') TO ('3000');

ALTER TABLE ONLY public.ord_pbft_messages_completed ATTACH PARTITION public.ord_pbft_messages_completed_p0 FOR VALUES FROM ('-1') TO ('1500');

ALTER TABLE ONLY public.ord_pbft_messages_completed ATTACH PARTITION public.ord_pbft_messages_completed_p1 FOR VALUES FROM ('1500') TO ('3000');

ALTER TABLE ONLY public.ord_pbft_messages_in_progress ATTACH PARTITION public.ord_pbft_messages_in_progress_p0 FOR VALUES FROM ('-1') TO ('1500');

ALTER TABLE ONLY public.ord_pbft_messages_in_progress ATTACH PARTITION public.ord_pbft_messages_in_progress_p1 FOR VALUES FROM ('1500') TO ('3000');

ALTER TABLE ONLY public.acs_no_wait_counter_participants
    ADD CONSTRAINT acs_no_wait_counter_participants_pkey PRIMARY KEY (synchronizer_id, participant_id);

ALTER TABLE ONLY public.acs_slow_counter_participants
    ADD CONSTRAINT acs_slow_counter_participants_pkey PRIMARY KEY (synchronizer_id, participant_id);

ALTER TABLE ONLY public.acs_slow_participant_config
    ADD CONSTRAINT acs_slow_participant_config_pkey PRIMARY KEY (synchronizer_id);

ALTER TABLE ONLY public.common_crypto_private_keys
    ADD CONSTRAINT common_crypto_private_keys_pkey PRIMARY KEY (key_id);

ALTER TABLE ONLY public.common_crypto_public_keys
    ADD CONSTRAINT common_crypto_public_keys_pkey PRIMARY KEY (key_id);

ALTER TABLE ONLY public.common_head_sequencer_counters
    ADD CONSTRAINT common_head_sequencer_counters_pkey PRIMARY KEY (physical_synchronizer_idx);

ALTER TABLE ONLY public.common_kms_metadata_store
    ADD CONSTRAINT common_kms_metadata_store_pkey PRIMARY KEY (fingerprint);

ALTER TABLE ONLY public.common_node_id
    ADD CONSTRAINT common_node_id_pkey PRIMARY KEY (identifier, namespace);

ALTER TABLE ONLY public.common_pending_operations
    ADD CONSTRAINT common_pending_operations_pkey PRIMARY KEY (synchronizer_id, operation_key, operation_name);

ALTER TABLE ONLY public.common_pruning_schedules
    ADD CONSTRAINT common_pruning_schedules_pkey PRIMARY KEY (node_type);

ALTER TABLE ONLY public.common_sequenced_event_store_pruning
    ADD CONSTRAINT common_sequenced_event_store_pruning_pkey PRIMARY KEY (physical_synchronizer_idx);

ALTER TABLE ONLY public.common_sequenced_events
    ADD CONSTRAINT common_sequenced_events_pkey PRIMARY KEY (physical_synchronizer_idx, ts);

ALTER TABLE ONLY public.common_static_strings
    ADD CONSTRAINT common_static_strings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.common_static_strings
    ADD CONSTRAINT common_static_strings_string_source_key UNIQUE (string, source);

ALTER TABLE ONLY public.common_topology_dispatching
    ADD CONSTRAINT common_topology_dispatching_pkey PRIMARY KEY (store_id);

ALTER TABLE ONLY public.common_topology_transactions
    ADD CONSTRAINT common_topology_transactions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.common_topology_transactions
    ADD CONSTRAINT common_topology_transactions_store_id_valid_from_batch_idx_key UNIQUE (store_id, valid_from, batch_idx);

ALTER TABLE ONLY public.flyway_schema_history
    ADD CONSTRAINT flyway_schema_history_pk PRIMARY KEY (installed_rank);

ALTER TABLE ONLY public.lapi_identity_provider_config
    ADD CONSTRAINT lapi_identity_provider_config_issuer_key UNIQUE (issuer);

ALTER TABLE ONLY public.lapi_identity_provider_config
    ADD CONSTRAINT lapi_identity_provider_config_pkey PRIMARY KEY (identity_provider_id);

ALTER TABLE ONLY public.lapi_ledger_end_synchronizer_index
    ADD CONSTRAINT lapi_ledger_end_synchronizer_index_pkey PRIMARY KEY (synchronizer_id);

ALTER TABLE ONLY public.lapi_party_record_annotations
    ADD CONSTRAINT lapi_party_record_annotations_internal_id_name_key UNIQUE (internal_id, name);

ALTER TABLE ONLY public.lapi_party_records
    ADD CONSTRAINT lapi_party_records_party_key UNIQUE (party);

ALTER TABLE ONLY public.lapi_party_records
    ADD CONSTRAINT lapi_party_records_pkey PRIMARY KEY (internal_id);

ALTER TABLE ONLY public.lapi_string_interning
    ADD CONSTRAINT lapi_string_interning_pkey PRIMARY KEY (internal_id);

ALTER TABLE ONLY public.lapi_user_annotations
    ADD CONSTRAINT lapi_user_annotations_internal_id_name_key UNIQUE (internal_id, name);

ALTER TABLE ONLY public.lapi_user_rights
    ADD CONSTRAINT lapi_user_rights_user_internal_id_user_right_for_party_key UNIQUE (user_internal_id, user_right, for_party);

ALTER TABLE ONLY public.lapi_users
    ADD CONSTRAINT lapi_users_pkey PRIMARY KEY (internal_id);

ALTER TABLE ONLY public.lapi_users
    ADD CONSTRAINT lapi_users_user_id_key UNIQUE (user_id);

ALTER TABLE ONLY public.med_response_aggregations
    ADD CONSTRAINT med_response_aggregations_pkey PRIMARY KEY (request_id);

ALTER TABLE ONLY public.mediator_synchronizer_configuration
    ADD CONSTRAINT mediator_synchronizer_configuration_pkey PRIMARY KEY (lock);

ALTER TABLE ONLY public.ord_availability_batch
    ADD CONSTRAINT ord_availability_batch_pkey1 PRIMARY KEY (epoch_number, id);

ALTER TABLE ONLY public.ord_availability_batch_p0
    ADD CONSTRAINT ord_availability_batch_p0_pkey PRIMARY KEY (epoch_number, id);

ALTER TABLE ONLY public.ord_availability_batch_p1
    ADD CONSTRAINT ord_availability_batch_p1_pkey PRIMARY KEY (epoch_number, id);

ALTER TABLE ONLY public.ord_epochs
    ADD CONSTRAINT ord_epochs_pkey1 PRIMARY KEY (epoch_number);

ALTER TABLE ONLY public.ord_epochs_p0
    ADD CONSTRAINT ord_epochs_p0_pkey PRIMARY KEY (epoch_number);

ALTER TABLE ONLY public.ord_epochs_p1
    ADD CONSTRAINT ord_epochs_p1_pkey PRIMARY KEY (epoch_number);

ALTER TABLE ONLY public.ord_leader_selection_state
    ADD CONSTRAINT ord_leader_selection_state_pkey1 PRIMARY KEY (epoch_number);

ALTER TABLE ONLY public.ord_leader_selection_state_p0
    ADD CONSTRAINT ord_leader_selection_state_p0_pkey PRIMARY KEY (epoch_number);

ALTER TABLE ONLY public.ord_leader_selection_state_p1
    ADD CONSTRAINT ord_leader_selection_state_p1_pkey PRIMARY KEY (epoch_number);

ALTER TABLE ONLY public.ord_metadata_output_blocks
    ADD CONSTRAINT ord_metadata_output_blocks_pkey1 PRIMARY KEY (epoch_number, block_number);

ALTER TABLE ONLY public.ord_metadata_output_blocks_p0
    ADD CONSTRAINT ord_metadata_output_blocks_p0_pkey PRIMARY KEY (epoch_number, block_number);

ALTER TABLE ONLY public.ord_metadata_output_blocks_p1
    ADD CONSTRAINT ord_metadata_output_blocks_p1_pkey PRIMARY KEY (epoch_number, block_number);

ALTER TABLE ONLY public.ord_metadata_output_epochs
    ADD CONSTRAINT ord_metadata_output_epochs_pkey1 PRIMARY KEY (epoch_number);

ALTER TABLE ONLY public.ord_metadata_output_epochs_p0
    ADD CONSTRAINT ord_metadata_output_epochs_p0_pkey PRIMARY KEY (epoch_number);

ALTER TABLE ONLY public.ord_metadata_output_epochs_p1
    ADD CONSTRAINT ord_metadata_output_epochs_p1_pkey PRIMARY KEY (epoch_number);

ALTER TABLE ONLY public.ord_output_lower_bound
    ADD CONSTRAINT ord_output_lower_bound_pkey PRIMARY KEY (single_row_lock);

ALTER TABLE ONLY public.ord_p2p_endpoints
    ADD CONSTRAINT ord_p2p_endpoints_pkey PRIMARY KEY (address, port, transport_security);

ALTER TABLE ONLY public.ord_partition_size_history
    ADD CONSTRAINT ord_partition_size_history_pkey PRIMARY KEY (epoch_number);

ALTER TABLE ONLY public.ord_pbft_messages_completed
    ADD CONSTRAINT ord_pbft_messages_completed_pkey1 PRIMARY KEY (epoch_number, block_number, from_sequencer_id, discriminator);

ALTER TABLE ONLY public.ord_pbft_messages_completed_p0
    ADD CONSTRAINT ord_pbft_messages_completed_p0_pkey PRIMARY KEY (epoch_number, block_number, from_sequencer_id, discriminator);

ALTER TABLE ONLY public.ord_pbft_messages_completed_p1
    ADD CONSTRAINT ord_pbft_messages_completed_p1_pkey PRIMARY KEY (epoch_number, block_number, from_sequencer_id, discriminator);

ALTER TABLE ONLY public.ord_pbft_messages_in_progress
    ADD CONSTRAINT ord_pbft_messages_in_progress_pkey1 PRIMARY KEY (epoch_number, block_number, view_number, from_sequencer_id, discriminator);

ALTER TABLE ONLY public.ord_pbft_messages_in_progress_p0
    ADD CONSTRAINT ord_pbft_messages_in_progress_p0_pkey PRIMARY KEY (epoch_number, block_number, view_number, from_sequencer_id, discriminator);

ALTER TABLE ONLY public.ord_pbft_messages_in_progress_p1
    ADD CONSTRAINT ord_pbft_messages_in_progress_p1_pkey PRIMARY KEY (epoch_number, block_number, view_number, from_sequencer_id, discriminator);

ALTER TABLE ONLY public.ord_pruning_schedules
    ADD CONSTRAINT ord_pruning_schedules_pkey PRIMARY KEY (lock);

ALTER TABLE ONLY public.par_acs_commitment_period_match
    ADD CONSTRAINT par_acs_commitment_period_match_pkey PRIMARY KEY (synchronizer_idx, participant_id, to_inclusive);

ALTER TABLE ONLY public.par_acs_commitment_period_mismatch
    ADD CONSTRAINT par_acs_commitment_period_mismatch_pkey PRIMARY KEY (synchronizer_idx, participant_id, to_inclusive);

ALTER TABLE ONLY public.par_acs_commitment_period_outstanding
    ADD CONSTRAINT par_acs_commitment_period_outstanding_pkey PRIMARY KEY (synchronizer_idx, participant_id, to_inclusive);

ALTER TABLE ONLY public.par_acs_commitment_period_pruning
    ADD CONSTRAINT par_acs_commitment_period_pruning_pkey PRIMARY KEY (synchronizer_idx);

ALTER TABLE ONLY public.par_acs_commitment_period_watermark
    ADD CONSTRAINT par_acs_commitment_period_watermark_pkey PRIMARY KEY (synchronizer_idx);

ALTER TABLE ONLY public.par_acs_commitment_sender_watermark
    ADD CONSTRAINT par_acs_commitment_sender_watermark_pkey PRIMARY KEY (synchronizer_idx);

ALTER TABLE ONLY public.par_acs_running_digests_checkpoint
    ADD CONSTRAINT par_acs_running_digests_checkpoint_pkey PRIMARY KEY (synchronizer_idx, change_offset);

ALTER TABLE ONLY public.par_acs_running_digests_pruning
    ADD CONSTRAINT par_acs_running_digests_pruning_pkey PRIMARY KEY (synchronizer_idx);

ALTER TABLE ONLY public.par_active_contract_pruning
    ADD CONSTRAINT par_active_contract_pruning_pkey PRIMARY KEY (synchronizer_idx);

ALTER TABLE ONLY public.par_active_contracts
    ADD CONSTRAINT par_active_contracts_pkey PRIMARY KEY (synchronizer_idx, contract_id, ts, repair_counter, change);

ALTER TABLE ONLY public.par_command_deduplication
    ADD CONSTRAINT par_command_deduplication_pkey PRIMARY KEY (change_id_hash);

ALTER TABLE ONLY public.par_command_deduplication_pruning
    ADD CONSTRAINT par_command_deduplication_pruning_pkey PRIMARY KEY (client);

ALTER TABLE ONLY public.par_commitment_checkpoint_snapshot
    ADD CONSTRAINT par_commitment_checkpoint_snapshot_pkey PRIMARY KEY (synchronizer_idx, stakeholders_hash);

ALTER TABLE ONLY public.par_commitment_checkpoint_snapshot_time
    ADD CONSTRAINT par_commitment_checkpoint_snapshot_time_pkey PRIMARY KEY (synchronizer_idx);

ALTER TABLE ONLY public.par_commitment_pruning
    ADD CONSTRAINT par_commitment_pruning_pkey PRIMARY KEY (synchronizer_idx);

ALTER TABLE ONLY public.par_commitment_queue
    ADD CONSTRAINT par_commitment_queue_pkey PRIMARY KEY (synchronizer_idx, sender, counter_participant, from_exclusive, to_inclusive, commitment);

ALTER TABLE ONLY public.par_commitment_reinitialization
    ADD CONSTRAINT par_commitment_reinitialization_pkey PRIMARY KEY (synchronizer_idx);

ALTER TABLE ONLY public.par_commitment_snapshot
    ADD CONSTRAINT par_commitment_snapshot_pkey PRIMARY KEY (synchronizer_idx, stakeholders_hash);

ALTER TABLE ONLY public.par_commitment_snapshot_time
    ADD CONSTRAINT par_commitment_snapshot_time_pkey PRIMARY KEY (synchronizer_idx);

ALTER TABLE ONLY public.par_computed_acs_commitments
    ADD CONSTRAINT par_computed_acs_commitments_pkey PRIMARY KEY (synchronizer_idx, counter_participant, from_exclusive, to_inclusive);

ALTER TABLE ONLY public.par_contracts
    ADD CONSTRAINT par_contracts_pkey PRIMARY KEY (contract_id) INCLUDE (internal_contract_id);

ALTER TABLE ONLY public.par_daml_packages
    ADD CONSTRAINT par_daml_packages_pkey PRIMARY KEY (package_id);

ALTER TABLE ONLY public.par_dar_packages
    ADD CONSTRAINT par_dar_packages_pkey PRIMARY KEY (main_package_id, package_id);

ALTER TABLE ONLY public.par_dars
    ADD CONSTRAINT par_dars_pkey PRIMARY KEY (main_package_id);

ALTER TABLE ONLY public.par_fresh_submitted_transaction
    ADD CONSTRAINT par_fresh_submitted_transaction_pkey PRIMARY KEY (physical_synchronizer_idx, root_hash_hex);

ALTER TABLE ONLY public.par_fresh_submitted_transaction_pruning
    ADD CONSTRAINT par_fresh_submitted_transaction_pruning_pkey PRIMARY KEY (physical_synchronizer_idx);

ALTER TABLE ONLY public.par_in_flight_submission
    ADD CONSTRAINT par_in_flight_submission_pkey PRIMARY KEY (change_id_hash);

ALTER TABLE ONLY public.par_journal_requests
    ADD CONSTRAINT par_journal_requests_pkey PRIMARY KEY (physical_synchronizer_idx, request_counter);

ALTER TABLE ONLY public.par_last_computed_acs_commitments
    ADD CONSTRAINT par_last_computed_acs_commitments_pkey PRIMARY KEY (synchronizer_idx);

ALTER TABLE ONLY public.par_pruning_operation
    ADD CONSTRAINT par_pruning_operation_pkey PRIMARY KEY (name);

ALTER TABLE ONLY public.par_pruning_schedules
    ADD CONSTRAINT par_pruning_schedules_pkey PRIMARY KEY (lock);

ALTER TABLE ONLY public.par_reassignments
    ADD CONSTRAINT par_reassignments_pkey PRIMARY KEY (target_synchronizer_idx, reassignment_id);

ALTER TABLE ONLY public.par_registered_synchronizers
    ADD CONSTRAINT par_registered_synchronizers_pkey PRIMARY KEY (physical_synchronizer_id);

ALTER TABLE ONLY public.par_settings
    ADD CONSTRAINT par_settings_pkey PRIMARY KEY (client);

ALTER TABLE ONLY public.par_synchronizer_connectivity_status
    ADD CONSTRAINT par_static_synchronizer_parameters_pkey PRIMARY KEY (physical_synchronizer_id);

ALTER TABLE ONLY public.par_synchronizer_connection_configs
    ADD CONSTRAINT par_synchronizer_connection_c_synchronizer_alias_empty_if_n_key UNIQUE (synchronizer_alias, empty_if_null_physical_synchronizer_id);

ALTER TABLE ONLY public.par_traffic_enforcement_balance
    ADD CONSTRAINT par_traffic_enforcement_balance_pkey PRIMARY KEY (account_id);

ALTER TABLE ONLY public.par_traffic_enforcement_correlations
    ADD CONSTRAINT par_traffic_enforcement_correlations_pkey PRIMARY KEY (change_id_hash, submission_id);

ALTER TABLE ONLY public.par_traffic_enforcement_event
    ADD CONSTRAINT par_traffic_enforcement_event_pkey PRIMARY KEY (event_source, event_id);

ALTER TABLE ONLY public.pekko_projection_management
    ADD CONSTRAINT pekko_projection_management_pkey PRIMARY KEY (projection_name, projection_key);

ALTER TABLE ONLY public.pekko_projection_offset_store
    ADD CONSTRAINT pekko_projection_offset_store_pkey PRIMARY KEY (projection_name, projection_key);

ALTER TABLE ONLY public.seq_block_height
    ADD CONSTRAINT seq_block_height_pkey PRIMARY KEY (height);

ALTER TABLE ONLY public.seq_in_flight_aggregated_sender
    ADD CONSTRAINT seq_in_flight_aggregated_sender_pkey PRIMARY KEY (aggregation_id, sender_id);

ALTER TABLE ONLY public.seq_in_flight_aggregation
    ADD CONSTRAINT seq_in_flight_aggregation_pkey PRIMARY KEY (aggregation_id);

ALTER TABLE ONLY public.seq_traffic_control_balance_updates
    ADD CONSTRAINT seq_traffic_control_balance_updates_pkey PRIMARY KEY (member_id, sequencing_timestamp);

ALTER TABLE ONLY public.seq_traffic_control_consumed_journal
    ADD CONSTRAINT seq_traffic_control_consumed_journal_pkey PRIMARY KEY (member_id, sequencing_timestamp);

ALTER TABLE ONLY public.seq_traffic_control_initial_timestamp
    ADD CONSTRAINT seq_traffic_control_initial_timestamp_pkey PRIMARY KEY (initial_timestamp);

ALTER TABLE ONLY public.sequencer_acknowledgements
    ADD CONSTRAINT sequencer_acknowledgements_pkey PRIMARY KEY (member);

ALTER TABLE ONLY public.sequencer_event_recipients
    ADD CONSTRAINT sequencer_event_recipients_pkey PRIMARY KEY (node_index, recipient_id, ts);

ALTER TABLE ONLY public.sequencer_events
    ADD CONSTRAINT sequencer_events_pkey PRIMARY KEY (ts);

ALTER TABLE ONLY public.sequencer_lower_bound
    ADD CONSTRAINT sequencer_lower_bound_pkey PRIMARY KEY (single_row_lock);

ALTER TABLE ONLY public.sequencer_members
    ADD CONSTRAINT sequencer_members_id_key UNIQUE (id);

ALTER TABLE ONLY public.sequencer_members
    ADD CONSTRAINT sequencer_members_pkey PRIMARY KEY (member);

ALTER TABLE ONLY public.sequencer_payloads
    ADD CONSTRAINT sequencer_payloads_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sequencer_synchronizer_configuration
    ADD CONSTRAINT sequencer_synchronizer_configuration_pkey PRIMARY KEY (lock);

ALTER TABLE ONLY public.sequencer_watermarks
    ADD CONSTRAINT sequencer_watermarks_pkey PRIMARY KEY (node_index);

CREATE INDEX account_id_timestamp_index ON public.par_traffic_enforcement_event USING btree (account_id, "timestamp");

CREATE INDEX flyway_schema_history_s_idx ON public.flyway_schema_history USING btree (success);

CREATE UNIQUE INDEX idx_common_sequenced_events_sequencer_counter ON public.common_sequenced_events USING btree (physical_synchronizer_idx, sequencer_counter);

CREATE INDEX idx_common_topology_transactions ON public.common_topology_transactions USING btree (store_id, transaction_type, namespace, identifier, valid_until, valid_from);

CREATE INDEX idx_common_topology_transactions_by_tx_hash ON public.common_topology_transactions USING btree (store_id, tx_hash, is_proposal, valid_from, valid_until, rejection_reason);

CREATE INDEX idx_common_topology_transactions_effective_changes ON public.common_topology_transactions USING btree (store_id, is_proposal, valid_from, valid_until, rejection_reason) WHERE (is_proposal = false);

CREATE INDEX idx_common_topology_transactions_for_old_unique_idx ON public.common_topology_transactions USING btree (store_id, mapping_key_hash, serial_counter, valid_from, operation, representative_protocol_version, tx_hash);

CREATE INDEX idx_common_topology_transactions_for_valid_until_update ON public.common_topology_transactions USING btree (store_id, mapping_key_hash, serial_counter, valid_from) WHERE (valid_until IS NULL);

CREATE INDEX idx_common_topology_transactions_max_timestamp ON public.common_topology_transactions USING btree (store_id, sequenced);

CREATE INDEX idx_common_topology_transactions_store_id_id ON public.common_topology_transactions USING btree (store_id, id);

CREATE INDEX idx_event_sequence ON public.par_traffic_enforcement_event USING btree (sequence_nb);

CREATE INDEX idx_journal_request_commit_time ON public.par_journal_requests USING btree (physical_synchronizer_idx, commit_time);

CREATE UNIQUE INDEX idx_journal_request_timestamp ON public.par_journal_requests USING btree (physical_synchronizer_idx, request_timestamp);

CREATE INDEX idx_lapi_command_completions_tx_hash ON public.lapi_command_completions USING btree (transaction_hash, completion_offset) WHERE ((transaction_hash IS NOT NULL) AND (update_id IS NULL));

CREATE INDEX idx_lapi_update_meta_tx_hash ON public.lapi_update_meta USING hash (transaction_hash) WHERE (transaction_hash IS NOT NULL);

CREATE INDEX idx_mediator_deduplication_store_expire_after ON public.mediator_deduplication_store USING btree (expire_after);

CREATE INDEX idx_ord_metadata_output_blocks_bft_ts ON ONLY public.ord_metadata_output_blocks USING btree (bft_ts);

CREATE INDEX idx_ord_metadata_output_blocks_block_number ON ONLY public.ord_metadata_output_blocks USING btree (block_number);

CREATE INDEX idx_par_active_contracts_contract_id ON public.par_active_contracts USING btree (contract_id);

CREATE INDEX idx_par_active_contracts_pruning ON public.par_active_contracts USING btree (synchronizer_idx, ts) WHERE (change = 'deactivation'::public.change_type);

CREATE INDEX idx_par_active_contracts_ts_synchronizer_idx ON public.par_active_contracts USING btree (ts, synchronizer_idx);

CREATE INDEX idx_par_command_dedup_offset ON public.par_command_deduplication USING btree (offset_definite_answer);

CREATE INDEX idx_par_commitment_queue_by_time ON public.par_commitment_queue USING btree (synchronizer_idx, to_inclusive);

CREATE INDEX idx_par_computed_acs_commitments_by_time ON public.par_computed_acs_commitments USING btree (synchronizer_idx, to_inclusive);

CREATE INDEX idx_par_contracts_find ON public.par_contracts USING btree (package_id, template_id);

CREATE INDEX idx_par_contracts_internal ON public.par_contracts USING btree (internal_contract_id);

CREATE INDEX idx_par_full_commitment ON public.par_received_acs_commitments USING btree (synchronizer_idx, sender, from_exclusive, to_inclusive);

CREATE INDEX idx_par_in_flight_submission_message_id ON public.par_in_flight_submission USING btree (submission_synchronizer_id, message_id);

CREATE INDEX idx_par_in_flight_submission_root_hash ON public.par_in_flight_submission USING btree (root_hash_hex);

CREATE INDEX idx_par_in_flight_submission_sequencing ON public.par_in_flight_submission USING btree (submission_synchronizer_id, sequencing_time);

CREATE INDEX idx_par_in_flight_submission_timeout ON public.par_in_flight_submission USING btree (submission_synchronizer_id, sequencing_timeout);

CREATE UNIQUE INDEX idx_par_outstanding_acs_commitments ON public.par_outstanding_acs_commitments USING btree (synchronizer_idx, from_exclusive, to_inclusive, counter_participant);

CREATE INDEX idx_par_received_acs_commitments_by_time ON public.par_received_acs_commitments USING btree (synchronizer_idx, to_inclusive);

CREATE UNIQUE INDEX idx_par_synchronizer_connection_configs_active_per_alias ON public.par_synchronizer_connection_configs USING btree (synchronizer_alias) WHERE (status = 'A'::bpchar);

CREATE INDEX idx_seq_block_height_latest_event_ts ON public.seq_block_height USING btree (latest_event_ts);

CREATE INDEX idx_traffic_correlation_timestamp ON public.par_traffic_enforcement_correlations USING btree ("timestamp");

CREATE INDEX idx_traffic_event_timestamp ON public.par_traffic_enforcement_event USING btree ("timestamp");

CREATE INDEX lapi_command_completions_offset_idx ON public.lapi_command_completions USING btree (completion_offset);

CREATE INDEX lapi_command_completions_publication_time_idx ON public.lapi_command_completions USING btree (publication_time, completion_offset);

CREATE INDEX lapi_command_completions_synchronizer_offset_idx ON public.lapi_command_completions USING btree (synchronizer_id, completion_offset);

CREATE INDEX lapi_command_completions_synchronizer_record_time_offset_idx ON public.lapi_command_completions USING btree (synchronizer_id, record_time, completion_offset);

CREATE INDEX lapi_command_completions_user_id_offset_idx ON public.lapi_command_completions USING btree (user_id, completion_offset);

CREATE INDEX lapi_events_acs_commitments_event_sequential_id_idx ON public.lapi_events_acs_commitments USING btree (event_sequential_id);

CREATE INDEX lapi_events_acs_commitments_sid_seq_id_idx ON public.lapi_events_acs_commitments USING btree (synchronizer_id, event_sequential_id);

CREATE INDEX lapi_events_activate_contract_key_idx ON public.lapi_events_activate_contract USING btree (create_key_hash, event_sequential_id) INCLUDE (internal_contract_id) WHERE (create_key_hash IS NOT NULL);

CREATE INDEX lapi_events_activate_internal_contract_id_idx ON public.lapi_events_activate_contract USING btree (internal_contract_id, event_sequential_id);

CREATE INDEX lapi_events_activate_offset_idx ON public.lapi_events_activate_contract USING btree (event_offset);

CREATE INDEX lapi_events_activate_sequential_id_idx ON public.lapi_events_activate_contract USING btree (event_sequential_id) INCLUDE (event_type, synchronizer_id);

CREATE INDEX lapi_events_deactivate_internal_contract_id_archive_idx ON public.lapi_events_deactivate_contract USING btree (internal_contract_id, event_sequential_id) WHERE ((internal_contract_id IS NOT NULL) AND (event_type = 3));

CREATE INDEX lapi_events_deactivate_internal_contract_id_idx ON public.lapi_events_deactivate_contract USING btree (internal_contract_id, event_sequential_id) WHERE (internal_contract_id IS NOT NULL);

CREATE INDEX lapi_events_deactivate_offset_idx ON public.lapi_events_deactivate_contract USING btree (event_offset);

CREATE INDEX lapi_events_deactivate_sequential_id_idx ON public.lapi_events_deactivate_contract USING btree (event_sequential_id) INCLUDE (event_type);

CREATE INDEX lapi_events_deactivated_event_sequential_id_idx ON public.lapi_events_deactivate_contract USING btree (deactivated_event_sequential_id) INCLUDE (event_sequential_id) WHERE (deactivated_event_sequential_id IS NOT NULL);

CREATE INDEX lapi_events_generic_topology_events_event_seq_id_idx ON public.lapi_events_generic_topology_events USING btree (event_sequential_id);

CREATE INDEX lapi_events_generic_topology_events_sid_recordt_idx ON public.lapi_events_generic_topology_events USING btree (synchronizer_id, record_time);

CREATE INDEX lapi_events_party_to_participant_event_did_recordt_idx ON public.lapi_events_party_to_participant USING btree (synchronizer_id, record_time);

CREATE INDEX lapi_events_party_to_participant_event_offset_idx ON public.lapi_events_party_to_participant USING btree (event_offset);

CREATE INDEX lapi_events_party_to_participant_event_party_sequential_id_idx ON public.lapi_events_party_to_participant USING btree (party_id, event_sequential_id);

CREATE INDEX lapi_events_party_to_participant_event_sequential_id_idx ON public.lapi_events_party_to_participant USING btree (event_sequential_id);

CREATE INDEX lapi_events_party_to_participant_party_id_idx ON public.lapi_events_party_to_participant USING btree (party_id, participant_id, synchronizer_id, event_sequential_id DESC) INCLUDE (participant_authorization_event);

CREATE INDEX lapi_events_party_to_participant_party_idx ON public.lapi_events_party_to_participant USING btree (party, event_sequential_id DESC) INCLUDE (party_id);

CREATE INDEX lapi_events_various_internal_contract_id_idx ON public.lapi_events_various_witnessed USING btree (internal_contract_id, event_sequential_id) WHERE (internal_contract_id IS NOT NULL);

CREATE INDEX lapi_events_various_offset_idx ON public.lapi_events_various_witnessed USING btree (event_offset);

CREATE INDEX lapi_events_various_sequential_id_idx ON public.lapi_events_various_witnessed USING btree (event_sequential_id) INCLUDE (event_type);

CREATE INDEX lapi_filter_achs_stakeholder_ps_idx ON public.lapi_filter_achs_stakeholder USING btree (party_id, event_sequential_id);

CREATE INDEX lapi_filter_achs_stakeholder_pts_idx ON public.lapi_filter_achs_stakeholder USING btree (party_id, template_id, event_sequential_id);

CREATE INDEX lapi_filter_achs_stakeholder_s_idx ON public.lapi_filter_achs_stakeholder USING btree (event_sequential_id, first_per_sequential_id);

CREATE INDEX lapi_filter_achs_stakeholder_ts_idx ON public.lapi_filter_achs_stakeholder USING btree (template_id, event_sequential_id) WHERE first_per_sequential_id;

CREATE INDEX lapi_filter_activate_stakeholder_ps_idx ON public.lapi_filter_activate_stakeholder USING btree (party_id, event_sequential_id);

CREATE INDEX lapi_filter_activate_stakeholder_pts_idx ON public.lapi_filter_activate_stakeholder USING btree (party_id, template_id, event_sequential_id);

CREATE INDEX lapi_filter_activate_stakeholder_s_idx ON public.lapi_filter_activate_stakeholder USING btree (event_sequential_id, first_per_sequential_id);

CREATE INDEX lapi_filter_activate_stakeholder_ts_idx ON public.lapi_filter_activate_stakeholder USING btree (template_id, event_sequential_id) WHERE first_per_sequential_id;

CREATE INDEX lapi_filter_activate_witness_ps_idx ON public.lapi_filter_activate_witness USING btree (party_id, event_sequential_id);

CREATE INDEX lapi_filter_activate_witness_pts_idx ON public.lapi_filter_activate_witness USING btree (party_id, template_id, event_sequential_id);

CREATE INDEX lapi_filter_activate_witness_s_idx ON public.lapi_filter_activate_witness USING btree (event_sequential_id, first_per_sequential_id);

CREATE INDEX lapi_filter_activate_witness_ts_idx ON public.lapi_filter_activate_witness USING btree (template_id, event_sequential_id) WHERE first_per_sequential_id;

CREATE INDEX lapi_filter_deactivate_stakeholder_ps_idx ON public.lapi_filter_deactivate_stakeholder USING btree (party_id, event_sequential_id);

CREATE INDEX lapi_filter_deactivate_stakeholder_pts_idx ON public.lapi_filter_deactivate_stakeholder USING btree (party_id, template_id, event_sequential_id);

CREATE INDEX lapi_filter_deactivate_stakeholder_s_idx ON public.lapi_filter_deactivate_stakeholder USING btree (event_sequential_id, first_per_sequential_id);

CREATE INDEX lapi_filter_deactivate_stakeholder_ts_idx ON public.lapi_filter_deactivate_stakeholder USING btree (template_id, event_sequential_id) WHERE first_per_sequential_id;

CREATE INDEX lapi_filter_deactivate_witness_ps_idx ON public.lapi_filter_deactivate_witness USING btree (party_id, event_sequential_id);

CREATE INDEX lapi_filter_deactivate_witness_pts_idx ON public.lapi_filter_deactivate_witness USING btree (party_id, template_id, event_sequential_id);

CREATE INDEX lapi_filter_deactivate_witness_s_idx ON public.lapi_filter_deactivate_witness USING btree (event_sequential_id, first_per_sequential_id);

CREATE INDEX lapi_filter_deactivate_witness_ts_idx ON public.lapi_filter_deactivate_witness USING btree (template_id, event_sequential_id) WHERE first_per_sequential_id;

CREATE INDEX lapi_filter_various_witness_ps_idx ON public.lapi_filter_various_witness USING btree (party_id, event_sequential_id);

CREATE INDEX lapi_filter_various_witness_pts_idx ON public.lapi_filter_various_witness USING btree (party_id, template_id, event_sequential_id);

CREATE INDEX lapi_filter_various_witness_s_idx ON public.lapi_filter_various_witness USING btree (event_sequential_id, first_per_sequential_id);

CREATE INDEX lapi_filter_various_witness_ts_idx ON public.lapi_filter_various_witness USING btree (template_id, event_sequential_id) WHERE first_per_sequential_id;

CREATE INDEX lapi_pruning_candidate_deactivated_activate_idx ON public.lapi_pruning_candidate_deactivated USING btree (activate_event_sequential_id);

CREATE INDEX lapi_pruning_candidate_deactivated_deactivate_idx ON public.lapi_pruning_candidate_deactivated USING btree (deactivate_event_sequential_id);

CREATE INDEX lapi_pruning_contract_candidate_idx ON public.lapi_pruning_contract_candidate USING btree (internal_contract_id);

CREATE INDEX lapi_update_meta_event_offset_idx ON public.lapi_update_meta USING btree (event_offset);

CREATE INDEX lapi_update_meta_publication_time_idx ON public.lapi_update_meta USING btree (publication_time, event_offset);

CREATE INDEX lapi_update_meta_synchronizer_offset_idx ON public.lapi_update_meta USING btree (synchronizer_id, event_offset);

CREATE INDEX lapi_update_meta_synchronizer_record_time_offset_idx ON public.lapi_update_meta USING btree (synchronizer_id, record_time, event_offset);

CREATE INDEX lapi_update_meta_uid_idx ON public.lapi_update_meta USING hash (update_id);

CREATE UNIQUE INDEX lapi_user_rights_user_internal_id_user_right_idx ON public.lapi_user_rights USING btree (user_internal_id, user_right) WHERE (for_party IS NULL);

CREATE INDEX ord_metadata_output_blocks_p0_bft_ts_idx ON public.ord_metadata_output_blocks_p0 USING btree (bft_ts);

CREATE INDEX ord_metadata_output_blocks_p0_block_number_idx ON public.ord_metadata_output_blocks_p0 USING btree (block_number);

CREATE INDEX ord_metadata_output_blocks_p1_bft_ts_idx ON public.ord_metadata_output_blocks_p1 USING btree (bft_ts);

CREATE INDEX ord_metadata_output_blocks_p1_block_number_idx ON public.ord_metadata_output_blocks_p1 USING btree (block_number);

CREATE INDEX par_acs_commitment_period_match_to_inclusive ON public.par_acs_commitment_period_match USING btree (synchronizer_idx, to_inclusive);

CREATE INDEX par_acs_commitment_period_mismatch_by_hash ON public.par_acs_commitment_period_mismatch USING btree (synchronizer_idx, participant_id, expected_hashed_digest, to_inclusive) WHERE (expected_hashed_digest IS NOT NULL);

CREATE INDEX par_acs_commitment_period_mismatch_to_inclusive ON public.par_acs_commitment_period_mismatch USING btree (synchronizer_idx, to_inclusive);

CREATE INDEX par_acs_commitment_period_outstanding_to_inclusive ON public.par_acs_commitment_period_outstanding USING btree (synchronizer_idx, to_inclusive);

CREATE UNIQUE INDEX par_acs_participant_running_digest_by_key ON public.par_acs_participant_running_digest USING btree (synchronizer_idx, participant_id, change_offset DESC);

CREATE INDEX par_acs_participant_running_digest_by_time ON public.par_acs_participant_running_digest USING btree (synchronizer_idx, change_offset, participant_id) INCLUDE (replaces_offset);

CREATE INDEX par_acs_participant_running_digest_tombstone ON public.par_acs_participant_running_digest USING btree (synchronizer_idx, change_offset) WHERE (digest IS NULL);

CREATE UNIQUE INDEX par_acs_party_running_digest_by_key ON public.par_acs_party_running_digest USING btree (synchronizer_idx, party_id, change_offset DESC);

CREATE INDEX par_acs_party_running_digest_by_time ON public.par_acs_party_running_digest USING btree (synchronizer_idx, change_offset, party_id) INCLUDE (replaces_offset);

CREATE INDEX par_acs_party_running_digest_tombstone ON public.par_acs_party_running_digest USING btree (synchronizer_idx, change_offset) WHERE (digest IS NULL);

CREATE INDEX par_acs_running_digests_checkpoint_by_type ON public.par_acs_running_digests_checkpoint USING btree (synchronizer_idx, checkpoint_type, change_offset) INCLUDE (ts);

CREATE INDEX projection_name_index ON public.pekko_projection_offset_store USING btree (projection_name);

CREATE INDEX seq_in_flight_aggregation_max_sequencing_time_idx ON public.seq_in_flight_aggregation USING btree (max_sequencing_time);

CREATE INDEX sequencer_event_recipients_node_recipient_topology_ts ON public.sequencer_event_recipients USING btree (node_index, recipient_id, is_topology_event, ts) WHERE (is_topology_event IS TRUE);

CREATE INDEX sequencer_event_recipients_ts_idx ON public.sequencer_event_recipients USING btree (ts);

ALTER INDEX public.ord_availability_batch_pkey1 ATTACH PARTITION public.ord_availability_batch_p0_pkey;

ALTER INDEX public.ord_availability_batch_pkey1 ATTACH PARTITION public.ord_availability_batch_p1_pkey;

ALTER INDEX public.ord_epochs_pkey1 ATTACH PARTITION public.ord_epochs_p0_pkey;

ALTER INDEX public.ord_epochs_pkey1 ATTACH PARTITION public.ord_epochs_p1_pkey;

ALTER INDEX public.ord_leader_selection_state_pkey1 ATTACH PARTITION public.ord_leader_selection_state_p0_pkey;

ALTER INDEX public.ord_leader_selection_state_pkey1 ATTACH PARTITION public.ord_leader_selection_state_p1_pkey;

ALTER INDEX public.idx_ord_metadata_output_blocks_bft_ts ATTACH PARTITION public.ord_metadata_output_blocks_p0_bft_ts_idx;

ALTER INDEX public.idx_ord_metadata_output_blocks_block_number ATTACH PARTITION public.ord_metadata_output_blocks_p0_block_number_idx;

ALTER INDEX public.ord_metadata_output_blocks_pkey1 ATTACH PARTITION public.ord_metadata_output_blocks_p0_pkey;

ALTER INDEX public.idx_ord_metadata_output_blocks_bft_ts ATTACH PARTITION public.ord_metadata_output_blocks_p1_bft_ts_idx;

ALTER INDEX public.idx_ord_metadata_output_blocks_block_number ATTACH PARTITION public.ord_metadata_output_blocks_p1_block_number_idx;

ALTER INDEX public.ord_metadata_output_blocks_pkey1 ATTACH PARTITION public.ord_metadata_output_blocks_p1_pkey;

ALTER INDEX public.ord_metadata_output_epochs_pkey1 ATTACH PARTITION public.ord_metadata_output_epochs_p0_pkey;

ALTER INDEX public.ord_metadata_output_epochs_pkey1 ATTACH PARTITION public.ord_metadata_output_epochs_p1_pkey;

ALTER INDEX public.ord_pbft_messages_completed_pkey1 ATTACH PARTITION public.ord_pbft_messages_completed_p0_pkey;

ALTER INDEX public.ord_pbft_messages_completed_pkey1 ATTACH PARTITION public.ord_pbft_messages_completed_p1_pkey;

ALTER INDEX public.ord_pbft_messages_in_progress_pkey1 ATTACH PARTITION public.ord_pbft_messages_in_progress_p0_pkey;

ALTER INDEX public.ord_pbft_messages_in_progress_pkey1 ATTACH PARTITION public.ord_pbft_messages_in_progress_p1_pkey;

ALTER TABLE ONLY public.seq_in_flight_aggregated_sender
    ADD CONSTRAINT foreign_key_seq_in_flight_aggregated_sender FOREIGN KEY (aggregation_id) REFERENCES public.seq_in_flight_aggregation(aggregation_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.lapi_party_record_annotations
    ADD CONSTRAINT lapi_party_record_annotations_internal_id_fkey FOREIGN KEY (internal_id) REFERENCES public.lapi_party_records(internal_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.lapi_party_records
    ADD CONSTRAINT lapi_party_records_identity_provider_id_fkey FOREIGN KEY (identity_provider_id) REFERENCES public.lapi_identity_provider_config(identity_provider_id);

ALTER TABLE ONLY public.lapi_user_annotations
    ADD CONSTRAINT lapi_user_annotations_internal_id_fkey FOREIGN KEY (internal_id) REFERENCES public.lapi_users(internal_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.lapi_user_rights
    ADD CONSTRAINT lapi_user_rights_user_internal_id_fkey FOREIGN KEY (user_internal_id) REFERENCES public.lapi_users(internal_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.lapi_users
    ADD CONSTRAINT lapi_users_identity_provider_id_fkey FOREIGN KEY (identity_provider_id) REFERENCES public.lapi_identity_provider_config(identity_provider_id);

ALTER TABLE ONLY public.par_dar_packages
    ADD CONSTRAINT par_dar_packages_main_package_id_fkey FOREIGN KEY (main_package_id) REFERENCES public.par_dars(main_package_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.par_dar_packages
    ADD CONSTRAINT par_dar_packages_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.par_daml_packages(package_id) ON DELETE CASCADE;

