//! Sequencer and mediator topology queries over a peer sequencer's Admin API.

use canton_proto::com::digitalasset::canton::crypto::v30::{public_key::Key, SigningKeyUsage};
use canton_proto::com::digitalasset::canton::topology::admin::v30 as admin;

use crate::onboarding::{Registered, Registry};

/// The sequencers of the synchronizer with the keys they authenticate with, read from the topology store of the synchronizer at `admin_url` (an existing
/// sequencer's admin API): the `OwnerToKeyMapping` of every `SEQ::` member in force.
pub async fn sequencer_registry(
    admin_url: &str,
    physical_synchronizer_id: &str,
) -> Result<Registry, String> {
    registry_of(admin_url, physical_synchronizer_id, "SEQ").await
}

/// The members of one kind (`SEQ`, `PAR`, `MED`) with the keys they sign with, read the same way.
pub async fn registry_of(
    admin_url: &str,
    physical_synchronizer_id: &str,
    owner_type: &str,
) -> Result<Registry, String> {
    use admin::topology_manager_read_service_client::TopologyManagerReadServiceClient;
    let channel = tonic::transport::Channel::from_shared(admin_url.to_string())
        .map_err(|e| e.to_string())?
        .connect()
        .await
        .map_err(|e| format!("{admin_url}: {e}"))?;
    let mut read = TopologyManagerReadServiceClient::new(channel);
    let results = read
        .list_owner_to_key_mapping(admin::ListOwnerToKeyMappingRequest {
            base_query: Some(admin::BaseQuery {
                store: Some(admin::StoreId {
                    store: Some(admin::store_id::Store::Synchronizer(admin::Synchronizer {
                        kind: Some(admin::synchronizer::Kind::PhysicalId(
                            physical_synchronizer_id.to_string(),
                        )),
                    })),
                }),
                proposals: false,
                operation: 0,
                filter_signed_key: String::new(),
                protocol_version: None,
                client_version: None,
                time_query: Some(admin::base_query::TimeQuery::HeadState(())),
            }),
            filter_key_owner_type: owner_type.to_string(),
            filter_key_owner_uid: String::new(),
        })
        .await
        .map_err(|e| format!("reading the sequencers' keys: {}", e.message()))?
        .into_inner()
        .results;
    let registry = Registry::default();
    for r in results {
        let Some(admin::list_owner_to_key_mapping_response::result::Item::V30(m)) = r.item else {
            continue;
        };
        let mut registered = Registered {
            member: m.member.clone(),
            signing_keys: Vec::new(),
            authentication_keys: Vec::new(),
            encryption_keys: Vec::new(),
        };
        for key in m.public_keys {
            if let Some(Key::SigningPublicKey(k)) = key.key {
                let Ok(key) = canton_algo::signing::parse_public_key(&k) else {
                    continue;
                };
                if k.usage
                    .contains(&(SigningKeyUsage::SequencerAuthentication as i32))
                {
                    registered.authentication_keys.push(key.clone());
                }
                registered.signing_keys.push(key);
            }
        }
        registry.insert(registered);
    }
    Ok(registry)
}

/// The mediator groups of a synchronizer, read from an official node's Admin API (the head state of its topology store): what a
/// sequencer that only observes that synchronizer gives its own store (`TopologyStore::observe_mediator_groups`).
///
/// [CANTON-NOTE: WHY] Who may send a mediator group's aggregated verdict, and how many of its mediators complete it, is decided from the
/// groups (`InFlightAggregationHandler`). An observer whose store does not know them refuses every verdict of the official mediators.
pub async fn mediator_groups_of(
    admin_url: &str,
    physical_synchronizer_id: &str,
) -> Result<
    std::collections::BTreeMap<u32, canton_participant::topology_state::MediatorGroup>,
    String,
> {
    use admin::topology_manager_read_service_client::TopologyManagerReadServiceClient;
    let channel = tonic::transport::Channel::from_shared(admin_url.to_string())
        .map_err(|e| e.to_string())?
        .connect()
        .await
        .map_err(|e| format!("{admin_url}: {e}"))?;
    let mut read = TopologyManagerReadServiceClient::new(channel);
    let results = read
        .list_mediator_synchronizer_state(admin::ListMediatorSynchronizerStateRequest {
            base_query: Some(admin::BaseQuery {
                store: Some(admin::StoreId {
                    store: Some(admin::store_id::Store::Synchronizer(admin::Synchronizer {
                        kind: Some(admin::synchronizer::Kind::PhysicalId(
                            physical_synchronizer_id.to_string(),
                        )),
                    })),
                }),
                proposals: false,
                operation: 0,
                filter_signed_key: String::new(),
                protocol_version: None,
                client_version: None,
                time_query: Some(admin::base_query::TimeQuery::HeadState(())),
            }),
            filter_synchronizer_id: String::new(),
        })
        .await
        .map_err(|e| format!("reading the mediator groups: {}", e.message()))?
        .into_inner()
        .results;
    let mut groups = std::collections::BTreeMap::new();
    for r in results {
        let Some(state) = r.item else {
            continue;
        };
        let serial = r
            .context
            .and_then(|c| u32::try_from(c.serial).ok())
            .unwrap_or(0);
        groups.insert(
            state.group,
            canton_participant::topology_state::MediatorGroup {
                serial,
                threshold: state.threshold,
                active: state.active,
                observers: state.observers,
            },
        );
    }
    Ok(groups)
}
