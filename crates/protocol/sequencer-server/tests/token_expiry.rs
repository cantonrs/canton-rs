//! A subscription made with a token ends when the token expires (`SubscriptionPool`: `ServerSubscriptionCloseReason.TokenExpired`).
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::sync::Arc;
use std::time::Duration;

use canton_sequencer_server::onboarding::Registry;
use canton_sequencer_server::sequencing::{wall_micros, Sequencer};
use canton_sequencer_server::synchronizer_state::{SynchronizerKeys, TopologyStore};
use tokio_stream::StreamExt as _;

#[test]
fn a_subscription_ends_when_its_token_expires() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let keys = Arc::new(SynchronizerKeys::for_sequencer([1; 32], [2; 32], [3; 32]));
        let store = Arc::new(TopologyStore::initial("sync", "seq", "med", &keys));
        let sequencer = Sequencer::new(
            "da::1220aa::37-0".to_string(),
            keys,
            Arc::new(Registry::default()),
            store,
        );
        let member = "PAR::p::1220bb".to_string();
        let mut expiring =
            sequencer.subscribe_until(member.clone(), None, Some(wall_micros() + 200_000));
        let ended = tokio::time::timeout(Duration::from_secs(3), expiring.next())
            .await
            .expect("the stream ends once the token expired")
            .expect("with a status");
        let status = ended.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(status.message(), "Subscription token has expired");
        // negative control: a subscription whose token does not expire stays open
        let mut open = sequencer.subscribe_until(member, None, None);
        assert!(
            tokio::time::timeout(Duration::from_millis(500), open.next())
                .await
                .is_err(),
            "nothing ends the stream"
        );
    });
}
