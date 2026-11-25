//! The sequencer's administration services are on its admin port only (internal review S-15): Canton's public API (`PublicServerConfig`)
//! serves the sequencer, authentication, connect, API-info and health services, and the traffic, topology and BFT administration services
//! are registered on the `admin-api` server.
#![allow(clippy::unwrap_used, reason = "integration test")]
use canton_proto::com::digitalasset::canton::sequencer::admin::v30::{
    sequencer_administration_service_client::SequencerAdministrationServiceClient,
    TrafficControlStateRequest,
};
use canton_proto::com::digitalasset::canton::topology::admin::v30::{
    topology_manager_read_service_client::TopologyManagerReadServiceClient,
    ListMediatorSynchronizerStateRequest,
};
use canton_sequencer_server::{serve_connect_with_admin, ConnectService};

fn free_addr() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn channel(addr: std::net::SocketAddr) -> tonic::transport::Channel {
    for _ in 0..50 {
        if let Ok(c) = tonic::transport::Channel::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
        {
            return c;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("no server on {addr}");
}

#[tokio::test]
async fn administration_is_answered_on_the_admin_port_and_not_on_the_public_port() {
    let config = canton_sequencer_server::new_synchronizer_with_groups("testsync", "ts1", 1);
    let connect = ConnectService::new(config.clone());
    let (public, admin) = (free_addr(), free_addr());
    let server = tokio::spawn(serve_connect_with_admin(
        public,
        Some(admin),
        config,
        connect,
        None,
    ));

    let traffic = |c| async move {
        SequencerAdministrationServiceClient::new(c)
            .traffic_control_state(TrafficControlStateRequest::default())
            .await
            .map(|_| ())
            .map_err(|s| s.code())
    };
    let topology = |c| async move {
        TopologyManagerReadServiceClient::new(c)
            .list_mediator_synchronizer_state(ListMediatorSynchronizerStateRequest::default())
            .await
            .map(|_| ())
            .map_err(|s| s.code())
    };
    assert_eq!(
        traffic(channel(public).await).await,
        Err(tonic::Code::Unimplemented)
    );
    assert_eq!(
        topology(channel(public).await).await,
        Err(tonic::Code::Unimplemented)
    );
    assert_ne!(
        traffic(channel(admin).await).await,
        Err(tonic::Code::Unimplemented)
    );
    assert_ne!(
        topology(channel(admin).await).await,
        Err(tonic::Code::Unimplemented)
    );
    server.abort();
}

/// Without an admin port the administration stays on the public port, where `canton-rs sequencer add-mediator --sequencer-url` reaches it.
#[tokio::test]
async fn without_an_admin_port_administration_stays_on_the_public_port() {
    let config = canton_sequencer_server::new_synchronizer_with_groups("testsync", "ts1", 1);
    let connect = ConnectService::new(config.clone());
    let public = free_addr();
    let server = tokio::spawn(serve_connect_with_admin(
        public, None, config, connect, None,
    ));
    let answer = SequencerAdministrationServiceClient::new(channel(public).await)
        .traffic_control_state(TrafficControlStateRequest::default())
        .await
        .map(|_| ())
        .map_err(|s| s.code());
    assert_ne!(answer, Err(tonic::Code::Unimplemented));
    server.abort();
}
