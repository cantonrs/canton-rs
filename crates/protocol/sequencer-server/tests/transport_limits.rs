//! The transport limits of the public API (internal review S-6, A-16): Canton serves it with `maxInboundMessageSize` set to the
//! synchronizer's `max_request_size` (`DynamicGrpcServer`, 10 MiB by default), above tonic's own 4 MiB, so a request between the two
//! reaches the sequencer's own checks.
mod common;
use canton_participant::sequencer_connect::ConnectError;

#[test]
fn a_request_between_four_and_ten_mebibytes_reaches_the_sequencer() {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "big");
    let answer = match m.client.send_async(
        &m.identity.member(),
        &physical,
        &m.token,
        vec![7u8; 6 * 1024 * 1024],
    ) {
        Ok(()) => "ACCEPTED".to_string(),
        Err(ConnectError::Status(s)) => s,
        Err(other) => panic!("{other}"),
    };
    assert!(!answer.contains("message length too large"), "{answer}");
}
