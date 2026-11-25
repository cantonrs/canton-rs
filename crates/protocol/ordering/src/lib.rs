//! A Rust PBFT ordering engine (G7, S-NET-038).
//!
//! [CANTON-NOTE: LIMITATION] This is a **Rust-native** Byzantine fault tolerant ordering engine with the usual guarantees of PBFT
//! (safety with at most `f` faulty nodes out of `3f + 1`, liveness once the network is synchronous enough and a quorum can talk). It is **not**
//! wire-compatible with the BFT orderer of the official Canton 3.7.2 (`BftOrderingSequencer`, an ISS-style protocol with epochs and
//! segments): the official protocol's messages, epochs and certificates were not reproduced, so a Rust ordering node cannot take part in an
//! official ordering cluster. What the engine claims is what its tests observe (partitions, crashes, equivocating leaders, forged
//! certificates, forked or stale state transfers); it is a bounded test of this implementation, not a proof of the protocol (AT-V08).
pub mod crypto;
pub mod node;
pub mod sim;
pub mod types;

pub use node::{BftNode, Durable, Event, Out};
pub use sim::Cluster;
pub use types::{CommittedBlock, Config, Msg, NodeId};
