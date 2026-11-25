//! The BFT orderer of Canton 3.7.2 (`...sequencer.block.bftordering`), ported from its Scala source (U-49, `doc/slices/BFT-ORDERER.md`).
//!
//! [CANTON-NOTE: LIMITATION] Not the Rust-native PBFT engine of `canton-ordering` (G7): that one is not wire-compatible with the official orderer. This crate
//! is the ISS/Narwhal-style protocol of the official one, built slice by slice (envelope and signing rules in `wire`, the consensus state
//! machine in `node`).
pub mod availability;
pub mod bft_time;
pub mod blacklist;
pub mod consensus;
pub mod epoch;
pub mod fair_queue;
pub mod node;
#[cfg(test)]
mod testing;
pub mod topology;
pub mod verify;
pub mod wire;
