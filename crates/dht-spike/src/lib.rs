//! Kademlia spike: k-buckets, XOR distance, iterative lookup, churn/sybil
//! simulation wired to `nexus-resolver` verification. EXPERIMENT ONLY.

pub mod kademlia;
pub mod sim;
pub use kademlia::{xordist, bucket_index, RoutingTable, lookup, Lookup, KademliaNet, K, ALPHA, BITS, MAX_ROUNDS};
pub use sim::{Network, Rng, ResolveOutcome, VerifyBoundary, value_key};