//! Kademlia routing core: XOR distance, k-buckets, iterative lookup.
//! Std-only; the spike adds no routing dependencies. EXPERIMENT ONLY.

use std::collections::HashSet;

pub const BITS: usize = 64;  // id width
pub const K: usize = 20;     // bucket capacity
pub const ALPHA: usize = 3;  // parallel queries per round
pub const MAX_ROUNDS: usize = 32;

/// XOR distance in the 64-bit id space.
pub fn xordist(a: u64, b: u64) -> u64 { a ^ b }
/// Bucket of `other` from `own` = index of first differing bit (63 = far
/// half of the space); `None` for `own` itself.
pub fn bucket_index(own: u64, other: u64) -> Option<usize> {
    let d = own ^ other;
    (d != 0).then(|| 63 - d.leading_zeros() as usize)
}

/// One table = `BITS` LRU buckets (front = least recently seen).
#[derive(Debug, Clone)]
pub struct RoutingTable { pub own_id: u64, buckets: Vec<Vec<u64>> }
impl RoutingTable {
    pub fn new(own_id: u64) -> Self { Self { own_id, buckets: vec![Vec::new(); BITS] } }
    pub fn insert(&mut self, id: u64) {
        let Some(b) = bucket_index(self.own_id, id) else { return };
        let bucket = &mut self.buckets[b];
        if let Some(i) = bucket.iter().position(|&e| e == id) {
            let e = bucket.remove(i);
            bucket.push(e); // refresh: most recently seen → back
            return;
        }
        if bucket.len() >= K { bucket.remove(0); } // LRU evict; spike skips ping
        bucket.push(id);
    }
    /// The `n` closest known ids to `target`, ascending XOR distance.
    pub fn closest(&self, target: u64, n: usize) -> Vec<u64> {
        let mut all: Vec<u64> = self.buckets.iter().flatten().copied().collect();
        all.sort_by_key(|&id| xordist(target, id));
        all.truncate(n);
        all
    }
}
/// Minimal network view the lookup loop needs (implemented by the sim).
pub trait KademliaNet {
    fn closest(&self, node: u64, target: u64, n: usize) -> Vec<u64>;
    fn online(&self, node: u64) -> bool;
}
/// Outcome of one iterative lookup.
#[derive(Debug, Clone)]
pub struct Lookup {
    pub rounds: usize,
    pub requests: usize,     // FIND_NODE sent
    pub responses: usize,    // FIND_NODE replies
    pub contacted: Vec<u64>, // repliers, closest-first (fetch targets)
}
impl Lookup {
    pub fn find_node_messages(&self) -> usize { self.requests + self.responses }
}
/// Classic iterative lookup: α parallel queries; stop when the K closest
/// known ids are all queried. Repliers' contacts are folded into `known`.
/// Silent nodes never enter `contacted`.
pub fn lookup<N: KademliaNet>(net: &N, from: u64, target: u64) -> Lookup {
    let mut known: Vec<u64> = net.closest(from, target, K);
    let mut queried: HashSet<u64> = HashSet::new();
    let mut repliers: Vec<u64> = Vec::new();
    let mut rounds = 0usize;
    let mut requests = 0usize;
    let mut responses = 0usize;
    while rounds < MAX_ROUNDS {
        rounds += 1;
        if known.is_empty() || known.iter().take(K).all(|id| queried.contains(id)) { break; }
        let batch: Vec<u64> = known
            .iter().filter(|id| !queried.contains(id)).copied().take(ALPHA).collect();
        for id in batch {
            queried.insert(id);
            requests += 1;
            if !net.online(id) { continue; } // request sent, no reply (churn)
            responses += 1;
            repliers.push(id);
            for c in net.closest(id, target, K) {
                if !known.contains(&c) { known.push(c); }
            }
        }
        known.sort_by_key(|&id| xordist(target, id));
    }
    repliers.sort_by_key(|&id| xordist(target, id));
    repliers.truncate(K);
    Lookup { rounds, requests, responses, contacted: repliers }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_index_and_lru_bucket() {
        let own = 0x8000_0000_0000_0000u64;
        assert_eq!(bucket_index(own, own), None);
        assert_eq!(bucket_index(own, own | 1), Some(0));
        assert_eq!(bucket_index(own, 1), Some(63));
        assert!(xordist(own, own | 1) < xordist(own, 1));

        let mut t = RoutingTable::new(0);
        let base = 1u64 << 59; // ids in one distance window → one bucket
        for i in 0..K + 2 { t.insert(base + i as u64); }
        let b = &mut t.buckets[59];
        assert_eq!(b.len(), K);
        assert!(!b.contains(&base));                 // LRU evicted (0 was first)
        assert!(b.contains(&(base + K as u64 + 1))); // newest present
        t.insert(base + 3);                          // refresh existing entry
        assert_eq!(t.buckets[59].last(), Some(&(base + 3)));
        assert_eq!(t.buckets[59].len(), K);
    }
    #[test]
    fn closest_sorted_and_limited() {
        let mut t = RoutingTable::new(42);
        for i in 1..=30 { t.insert(i); }
        let c = t.closest(42, 5);
        assert_eq!(c.len(), 5);
        assert!(c.windows(2).all(|w| xordist(42, w[0]) <= xordist(42, w[1])));
    }
    #[test]
    fn lookup_converges_small_net() {
        let mut rng = crate::sim::Rng::new(7);
        let net = crate::sim::Network::build(&mut rng, 50, 0, false, K);
        let lk = lookup(&net, net.nodes[49].id, net.key);
        assert!(lk.rounds <= MAX_ROUNDS);
        assert_eq!(lk.requests, lk.responses); // no churn → every request answered
        assert_eq!(lk.contacted.len(), lk.responses.min(K));
    }
}