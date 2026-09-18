//! Simulated network over the routing core, wired to the REAL
//! `nexus-resolver` admission boundary: every record a lookup returns is
//! admitted via `RecordStore::admit` under the out-of-band trust anchor
//! (ADR 006 §4; ADR 009 seq high-water). EXPERIMENT ONLY.

use std::collections::{BTreeSet, HashMap};
use ed25519_dalek::SigningKey;
use nexus_resolver::resolve::{EndpointRecord, RecordStore, Transport};
use crate::kademlia::{lookup, KademliaNet, Lookup, RoutingTable, K, xordist};

/// Deterministic xorshift64: fixed seeds → reproducible numbers.
#[derive(Debug)]
pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Self { Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1) }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        self.0 = x;
        x
    }
    pub fn pick(&mut self, n: usize) -> usize { (self.next() % n as u64) as usize }
}
/// ADR 006 frozen key contract: `blake3(name ‖ 0x00 ‖ kind)` → 64-bit id.
pub fn value_key(name: &str, kind: &str) -> u64 {
    let b = blake3::hash(format!("{name}\x00{kind}").as_bytes());
    let h = b.as_bytes();
    u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]])
}

#[derive(Debug, Clone)]
pub struct Node {
    pub id: u64,
    pub table: RoutingTable,
    pub malicious: bool,
    pub offline: bool,
    pub holder: bool, // replica of the "alice" record (serves it if honest)
}
/// The boundary under test: "alice" anchors to the HONEST key only
/// (out-of-band). Attacker-signed records must die at `RecordStore::admit`.
#[derive(Debug, Clone)]
pub struct VerifyBoundary {
    honest: SigningKey,
    pub record: EndpointRecord, // honestly signed ("alice", seq 1)
    pub forged: EndpointRecord, // attacker-signed, same name, seq 1
}
impl VerifyBoundary {
    pub fn new() -> Self {
        let honest = SigningKey::from_bytes(&[7; 32]);
        let attacker = SigningKey::from_bytes(&[9; 32]);
        let hs = hex::encode(honest.verifying_key().to_bytes());
        let as_ = hex::encode(attacker.verifying_key().to_bytes());
        let expiry = 4_000_000_000u64; // year 2096
        let record = EndpointRecord::sign(&honest, &hs, Transport::Tcp, "10.0.0.1", 7443, 1, expiry);
        let forged = EndpointRecord::sign(&attacker, &as_, Transport::Tcp, "6.6.6.6", 6666, 1, expiry);
        Self { honest, record, forged }
    }
    /// Fresh store per cold resolve, trusting only the honest key.
    pub fn fresh_store(&self) -> RecordStore {
        let mut s = RecordStore::new();
        s.trust("alice", self.honest.verifying_key());
        s
    }
}

#[derive(Debug)]
pub struct Network {
    pub nodes: Vec<Node>,
    idx: HashMap<u64, usize>,
    pub key: u64,
    pub boundary: VerifyBoundary,
}
impl Network {
    /// First `malicious` joiners are attackers. `targeted` places their ids
    /// within XOR distance 2^30 of the key (sybil ID targeting), else ids
    /// are uniform-random.
    pub fn build(rng: &mut Rng, n: usize, malicious: usize, targeted: bool, replicate: usize) -> Self {
        let key = value_key("alice", "endpoint");
        let mut ids = Vec::with_capacity(n);
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        while ids.len() < n {
            let id = if targeted && ids.len() < malicious {
                key ^ (rng.next() % (1u64 << 30) + 1)
            } else { rng.next() };
            if id != 0 && seen.insert(id) { ids.push(id); }
        }
        let mut nodes: Vec<Node> = Vec::with_capacity(n);
        for i in 0..n {
            let mut node = Node {
                id: ids[i], table: RoutingTable::new(ids[i]),
                malicious: i < malicious, offline: false, holder: false,
            };
            if i > 0 {
                // Join: query ≤3 earlier nodes; they learn us, we learn their
                // closest-to-us contacts (one refresh round).
                let mut seeds = BTreeSet::new();
                while seeds.len() < 3 && seeds.len() < i { seeds.insert(rng.pick(i)); }
                for s in seeds {
                    nodes[s].table.insert(ids[i]);
                    node.table.insert(ids[s]);
                    for c in nodes[s].table.closest(ids[i], K) { node.table.insert(c); }
                }
            }
            nodes.push(node);
        }
        let idx = ids.iter().enumerate().map(|(i, &id)| (id, i)).collect();
        let mut net = Self { nodes, idx, key, boundary: VerifyBoundary::new() };
        let mut order: Vec<usize> = (0..net.nodes.len()).collect();
        order.sort_by_key(|&i| xordist(net.key, net.nodes[i].id));
        for &i in order.iter().take(replicate) { net.nodes[i].holder = true; } // publish: R closest hold the record
        net
    }
    /// Take `offline_frac` of nodes offline; `except` stays up.
    pub fn apply_churn(&mut self, rng: &mut Rng, offline_frac: f64, except: usize) {
        let mut left = (self.nodes.len() as f64 * offline_frac).round() as usize;
        while left > 0 {
            let i = rng.pick(self.nodes.len());
            if i != except && !self.nodes[i].offline {
                self.nodes[i].offline = true;
                left -= 1;
            }
        }
    }
    /// Cold resolve of "alice": iterative lookup, fetch from repliers,
    /// push every returned record through the real boundary.
    pub fn resolve(&self, from: usize) -> ResolveOutcome {
        let lk = lookup(self, self.nodes[from].id, self.key);
        let mut store = self.boundary.fresh_store();
        let mut verified = 0usize; // honest records admitted (≥1 ⟺ route found)
        let mut forged = 0usize;   // attacker records admitted (invariant: 0)
        for &nid in &lk.contacted {
            let node = &self.nodes[self.idx[&nid]];
            let rec = if node.malicious { Some(&self.boundary.forged) }
                      else if node.holder { Some(&self.boundary.record) }
                      else { None };
            if let Some(rec) = rec {
                let ok = store.admit("alice", rec.clone());
                if ok { if node.malicious { forged += 1 } else { verified += 1 } }
            }
        }
        let fetches = lk.contacted.len() * 2;
        ResolveOutcome { lookup: lk, fetches, verified, forged }
    }
}
impl KademliaNet for Network {
    fn closest(&self, node: u64, target: u64, n: usize) -> Vec<u64> {
        self.nodes[self.idx[&node]].table.closest(target, n)
    }
    fn online(&self, node: u64) -> bool { !self.nodes[self.idx[&node]].offline }
}

#[derive(Debug, Clone)]
pub struct ResolveOutcome {
    pub lookup: Lookup,
    pub fetches: usize,  // GET request + response per contacted node
    pub verified: usize, // honest records admitted
    pub forged: usize,   // forged admissions — the safety invariant
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forged_records_die_at_verification_boundary() {
        let b = VerifyBoundary::new();
        let mut store = b.fresh_store();
        assert!(store.admit("alice", b.record.clone()));   // honest → admitted
        assert!(!store.admit("alice", b.forged.clone()));  // forged → refused
        let route = store.route("alice").expect("route");
        assert_eq!(route.endpoints, vec!["10.0.0.1:7443"]);
        assert!(!route.endpoints.contains(&"6.6.6.6:6666".to_string()));
    }
    #[test]
    fn healthy_network_resolves_verified_record() {
        let mut rng = Rng::new(1);
        let net = Network::build(&mut rng, 100, 0, false, K);
        for _ in 0..10 {
            let o = net.resolve(99);
            assert_eq!(o.verified, 1, "healthy lookup must find the record");
            assert_eq!(o.forged, 0);
        }
    }
    #[test]
    fn sybil_forgery_never_admits_even_under_eclipse() {
        let mut rng = Rng::new(2);
        // random-id sybil: forgeries rejected (availability kept)
        let net = Network::build(&mut rng, 100, 25, false, K);
        assert_eq!(net.resolve(99).forged, 0);
        // targeted sybil: eclipse kills availability, forgeries still rejected
        let net = Network::build(&mut rng, 100, 50, true, K);
        let routed: usize = (0..20).map(|_| net.resolve(99).verified).sum();
        let forged: usize = (0..20).map(|_| net.resolve(99).forged).sum();
        assert_eq!(routed, 0, "targeted sybil eclipses honest replicas");
        assert_eq!(forged, 0, "…and never admits a forged record");
    }
}