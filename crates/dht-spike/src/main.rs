//! Measurement driver: `cargo run -p dht-spike --release`. Every number is
//! produced by the sim; cells average `REALIZATIONS` builds × lookups.

use dht_spike::{Network, ResolveOutcome, Rng, K};

const LOOKUPS_PER_REALIZATION: usize = 40;
const REALIZATIONS: usize = 10;

fn avg(out: &[ResolveOutcome], f: impl Fn(&ResolveOutcome) -> usize) -> f64 {
    out.iter().map(f).sum::<usize>() as f64 / out.len() as f64
}
fn msgs(o: &ResolveOutcome) -> usize { o.lookup.find_node_messages() + o.fetches }
fn run(net: &Network, from: usize, lookups: usize) -> Vec<ResolveOutcome> {
    (0..lookups).map(|_| net.resolve(from)).collect()
}
fn collect(rng: &mut Rng, n: usize, malicious: usize, targeted: bool, replicate: usize, churn: f64) -> Vec<ResolveOutcome> {
    let mut out = Vec::new();
    for _ in 0..REALIZATIONS {
        let mut net = Network::build(rng, n, malicious, targeted, replicate);
        if churn > 0.0 { net.apply_churn(rng, churn, n - 1); }
        out.extend(run(&net, n - 1, LOOKUPS_PER_REALIZATION));
    }
    out
}
fn report(out: &[ResolveOutcome]) -> (usize, usize, f64) {
    (out.iter().filter(|o| o.verified > 0).count(),
     out.iter().map(|o| o.forged).sum(),
     avg(out, msgs))
}
fn main() {
    println!("== dht-spike measurements (all numbers produced by the sim below) ==");
    let total = LOOKUPS_PER_REALIZATION * REALIZATIONS;

    println!("\nE1 — messages & rounds vs network size (K=20, alpha=3, {total} lookups/cell, 0 malicious)");
    println!("| nodes | find_node msgs | fetch msgs | total msgs | rounds | contacted |");
    for n in [100usize, 1000] {
        let mut rng = Rng::new(n as u64);
        let out = collect(&mut rng, n, 0, false, K, 0.0);
        println!("| {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} |", n,
            avg(&out, |o| o.lookup.find_node_messages()), avg(&out, |o| o.fetches),
            avg(&out, msgs), avg(&out, |o| o.lookup.rounds),
            avg(&out, |o| o.lookup.contacted.len()));
    }

    println!("\nE2/E3 — sybil: success vs malicious fraction (N=100, {total} lookups/cell)");
    println!("| mode | malicious_frac | verified | success% | forged_admitted_total | avg_msgs |");
    for (mode, targeted) in [("random", false), ("targeted", true)] {
        for f in [0.0f64, 0.1, 0.15, 0.2, 0.25, 0.5] {
            let m = (100.0 * f) as usize;
            let mut rng = Rng::new(10_000 + 100 * m as u64 + if targeted { 1 } else { 0 });
            let out = collect(&mut rng, 100, m, targeted, K, 0.0);
            let (ok, forged, m) = report(&out);
            println!("| {} | {:.2} | {} | {:.1} | {} | {:.2} |", mode, f, ok,
                100.0 * ok as f64 / out.len() as f64, forged, m);
        }
    }

    println!("\nE4 — churn: success vs offline fraction (N=100, {total} lookups/cell, 0 malicious)");
    println!("| offline_frac | replication R | verified | success% | avg_msgs |");
    for (c, r) in [(0.5f64, K), (0.8, K), (0.8, 4usize), (0.9, 4)] {
        let mut rng = Rng::new(20_000 + (10.0 * c) as u64 + r as u64);
        let out = collect(&mut rng, 100, 0, false, r, c);
        let (ok, _forged, m) = report(&out);
        println!("| {:.1} | {} | {} | {:.1} | {:.2} |", c, r, ok,
            100.0 * ok as f64 / out.len() as f64, m);
    }
}