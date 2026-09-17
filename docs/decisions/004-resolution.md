# 004 — Local-first resolution behind a trait

- Status: accepted (v0)
- Context: name -> identity -> records -> nodes.
- Problem: DHT/gossip before the record model is correct risks building the wrong distributed system.
- Options: DHT now / gossip now / federated / local-first + trait.
- Decision: ship `Resolver` trait + `LocalResolver`; signed-record verification in M3; DHT experiment branch only after.
- Consequences: M1/M2 stay testable offline; distributed work has a clean seam.
