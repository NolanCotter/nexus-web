# 001 — Site identity as Ed25519 public key

- Status: accepted (v0)
- Context: need "this content belongs to this identity" without DNS/CA.
- Problem: human names are not authentic; servers are not identities.
- Options: DNS-like registry / content-hash only / pubkey identity / DHT names / hybrid.
- Decision: site = Ed25519 pubkey (hex); human petnames map locally to pinned IDs; content hashes map versions to bytes.
- Consequences: keys are ugly but self-certifying; petname squatting is a UI problem; rotation/revocation needed in M3.
