# 002 — Content addressing with BLAKE3

- Status: accepted (v0)
- Context: caching, integrity, versioning, dedup, offline.
- Problem: byte streams need self-verifying names.
- Options: SHA-256 / BLAKE3 / multihash prefixes.
- Decision: `b3:<hex(blake3)>` for v0; `alg:` agility reserved (prefix parse rejects unknown IDs, so migration is additive).
- Consequences: fast verify-on-read everywhere; 64-hex chars are verbose, so petnames/paths stay human-facing.
