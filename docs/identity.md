# Identity model (v0)

- Algorithm: Ed25519 (`ed25519-dalek` v2). No invented crypto.
- Site ID: lowercase hex of 32-byte public key (64 chars).
- Record: `(site, path, content_hash, expires_at_unix)` signed with site key.
- Canonical bytes: fields joined by `0x00`, expiry as decimal ASCII.
- Verification: site match + `expires_at > now` + signature check.
- Rotation/delegation: `Delegation` + `RotationLog` types exist; enforcement lands in M3.
- Key recovery: out of scope for v0; private keys are local files.

Fetch path does not yet enforce signatures (M3 wires resolver pinned IDs +
record checks into the browser). The crate and tests exist now so M3 is pure wiring.
