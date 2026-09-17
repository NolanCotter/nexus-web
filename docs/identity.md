# Identity model (v1)

- Algorithm: Ed25519 (`ed25519-dalek` v2). No invented crypto.
- Site ID: lowercase hex of 32-byte public key (64 chars).
- Record: `(site, path, content_hash, expires_at_unix)` signed with site key.
- Canonical bytes: fields joined by `0x00`, expiry as decimal ASCII.
  **Frozen** — resolver `EndpointRecord` mirrors it and test vectors depend on it.
- Verification: site match + `expires_at > now` + signature check.

## Signature versioning (M3)

- v1 signatures (new default): sign `SIG_V1_TAG\0 || canonical_bytes()`
  where `SIG_V1_TAG = b"nexus/v1/record"`.
- v0 signatures (legacy): sign bare `canonical_bytes()`.
- `verify_record` accepts both: tries v1 first, falls back to v0.
- **Cross-reject is by construction**: Ed25519 binds a signature to the exact
  message; the two messages differ by the tag prefix, so a v1 signature cannot
  verify against the v0 message and vice versa. No allow-list needed.
- The version lives in the signed message, not in `SignedRecord` — the
  signature self-describes. `SignedRecord { record, signature_hex }` is
  unchanged, so old serde payloads and `nexus-resolver` (which constructs
  `SignedRecord` directly) are unaffected.

### Migration
Old verifiers deployed against v0 (bare `canonical_bytes()`) will accept v0
records forever and simply fail on v1 records until upgraded. Rollout order:
1. Ship the new verifier (accepts both) first.
2. Flip signers to v1.
3. Old v0-only verifiers can be retired once all signers emit v1.

## Key files (M3)

- `save_secret_key(path)`: writes the 32-byte seed; unix mode forced to 0600.
- `load_secret_key(path)`: refuses files with group/other permission bits
  (`InsecureKeyPerms`) on unix; rejects non-32-byte files.
- `generate_key_file(path)`: generate + persist in one step.

## Rotation chains (M3)

- `RotationLog.rotate(old, new)`: old key signs the domain-separated binding
  `b"nexus/v1/rotation"\0 || old_hex\0new_hex`.
- `verify_rotation_chain(from_pubkey)`: walks hops, each verified under the
  *previous* key, returns the current key. Broken chains (bad signature,
  tampered target, malformed bytes, cycles) fail loudly.
- A key that never rotated is its own chain end.

## Out of scope (unchanged)

- Delegation: `Delegation` type exists; enforcement lands later.
- Key recovery: private keys are local 0600 files.

Fetch path does not yet enforce signatures (M3 wires resolver pinned IDs +
record checks into the browser). The crate and tests exist now so M3 is pure wiring.