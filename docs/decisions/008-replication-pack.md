# 008 — NXPACK1 replication pack (export/import)

- Status: accepted (v0, milestone H)
- Context: a store must hand a subset of its blobs to another node as exactly
  one file, and the receiver must be able to trust it. The pack crosses
  untrusted links, so decode has to be total and verification has to happen
  before any byte is stored.
- Problem: naive length-prefixed packing (`magic, count, len, bytes`) makes
  single-byte tampering undetectable — flipped payload bytes simply hash to a
  different, still-internally-consistent content id.
- Options: hash-at-end framing / per-blob embedded id / no verification.
- Decision: embed the raw 32-byte BLAKE3 id per blob so `import` can re-hash
  every payload and reject the whole pack on any mismatch, before writing
  anything. Format (all integers little-endian, no padding):

  ```text
  magic   7 bytes  "NXPACK1"
  count   u32      number of blobs
  per blob:
    len   u32      payload length in bytes
    id    32 bytes raw BLAKE3 content id (payload without the "b3:" prefix)
    data  len bytes
  ```

  Caps: each blob ≤ `MAX_BLOB` (4 MiB); total pack ≤ `MAX_PACK` (64 MiB).
  `import` rejects: bad magic, truncated reads, a blob over `MAX_BLOB`, a pack
  over `MAX_PACK`, hash mismatch, and any trailing bytes. The import path
  contains no `unwrap` on pack bytes; all arithmetic is checked.
- Consequences: exporter re-hashes on the way out (verify-on-read), so a
  tampered file on disk fails export too. `import` is verify-then-store:
  the whole pack is parsed and hashed before the first write; an IO failure
  mid-write can still leave a partial store (io faults only, never attacker
  input). Duplicate blobs in one pack are deduped by `put` (idempotent).
  Versioned magic leaves room for a future `NXPACK2`.
