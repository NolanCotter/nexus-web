# NXP/0.1 — Nexus eXchange Protocol, revision 0.1 (prototype draft)

Status: prototype draft · Date: 2026-09-16 · Task B deliverable (Protocol Engineering)
Companion crate: `crates/nxp-proto` (wire format primitives + parser skeleton)

---

## 0. What this document is

NXP is the application-layer protocol of Nexus, an experimental alternative internet.
NXP/0.1 is the minimal first revision: one connection, multiplexed streams, signed
content-addressed resources, exact revalidation, demand-driven push, and offline
catch-up. It replaces HTTP *semantics*, not just transport — HTTP's worst problems
(heuristic caching, parse ambiguity, broken push, no end-to-end integrity, no offline
story) are semantic, and HTTP/2/3 only replaced the transport.

Scope of 0.1: read-centric web (FETCH), subscriptions, caching, integrity, offline
reads + sync. Writes/authoring and private (auth'd) subscriptions are 0.2+.

---

## 1. Design space: how the alternatives compare

### 1.1 Text vs binary
- HTTP/1.1 — text. Readable, but the grammar is ambiguous (obs-fold, whitespace,
  duplicate/merged headers) → a permanent class of request-smuggling CVEs; slow to
  parse; no framing without Content-Length/Transfer-Encoding tricks.
- HTTP/2, HTTP/3, QUIC, gRPC — binary framing. Unambiguous, fast, compact. Trade-off:
  tooling needed for debugging.
- MQTT — binary; compact, but the minimal packet path is murky and extension-heavy.
- IPFS/libp2p — binary, self-describing length prefixes (multiformats).
- **Decision: binary framing with an ASCII connection preface and optional
  human-readable debug strings in STATUS frames.** Machine-fast and unambiguous, still
  debuggable with `nc` + hexdump, and smuggling is structurally impossible (no
  in-band delimiters anywhere).

### 1.2 Streaming
- HTTP/1.1 chunked encoding is a band-aid (in-band lengths, trailer quirks, request
  streaming arrived late). SSE streams one direction, text-only, over HTTP. gRPC
  streams both ways but is RPC-shaped (unary/stream permutations).
- **Decision: every message is a frame; a stream is an ordered sequence of frames
  terminated by END_STREAM.** Request and response bodies both stream natively in
  both directions, always full-duplex. There is no "chunked" special case — framing
  already is chunking.

### 1.3 Multiplexing
- HTTP/2: many streams over one TCP connection — but TCP head-of-line blocking
  remains, and HPACK is a DoS/attack surface. HTTP/3/QUIC: streams over UDP, no HOL —
  but still carries HTTP's semantic baggage plus QPACK complexity.
- **Decision: HTTP/2-style stream IDs (client-initiated = odd) with per-stream flow
  control over TCP+TLS 1.3 for 0.1; QUIC transport planned for 0.2 with zero semantic
  change.** The framing layer is transport-agnostic by design. No header-compression
  table in 0.1 (records are small); revisit with a static-table scheme later.

### 1.4 Push / subscriptions
- HTTP/2 push failed: server pushes *without a demand signal* → cache pollution and
  invalidation ambiguity; removed from HTTP/3. SSE is server→client only, HTTP-bound,
  no multiplexing. MQTT has real pub/sub but requires a broker, has no integrity
  model (QoS is retransmission, not verification), and is message-centric.
- **Decision: explicit SUBSCRIBE with a pattern + starting cursor; server sends a
  snapshot then UPDATE frames.** Push only ever happens on demand, so the HTTP/2
  failure mode is structurally impossible. No broker: endpoints subscribe directly
  over the same multiplexed connection (pub-sub without the MQTT middleman, with
  MQTT's retained-message/cursor idea kept).

### 1.5 Caching
- HTTP: heuristic freshness (Age/Expires), stringly validators (ETag / If-None-Match),
  Vary, shared-vs-private rules, conditional-request races. CDN-grade caching is an
  art form and still goes wrong (stale-while-revalidate bugs).
- **Decision: every resource has a content hash (immutable truth) and a cursor
  (mutable version).** Conditional FETCH with `if_cursor` or `hash_pin` is exact,
  race-free revalidation. Any cache can serve any resource without being trusted:
  records are signed and bodies hash-verified (1.7). No heuristics, no Vary, no
  Expires, no string ETags.

### 1.6 Version / capability negotiation
- HTTP: no wire-level negotiation; UA strings and Alt-Svc hacks. TLS ALPN offers one
  bit per protocol, no feature matrix. SSH has version exchange but no features.
- **Decision: connection preface = ASCII magic + version, then a capability bitmask
  + settings.** Server replies with its highest supported version ≤ client's and the
  capability intersection. Everything is additive; unknown capability bits are
  negotiated down, never fatal. A minimal `NX/0.0` profile guarantees baseline interop.

### 1.7 Integrity
- HTTP/1-3: integrity only at transport (TLS terminates at every CDN/proxy and the
  hop beyond it is plaintext to the edge). No end-to-end guarantee, no per-resource
  verification; a compromised edge can rewrite content silently.
- **Decision: three layers — (1) TLS 1.3 AEAD per connection; (2) blake3 content hash
  in every resource record, verified over the bytes received; (3) Ed25519 publisher
  signature over the canonical record, making every intermediary untrusted.**
  Records link `prev_cursor` → per-name hash chain → rollback/fork detection
  (Hypercore/DAT lineage; hashes in multihash encoding).

### 1.8 Partial retrieval
- HTTP: byte Range (RFC 7233) works, but validators are stringly and structural
  access is absent. IPFS: subtree retrieval via DAG selectors (excellent, but has no
  byte-range story over HTTP gateways).
- **Decision: byte ranges `(start, end)` in FETCH with a `range-hash` (blake3 of the
  returned slice) so partial retrievals verify independently of the full body, plus
  selector paths (`NX://a/b#section`) for structured resources.** 0.1 = blob byte
  ranges; structural selectors resolve server-side (recursive tree descent).

### 1.9 Offline operation
- HTTP: nothing native. Service workers bolt a cache on top with the same broken
  validators. gRPC/MQTT: nothing.
- **Decision: local-first by construction.** Content-addressed bodies + signed records
  make the local store a correct cache by itself; cursors make catch-up deterministic
  (SYNC = SUBSCRIBE replayed from the last seen cursor). 0.1: offline reads + sync
  replay. 0.2: offline writes (logged locally, synced later — conflict headers/CRDTs).

### 1.10 Matrix (✓ native · ± partial/bolted-on · ✗ absent)

| protocol   | enc | stream | mux | push | cache | negot | integ | partial | offline |
|------------|-----|--------|-----|------|-------|-------|-------|---------|---------|
| HTTP/1.1   | text| ±      | ✗   | ✗    | ±     | ✗     | ✗     | ±       | ✗       |
| HTTP/2     | bin | ±      | ✓   | ±    | ±     | ✗     | ✗     | ±       | ✗       |
| HTTP/3     | bin | ±      | ✓   | ✗    | ±     | ✗     | ✗     | ±       | ✗       |
| WebSocket/SSE | text | ✓  | ✗   | ±    | ✗     | ✗     | ✗     | ✗       | ±       |
| gRPC       | bin | ✓      | ✓   | ±    | ✗     | ✗     | ✗     | ✗       | ✗       |
| MQTT       | bin | ±      | ✗   | ✓    | ±     | ✗     | ±     | ✗       | ±       |
| IPFS/libp2p| bin | ±      | ✓   | ±    | ✓     | ±     | ✓     | ✓       | ✓       |
| **NXP/0.1**| bin | ✓      | ✓   | ✓    | ✓     | ✓     | ✓     | ✓       | ✓       |

---

## 2. NXP/0.1 protocol

### 2.1 Naming
`NX://<authority>/<path>[#selector]`. Authority = a namespace key: a domain-like name
resolved through the Nexus directory (NXmap) to an Ed25519 public key, or the key
itself inline (`NX://k51q.../path`, IPFS-style). Name→key resolution is the only fully
mutable step; everything downstream is hash-addressed. Records are keyed per
(name, selector).

### 2.2 Connection lifecycle
1. TCP connect; TLS 1.3 mandatory (ALPN `nxp/0.1`).
2. Client preface: ASCII `NX/0.1\r\n`, caps bitmask, settings pairs.
   Server replies with the highest version it supports ≤ client's, the caps
   intersection, and its settings. `NX/0.0\r\n` = minimal profile, no features.
3. Streams: client-initiated odd IDs; server-initiated even (reserved for 0.1,
   unused — push goes over the subscriber's own stream).
4. GOAWAY drains (last processed stream + code + debug); PING carries 8 opaque bytes
   that must be echoed (keepalive/RTT).

Capability bits (0.1):

| bit | name        | meaning                                  |
|-----|-------------|------------------------------------------|
| 0   | STREAMS     | multiplexed streams                      |
| 1   | PUSH        | SUBSCRIBE/UPDATE                         |
| 2   | BLAKE3      | content hashing (multihash id 0x1e)      |
| 3   | ZSTD        | zstd content encoding                    |
| 4   | RANGES      | byte-range partial retrieval             |
| 5   | SYNC        | cursor catch-up / offline sync           |
| 6   | SIG_ED25519 | publisher signature verification         |

Settings (varint id/value pairs): 1 MAX_FRAME (default 16 MiB) · 2 MAX_STREAMS (256) ·
3 WINDOW per-stream initial window (64 KiB) · 4 MAX_RECORD (64 KiB) · 5 KEEPALIVE ms (30 000).

### 2.3 Frames
10-byte header, big-endian: `length u32 | type u8 | flags u8 | stream_id u32`.
Payload ≤ MAX_FRAME.

| type        | id   | direction        | payload (0.1)                          |
|-------------|------|------------------|----------------------------------------|
| DATA        | 0x01 | both             | `offset u64` + body bytes              |
| HEADERS     | 0x02 | server→client    | resource record (2.4)                  |
| FETCH       | 0x03 | client→server    | FetchRequest (2.5)                     |
| SUBSCRIBE   | 0x04 | client→server    | pattern, cursor, flags                 |
| UPDATE      | 0x05 | server→client    | cursor, kind, record \| name           |
| STATUS      | 0x06 | both             | code, debug str, cursor, record?       |
| PING        | 0x07 | both             | 8 opaque bytes                         |
| GOAWAY      | 0x08 | both             | last_stream u32, code varint, debug    |
| CAPABILITIES| 0x09 | (reserved)       | renegotiation later                    |
| WINDOW      | 0x0A | both             | delta varint (flow control)            |

Flags: END_STREAM 0x01 · END_HEADERS 0x02 · INTERRUPT 0x04 (stream reset) · SYN 0x08.

### 2.4 Resource record (the core type)
Fields: `name`, `selector`, `kind` (0 blob · 1 tree · 2 stream · 3 namespace),
`content_hash` (hash-id byte + varint digest-len + digest; blake3 = 0x1e, 32 B),
`size`, `encoding` (0 identity · 1 deflate · 2 zstd), `mime`, `cursor`,
`prev_cursor`, `signature` (Ed25519 over canonical bytes), `meta` TLVs.
`cursor`+`prev_cursor` form a per-name append-only log: tracking clients detect any
rewrite of history. Canonical bytes = fixed deterministic field order, signature
excluded. Signature covers name+selector+kind+hash+size+encoding+mime+cursor+prev —
a cache operator cannot alter anything without breaking the chain.

### 2.5 FETCH semantics
```
FETCH { name, selector, ranges[], if_cursor, hash_pin }
```
1. Server resolves (name, selector) → record; applies preconditions.
2. `HEADERS(record)` then `DATA` frames (first 8 payload bytes = absolute offset,
   rest = bytes), `END_STREAM`.
3. `if_cursor ≥ current` → `STATUS 304` + current cursor only (cheap poll, exact).
4. `hash_pin` set → send body only if hash matches, else `409` + fresh record.
5. Ranges: requested range echoed in record meta + `range-hash` (blake3 of slice).
6. Errors: 404, 409, 412 (precondition), 416 (range), 429, 500, 501.

### 2.6 SUBSCRIBE semantics (demand-driven push)
```
SUBSCRIBE { pattern, cursor, flags }
```
- With snapshot flag: `HEADERS` (current matching records), then `STATUS 204`
  (snapshot done, cursor = current), then `UPDATE {cursor, kind=upsert|delete, record|name}`.
- Stream stays open; WINDOW frames apply backpressure per stream.
- Re-issuing SUBSCRIBE with a saved cursor = offline catch-up (SYNC).
- Server enforces per-connection subscription limits and per-topic fanout caps.

### 2.7 Caching rules (short)
Cache key = (name, selector) with record.cursor; body keyed by content_hash.
Serve cached body if record matches; revalidate with `if_cursor` (one small STATUS
round trip when unchanged — never a full body). Shared caches are safe because
records are signed and bodies hash-checked. No heuristics.

### 2.8 Integrity model (recap)
- Connection: TLS 1.3 AEAD; ALPN `nxp/0.1`.
- Content: blake3 in record, verified over bytes received (full body or per range).
- Authority: Ed25519 over canonical record, verified against the authority key
  (NXmap or inline `k51...` key).
- Version history: `prev_cursor` chain; a client that tracked cursor N detects any
  rewrite of history < N.
- Known gap (documented): a fresh client cannot distinguish an old-but-valid record
  from the newest; cursors are advisory for new joiners. Acceptable for 0.1.

---

## 3. Wire format sketch (concrete bytes)

### 3.1 Connection preface
```
client:  "NX/0.1\r\n"   caps=0x7F   nset=0         (8 + 1 + 1 bytes)
server:  "NX/0.1\r\n"   caps=0x6F   nset=3 id,val… (no zstd bit → intersection)
```

### 3.2 FETCH exchange (stream 1) — GET `NX://acme.nexus/docs/guide`
```
C>  00 00 00 26  03  00  00 00 00 01     hdr: len=38 FETCH flags=0 stream=1
    1A                                  varint 26 (name len)
    4E 58 3A 2F 2F 61 63 6D 65 2E 6E 65 78 75 73 2F 64 6F 63 73 2F 67 75 69 64 65
                                        "NX://acme.nexus/docs/guide"
    00                                   selector len 0
    00                                   ranges: 0 (whole resource)
    00 00 00 00 00 00 00 00             if_cursor 0
    00                                   hash_pin len 0

S>  00 00 00 5C  02  02  00 00 00 01     hdr: len=92 HEADERS END_HEADERS stream=1
    [resource record, 92 bytes]
S>  00 00 03 F0  01  01  00 00 00 01     hdr: len=1008 DATA END_STREAM stream=1
    00 00 00 00 00 00 00 00             body offset 0
    [1000 body bytes]
```

### 3.3 Revalidation poll (unchanged)
```
C>  00 00 00 26  03  00  00 00 00 03     FETCH, if_cursor=42, rest as before
S>  00 00 00 0C  06  01  00 00 00 03     hdr: len=12 STATUS END_STREAM stream=3
    B0 02                                  varint code 304
    00                                     debug len
    00 00 00 00 00 00 00 2A               cursor 42
    00                                     record len 0
```

### 3.4 Record encoding
```
canonical  = lenstr(name) lenstr(selector) u8(kind) lenstr(hash)
             u64(size) u8(encoding) lenstr(mime) u64(cursor) u64(prev_cursor)
             varint(nmeta) { varint(id) lenstr(val) }*
wire       = lenstr(canonical) lenstr(signature)
```
Varints are LEB128; all multi-byte integers big-endian. No delimiters exist inside
payloads, so frame-boundary confusion (the request-smuggling class) is impossible.

---

## 4. Rust parser sketch (core; full crate in `crates/nxp-proto`)

```rust
// ---- wire.rs: bounds-checked reader/writer ----
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError { UnexpectedEof, VarintOverflow, LengthOverflow{max:usize,got:usize},
                     BadUtf8, InvalidTag(u8), TrailingData }

pub struct Reader<'a> { buf: &'a [u8], pos: usize }
impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }
    pub fn remaining(&self) -> usize { self.buf.len().saturating_sub(self.pos) }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::UnexpectedEof)?;
        let s = self.buf.get(self.pos..end).ok_or(WireError::UnexpectedEof)?;
        self.pos = end; Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, WireError> { Ok(self.take(1)?[0]) }
    pub fn be_u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?; Ok(u32::from_be_bytes([b[0],b[1],b[2],b[3]]))
    }
    pub fn be_u64(&mut self) -> Result<u64, WireError> {
        let b = self.take(8)?; Ok(u64::from_be_bytes([b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]]))
    }
    pub fn varint(&mut self) -> Result<u64, WireError> {   // LEB128, ≤10 bytes
        let mut out = 0u64;
        for i in 0..10u32 {
            let b = self.u8()?;
            if i == 9 && (b & 0x7e) != 0 { return Err(WireError::VarintOverflow); }
            out |= u64::from(b & 0x7f) << (i * 7);
            if b & 0x80 == 0 { return Ok(out); }
        }
        Err(WireError::VarintOverflow)
    }
    pub fn lenstr(&mut self, max: usize) -> Result<&'a [u8], WireError> {
        let len = usize::try_from(self.varint()?)
            .map_err(|_| WireError::LengthOverflow { max, got: usize::MAX })?;
        if len > max { return Err(WireError::LengthOverflow { max, got: len }); }
        self.take(len)
    }
    pub fn str(&mut self, max: usize) -> Result<&'a str, WireError> {
        std::str::from_utf8(self.lenstr(max)?).map_err(|_| WireError::BadUtf8)
    }
}

#[derive(Default)]
pub struct Writer { out: Vec<u8> }
impl Writer {
    pub fn new() -> Self { Self::default() }
    pub fn u8(&mut self, b: u8) { self.out.push(b); }
    pub fn be_u32(&mut self, v: u32) { self.out.extend_from_slice(&v.to_be_bytes()); }
    pub fn be_u64(&mut self, v: u64) { self.out.extend_from_slice(&v.to_be_bytes()); }
    pub fn varint(&mut self, mut v: u64) {
        loop { let b = (v & 0x7f) as u8; v >>= 7;
               self.out.push(if v == 0 { b } else { b | 0x80 }); if v == 0 { return; } }
    }
    pub fn lenstr(&mut self, s: &[u8]) { self.varint(s.len() as u64); self.out.extend_from_slice(s); }
    pub fn into_bytes(self) -> Vec<u8> { self.out }
}

// ---- frame.rs: 10-byte header + FETCH payload ----
pub const HEADER_LEN: usize = 10;
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

#[repr(u8)] #[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType { Data=0x01, Headers=0x02, Fetch=0x03, Subscribe=0x04,
    Update=0x05, Status=0x06, Ping=0x07, GoAway=0x08, Capabilities=0x09, Window=0x0A }
impl FrameType { pub fn from_u8(b: u8) -> Option<FrameType> {
    use FrameType::*;
    match b { 0x01=>Some(Data),0x02=>Some(Headers),0x03=>Some(Fetch),0x04=>Some(Subscribe),
              0x05=>Some(Update),0x06=>Some(Status),0x07=>Some(Ping),0x08=>Some(GoAway),
              0x09=>Some(Capabilities),0x0A=>Some(Window), _=>None } } }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader { pub len: u32, pub ty: FrameType, pub flags: u8, pub stream_id: u32 }
impl FrameHeader {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.len.to_be_bytes()); out.push(self.ty as u8);
        out.push(self.flags); out.extend_from_slice(&self.stream_id.to_be_bytes());
    }
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let len = r.be_u32()?;
        if len > MAX_FRAME { return Err(WireError::LengthOverflow { max: MAX_FRAME as usize, got: len as usize }); }
        let b = r.u8()?; let ty = FrameType::from_u8(b).ok_or(WireError::InvalidTag(b))?;
        let flags = r.u8()?; let stream_id = r.be_u32()?;
        Ok(Self { len, ty, flags, stream_id })
    }
}

// ---- codec.rs: async frame reader over tokio (TCP + TLS both implement AsyncRead) ----
pub struct FrameReader<R> { inner: R }
impl<R: tokio::io::AsyncRead + Unpin> FrameReader<R> {
    pub fn new(inner: R) -> Self { Self { inner } }
    /// True clean-EOF at a frame boundary → Ok(None); truncated frame → Err.
    async fn read_full(inner: &mut R, buf: &mut [u8]) -> Result<bool, std::io::Error> {
        let mut off = 0;
        while off < buf.len() {
            let n = inner.read(&mut buf[off..]).await?;
            if n == 0 { return Ok(off == 0); }
            off += n;
        }
        Ok(true)
    }
    pub async fn next_frame(&mut self) -> Result<Option<Frame>, FrameReadError> {
        let mut hdr = [0u8; HEADER_LEN];
        use tokio::io::AsyncReadExt;
        if !Self::read_full(&mut self.inner, &mut hdr).await.map_err(FrameReadError::Io)? {
            return Ok(None);
        }
        let header = FrameHeader::decode(&mut Reader::new(&hdr)).map_err(FrameReadError::Wire)?;
        let mut payload = vec![0u8; header.len as usize];
        self.inner.read_exact(&mut payload).await.map_err(FrameReadError::Io)?;
        Ok(Some(Frame { header, payload }))
    }
}
```
The full crate adds `record.rs` (ResourceRecord canonical bytes + encode/decode),
`FetchRequest` encode/decode, STATUS/UPDATE codecs, fuzz harness, and roundtrip tests.

---

## 5. Advantages

1. **Integrity by construction** — blake3 + Ed25519 end-to-end; HTTP has nothing.
2. **Exact revalidation** — cursor/hash preconditions kill the heuristics bug class.
3. **Push that works** — SUBSCRIBE is an explicit demand signal; the HTTP/2 push
   failure mode is structurally impossible.
4. **Offline-first** — the local store is a correct cache; cursor catch-up is
   deterministic sync. Service workers become unnecessary.
5. **One model for everything** — requests, uploads, SSE-style streams, and fanout
   are all just frames on streams; no chunked/SSE/WebSocket special cases.
6. **Binary + fixed framing** — fast parse, no smuggling, no HPACK/QPACK attack
   surface.
7. **Semantic clarity** — no header soup (no 40+ hop-by-hop directives), and the
   transport is swappable (0.2 → QUIC) without touching semantics.

## 6. Disadvantages

1. Not human-readable on the wire; debugging needs tooling (mitigated: ASCII preface,
   debug strings in STATUS, `nxget`/`nx-tail` CLIs in plan).
2. Ecosystem cost: no curl, proxies, CDNs, WAFs, middleboxes; migration is expensive.
   An nxp→HTTP gateway is the planned bridge.
3. TLS-mandatory excludes plaintext embedded/LAN niches where HTTP/1.1 still wins.
4. Stream machinery is genuinely hard: flow control, backpressure, reset races —
   these are HTTP/2's hard lessons, now ours to re-learn.
5. Namespace bootstrap: NXmap directory + key distribution is a chicken-and-egg
   problem (IPFS's hardest lesson).
6. Dynamic/per-user content (auth'd dashboards) needs per-subscriber crypto — a 0.1
   gap.
7. No header compression in 0.1 → fatter metadata than HPACK at scale.

## 7. Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| Stream/flow-control bugs (deadlock, HOL, reset races) | Strict stream state machine; fixed windows in 0.1; cargo-fuzz the parser; two independent implementations must interop from day 1 |
| Version split (0.1 vs 0.2 in the wild) | 0.x ladder with a guaranteed minimal 0.0 profile; gate version growth; translators as last resort |
| Key/namespace bootstrap fails | NXmap directory + DNS TXT fallback + TOFU pinning (SSH-style); inline pubkey URIs |
| Subscription DoS (fanout storms, memory) | Per-conn sub limits, per-topic fanout caps, WINDOW backpressure, GOAWAY drain |
| Replay of old signed records | prev_cursor chain detects rewrites for tracking clients; advisory semantics documented |
| Adoption chicken-and-egg | nxp→HTTP gateway: any HTTP client reaches NX content day one; content dual-served |
| Parser memory DoS | Bounded lengths everywhere (MAX_FRAME, MAX_RECORD, string caps) enforced before allocation |
| Signature overhead at scale | Per-record Ed25519 fine for 0.1; batch/aggregate schemes later; sigs optional in test profile |

## 8. Recommended prototype (5 weeks)

- **W1 — wire crate:** `crates/nxp-proto` — wire/frame/record codecs, unit + roundtrip
  tests, cargo-fuzz on the frame parser (no panic, no unbounded alloc on 100k frames).
  *Delivered with this task: crate skeleton at `crates/nxp-proto`.*
- **W2 — server + client:** `nxpd` (tokio) — TLS, preface/caps handshake, FETCH over a
  static store, RANGES, `if_cursor`. DoD: `nxget` fetches and verifies blake3.
- **W3 — push:** SUBSCRIBE + UPDATE + SYNC catch-up + `nx-tail`. DoD: `tail -f` a
  namespace over a flaky link with zero loss.
- **W4 — integrity + offline:** Ed25519 signing/verification, offline store, `nx-sync`.
  DoD: full offline read + catch-up on a disconnected laptop.
- **W5 — bridge + benchmarks:** nxp→HTTP gateway; compare vs HTTP/1.1 and HTTP/3
  (nghttp3/h2o): fetch latency, 100-stream multiplexed throughput, revalidation round
  trips, fanout cost. DoD: ≥ HTTP/2 throughput on the same box; report published.

## 9. Open questions

1. NXmap: DNS TXT records vs a dedicated directory protocol — 0.1 uses DNS TXT +
   inline keys; revisit after W4.
2. Private subscriptions: per-subscriber key wrapping (MLS-style ratchets) for 0.2?
3. Structural selectors on trees: server-side recursion acceptable for 0.1, or do we
   need IPLD-style DAG walking client-side?
4. Header compression when records grow: static-table scheme (HPACK-lite) or just
   larger MAX_RECORD?
5. 0.2 transport: bind NXP streams 1:1 to QUIC streams, or run NXP frames over a
   single QUIC stream (nested mux)?