# Task B: Protocol design — proposal (archived subagent report)

> Source: Protocol Engineer (background research crew).
> Status: proposal + working prototype crate, parked on
> `experiment/binary-protocol` (verified: 14/14 tests green).
> Current `main` keeps the text `NXP/0.1 FETCH` prototype (ADR 005) until
> the binary design is reviewed against running code.

## Decision under review: binary framing + ASCII preface

Binary frames (no in-band delimiters, so no smuggling class), fixed
10-byte header (`length u32 | type u8 | flags u8 | stream_id u32`),
LEB128 varints, ASCII `NX/0.1` connection preface, human-readable debug
strings in STATUS frames. Full spec: `protocol/NXP-0.1.md` on the branch.

## Semantics (beyond transport)

- Streams: ordered frame sequences terminated by END_STREAM; full-duplex.
- Multiplexing: client-odd stream IDs, per-stream flow control; TCP+TLS
  1.3 for 0.1, QUIC in 0.2 with zero semantic change.
- Push that works: explicit SUBSCRIBE (pattern + cursor) -> snapshot then
  UPDATE frames. Demand-signal only, so the HTTP/2-push failure mode
  (push without demand, cache pollution) is structurally impossible.
- Exact caching: every resource has content hash (immutable truth) +
  cursor (mutable version); `if_cursor`/`hash_pin` preconditions give
  race-free revalidation. No heuristics, no Vary, no Expires.
- Integrity in three layers: TLS per connection, BLAKE3 per resource,
  Ed25519 per record + `prev_cursor` hash chain per name.
- Partial retrieval: byte ranges with `range-hash` so slices verify
  independently, plus selector paths.
- Offline-first: hash-addressed bodies + signed records make the local
  store a correct cache; SUBSCRIBE replayed from saved cursor = SYNC.
- Negotiation: preface magic + version, capability bitmask + settings;
  server replies highest supported version and caps intersection.

## Comparison matrix (report's verdict)

| protocol | enc | stream | mux | push | cache | negot | integ | partial | offline |
|---|---|---|---|---|---|---|---|---|---|
| HTTP/1.1 | text | partial | no | no | heuristic | no | no | partial | no |
| HTTP/2 | bin | partial | yes | broken | heuristic | no | no | partial | no |
| HTTP/3 | bin | partial | yes | no | heuristic | no | no | partial | no |
| gRPC | bin | yes | yes | partial | no | no | no | no | no |
| MQTT | bin | partial | no | yes | partial | no | partial | no | partial |
| IPFS/libp2p | bin | partial | yes | partial | yes | partial | yes | yes | yes |
| **NXP/0.1 (branch)** | bin | yes | yes | yes | exact | yes | yes | yes | reads+sync |

## Advantages / disadvantages (abridged)

Plus: end-to-end integrity; exact revalidation; working push; offline as
the normal case; one frame model for requests/streams/fanout; no
HPACK/QPACK surface. Minus: not human-readable on the wire; no
curl/CDN/WAF ecosystem (nxp->HTTP gateway planned); stream machinery is
genuinely hard (flow control, reset races); namespace bootstrap
(NXmap/DNS-TXT/TOFU) is the hardest non-wire problem; per-record Ed25519
cost at scale.

## Risks carried as gates

- Stream/flow-control bugs -> strict state machine + fuzz + two
  implementations must interop from day one.
- Subscription DoS -> per-conn sub limits, fanout caps, WINDOW
  backpressure, GOAWAY drain.
- Replay of old records -> `prev_cursor` chain (advisory in 0.1).
- Parser memory DoS -> MAX_FRAME/MAX_RECORD/string caps before allocation.

## Relationship to `main`

`main` ships the text prototype deliberately (ADR 005: debuggable now,
negotiated upgrade later). The branch's `nxp-proto` crate (wire, frame,
record, tokio codec + 14 tests) is the candidate binary upgrade. Merge
criteria: interop test text<->binary gateway, fuzz target green,
benchmark note showing it earns its complexity. Prototype roadmap W2-W5
(server+client, push, integrity+offline, bridge+benchmarks) stays open
for a future lane.
