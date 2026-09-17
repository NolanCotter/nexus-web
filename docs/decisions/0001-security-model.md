# ADR 0001 — Security Model, Threat Model & M0/M1 Hardening (Task K)

Status: proposed · Owner: security engineering · Depends on: protocol, identity, resolver,
transport, content, storage, server, renderer, webvm, browser designs (Tasks A–J)

---

## 1. Scope and ground rules

This review covers the whole workspace crate layout. No crate has code yet, so this is a
*design-time* security model: it fixes the invariants each crate must hold, the threat model
they must be tested against, and the minimum hardening gates for the M0/M1 prototype. Where a
behavior is not yet specified by a sibling task, it is called out as an **assumption (A)**.

Ground rules that apply from this ADR forward:

- **Never claim security because Rust.** `forbid(unsafe_code)` (already in the workspace) is a
  floor, not a ceiling. The memory-safety argument only covers code written in Rust; the threat
  surface is the *host-ABI boundary*, *parser logic*, *state machines*, and *resource policy*,
  where logic bugs are indistinguishable from memory bugs in effect.
- **Total parsing.** Every parser in the stack must be total: no panics on untrusted input, no
  `unwrap`/`expect`/indexing in decode paths. Panics in a decode path are a DoS primitive.
- **Fail closed.** Unknown fields, unknown versions, malformed lengths, unexpected states →
  reject the message/message, close the stream. Never "best-effort parse".
- **Zero ambient authority.** The webvm/renderer never gets access it did not explicitly
  request; capabilities are per-origin, per-session, revocable, audited.
- **Untrusted-by-default.** Anything received from the network is data, not instructions:
  lengths are advisory, names are strings, not paths, HTML is not the browser chrome.

---

## 2. Architecture recap (crate boundaries assumed for this review)

| Crate | Assumed responsibility |
|---|---|
| `protocol` | Framing, wire encoding, message types, length rules |
| `transport` | Connection lifecycle, encryption, handshake, peer auth |
| `identity` | Keypair, node/site IDs, signing/verification, key storage |
| `resolver` | Name → content mapping, binding records, lookup |
| `content` | Content-addressed blobs, manifests, fetch semantics |
| `storage` | Local blob cache, index, quotas, eviction |
| `server` | Node-side listener: serves browser and peer requests |
| `renderer` | HTML/CSS parse + layout, subresource loading, pixels |
| `webvm` | Hosted execution of site code (WASM/JS), sandbox boundary |
| `browser` | Chrome UI, tabs, origins, permissions, navigation |

Trust domains, in increasing order of hostility:

1. **Chrome core** (browser + identity + server-side of transport/storage): trusted, minimal.
2. **Signed content pipeline** (protocol, resolver, content, storage): adversarial *inputs*,
   but the *pipeline code* is trusted.
3. **Untrusted execution** (webvm, renderer): fully hostile — site code and site markup are
   attacker-controlled payloads. Everything below this boundary must assume compromise.
4. **Network** (transport inbound, other nodes): hostile, plus active MITM.

The single most important architectural property: **domain 3 can never touch domain 1 except
through the capability API**, and everything domain 3 can do must be expressible as typed,
logged, revocable grants.

---

## 3. Threat model

Method: STRIDE per trust domain, then cross-cutting lists. Likelihood (L) and impact (I) are
rated H/M/L for prototype planning.

### 3.1 Protocol — parsing & framing

| Threat | STRIDE | L | I | Notes |
|---|---|---|---|---|
| Length-field integer overflow → huge alloc | DoS | M | H | `u32` length read then `vec![0; len]` = instant OOM |
| Negative/sentinel length values | DoS/E | M | H | sign-extension bugs in hand-rolled codecs |
| Missing/too-small frames → short read hang | DoS | M | M | no frame-length check before buffering |
| Varint/field overlong encodings, aliasing | DoS/E | M | M | two encodings of one value → state confusion |
| Unknown enum discriminants/fields | E | H | M | must be rejected, or forward-compat breaks auth |
| Deeply nested length-prefixed structures | DoS | M | H | recursion/stack or exponential expansion |
| Huge string fields, embedded NULs | DoS/input | H | M | NULs feed path traversal later (see 3.8) |
| Ambiguous framing, pipelining desync | DoS | M | H | no magic+version+length header = desync risk |
| Codec bomb (small packet → big decoded object) | DoS | M | H | e.g. 4-byte length claiming 4 GB, zlib bombs |
| Hash collision attacks on decode maps | DoS | L | M | only if untrusted strings key interned maps |

Design rules that neutralize this class:

- Frame header = magic + version + declared length; length is **capped before allocation**;
  anything over cap is a protocol error, connection drop.
- All variable-length fields have a declared maximum that is enforced at the *field* level and
  the *message* level. A message may not exceed `MAX_MESSAGE`.
- Fixed-width integer fields, no varints in v1 (varints are for human-readable encodings that
  get optimized later; correctness first — fixed widths are trivially total).
- One canonical encoding; canonicalization is checked in tests (property tests over
  round-trips, plus explicit "two encodings of the same value" rejection tests).
- Parse depth budget (max 8 nested containers); parser is table-driven, no recursion.
- Strings are validated (UTF-8, no NUL, no control chars, bounded length) at the codec
  boundary — field type is `String`, checked, never raw `&[u8]` passed onward.
- **Fuzz from day one**: `cargo fuzz` targets for each frame type + a grammar-aware fuzzer
  that knows the framing so it can attack the payload, not just the header.

### 3.2 Transport

| Threat | STRIDE | L | I | Notes |
|---|---|---|---|---|
| Unauthenticated handshake → MITM | Spoofing | H | H | if v1 ships plaintext or unauthenticated AEAD, everything else is moot |
| Downgrade (offer/accept weaker ciphers) | Tampering | M | H | whitelist exactly one cipher suite |
| Replay of handshake messages | Replay | M | H | per-connection nonce + identity-bound static keys |
| Slowloris / half-open connections | DoS | H | M | accept + read timeouts, handshake deadline |
| Connection flood / socket exhaustion | DoS | H | M | max conns, SYN backlog, per-peer caps |
| Backpressure failure (unbounded queues) | DoS | M | H | every channel needs bounded queue + drop policy |
| Peer ID spoofing on plaintext channels | Spoofing | H | H | never trust claimed IDs; ID comes from the handshake key |

Rules: one authenticated key-exchange protocol (Noise `XX` or `KK` with the *node identity key
pinned as the static key*, or TLS 1.3 with cert fingerprint binding immediately following
handshake). v1: exactly one suite, no negotiation. Node identity is derived from the handshake
key — never from a field in a later message.

### 3.3 Identity

| Threat | STRIDE | L | I | Notes |
|---|---|---|---|---|
| Private key compromise (file perms, backups) | Spoofing | M | H | key files must be 0600, dir 0700, in data dir |
| Weak entropy in keygen | Spoofing | L | H | use OS RNG (`rand`/`getrandom`), never seeded PRNG |
| Key confusion (attacker supplies pubkey+sig) | Spoofing | M | H | verify against the *resolved* identity, not any key in the message |
| Alg/hash confusion | Tampering | M | H | domain-tagged signatures, one alg, explicit algorithm byte |
| Signature malleability | Tampering | M | M | strict verification (reject non-canonical sigs) |
| Timestamp/clock trust for freshness | Replay | M | M | monotonic counters over wall-clock where possible |
| Key loss = total site loss | Availability | H | H | self-sovereign identity: no recovery path — document, warn, plan rotation |

Rules: `ed25519` only; every signature over a **domain-separated message** (`"nexus/v1/manifest" ‖
method ‖ path ‖ body_hash ‖ nonce ‖ version`). Domain separation prevents cross-protocol
replay (e.g. reusing a content signature as an identity signature). Private keys never enter
the webvm/renderer; signing happens only in `identity`, via a narrow API.

### 3.4 Resolver — names & bindings

| Threat | STRIDE | L | I | Notes |
|---|---|---|---|---|
| Name squatting / typosquatting | Spoofing | H | M | inherent without authority; UI must show full ID |
| Signed-name rollback (replay old binding) | Replay | M | H | binding records carry monotonic version; nodes reject older |
| Resolver MITM / poisoned responses | Spoofing | M | H | bindings are signed by the name owner; resolver is a cache, not a CA |
| Eclipse/sybil on P2P resolution | DoS | M | H | bounded peer sets, diverse bootstrap, no unbounded fan-out |
| Reflective amplification (lookup loops) | DoS | M | M | rate-limit resolution, cache negatives |
| Supplying a malicious resolver → wrong content | Spoofing | M | H | client must verify binding sig + content hash itself |

Key rule: **the resolver never authenticates anything.** It returns candidate bindings; the
client verifies the owner signature and the content hash chain. A malicious resolver can only
withhold service, not forge content.

### 3.5 Content

| Threat | STRIDE | L | I | Notes |
|---|---|---|---|---|
| Hash mismatch served as valid content | Tampering | M | H | hash verified *before* parse/render/exec |
| Hash truncation/prefix collisions | Tampering | L | M | full 256-bit hashes in v1; no truncation |
| Decompression bombs (HTML/image/archive) | DoS | H | H | hard byte caps on decompressed output |
| Content-type confusion (HTML served as image) | E | H | H | active content never served from arbitrary blobs; MIME is derived from manifest, not sniffed |
| Replay of old site version | Replay | M | M | content-addressing makes this natural; binding version prevents rollback |
| Huge manifests → many subfetches | DoS | M | M | cap manifest size and subresource count |

### 3.6 Storage

| Threat | STRIDE | L | I | Notes |
|---|---|---|---|---|
| Disk quota exhaustion | DoS | H | M | hard quota per origin + global; eviction before write |
| Path traversal via names/hashes | E | H | H | storage keys are *computed* (hash hex), never from strings; no user string is a path |
| Symlink attacks on cache dir | E | M | H | create data dir 0700, `O_NOFOLLOW`, no symlink support, verify ownership |
| TOCTOU between check and write | E | L | M | write via temp + atomic rename in the storage dir only |
| Index corruption / partial writes | Availability | M | M | atomic rename, periodic fsync policy, crash-recoverable index |

### 3.7 Server

| Threat | STRIDE | L | I | Notes |
|---|---|---|---|---|
| Request floods | DoS | H | M | per-peer rate limits, semaphore on concurrent handlers |
| Header/length bombs | DoS | H | H | same caps as 3.1, enforced at the socket read loop |
| Serving data to unauthenticated peers | Info disc | M | M | decide v1 access policy explicitly (serving is public? gated?) |
| Bind to wildcard accidentally | E | M | H | default bind 127.0.0.1; explicit flag for serving |
| Local proxy abuse (SSRF through node) | E | M | H | browser→node and node→network are distinct hops; node must not forward arbitrary URLs |

### 3.8 Path traversal (content fetch pipeline)

Attack: name/URL containing `..`, absolute paths, backslashes, encoded separators
(`%2e%2e`, `\`, `//`), NULs, tricks to make the content layer read outside the site's subtree
or write outside the cache. Enforced by construction:

- URLs are parsed as strictly typed structures, not strings. Path components are validated
  against `[A-Za-z0-9._-]`; anything else → parse error.
- The only filesystem writes are in `storage`, keyed by content hash (hex) or origin-derived
  keys. No name string ever reaches the filesystem.
- Resolved content paths are rendered through a single `resolve(key)` function that
  canonicalizes and asserts the result stays under the root (belt-and-braces; plus tests).
- Symlinks are not followed anywhere in the data dir.

### 3.9 Renderer & webvm — the hostile boundary

| Threat | STRIDE | L | I | Notes |
|---|---|---|---|---|
| WASM/JS engine escape | E | M | H | engine bugs are real; process isolation required even if WASM is memory-safe |
| Host-ABI confusion (raw pointers, fd passing) | E | M | H | host imports take only plain data; cross boundary by copy; no handles, no pointers |
| Capability escalation (ask for more later) | E | M | H | grants are fixed at load; no dynamic extension; re-navigation re-negotiates |
| HTML smuggling (markup that activates script without explicit grant) | E | H | H | script execution only under explicit site-code manifest; inline handlers disabled in v1 |
| CSS/selector DoS, layout bombs | DoS | M | M | parse depth/size caps; no `position:fixed`-style runaway loops in v1; render deadlines |
| Memory bomb (site allocates until OOM) | DoS | H | M | per-origin memory cap in webvm; killing the cap must not kill the browser |
| Infinite loop / busy-wait | DoS | H | M | instruction budget or cooperative yield + watchdog thread |
| Rendering sensitive chrome data into site context | Info disc | L | H | renderer output is pixels; DOM/state must never leak chrome objects |
| Clickjacking / UI redressing of the browser chrome | Tampering | M | H | synthetic overlay events are site-content; chrome is composited above and input-routed by the browser, not the webvm |
| DNS-rebinding-of-the-node (site dials its own node as "another site") | Spoofing | M | M | origin model must key on *identity*, not on socket address |

The webvm host ABI is the crown jewel. Rules:

- No ambient authority: `getrandom`, `clock`, `bytes_out`, `fetch` (capability-gated),
  `storage` (per-origin). That's ~5 imports in v1. Each import validates args, enforces caps,
  and logs.
- Webvm runs in its own OS process, no shared memory with the browser, `seccomp`-filtered
  syscalls (or equivalent on non-Linux), no file/network syscalls outside the ABI.
- The renderer and webvm never see: private keys, identity of *other* origins, node config,
  storage of other origins.

### 3.10 Browser — chrome & origins

| Threat | STRIDE | L | I | Notes |
|---|---|---|---|---|
| Spoofed identity display (phishing via chrome likeness) | Spoofing | H | H | URL/identity bar is chrome-drawn from verified data only; site can't draw into it |
| Same-origin confusion across sites | E | H | H | origin = (identity hash, path root); enforce in capability layer, not UI |
| Permission prompt abuse (auto-dismiss, timing) | Tampering | M | M | prompts are modal, chrome-owned; no programmatic dismissal |
| Tab nabbing / focus stealing | Tampering | M | M | navigation requires user gesture or explicit grant |
| Forced navigation to `nexus:` internal pages | E | M | H | internal scheme only reachable from chrome; webvm fetch denies it |

### 3.11 Cross-cutting: capability abuse

Model capability as: `(grantee_origin, capability_kind, resource_id, constraints, expiry)`.
Every webvm request is checked against the grant table by the browser (not by the webvm), and
audit-logged. Abuse patterns covered: asking for too-broad fetch, combining two benign
capabilities into abuse (confused deputy), holding grants after origin navigation (grants die
with the page), storage quota games (per-origin quota + global).

---

## 4. Advantages / disadvantages of the design choices

### 4.1 Content addressing for all content
- **Advantages:** integrity is structural (mismatch = unusable, no "trust this fetch"); natural
  dedup; replay-safe per blob; cache-friendly; makes third-party mirrors safe (a mirror cannot
  alter bytes and stay addressable).
- **Disadvantages:** no built-in mutation — every update needs the resolver binding layer, which
  re-introduces the trust problem; full re-hash cost on large blobs (mitigate: stream-verify);
  hash algorithm lock-in (plan SHA-256 → BLAKE3 upgrade path, include alg byte in address);
  content-addressing protects *integrity*, never *confidentiality* — nothing is encrypted by it.

### 4.2 Self-sovereign identity (ID = hash of pubkey)
- **Advantages:** no CA, no certificate cost, signatures verifiable by anyone, no central
  revocation authority to attack.
- **Disadvantages:** key loss is total and permanent — no recovery; no built-in revocation; key
  rotation under compromise is a manual, decentralized dance (publish new key signed by old —
  works but slow); phishing is mitigated only as well as the UI displays the *long* ID, and
  humans are bad at long IDs — expect typosquat pressure.

### 4.3 WASM-first webvm with capability host ABI
- **Advantages:** memory-safe execution of untrusted code; sandbox *by construction* instead of
  by CVE-patching; tiny, auditable import surface; near-native performance possible.
- **Disadvantages:** host ABI is where the real bugs live (any imported function is a syscall
  equivalent); WASM spec itself has had CVEs in engines (you still ship an engine); JS
  interop/GC in WASM is hard (you'll likely embed a JS engine anyway → a second, larger
  attack surface inside the sandbox); capability systems are notoriously easy to accidentally
  widen during a refactor — needs the grant table as a single choke point, not scattered checks.

### 4.4 Node-local server + P2P resolver
- **Advantages:** no big-tech dependency; works offline-ish; resilience.
- **Disadvantages:** eclipse/sybil surface for an identity keyed by address; bootstrap trust
  problem (who is the first peer?); amplification risk if serving is public; the node becomes a
  high-value local target (one compromise = full browser cache + identity + browsing record).

### 4.5 Rust everywhere + `forbid(unsafe_code)`
- **Advantages:** memory safety by construction; panic-freedom is enforceable with lint
  (`clippy::panic` guard in untrusted decode paths); single language across the stack.
- **Disadvantages:** (per ground rule) not a security model by itself; `unsafe` will be needed
  eventually in the JS engine binding if a C engine is embedded — decide *now* where that
  unsafe lives and isolate it in one crate with a review gate. Easier: pick a Rust/WASM-hosted
  JS engine (quickjs-ng via wasm, or run JS *inside* WASM) to keep `forbid(unsafe_code)` true
  workspace-wide.

### 4.6 Protocol: fixed-width, length-capped, fail-closed
- **Advantages:** trivially total parsing, no allocation bombs, easy fuzzing, fast.
- **Disadvantages:** slightly larger frames; less flexible than varint encodings; requires
  discipline in versioning (old nodes must reject, not guess). Acceptable for v1.

---

## 5. Risks (ranked, with mitigation)

| # | Risk | L×I | Mitigation |
|---|---|---|---|
| 1 | Webvm/renderer escape → host compromise | H | Process isolation + seccomp + capability ABI + memory caps + fuzzing; treat as loss-of-node, not loss-of-user |
| 2 | Transport ships without peer auth (shortcut) | H | Handshake auth is an M0 gate, not M1; no plaintext mode in v1 builds except explicit localhost/dev flag |
| 3 | Parser panics on hostile frames | M | Total parser rule + fuzz in CI + `panic=abort` in release |
| 4 | Key file mishandling → identity theft | M | 0600/0700, data-dir lock, key never leaves `identity`, backup guidance |
| 5 | Replay/rollback of site versions | M | Monotonic binding versions + content addressing + nonces in signed records |
| 6 | Storage/disk exhaustion via cache abuse | M | Quotas at write time, eviction first, global cap |
| 7 | DoS via decompression bombs | H | Decompressed-byte caps enforced at stream level in all fetch paths |
| 8 | Resolver eclipse → censored/wrong content | M | Verified bindings client-side; bounded peer sets; manual bootstrap pin |
| 9 | Phishing via identity confusion | H | Chrome-drawn identity bar with full hash + verified name; no site-drawn chrome |
| 10 | Dependency CVEs (engines, crypto impls) | M | `cargo audit` in CI, pinned+audited crypto crate set, update policy documented |

---

## 6. Validation checklist (M0/M1 gate)

**Parsing & protocol** — [ ] fuzz targets exist and run in CI (`cargo fuzz`, 60s/corpus) ·
[ ] no panics reachable from decode paths (lint + fuzz) · [ ] length caps on every field and
message · [ ] depth cap · [ ] unknown field/discriminant → reject test · [ ] canonical-encoding
round-trip property tests · [ ] codec-bomb test (claim big, deliver small) · [ ] UTF-8/NUL
validation tests.

**Transport** — [ ] handshake authenticates peer identity (test: wrong key → rejected) ·
[ ] single cipher suite, no downgrade path · [ ] read/write deadlines everywhere · [ ] max
connections + per-peer cap · [ ] bounded queues with drop policy · [ ] handshake replay test
(replay captured handshake → rejected).

**Identity & signatures** — [ ] keygen uses OS RNG (test: two keys differ, file perms 0600) ·
[ ] domain-separated signing (test: same bytes signed under two contexts fail cross-verify) ·
[ ] strict ed25519 verify · [ ] key-confusion test (message with attacker-supplied key+sig →
rejected) · [ ] no signature validation of any kind inside webvm/renderer.

**Resolver & content** — [ ] binding signed + version monotonic (rollback test) · [ ] content
hash verified before use (tamper test: flip one byte) · [ ] decompression byte caps · [ ]
manifest size/subresource caps · [ ] resolver rate limits.

**Storage** — [ ] no user string ever becomes a path (traversal fuzz over URL/name inputs) ·
[ ] data dir 0700, no symlink follow · [ ] quota enforcement test · [ ] atomic writes.

**Server** — [ ] binds loopback by default · [ ] request caps + rate limits · [ ] slowloris
test (incomplete request → timeout, no resource leak) · [ ] no arbitrary-URL forwarding.

**Renderer/webvm** — [ ] process isolation (kill webvm → browser survives) · [ ] memory cap
test (site allocs until cap → site killed, browser fine) · [ ] infinite-loop watchdog test ·
[ ] host ABI: each import unit-tested with hostile args · [ ] no raw pointers/handles across
boundary (type-level guarantee) · [ ] per-origin storage isolation test.

**Browser** — [ ] origin = identity-based, not address-based (test: two sites same addr) ·
[ ] grant table single choke point (test: navigation revokes grants) · [ ] internal scheme
unreachable from webvm · [ ] identity bar renders only verified data.

**Pipeline hygiene** — [ ] `cargo audit` green in CI · [ ] `forbid(unsafe_code)` enforced at
workspace level (unless webvm engine binding lands — then: unsafe confined to one crate +
review gate) · [ ] `panic=abort` in release · [ ] CI runs: fmt, clippy -D warnings, tests,
fuzz-smoke, audit.

---

## 7. Minimal hardening for the M0/M1 prototype (concrete)

**M0 (single-node demo: browser ↔ local server ↔ example site):**
1. Loopback-only bind for all listeners; no serving to LAN without explicit flag.
2. Frame parser with magic+version+length, `MAX_FRAME = 1 MiB`, per-field caps, fail-closed
   unknown fields; total parser (no unwraps in decode).
3. ed25519 identity crate with domain separation and 0600 key file; M0 site manifest signed;
   browser verifies manifest sig + content hash before render.
4. webvm: even at M0, run site code in a *separate OS process* with a 4-import host ABI and no
   network/file syscalls (seccomp where available). M0 is where the isolation skeleton must
   land, or it never will.
5. Per-origin storage directory under a 0700 data root; keys derived from hashes only.
6. Decompression cap (e.g. 16:1 / 8 MiB absolute) on every fetch path.
7. Timeouts on every socket op; connection cap per peer.
8. Everything logged to a ring buffer; M0 panic hooks dump last N events.
9. CI: 3 fuzz targets (frame, manifest, URL/name), cargo audit, clippy -D.

**M1 (multi-node P2P):**
1. Authenticated handshake (Noise/TLS with identity-pinned keys); exactly one suite.
2. Signed resolver bindings with monotonic versions + rollback rejection; client-side
   verification of owner signature and content hash (resolver is a cache, never a CA).
3. Per-peer rate limits + handshake deadlines; eclipse mitigation: bounded peer set, pinned
   bootstrap, address-diversity tracking.
4. Grant table for webvm capabilities: per-origin, expiry-bounded, revoked on navigation,
   audited; grant table is the *only* authority path.
5. Storage quotas (per-origin + global) with eviction-before-write.
6. Key rotation path (new key signed by old) + documented recovery/backup for identity keys.
7. Public-serve opt-in flag with rate limiting and size caps for responses.

Deliberate M1 non-goals (accepted risk, documented): revocation infrastructure, encrypted-at-
rest cache, multi-suite negotiation, anonymous browsing, anti-sybil proof-of-work.

---

## 8. Open questions for sibling tasks (needed to close this model)

1. Does the browser embed a JS engine for webvm, or is site code WASM-only in v1? (Changes
   process-isolation design and the unsafe-code gate.)
2. Is node serving public-by-default or request-gated? (Changes amplification risk.)
3. Who are bootstrap peers / who pins the resolver network? (Changes eclipse assumptions.)
4. Is the renderer shared with any existing engine (Servo/WebKit), and does it run in-process
   with webvm or separate? (Changes the hostile-boundary diagram.)
5. What is the exact origin model — (identity, path root) vs (identity, site-id)? (Affects
   same-origin enforcement tests.)

---

*Security is not a feature; it is the property that the threat model's listed attacks fail.
If an attack is not in this list and ships, the model will be updated — the checklist in §6 is
the enforcement mechanism, not this document.*