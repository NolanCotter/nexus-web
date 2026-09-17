# Transport hardening (two-process path)

Wire protocol is unchanged (text NXP/0.1). This note documents the
server/transport robustness policy (Milestone C).

## Connection cap

- `serve_with_config` caps concurrent connections (`ServerConfig`,
  default 64, `--max-connections N`). Counter is `AtomicUsize` + CAS
  try-acquire (std only, no semaphore crate).
- Connections beyond the cap get `NXP/0.1 503 <len>` (`server busy`)
  written inline on the accept loop (2s write timeout, no slot consumed),
  then close. 503 bodies are tiny and fixed-size.
- Slots release when the handler thread exits (RAII guard), including on
  read/write errors — a dead peer can never leak a slot.

## Read deadlines (slowloris protection)

- Every admitted connection gets `SO_RCVTIMEO`/`SO_SNDTIMEO` from
  `ServerConfig` (defaults 10s/10s). A client that trickles a partial
  request line is closed when the read deadline fires; the slot is freed.
- The client side already had `IO_TIMEOUT` (10s) in `nexus-transport`.

## Request rate policy (documented, not enforced)

- No per-IP token bucket: the reference server is single-origin, one
  request per connection, responses are tiny. The cap + deadlines bound
  total work: at most `max_connections` threads, each holding at most one
  ≤4KiB line and one ≤1MiB body.
- Operators needing abuse resistance should put a reverse proxy / firewall
  rate limit in front. A built-in limiter would add per-peer state and
  clock plumbing disproportionate to a reference server; revisit if the
  server ever accepts pipelined or authenticated-write traffic.

## Transport framing guarantees

- `read_body` checks `len > MAX_BODY` **before** allocating or reading:
  oversized length claims error as `BodyTooLarge` with zero allocation.
- EOF mid-line or mid-body maps to `ProtocolError::Truncated` (was: bare
  `io::UnexpectedEof`), so callers can distinguish truncation from slow
  peers (timeouts stay `Io`).
