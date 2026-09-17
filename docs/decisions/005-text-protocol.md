# 005 — Text NXP/0.1 prototype, binary later

- Status: accepted (v0)
- Context: need client<->server bytes now without over-engineering.
- Problem: multiplexing/streaming/versioning matter, but not before one fetch works.
- Options: binary frame now / text line now / QUIC now.
- Decision: `NXP/0.1 FETCH` text line + `NXP/0.1 CODE LEN` response over TCP with strict limits; binary/multiplex as negotiated upgrade later.
- Consequences: debuggable with netcat; limits enforced at every layer; wire will change, so version string is mandatory.
