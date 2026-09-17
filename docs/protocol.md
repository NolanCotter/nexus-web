# NXP/0.1 wire spec (prototype)

Transport: TCP. One request line, one response frame, connection closes.

## Request

```text
NXP/0.1 FETCH <site> <path>\n
```

- `site`: `[a-z0-9-]{1,64}`, no leading/trailing `-`.
- `path`: `[A-Za-z0-9/_.\-+]{1,256}`, no `..`, no `//`, no leading `/`. Example: `home`, `blog/hello`.
- Line max 4096 bytes incl. `\n`. Anything else -> server replies `400`.

## Response

```text
NXP/0.1 <CODE> <LEN>\n<body>
```

- `CODE`: `200` page JSON, `404` not found, `400` bad request.
- `LEN`: exact body byte length, `0 <= LEN <= 1048576`.
- Body for `200` is canonical page JSON (see content model). Error bodies are short ASCII.

## Example

```text
C: NXP/0.1 FETCH example home\n
S: NXP/0.1 200 512\n{"metadata":{...},...}
```

## Non-goals for 0.1

No multiplexing, streaming, push, auth, or encryption. Those are explicit
future negotiations (see `docs/decisions/005-text-protocol.md`).
