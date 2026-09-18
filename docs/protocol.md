# NXP/0.1 wire spec (prototype)

Transport: TCP. One request line, one response frame, connection closes.

## Request

```text
NXP/0.1 FETCH <site> <path>\n
NXP/0.1 RECORDS <site> <path>\n
```

- `site`: `[a-z0-9-]{1,64}`, no leading/trailing `-`.
- `path`: `[A-Za-z0-9/_.\-+]{1,256}`, no `..`, no `//`, no leading `/`. Example: `home`, `blog/hello`.
- Line max 4096 bytes incl. `\n`. Anything else -> server replies `400`.
- `FETCH` returns the page body. `RECORDS` returns a JSON array of
  `SignedRecord` vouching for the page (or `404` when the server has no
  records — e.g. started without `--key`). Unknown verbs -> `400`.

## Response

```text
NXP/0.1 <CODE> <LEN>\n<body>
```

- `CODE`: `200` page JSON (FETCH) or record array (RECORDS), `404` not found / no records, `400` bad request.
- `LEN`: exact body byte length, `0 <= LEN <= 1048576`.
- Body for `200` is canonical page JSON (see content model). Error bodies are short ASCII.

## Example

```text
C: NXP/0.1 FETCH example home\n
S: NXP/0.1 200 512\n{"metadata":{...},...}

C: NXP/0.1 RECORDS example home\n
S: NXP/0.1 200 231\n[{"record":{...},"signature_hex":"..."}]
```

## Non-goals for 0.1

No multiplexing, streaming, push, auth, or encryption. Those are explicit
future negotiations (see `docs/decisions/005-text-protocol.md`).
