# Resolution model (v0)

```text
petname -> Route { endpoints, pinned_site_id }
```

- `LocalResolver`: in-memory `name -> Route`, names `[a-z0-9-]{1,64}`.
- Browser builds one from `--server` today; config-file + signed-record
  resolvers come next.
- The `Resolver` trait is the extension point for DHT/gossip/federated
  backends (see `docs/decisions/004-resolution.md`). No distributed code
  until the local data model + signed records are wired (M3/M4).
