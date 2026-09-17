# 003 — Typed page model instead of HTML

- Status: accepted (v0)
- Context: browser should understand structure natively.
- Problem: HTML/CSS/JS string soup brings XSS, cascade complexity, unbounded parser surface.
- Options: HTML subset / Markdown / JSON typed tree / binary serde.
- Decision: typed `Page` (Text/Heading/Image/Link/Collection/App) as canonical JSON for v0; binary codec negotiable later from the same serde model.
- Consequences: small validator (~100 lines), snapshot-testable renderer; custom designs need schema evolution, not CSS hacks.
