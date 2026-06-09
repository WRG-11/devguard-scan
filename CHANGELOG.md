# Changelog

All notable changes to `devguard-scan` (devguard-in-browser) are documented
here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Versioning note:** this is a static, client-side browser demo (no build
> step, no published artifact). The current in-tree version is `0.1.0`
> (`package.json`); there are no Git tags or GitHub releases yet, so the
> `[0.1.0]` entry below is seeded from the repository history. This is an
> intentionally minimal CHANGELOG for a single-version POC.

## [Unreleased]

Documentation and CI maintenance after the initial `0.1.0` cut; no change to the
scan engine or detection rules.

### Changed

- docs(README): reconciled the "parked" status note with the live GitHub Pages
  demo — the README now links the live instance and scopes "parked" to the
  Pyodide pattern only. (a0a1673)

### Maintenance

- ci(security): pinned `codeql-action` / `checkout` workflow refs to commit
  SHAs (0ba02ee #4); `actions/checkout` 4.3.1 -> 6.0.3 (#5).
- ci: added `dependabot.yml` (GitHub Actions + npm, weekly). (8147fad #3)

## [0.1.0] - 2026-05-30

First public POC: a **100% client-side** secret scanner. Paste code or drop
files and it flags leaked API keys, tokens, and private-key blocks **without a
single byte leaving the browser** — a static, dependency-free port of the
`scan-secrets` detection engine.

### Added

- **Client-side secret scanning** (`scan.js`) — 0-byte upload: no `fetch`,
  `XMLHttpRequest`, `WebSocket`, `sendBeacon`, analytics, or external CDN. All
  scanning runs in-browser.
- **Detection rule set grown to 10 rules**, parity-safe with the canonical
  scan engine; same include/exclude logic and line/column reporting.
- **Redacted-by-default output** — every match is reported as `[REDACTED]`;
  raw secret values never enter the results table, the DOM, or any payload.
- **Inline data-URI favicon** for a pristine zero-request Network tab.
- `secret_rule_count` metric markers in the README plus a free GitHub Actions
  workflow to keep the count in sync. (98bf4a3 #2)
- MIT `LICENSE`, `SECURITY.md`, and a CodeQL/Dependabot security setup.

### Notes

- Positioned as a "try-it-now" capability demo of the detection engine, not a
  product.
