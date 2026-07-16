# Changelog

All notable changes to `devguard-scan` (devguard-in-browser) are documented
here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Versioning note:** this is a static, client-side browser demo (no build
> step, no published artifact). The current in-tree version is `0.1.0`
> (`package.json`); there are no Git tags or GitHub releases yet, so the
> `[0.1.0]` entry below is seeded from the repository history. This is an
> intentionally minimal CHANGELOG for a single-version POC.

## [Unreleased]

Documentation and CI maintenance after the initial `0.1.0` cut, plus one real
UI fix; no change to the scan engine or detection rules.

### Added

- `app.js`: real recursive directory-drop support via the
  `DataTransferItem.webkitGetAsEntry()` + `FileSystemDirectoryReader` walk.
  The UI copy already claimed "Folders supported in Chromium" but the drop
  handler only ever read `dataTransfer.files` (flat, top-level files only --
  a dropped folder contributes nothing there); nested files never actually
  reached the scanner. Verified end-to-end with a new UI-smoke scenario
  (nested `project/sub/nested.env` -> finding rendered with its relative
  path, secret redacted).

### Changed

- docs(README): reconciled the "parked" status note with the live GitHub Pages
  demo — the README now links the live instance and scopes "parked" to the
  Pyodide pattern only. (a0a1673)

### Fixed

- `SECURITY.md` + `scan.js` + `scripts/run_parity.ps1`: corrected a dead
  link/instruction pointing at `WRG-11/wrg-devguard` -- that repo was never
  published standalone (confirmed 404); the canonical `wrg_devguard` source
  lives in the private WinstonRedGuard monorepo. Docs now say so honestly
  instead of pointing contributors at a nonexistent clone target.
  `scan.js`'s source-line citations for `common.py`'s `match_any`/`line_col`
  were also stale (L34-44/L53-57 claimed, actual L42-52/L74-78) -- corrected
  after re-verifying byte-identical parity (9/9 findings) against the
  current monorepo source.
- README.md: the WRG-11 ecosystem link for `wrg-sigma-rules` hardcoded
  "68 sigma detection rules" -- that repo has since grown to 73+. Dropped
  the hardcoded count (cross-repo counts can't be self-stamped the way
  `secret_rule_count` is within this repo).

### Maintenance

- ci: bumped `github/codeql-action/init` + `/analyze` 4.36.2 -> 4.36.3,
  grouped so both bump together going forward (#8, #9, #12, #13).
- ci: bumped `actions/checkout` 6.0.3 -> 7.0.0 (#7).
- test: tidied synthetic fixture comment headers; no detection-behaviour
  change. (03948ab)
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
