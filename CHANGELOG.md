# Changelog

All notable changes to `devguard-scan` (devguard-in-browser) are documented
here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Versioning note:** this is a static, client-side browser demo (no build
> step, no published artifact). The current in-tree version is `0.1.0`
> (`package.json`); there are no Git tags or GitHub releases yet, so the
> `[0.1.0]` entry below is seeded from the repository history. This is an
> intentionally minimal CHANGELOG for a single-version POC.

## [Unreleased]

Documentation and CI maintenance after the initial `0.1.0` cut, two real UI
fixes, and two usability upgrades (allowlist support, CLI/Action); no change
to the 10 detection rules themselves.

### Added

- **Allowlist support** (`scan.js`: `findingMatchesRule`/`applyAllowlist`;
  `bin/scan.mjs`: `--allowlist <path>`, auto-discovers `<dir>/.wrg/
  allowlist.json`; browser: n/a this round, CLI/CI is the primary use case).
  Every prior report hardcoded `summary.suppressed` to `0` -- the canonical
  CLI's real allowlist mechanism (`_apply_allowlist`, matches on
  check/rule_id/severity/file-glob/snippet_contains) was never ported.
  Cross-checked directly against `wrg_devguard.cli._apply_allowlist()` with
  an identical rule set (2026-07-17): 9 findings -> 5 active + 4 suppressed,
  same findings suppressed, same counts.
- **Browser UI: include/exclude override** -- a collapsible "Advanced"
  section lets a one-off scan override either glob list (e.g. force-include
  an extension the built-in list skips) without touching the defaults.
  Verified with a dedicated UI-smoke scenario (a no-extension file is
  skipped by default, then picked up once overridden).
- **Browser UI: "Download report (.json)" button** -- exports the last scan
  result (same schema as CLI `--json`) as a local file download; disabled
  until a scan has run, re-disabled on Clear.

- **`bin/scan.mjs`** -- a filesystem CLI over the same zero-dependency engine
  (`scan.js`) the browser uses. `node bin/scan.mjs <dir> [--include ...]
  [--exclude ...] [--json]`, exit code 1 on any ERROR-severity finding.
  `scan.js` was already documented as running "in browser AND Node" but the
  only Node entrypoint was the internal parity-dump script; this makes that
  capability directly usable (pre-commit hook, plain CI step).
- **`action.yml`** -- a composite GitHub Action wrapping the CLI, so other
  repos can add `uses: WRG-11/devguard-scan@main` as a secret-scan CI gate
  without vendoring anything. Exposes `path`/`include`/`exclude` inputs and
  `total-findings`/`error-count`/`status` outputs.
- `.github/workflows/self-scan.yml` -- dogfoods `action.yml` against this
  repo's own source on every push/PR (also the working usage example).
- `scripts/cli_smoke.mjs` -- smoke-tests `bin/scan.mjs` (known-corpus finding
  count, `--exclude` override, clean-directory PASS/exit-0), wired into
  `run_parity.ps1` as step 5/5.
- `index.html`/`app.js`: light/dark theme toggle (CSS custom-property token
  swap via `[data-theme]`; localStorage-persisted, falls back to
  `prefers-color-scheme`, applied pre-paint to avoid a flash of the wrong
  theme). Purely cosmetic -- no change to scanning behavior.
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

- `index.html`: `textarea`, `input[type="text"]`, and `code` backgrounds
  were hardcoded dark hex values (`#0b0f14`) instead of `var(--bg)` --
  latent since the CSS predates the theme toggle, but broke light mode the
  moment it existed (dark input wells against a light page). The primary
  `button`'s text color was also hardcoded dark (`#0d1117`), which is fine
  against dark mode's light-blue `--accent` but low-contrast against light
  mode's more saturated blue -- added a theme-aware `--on-accent` token
  (dark text in dark mode, white in light mode) instead of guessing a
  single accent shade that would look right in both.
- `SECURITY.md` + `scan.js` + `scripts/run_parity.ps1`: corrected a dead
  link/instruction pointing at `WRG-11/wrg-devguard` -- that repo was never
  published standalone (confirmed 404); the canonical `wrg_devguard` source
  lives in a private monorepo. Docs now say so honestly
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
