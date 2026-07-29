# Changelog

All notable changes to `devguard-scan` (devguard-in-browser) are documented
here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Versioning note:** the in-tree version is `0.2.0` (`package.json`). There
> are still no Git tags or GitHub releases: the `[0.1.0]` entry below was
> seeded from repository history, and `[Unreleased]` is staged to be cut as
> `v0.2.0`. Until a tag exists, `uses: WRG-11/devguard-scan@main` tracks a
> moving branch -- pin to a commit SHA if you need stability. Cutting the tag
> is a maintainer action; see "Releasing" at the end of this file.

## [Unreleased]

Staged as `0.2.0`. Two rounds of work: the `0.1.0` follow-ups (allowlist, CLI,
Action, UI fixes), and then a parity/measurement round that found the port had
silently stopped scanning `.env.local` and `.cfg` files.

### Fixed -- detection

- **`DEFAULT_INCLUDE` parity: `**/*.env.*` and `**/*.cfg` were missing.** The
  canonical `secrets.py` gained both on 2026-07-21; this port last
  hand-verified parity on 2026-07-17 and never picked them up. `**/*.env` does
  not match a suffixed env file, so `.env.local` / `.env.production` and
  `setup.cfg` / `tox.cfg` -- the two places a leak most often sits -- were
  skipped by the browser demo, the CLI and the Action alike. Measured on one
  directory before the fix: canonical Python 3 findings including an AWS key in
  `.env.local`, this engine 1. The live GitHub Pages copy carried the same gap.
- **Columns are counted in code points, not UTF-16 units.** `RegExp.exec`
  returns a UTF-16 offset and Python's `match.start()` a code-point offset, so
  any character outside the BMP before a match made this engine report a column
  two higher than the canonical tool for the same finding. Previously
  documented as a known divergence and left alone because the corpus is ASCII;
  the corpus is not the input.

### Fixed -- the gate itself

- **A misconfigured scan reported a clean tree.** `node bin/scan.mjs ./typo`
  walked a directory that does not exist, found nothing and exited `0`; a
  mistyped flag such as `--jsonn` was silently taken as the directory to scan,
  with the same result; a flag missing its value died with a raw `TypeError`
  stack trace. As a CI gate the first two are the dangerous ones -- a typo in
  the Action's `path:` input buys a permanently green check. Added exit code
  `2` for "the scan did not run", and the Action now fails the step on it
  explicitly instead of parsing an absent report.
- Reports carry `files_scanned`, `skipped_oversize` and `skipped_unreadable`.
  "0 findings" and "0 files matched the include list" used to be the same
  output. The fields are `null` rather than `0` when not measured, so
  "unmeasured" stays distinguishable from "measured, and it was zero".
- `scripts/js_reference_dump.mjs` now mirrors `read_text_safely`: an unreadable
  directory or a file vanishing mid-walk no longer aborts the dump, and a file
  over the size cap is skipped rather than read and scanned -- the harness must
  not diverge from the engine it measures.

### Added -- so it cannot drift again

- **`parity/contract.json` + `scripts/contract_check.mjs`.** Parity was checked
  by scanning `fixtures/` with both engines and diffing the findings, which is
  exactly as good as the corpus: it printed ALL GREEN for eight days over the
  include-list gap above, because `fixtures/` contained neither extension. The
  contract file carries the canonical rule ids, regex sources, severities,
  messages, both glob lists and the size cap, sealed with a sha256 so it cannot
  be hand-edited to match the code. Comparing lists needs no Python and no
  access to the private canonical source, so unlike the parity harness it runs
  in CI on every push.
- **`scripts/contract_selftest.mjs`** -- ten deliberately broken contracts that
  must each be caught with a message naming the problem, plus the real one,
  which must still pass. A guard that has only ever been seen to pass is an
  assumption.
- **`.github/workflows/tests.yml`** -- the repository's own suite, in CI, for
  the first time. Contract check, self-test, CSP audit, UI smoke, CLI smoke,
  exit codes (node 20/22/24), the glob differential, EOL and README-marker
  checks; weekly as well as on push, since the canonical contract can move
  without anything here changing.
- The glob differential could not have run in CI regardless: its oracle corpus
  is gitignored. It is now generated in the job -- `glob_corpus.py` is CPython
  stdlib only, because Python's own `fnmatch`/`pathlib` *is* the contract being
  ported. 2950 cases, 0 mismatches.
- **`scripts/exit_code_smoke.mjs`** -- covers what `cli_smoke` cannot: it
  imports the functions, so it never executes `main()`, where the exit code
  that CI actually consumes is produced.
- **`scripts/csp_check.mjs` + a strict `Content-Security-Policy`.** The 0-byte
  upload claim was true and verified by reading, which does not survive the
  next edit. `index.html` now ships `default-src 'none'; connect-src 'none'`,
  so a request is refused by the browser instead of being trusted not to
  happen. `script-src 'self'` with no `'unsafe-inline'` also closes inline
  event handlers, the realistic XSS shape for a page that renders
  attacker-chosen file names; that required moving the pre-paint theme
  initialiser into `theme.js`.
- **`scripts/readme_stamp.mjs`** -- ten measured metrics stamped into README
  markers, `--check` in CI. "Last run: 9/9 findings ... CLI smoke PASS (14/14)"
  was hand-maintained prose and was wrong within an afternoon of edits.
- **`--max-file-bytes`** on the CLI and the Action. The engine already
  supported the option; nothing exposed it.
- **`.gitattributes` + `scripts/eol_check.mjs`.** The index stored `README.md`
  and `run_parity.ps1` as CRLF and everything else as LF, so an edit from a
  tool with different defaults rewrote every line and buried the real change.

### Added -- earlier in this cycle

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

---

## Releasing

There are no tags yet, so `@main` is the only usable ref and it moves. Cutting
`v0.2.0` needs push rights, so it is a maintainer action and deliberately not
automated:

```bash
# from a clean main, with CI green
git tag -a v0.2.0 -m "devguard-scan 0.2.0"
git push origin v0.2.0

# Actions convention: a moving major tag consumers can follow
git tag -f v0 v0.2.0
git push -f origin v0

gh release create v0.2.0 --title "devguard-scan 0.2.0" --notes-from-tag
```

Once `v0` exists, the README and `action.yml` usage examples should move from
`@main` to `@v0`. Until then the honest advice for a consumer is `@main` for
convenience or a commit SHA for stability, which is what the README says.
