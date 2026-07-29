# devguard-in-browser

A **100% client-side** secret scanner. Paste code or drop files; it flags leaked
API keys, tokens, and private-key blocks **without a single byte leaving your
browser**. It is a static, dependency-free port of the `wrg_devguard`
`scan-secrets` engine — the same <!-- METRIC:secret_rule_count -->10<!-- /METRIC:secret_rule_count --> rules, the same include/exclude logic, the
same line/column reporting.

## Status

Proof-of-concept — a "try-it-now" capability demo of the engine, not a product.

## Why it's interesting

- **0-byte upload.** All scanning runs in `scan.js` in your browser. There is no
  `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, analytics, or external
  CDN anywhere in the source. Open the DevTools **Network** tab, scan a file,
  and you will see **zero** requests after the initial page load.
- **Secrets are never shown.** Every match is reported as `[REDACTED]`; the raw
  secret value never enters the results table, the DOM, or any payload (parity
  with `secrets.py:107`).
- **Detection parity** with the canonical Python tool, proven by a test harness
  (see below) — not just visually similar.

## Run it

It uses ES modules, so serve it over http (modules are blocked on `file://`):

```powershell
# from the repo root
py -3 -m http.server 8080
# then open http://localhost:8080/
```

Any static host (GitHub Pages, Netlify, S3) works the same way — a live
instance runs at <https://wrg-11.github.io/devguard-scan/>. After the page
loads, you can disconnect from the network entirely — it keeps working.

## Use it in CI

`scan.js` runs unchanged in Node, so the same engine is also a filesystem CLI
(`bin/scan.mjs`):

```bash
node bin/scan.mjs .                       # scan the current directory, text summary
node bin/scan.mjs . --json                # full JSON report (same schema as the browser)
node bin/scan.mjs . --exclude "**/dist/**,**/*.lock"   # override the built-in exclude list
node bin/scan.mjs . --allowlist .wrg/allowlist.json    # suppress known-accepted findings
node bin/scan.mjs . --max-file-bytes 262144            # lower the 1 MiB per-file cap
```

| exit | meaning |
|------|---------|
| `0`  | scan ran, no ERROR-severity finding |
| `1`  | scan ran, at least one ERROR-severity finding |
| `2`  | **the scan did not run** — missing/unreadable scan root, unknown option, bad value |

Exit `2` exists because the alternative is worse than no gate: `bin/scan.mjs`
used to walk a non-existent directory, find nothing and exit `0`, so a typo in
a CI `path:` bought a permanently green check. For the same reason an unknown
option is now an error rather than being treated as the directory to scan, and
every report carries `summary.files_scanned` — a clean result over zero files
is not evidence of anything.

An allowlist (auto-discovered at `<dir>/.wrg/allowlist.json` if present, same
convention as the canonical CLI) suppresses matching findings instead of
failing the scan on them. Pass `--no-auto-allowlist` to skip that in-tree
discovery and honour only an explicit `--allowlist` — the GitHub Action does
this unconditionally, since as a gate it scans code it may not control and the
default file lives inside that code:

```json
{ "rules": [
  { "rule_id": "google_api_key", "file": "**/testdata/**", "reason": "synthetic fixture" }
] }
```

Each field (`check`/`rule_id`/`severity`/`file`/`snippet_contains`) is a
wildcard when omitted; a rule matches when every field it DOES specify
matches. Verified byte-for-byte against the canonical `wrg_devguard.cli`
`_apply_allowlist()` with an identical rule set (2026-07-17): same active
findings, same suppressed count.

Or as a GitHub Action, in any repo:

```yaml
- uses: actions/checkout@v7
- uses: WRG-11/devguard-scan@main
  with:
    path: '.'              # optional, default '.'
    exclude: ''            # optional, comma-separated; overrides the built-in list
    max-file-bytes: ''     # optional, default 1048576
```

Outputs: `total-findings`, `error-count`, `status`, `files-scanned`,
`skipped-oversize`. The action fails the step on exit `2` with an explicit
`::error::` rather than parsing an absent report, and emits a `::warning::`
when `files-scanned` is `0`.

`.github/workflows/self-scan.yml` in this repo runs the action against its
own source as both a real CI gate and a working usage example. No version
tags exist yet (see CHANGELOG) — pin to `@main` for now, or to a commit SHA
if you want stability against future changes on this branch.

## What it detects (<!-- METRIC:secret_rule_count -->10<!-- /METRIC:secret_rule_count --> rules — ported verbatim)

| rule_id                     | severity | source                  |
|-----------------------------|----------|-------------------------|
| `openai_api_key`            | ERROR    | `secrets.py` SECRET_RULES |
| `github_token`              | ERROR    | "                       |
| `aws_access_key_id`         | ERROR    | "                       |
| `slack_token`               | ERROR    | "                       |
| `private_key_block`         | ERROR    | "                       |
| `generic_secret_assignment` | WARNING  | "                       |
| `google_api_key`            | ERROR    | "                       |
| `stripe_secret_key`         | ERROR    | "                       |
| `github_fine_grained_pat`   | ERROR    | "                       |
| `slack_webhook_url`         | ERROR    | "                       |

Include/exclude follow `secrets.py` `DEFAULT_INCLUDE` + `policy.py`
`DEFAULT_EXCLUDE` (e.g. `node_modules/`, `dist/`, `*.png`, `*.lock` are skipped;
only `.env/.py/.js/.json/...` extensions are scanned). The file name you assign
to pasted content drives those rules. The "Advanced: include/exclude patterns"
section in the UI lets you override either list for a one-off scan (e.g. to
force-include a file extension not in the default list) without touching the
built-in defaults. A "Download report (.json)" button exports the last scan
result in the same schema as `--json` on the CLI.

## How this port is kept honest

`scan.js` is a port, and a port drifts. This repo checks that two ways, and the
distinction matters:

**Contract check** (`scripts/contract_check.mjs`) compares the *lists* — rule
ids, regex sources, severities, messages, `DEFAULT_INCLUDE`, `DEFAULT_EXCLUDE`,
the size cap — against `parity/contract.json`, generated from the canonical
Python source and copied here verbatim (with a sha256 over the document, so a
contract edited by hand to match the code is rejected). It needs no Python and
no access to the canonical source, so it runs in CI on every push.

**Parity harness** compares the *findings* both engines produce over
`fixtures/`. It needs the canonical source and therefore only runs locally, for
a maintainer.

The second one cannot see a divergence the corpus does not exercise, and on
2026-07-21 it did not: the canonical include list gained `**/*.env.*` and
`**/*.cfg`, this port did not, `fixtures/` contained neither extension, and the
harness reported ALL GREEN for eight days while the published demo, CLI and
Action all skipped `.env.local` and `setup.cfg`. The contract check exists
because of that, and `scripts/contract_selftest.mjs` runs ten deliberately
broken contracts through it to prove it fails when it should.

```powershell
# everything, including the maintainer-only Python leg
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_parity.ps1 `
  -WrgDevguardSrc <monorepo-checkout>/apps/wrg_devguard/src
```

```bash
npm test    # everything that does not need the canonical source
```

The eight steps:

1. **Contract check** — this engine's rule + glob lists vs `parity/contract.json`.
2. **Contract self-test** — ten mutated contracts, each of which must be caught.
3. Runs the **JS** engine (`scan.js`) over `fixtures/` via Node.
4. Runs the **canonical Python** `wrg_devguard.secrets.scan_secrets()` over the
   same `fixtures/` and compares finding sets + severity counts
   (`rule_id`/`file`/`line`/`column`). *Maintainer-only; skipped otherwise.*
5. **Glob differential** — 2950 pattern/path pairs whose expected answers come
   from CPython's own `fnmatch`/`pathlib`, replayed against `matchAny`, plus a
   ReDoS probe. CPython stdlib only, so this runs in CI too.
6. **UI-path smoke** — the browser glue renders findings with `[REDACTED]` and
   never the raw value, a dropped directory's nested files are picked up, and
   an include-override reaches the scan.
7. **CLI smoke** — `bin/scan.mjs` finds the same 11/11 corpus findings, honours
   `--exclude`/`--allowlist`/`--max-file-bytes`, and reports how many files it
   actually read.
8. **Exit codes** — across the real process boundary: findings → 1, clean → 0,
   missing root / unknown flag / malformed value → 2.

> The Python CLI's `--json-out` is fully redacted (counts only, no locations)
> for OPSEC, so step 4 is checked against the detection *library* directly via
> `scripts/py_reference_dump.py` — the same code the CLI calls.

**Last run:** 11/11 findings byte-identical across the 10-rule corpus, summary
counts identical (7 ERROR + 4 WARNING); UI smoke PASS (13/13); CLI smoke
PASS (21/21, including allowlist parity).

## Fixtures

`fixtures/` contains **synthetic-only** content — every "secret" is
fake/non-functional and exists solely to exercise the 10 rules plus the
include/exclude/no-false-positive paths. No real credential is committed.

## Files

```
index.html   static SPA (inline CSS, no CDN)
app.js       UI glue (intake → scan → render); no network APIs
scan.js      shared engine — runs in browser AND Node (single source of truth)
bin/scan.mjs filesystem CLI over the same engine (see "Use it in CI")
action.yml   GitHub Action wrapper around bin/scan.mjs
package.json type:module (zero runtime deps)
fixtures/    synthetic parity corpus
parity/      contract.json — the canonical rule/glob lists, generated upstream
scripts/     contract_check.mjs · contract_selftest.mjs · contract_digest.mjs
             js_reference_dump.mjs · py_reference_dump.py · parity_compare.py
             glob_corpus.py · glob_parity_check.mjs
             ui_smoke.mjs · cli_smoke.mjs · exit_code_smoke.mjs
             eol_check.mjs · run_parity.ps1
```

## Out of scope (MVP)

git/repo clone · policy-lint / ai_check / threat checks · accounts / backend /
network · Pyodide · publishing/hosting. Single page, single job: secret-scan.

## Phase 2 (not this POC)

If it gets traction: a Pyodide-based pattern that runs `secrets.py` (and other
zero-dep WRG tools) unmodified in-browser. The public GitHub Pages host is
already live (<https://wrg-11.github.io/devguard-scan/>); the Pyodide pattern
stays parked until the live demo proves demand.

## License

MIT — see [LICENSE](LICENSE).

---

## Part of the WRG-11 ecosystem

- [mcp-objauthz-lab](https://github.com/WRG-11/mcp-objauthz-lab) — vulnerable-by-design MCP server for learning BOLA/IDOR
- [wrg-sigma-rules](https://github.com/WRG-11/wrg-sigma-rules) — sigma detection rules for AI/LLM threat scenarios + 3 MCP tools

Full index → [github.com/WRG-11](https://github.com/WRG-11)
