# devguard-in-browser

A **100% client-side** secret scanner. Paste code or drop files; it flags leaked
API keys, tokens, and private-key blocks **without a single byte leaving your
browser**. It is a static, dependency-free port of the `wrg_devguard`
`scan-secrets` engine — the same 6 rules, the same include/exclude logic, the
same line/column reporting.

> **POC / demo.** A "try-it-now" capability demo of the engine, not a product.

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

Any static host (GitHub Pages, Netlify, S3) works the same way. After the page
loads, you can disconnect from the network entirely — it keeps working.

## What it detects (6 rules — ported verbatim)

| rule_id                     | severity | source                  |
|-----------------------------|----------|-------------------------|
| `openai_api_key`            | ERROR    | `secrets.py` SECRET_RULES |
| `github_token`              | ERROR    | "                       |
| `aws_access_key_id`         | ERROR    | "                       |
| `slack_token`               | ERROR    | "                       |
| `private_key_block`         | ERROR    | "                       |
| `generic_secret_assignment` | WARNING  | "                       |

Include/exclude follow `secrets.py` `DEFAULT_INCLUDE` + `policy.py`
`DEFAULT_EXCLUDE` (e.g. `node_modules/`, `dist/`, `*.png`, `*.lock` are skipped;
only `.env/.py/.js/.json/...` extensions are scanned). The file name you assign
to pasted content drives those rules.

## Parity & smoke harness

```powershell
# from the repo root
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_parity.ps1
```

The JS engine + UI smoke run standalone. To also run the **Python parity**
compare against the canonical engine, clone the public detection source and
point the harness at it:

```powershell
git clone https://github.com/WRG-11/wrg-devguard
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_parity.ps1 -WrgDevguardSrc .\wrg-devguard\src
```

This:

1. Runs the **JS** engine (`scan.js`) over `fixtures/` via Node.
2. Runs the **canonical Python** `wrg_devguard.secrets.scan_secrets()` over the
   same `fixtures/`.
3. Compares finding sets + severity counts (`rule_id`/`file`/`line`/`column`) —
   exits non-zero on any divergence.
4. Runs a headless UI-path smoke proving the browser glue renders findings with
   `[REDACTED]` and never the raw value.

> The Python CLI's `--json-out` is fully redacted (counts only, no locations)
> for OPSEC, so parity is checked against the detection *library* directly via
> `scripts/py_reference_dump.py` — the same code the CLI calls.

**Last run:** 9/9 findings byte-identical, summary counts identical
(6 ERROR + 3 WARNING); UI smoke PASS.

## Fixtures

`fixtures/` contains **synthetic-only** content (Pattern 34) — every "secret" is
fake/non-functional and exists solely to exercise the 6 rules plus the
include/exclude/no-false-positive paths. No real credential is committed.

## Files

```
index.html   static SPA (inline CSS, no CDN)
app.js       UI glue (intake → scan → render); no network APIs
scan.js      shared engine — runs in browser AND Node (single source of truth)
package.json type:module (zero runtime deps)
fixtures/    synthetic parity corpus
scripts/     js_reference_dump.mjs · py_reference_dump.py · parity_compare.py
             ui_smoke.mjs · run_parity.ps1
```

## Out of scope (MVP)

git/repo clone · policy-lint / ai_check / threat checks · accounts / backend /
network · Pyodide · publishing/hosting. Single page, single job: secret-scan.

## Phase 2 (not this POC)

If it gets traction: a Pyodide-based pattern that runs `secrets.py` (and other
zero-dep WRG tools) unmodified in-browser, plus a public GitHub Pages host.
Parked until the try-it-now demo proves demand.
