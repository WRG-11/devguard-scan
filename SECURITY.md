# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release on main | Yes |
| Older versions | No |

## Reporting a Vulnerability

If you discover a security vulnerability in `devguard-scan` (the browser-side
scanning engine, parity harness, or this repository's workflows), please
report it responsibly.

**Do not open a public issue.**

Instead, please use GitHub's
[private vulnerability reporting](https://github.com/WRG-11/devguard-scan/security/advisories/new)
or email **detectionfrontier@proton.me**.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected surface (scan engine / parity harness / workflow / docs)
- Potential impact
- Suggested fix or mitigation, if any

### Response timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 1 week
- **Fix (if confirmed):** as soon as practical, typically within 2 weeks

## Scope

In scope — everything this repository publishes and someone else can run:

- `scan.js` — the detection engine, shared by all three surfaces below
- `index.html` / `theme.js` / `app.js` — the browser demo, including its
  Content-Security-Policy
- `bin/scan.mjs` — the Node CLI
- `action.yml` — the composite GitHub Action, i.e. code that runs inside other
  people's workflows. Findings about how it handles untrusted input from a
  scanned repository (allowlist discovery, glob patterns, report parsing) are
  especially welcome
- `scripts/` — the parity, contract and smoke harness
- this repository's own workflows

A detection *gap* counts: a pattern that a scanned repository can craft to be
skipped, an input that makes the scanner report a clean tree without having
scanned it, or a way to make the CLI exit 0 when it should not. So does a
divergence from the canonical contract in `parity/contract.json`.

The rule patterns are ported verbatim from a canonical `wrg_devguard` Python
detection engine that is not published as a standalone public repo (it is part
of a private monorepo) — report findings against the patterns as they appear in
this repo's own `scan.js` and `parity/contract.json`.
