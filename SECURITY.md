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

This policy covers the `devguard-scan` static scanner (browser JS engine and
parity harness). The rule patterns are ported verbatim from a canonical
`wrg_devguard` Python detection engine that is not published as a standalone
public repo (part of a private monorepo) — report findings against the
patterns as they appear in this repo's own `scan.js`.
