# Contributing

`devguard-scan` is a single-author, zero-dependency secret scanner with two
faces: a static browser page and a Node CLI / GitHub Action that share one
engine. Contributions are welcome, but the two invariants below are not
negotiable, because the project's entire claim rests on them.

## The two invariants

**1. Nothing leaves the browser.** The page must not reference `fetch`,
`XMLHttpRequest`, `WebSocket`, `sendBeacon`, analytics, or any off-origin
resource. This is checked statically by `npm run csp` rather than by reading,
because reading does not survive the next edit. A PR that adds a network call
to the browser bundle cannot be accepted, however useful the feature.

**2. Zero dependencies.** `package.json` has no `dependencies` and no
`devDependencies`, and that is a feature, not an oversight — a secret scanner
people paste credentials into should have no supply chain. Node's standard
library only.

## Before you start

- Search existing issues and pull requests first.
- Open an issue before larger work, especially anything touching detection
  rules — a rule change is a parity change (see below).
- Typo fixes, docs corrections and test additions can go straight to a PR.

## Local dev setup

```bash
git clone https://github.com/WRG-11/devguard-scan.git
cd devguard-scan
npm test          # no install step -- there is nothing to install
```

To try the browser page, open `index.html` directly (`file://` works; there is
no build step and no dev server).

## What `npm test` actually checks

Each of these exists because something slipped past the previous set:

| script | what it protects |
| --- | --- |
| `contract` | parity with the canonical `wrg_devguard` `scan-secrets` engine. On 2026-07-21 the canonical `DEFAULT_INCLUDE` gained `**/*.env.*` and `**/*.cfg`, this port did not, and `fixtures/` exercised neither -- a corpus-based check cannot see a divergence the corpus does not contain. |
| `contract-selftest` | that the contract check itself still fails when it should |
| `csp` | invariant 1, statically |
| `smoke-ui` | the page still loads and scans |
| `smoke` | the CLI's argument parsing and output |
| `smoke-exit` | the `0` / `1` / `2` exit-code contract -- `2` is a configuration error, deliberately distinct from `1` (findings) so a broken invocation cannot read as a clean scan |
| `eol` | LF line endings; the repo stores LF and a CRLF flip makes every diff unreadable |
| `stamp` | README metric markers match the code (`readme_stamp.mjs --check`) |

`npm run glob-corpus && npm run glob-parity` is a separate differential check
of the glob matcher against CPython's `fnmatch`. It needs Python and is not
part of `npm test`; run it when you touch include/exclude matching.

## Bar for accepting a PR

- `npm test` green.
- A new or changed detection rule needs a fixture that fires on the
  vulnerable form and stays silent on the fixed one, plus the canonical-engine
  parity implication stated in the PR body.
- Counts in the README are stamped, not typed: run `npm run stamp` rather
  than editing a number by hand.
- No new dependency, in either `dependencies` or `devDependencies`.
- No network call reachable from the browser page.

## Commit messages

Conventional commit style:

- `feat(rules): detect <provider> tokens`
- `fix(cli): --exclude was ignored after --allowlist`
- `docs: correct the exit-code table`

## Security issues

Do not open a public issue for a vulnerability in this scanner. Use GitHub
Security Advisories:

- https://github.com/WRG-11/devguard-scan/security/advisories

A scanner that mis-reports is a security problem: a false negative on a live
credential is in scope, not just code execution.
