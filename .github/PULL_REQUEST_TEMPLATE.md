<!--
Read CONTRIBUTING.md first, especially "The two invariants". The checklist
below mirrors it so a reviewer does not have to cross-reference a second
document.
-->

## What this changes

## Checklist

- [ ] `npm test` green (contract, selftest, csp, ui, cli, exit-code, eol, stamp)
- [ ] No network call reachable from the browser page -- `fetch`,
      `XMLHttpRequest`, `WebSocket`, `sendBeacon`, analytics, off-origin
      resources. `npm run csp` enforces this; the 0-byte-upload claim is the
      whole product
- [ ] No new entry in `dependencies` or `devDependencies`
- [ ] Detection-rule change: fixture fires on the vulnerable form and stays
      silent on the fixed one, and the parity implication against the
      canonical `wrg_devguard` engine is stated above
- [ ] Include/exclude change: `npm run glob-corpus && npm run glob-parity`
      run against CPython `fnmatch`
- [ ] README counts changed via `npm run stamp`, not typed by hand
- [ ] Line endings still LF (`npm run eol`)
