#!/usr/bin/env node
// JS side of the glob differential harness: replays the Python-generated oracle
// (scripts/glob_corpus.py) against the shared engine's matchAny and fails on any
// divergence, then times the pattern shape that used to hang the scanner.
//
// Usage:
//   python scripts/glob_corpus.py glob_corpus.json
//   node scripts/glob_parity_check.mjs glob_corpus.json
//
// Exit 0 when every case agrees and the hostile pattern answers promptly.
import { readFileSync } from "node:fs";
import { matchAny } from "../scan.js";

const corpusPath = process.argv[2] || "glob_corpus.json";
const cases = JSON.parse(readFileSync(corpusPath, "utf-8"));

const mismatches = [];
for (const c of cases) {
  if (matchAny(c.path, [c.pattern]) !== c.expected) {
    mismatches.push({ ...c, got: !c.expected });
  }
}

for (const m of mismatches.slice(0, 25)) {
  console.log(
    `FAIL  pattern=${JSON.stringify(m.pattern)} path=${JSON.stringify(m.path)} ` +
      `python=${m.expected} js=${m.got}`,
  );
}
if (mismatches.length > 25) {
  console.log(`  ... and ${mismatches.length - 25} more`);
}

// A glob reaches matchAny from --include/--exclude and from an allowlist rule's
// `file` field, which is read out of the scanned repository itself. Under the
// old translate-to-RegExp approach this shape backtracked exponentially: 22
// characters were enough to hang a scan indefinitely, so a scanned repo could
// silence the scanner by shipping one .wrg/allowlist.json entry. Budget is
// deliberately loose -- the point is linear vs exponential, not a microbenchmark.
const HOSTILE = "*a".repeat(12) + "*b";
const SUBJECT = "a".repeat(40) + "!";
const BUDGET_MS = 250;
const t0 = process.hrtime.bigint();
matchAny(SUBJECT, [HOSTILE]);
const elapsed = Number(process.hrtime.bigint() - t0) / 1e6;
const slow = elapsed > BUDGET_MS;
if (slow) {
  console.log(
    `FAIL  redos guard: ${HOSTILE.length}-char pattern took ${elapsed.toFixed(1)}ms ` +
      `(budget ${BUDGET_MS}ms) -- matching is not linear`,
  );
}

console.log(
  `glob parity: ${cases.length} cases, ${mismatches.length} mismatch(es), ` +
    `redos probe ${elapsed.toFixed(1)}ms -- ${mismatches.length || slow ? "FAIL" : "PASS"}`,
);
process.exit(mismatches.length || slow ? 1 : 0);
