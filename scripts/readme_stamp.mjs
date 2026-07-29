#!/usr/bin/env node
// Recompute the <!-- METRIC:name --> markers in README.md from the source of
// truth, and either write them (--write) or fail on drift (--check).
//
// Replaces `grep -c "^    id:" scan.js` in the refresh workflow, which counted
// a text shape rather than a fact: reindent the rule table, or add a property
// called `id:` anywhere else in the file, and the published rule count changes
// without anyone touching a rule. Here the engine is imported and its exported
// arrays are measured, so the number cannot disagree with the code that
// produces it.
//
// The corpus counts matter more than the rule count. Every number in the
// README's "Last run" line -- findings, ERROR/WARNING split, how many checks
// each smoke suite runs -- was maintained by hand, and hand-maintained numbers
// rot: this repo shipped "9/9 findings" and "CLI smoke PASS (14/14)" as
// prose while both were wrong within a single afternoon of edits. Anything a
// script can count, a script should count.
//
// Usage:
//   node scripts/readme_stamp.mjs --check   (exit 1 on drift; CI runs this)
//   node scripts/readme_stamp.mjs --write
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SECRET_RULES, DEFAULT_INCLUDE, DEFAULT_EXCLUDE } from "../scan.js";
import { runScan } from "../bin/scan.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const README = join(ROOT, "README.md");
const FIXTURES = join(ROOT, "fixtures");

// Count PASS/FAIL lines a smoke script prints, by running it. Parsing the
// source for `checks[` would be the same text-shape mistake this script
// exists to remove -- and it would keep reporting a number for a suite that
// has started crashing.
function smokeCheckCount(script) {
  const res = spawnSync(process.execPath, [join(HERE, script)], { encoding: "utf-8" });
  if (res.status !== 0) {
    throw new Error(`${script} did not pass, so its check count is not a fact worth publishing`);
  }
  return (res.stdout.match(/^(PASS|FAIL)\s/gm) || []).length;
}

const report = runScan({ root: FIXTURES });

const METRICS = {
  secret_rule_count: SECRET_RULES.length,
  include_pattern_count: DEFAULT_INCLUDE.length,
  exclude_pattern_count: DEFAULT_EXCLUDE.length,
  corpus_finding_count: report.summary.total_findings,
  corpus_error_count: report.summary.error,
  corpus_warning_count: report.summary.warning,
  ui_smoke_checks: smokeCheckCount("ui_smoke.mjs"),
  cli_smoke_checks: smokeCheckCount("cli_smoke.mjs"),
  exit_code_checks: smokeCheckCount("exit_code_smoke.mjs"),
  contract_selftest_checks: smokeCheckCount("contract_selftest.mjs"),
};

const original = readFileSync(README, "utf-8");
let updated = original;
const missing = [];

for (const [name, value] of Object.entries(METRICS)) {
  const marker = new RegExp(
    `<!-- METRIC:${name} -->.*?<!-- /METRIC:${name} -->`,
    "gs",
  );
  if (!marker.test(updated)) {
    missing.push(name);
    continue;
  }
  marker.lastIndex = 0;
  updated = updated.replace(marker, `<!-- METRIC:${name} -->${value}<!-- /METRIC:${name} -->`);
}

const mode = process.argv[2] || "--check";

// A metric with no marker in the README is silent drift of the worst kind:
// the stamper reports "in sync" while the number it computes appears nowhere.
if (missing.length) {
  console.log(`FAIL  no marker in README.md for: ${missing.join(", ")}`);
  console.log("      add <!-- METRIC:name -->0<!-- /METRIC:name --> where the number belongs");
  process.exit(1);
}

if (mode === "--write") {
  if (updated === original) {
    console.log("readme stamp: already up to date");
  } else {
    writeFileSync(README, updated, "utf-8");
    console.log("readme stamp: README.md updated");
  }
  for (const [k, v] of Object.entries(METRICS)) console.log(`  ${k} = ${v}`);
  process.exit(0);
}

if (mode !== "--check") {
  console.log(`unknown mode: ${mode} (expected --check or --write)`);
  process.exit(2);
}

if (updated === original) {
  console.log(`readme stamp: in sync (${Object.keys(METRICS).length} metrics)`);
  process.exit(0);
}

console.log("FAIL  README.md metric markers are stale:");
for (const [name, value] of Object.entries(METRICS)) {
  const found = original.match(new RegExp(`<!-- METRIC:${name} -->(.*?)<!-- /METRIC:${name} -->`, "s"));
  if (found && found[1] !== String(value)) {
    console.log(`      ${name}: README says ${JSON.stringify(found[1])}, measured ${value}`);
  }
}
console.log("      fix: node scripts/readme_stamp.mjs --write");
process.exit(1);
