#!/usr/bin/env node
// Smoke test for bin/scan.mjs (the filesystem CLI). Complements the
// browser-path UI smoke (ui_smoke.mjs) and the engine parity check
// (parity_compare.py) -- this proves the Node/filesystem entrypoint wires
// the same engine correctly: known-corpus findings, include/exclude
// override, and a clean-directory PASS/exit-code path.
//
// Usage: node scripts/cli_smoke.mjs   (exit 0 = pass)
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { runScan } from "../bin/scan.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "fixtures");
const CLEAN_DIR = join(HERE, "..", "bin"); // no secrets in the CLI source itself

const checks = {};

const full = runScan({ root: FIXTURES });
checks["full fixtures scan finds 9"] = full.summary.total_findings === 9;
checks["full fixtures scan: 6 error"] = full.summary.error === 6;
checks["full fixtures scan: 3 warning"] = full.summary.warning === 3;
checks["full fixtures scan status FAIL"] = full.status === "FAIL";

const excluded = runScan({
  root: FIXTURES,
  exclude: ["**/cloud_tokens.txt", "**/.git/**", "**/node_modules/**"],
});
checks["--exclude override drops cloud_tokens.txt findings"] =
  excluded.summary.total_findings === 5 && !excluded.findings.some((f) => f.file.includes("cloud_tokens"));

const clean = runScan({ root: CLEAN_DIR });
checks["clean directory finds 0"] = clean.summary.total_findings === 0;
checks["clean directory status PASS"] = clean.status === "PASS";

let ok = true;
for (const [k, v] of Object.entries(checks)) {
  console.log(`${v ? "PASS" : "FAIL"}  ${k}`);
  if (!v) ok = false;
}
console.log(ok ? "\nCLI smoke: PASS" : "\nCLI smoke: FAIL");
process.exit(ok ? 0 : 1);
