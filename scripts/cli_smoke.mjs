#!/usr/bin/env node
// Smoke test for bin/scan.mjs (the filesystem CLI). Complements the
// browser-path UI smoke (ui_smoke.mjs) and the engine parity check
// (parity_compare.py) -- this proves the Node/filesystem entrypoint wires
// the same engine correctly: known-corpus findings, include/exclude
// override, allowlist suppression, and a clean-directory PASS/exit-code
// path. The allowlist numbers below (9 -> 5 active, 4 suppressed) were
// cross-checked directly against the canonical wrg_devguard.cli
// _apply_allowlist() with the identical rule set (2026-07-17) -- exact
// match, including which 4 findings get suppressed.
//
// Usage: node scripts/cli_smoke.mjs   (exit 0 = pass)
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { writeFileSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { runScan, loadAllowlist } from "../bin/scan.mjs";

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

// Allowlist: same rule set + same fixtures/ corpus verified against the
// real Python _apply_allowlist() -- see comment above.
const allowlisted = runScan({
  root: FIXTURES,
  allowlistRules: [
    { rule_id: "google_api_key", reason: "known test fixture, not a real key" },
    { file: "config.py", severity: "WARNING", reason: "reviewed, accepted risk" },
  ],
});
checks["allowlist suppresses 4 of 9 findings"] =
  allowlisted.summary.total_findings === 5 && allowlisted.summary.suppressed === 4;
checks["allowlist leaves only ERROR findings"] = allowlisted.summary.warning === 0 && allowlisted.summary.error === 5;
checks["allowlist: google_api_key fully suppressed"] = !allowlisted.findings.some((f) => f.rule_id === "google_api_key");

const noAllowlist = runScan({ root: FIXTURES });
checks["no allowlist -> suppressed is 0 (backward compatible)"] = noAllowlist.summary.suppressed === 0;

// --allowlist file loading: explicit path, and the .wrg/allowlist.json
// default-discovery convention (matches the canonical CLI's own default).
{
  const tmp = mkdtempSync(join(tmpdir(), "devguard-scan-allowlist-"));
  const explicitPath = join(tmp, "custom-allowlist.json");
  writeFileSync(explicitPath, JSON.stringify({ rules: [{ rule_id: "google_api_key" }] }));
  const loadedExplicit = loadAllowlist(explicitPath, tmp);
  checks["loadAllowlist: explicit path"] = loadedExplicit.length === 1 && loadedExplicit[0].rule_id === "google_api_key";

  checks["loadAllowlist: missing default path returns []"] = loadAllowlist(null, tmp).length === 0;

  mkdirSync(join(tmp, ".wrg"));
  writeFileSync(join(tmp, ".wrg", "allowlist.json"), JSON.stringify({ rules: [{ rule_id: "stripe_secret_key" }] }));
  const loadedDefault = loadAllowlist(null, tmp);
  checks["loadAllowlist: <root>/.wrg/allowlist.json default-discovery"] =
    loadedDefault.length === 1 && loadedDefault[0].rule_id === "stripe_secret_key";

  rmSync(tmp, { recursive: true, force: true });
}

let ok = true;
for (const [k, v] of Object.entries(checks)) {
  console.log(`${v ? "PASS" : "FAIL"}  ${k}`);
  if (!v) ok = false;
}
console.log(ok ? "\nCLI smoke: PASS" : "\nCLI smoke: FAIL");
process.exit(ok ? 0 : 1);
