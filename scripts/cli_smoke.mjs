#!/usr/bin/env node
// Smoke test for bin/scan.mjs (the filesystem CLI). Complements the
// browser-path UI smoke (ui_smoke.mjs) and the engine parity check
// (parity_compare.py) -- this proves the Node/filesystem entrypoint wires
// the same engine correctly: known-corpus findings, include/exclude
// override, allowlist suppression, and a clean-directory PASS/exit-code
// path. The allowlist numbers below (11 -> 6 active, 5 suppressed) were
// re-measured against the canonical wrg_devguard.cli _apply_allowlist()
// with the identical rule set on 2026-07-29 -- exact match, including
// which 5 findings get suppressed and that the 6 survivors are all ERROR.
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
checks["full fixtures scan finds 11"] = full.summary.total_findings === 11;
checks["full fixtures scan: 7 error"] = full.summary.error === 7;
checks["full fixtures scan: 4 warning"] = full.summary.warning === 4;
checks["full fixtures scan status FAIL"] = full.status === "FAIL";

// The two extensions the port was missing until 2026-07-29. Asserted by file
// rather than only through the totals above, so a regression names itself
// instead of surfacing as "expected 11, got 9".
checks["**/*.env.* is scanned (app.env.local)"] = full.findings.some(
  (f) => f.file === "app.env.local" && f.rule_id === "aws_access_key_id",
);
checks["**/*.cfg is scanned (settings.cfg)"] = full.findings.some(
  (f) => f.file === "settings.cfg" && f.rule_id === "generic_secret_assignment",
);

// The leading-dot shape (`.env.local`, `.env.production`) is the one a real
// leak actually wears, and it is exactly what `**/*.env` fails to match. It is
// written at runtime instead of committed: a bare `.env*` rule in a user or
// global gitignore is common enough that a committed fixture would silently
// vanish from some clones -- and a fixture that disappears takes its assertion
// with it, leaving a green run over a corpus missing the case it exists for.
{
  const tmp = mkdtempSync(join(tmpdir(), "devguard-scan-dotenv-"));
  writeFileSync(join(tmp, ".env.local"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
  writeFileSync(join(tmp, ".env.production"), "GH=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD\n");
  const dotenv = runScan({ root: tmp });
  checks["dotfile .env.local is scanned"] = dotenv.findings.some((f) => f.file === ".env.local");
  checks["dotfile .env.production is scanned"] = dotenv.findings.some((f) => f.file === ".env.production");
  checks["dotfile env scan reports FAIL"] = dotenv.status === "FAIL";
  rmSync(tmp, { recursive: true, force: true });
}

const excluded = runScan({
  root: FIXTURES,
  exclude: ["**/cloud_tokens.txt", "**/.git/**", "**/node_modules/**"],
});
checks["--exclude override drops cloud_tokens.txt findings"] =
  excluded.summary.total_findings === 7 && !excluded.findings.some((f) => f.file.includes("cloud_tokens"));

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
    { file: "*.cfg", severity: "WARNING", reason: "reviewed, accepted risk" },
  ],
});
checks["allowlist suppresses 5 of 11 findings"] =
  allowlisted.summary.total_findings === 6 && allowlisted.summary.suppressed === 5;
checks["allowlist leaves only ERROR findings"] = allowlisted.summary.warning === 0 && allowlisted.summary.error === 6;
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

  // --no-auto-allowlist (autoDiscover=false): the in-tree .wrg/allowlist.json
  // must be ignored, so a scanned repo cannot suppress its own findings when
  // devguard-scan runs as a gate. An explicit --allowlist still works.
  checks["loadAllowlist: auto-discovery off ignores in-tree .wrg/allowlist.json"] =
    loadAllowlist(null, tmp, false).length === 0;
  checks["loadAllowlist: auto-discovery off still honours explicit --allowlist"] =
    loadAllowlist(explicitPath, tmp, false).length === 1;

  rmSync(tmp, { recursive: true, force: true });
}

let ok = true;
for (const [k, v] of Object.entries(checks)) {
  console.log(`${v ? "PASS" : "FAIL"}  ${k}`);
  if (!v) ok = false;
}
console.log(ok ? "\nCLI smoke: PASS" : "\nCLI smoke: FAIL");
process.exit(ok ? 0 : 1);
