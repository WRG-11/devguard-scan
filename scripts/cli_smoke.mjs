#!/usr/bin/env node
// Smoke test for bin/scan.mjs (the filesystem CLI). Complements the
// browser-path UI smoke (ui_smoke.mjs) and the engine parity check
// (parity_compare.py) -- this proves the Node/filesystem entrypoint wires
// the same engine correctly: known-corpus findings, include/exclude
// override, allowlist suppression, and a clean-directory PASS/exit-code
// path. The allowlist numbers below (14 -> 9 active, 5 suppressed) were
// re-measured against the canonical wrg_devguard.cli _apply_allowlist()
// with the identical rule set on 2026-07-29 -- exact match, including
// which 5 findings get suppressed and that the 9 survivors are all ERROR.
//
// Usage: node scripts/cli_smoke.mjs   (exit 0 = pass)
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { writeFileSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { runScan, loadAllowlist, parseArgs, assertScanRoot } from "../bin/scan.mjs";
import { lineCol, reportToSarif } from "../scan.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "fixtures");
const CLEAN_DIR = join(HERE, "..", "bin"); // no secrets in the CLI source itself

const checks = {};

const full = runScan({ root: FIXTURES });
checks["full fixtures scan finds 14"] = full.summary.total_findings === 14;
checks["full fixtures scan: 10 error"] = full.summary.error === 10;
checks["full fixtures scan: 4 warning"] = full.summary.warning === 4;
checks["full fixtures scan status FAIL"] = full.status === "FAIL";
const fullSarif = reportToSarif(full);
checks["SARIF preserves findings and redacts snippets"] =
  fullSarif.version === "2.1.0" &&
  fullSarif.runs[0].results.length === full.findings.length &&
  fullSarif.runs[0].results.every((r) => r.properties.redacted === true && !r.message.text.includes("AKIA"));

// The two extensions the port was missing until 2026-07-29. Asserted by file
// rather than only through the totals above, so a regression names the
// extension that stopped being scanned instead of surfacing as a total that
// is off by some number.
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
  excluded.summary.total_findings === 10 && !excluded.findings.some((f) => f.file.includes("cloud_tokens"));

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
checks["allowlist suppresses 5 of 14 findings"] =
  allowlisted.summary.total_findings === 9 && allowlisted.summary.suppressed === 5;
checks["allowlist leaves only ERROR findings"] = allowlisted.summary.warning === 0 && allowlisted.summary.error === 9;
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

// --- columns are counted in code points, like Python, not UTF-16 units.
// The corpus fixture (unicode_columns.py) proves this against the canonical
// engine, but only a maintainer with the private source can run that leg.
// These assertions encode the same answers so CI catches a regression too:
// each expected column is the code-point answer, and each differs from what
// UTF-16 arithmetic would produce.
{
  // "🔐x": the emoji is 2 UTF-16 units and 1 code point, so 'x' sits at
  // UTF-16 offset 2 and code-point offset 1 -> column 2, not 3.
  checks["lineCol counts an astral char as one column"] = lineCol("\u{1F510}x", 2)[1] === 2;
  checks["lineCol counts a BMP non-ASCII char as one column"] = lineCol("şx", 1)[1] === 2;
  checks["lineCol is unchanged for ASCII"] = lineCol("abc", 2)[1] === 3;
  // Line numbers were never affected -- U+000A cannot be half a surrogate --
  // but assert it so a future rewrite of the loop cannot break them quietly.
  checks["lineCol still counts lines across astral chars"] =
    lineCol("\u{1F510}\n\u{1F510}\nx", 6)[0] === 3;

  const uni = full.findings.filter((f) => f.file === "unicode_columns.py");
  checks["unicode fixture yields 3 findings"] = uni.length === 3;
  checks["astral prefix does not shift the reported column"] =
    uni.every((f) => f.column === 20);
}

// --- argument handling: every one of these used to end in a clean exit 0 or a
// raw stack trace. A gate that cannot distinguish "nothing found" from "never
// ran" is worse than no gate, because it reports the reassuring answer.
function rejects(fn) {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
}

checks["parseArgs: unknown option is rejected"] = rejects(() => parseArgs([".", "--jsonn"]));
checks["parseArgs: value flag with no value is rejected"] = rejects(() => parseArgs([".", "--exclude"]));
checks["parseArgs: value flag followed by another flag is rejected"] =
  rejects(() => parseArgs([".", "--exclude", "--json"]));
checks["parseArgs: second positional is rejected"] = rejects(() => parseArgs(["a", "b"]));
checks["parseArgs: non-integer --max-file-bytes is rejected"] =
  rejects(() => parseArgs([".", "--max-file-bytes", "12abc"]));
checks["parseArgs: zero --max-file-bytes is rejected"] = rejects(() => parseArgs([".", "--max-file-bytes", "0"]));
checks["parseArgs: empty pattern list is rejected"] = rejects(() => parseArgs([".", "--exclude", " , "]));
{
  const parsed = parseArgs(["fixtures", "--json", "--max-file-bytes", "4096", "--exclude", "a,b"]);
  checks["parseArgs: valid arguments still parse"] =
  parsed.root === "fixtures" && parsed.json === true && parsed.maxFileBytes === 4096 && parsed.exclude.length === 2;
  checks["parseArgs: default root is ."] = parseArgs([]).root === ".";
}
checks["parseArgs: SARIF output path"] = parseArgs([".", "--sarif-output", "out.sarif"]).sarifOutput === "out.sarif";
checks["assertScanRoot: missing directory is rejected"] = rejects(() => assertScanRoot(join(HERE, "no-such-dir")));
checks["assertScanRoot: a file is not a directory"] = rejects(() => assertScanRoot(join(HERE, "cli_smoke.mjs")));
checks["assertScanRoot: real directory passes"] = !rejects(() => assertScanRoot(FIXTURES));

// --- counts: the report must say how much was actually looked at.
{
  const counted = runScan({ root: FIXTURES });
  checks["report counts files scanned"] = counted.summary.files_scanned === 6;
  checks["report counts oversize skips"] = counted.summary.skipped_oversize === 0;

  // --max-file-bytes small enough to exclude everything: findings drop to zero
  // while files_scanned stays 0 and skipped_oversize accounts for the corpus.
  // Without those two fields this is byte-identical to scanning a clean tree.
  const tiny = runScan({ root: FIXTURES, maxFileBytes: 1 });
  checks["--max-file-bytes suppresses findings"] = tiny.summary.total_findings === 0;
  checks["--max-file-bytes is visible in the report"] =
    tiny.summary.files_scanned === 0 && tiny.summary.skipped_oversize === 6;
  checks["a tree where nothing was read is distinguishable from a clean one"] =
    tiny.summary.skipped_oversize !== clean.summary.skipped_oversize;

  // An oversize file that the exclude list would have dropped anyway must not
  // inflate the skipped-for-size count -- that number is a prompt to go look.
  const tmp = mkdtempSync(join(tmpdir(), "devguard-scan-oversize-"));
  mkdirSync(join(tmp, "node_modules"));
  writeFileSync(join(tmp, "node_modules", "bundle.js"), "x".repeat(4096));
  writeFileSync(join(tmp, "real.js"), "y".repeat(4096));
  const mixed = runScan({ root: tmp, maxFileBytes: 1024 });
  checks["excluded oversize files are not counted as size skips"] = mixed.summary.skipped_oversize === 1;
  rmSync(tmp, { recursive: true, force: true });
}

let ok = true;
for (const [k, v] of Object.entries(checks)) {
  console.log(`${v ? "PASS" : "FAIL"}  ${k}`);
  if (!v) ok = false;
}
console.log(ok ? "\nCLI smoke: PASS" : "\nCLI smoke: FAIL");
process.exit(ok ? 0 : 1);
