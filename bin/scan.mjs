#!/usr/bin/env node
// devguard-scan CLI -- filesystem entrypoint for the same zero-dependency
// engine the browser UI uses (../scan.js). Scans a real directory tree and
// exits non-zero when any ERROR-severity finding is present, so it can gate
// a pre-commit hook or a CI step (see .github/actions/scan for a wrapper).
//
// Walks the tree unconditionally (like the canonical Python tool's
// root.rglob("*")) and lets scanFiles() apply include/exclude per file --
// same source of truth as the browser, no separate directory-level glob
// logic to drift out of parity. The only hardcoded shortcut is skipping
// .git/ during the walk (always excluded anyway; its object store is large
// and irrelevant, so there's no correctness cost to skipping the descent).
import { readdirSync, statSync, readFileSync, existsSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import {
  scanFiles,
  buildReport,
  applyAllowlist,
  DEFAULT_INCLUDE,
  DEFAULT_EXCLUDE,
  MAX_FILE_BYTES,
} from "../scan.js";

const ALWAYS_SKIP_DIRS = new Set([".git"]);

function usage() {
  console.log(`devguard-scan CLI -- zero-dependency secret scanner (Node, filesystem)

Usage: node bin/scan.mjs [dir] [options]

  dir                  root directory to scan (default: .)
  --include p1,p2,...  override include glob patterns (default: built-in list)
  --exclude p1,p2,...  override exclude glob patterns (default: built-in list)
  --allowlist path     allowlist JSON path (default: <dir>/.wrg/allowlist.json
                        if it exists). Same schema as the canonical CLI:
                        {"rules": [{"rule_id": "...", "file": "glob*",
                        "reason": "why"}]} -- unspecified fields are wildcards.
  --json               print the full JSON report instead of a text summary
  -h, --help           show this help

Exit code 1 if any ERROR-severity finding is present, 0 otherwise.
Same rules, same include/exclude, same line/column as the browser UI and
the canonical wrg_devguard Python engine (see SECURITY.md).`);
}

function parseArgs(argv) {
  const opts = { root: ".", include: null, exclude: null, allowlist: null, json: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") opts.help = true;
    else if (a === "--include") opts.include = argv[++i].split(",");
    else if (a === "--exclude") opts.exclude = argv[++i].split(",");
    else if (a === "--allowlist") opts.allowlist = argv[++i];
    else if (a === "--json") opts.json = true;
    else opts.root = a;
  }
  return opts;
}

export function loadAllowlist(allowlistArg, root) {
  const path = allowlistArg || join(root, ".wrg", "allowlist.json");
  if (!existsSync(path)) return [];
  let payload;
  try {
    payload = JSON.parse(readFileSync(path, "utf-8"));
  } catch (err) {
    throw new Error(`allowlist file is not valid json: ${path} (${err.message})`);
  }
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.rules)) return [];
  return payload.rules.filter((r) => r && typeof r === "object");
}

function collectAllFiles(dir, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // unreadable dir (permissions, vanished) -- skip, don't abort the scan
  }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (ALWAYS_SKIP_DIRS.has(entry.name)) continue;
      collectAllFiles(join(dir, entry.name), out);
    } else if (entry.isFile()) {
      out.push(join(dir, entry.name));
    }
  }
}

export function runScan({ root, include, exclude, allowlistRules } = {}) {
  const inc = include || DEFAULT_INCLUDE;
  const exc = exclude || DEFAULT_EXCLUDE;

  const allPaths = [];
  collectAllFiles(root, allPaths);

  const files = [];
  for (const full of allPaths) {
    try {
      const st = statSync(full);
      if (st.size > MAX_FILE_BYTES) continue; // mirrors read_text_safely's size guard
      const text = readFileSync(full, "utf-8");
      files.push({ path: relative(root, full), text });
    } catch {
      /* vanished mid-scan / unreadable / binary -- skip, matches read_text_safely */
    }
  }

  const rawFindings = scanFiles(files, { include: inc, exclude: exc });
  const { active, suppressed } = applyAllowlist(rawFindings, allowlistRules || []);
  return buildReport(active, root, suppressed.length);
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    usage();
    process.exit(0);
  }

  const allowlistRules = loadAllowlist(opts.allowlist, opts.root);
  const report = runScan({
    root: opts.root,
    include: opts.include,
    exclude: opts.exclude,
    allowlistRules,
  });

  if (opts.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    const suppressedNote = report.summary.suppressed > 0 ? `, ${report.summary.suppressed} suppressed` : "";
    console.log(
      `devguard-scan: ${report.summary.total_findings} finding(s) ` +
        `(${report.summary.error} error, ${report.summary.warning} warning${suppressedNote}) in ${opts.root}`,
    );
    for (const f of report.findings) {
      console.log(`  ${f.severity.padEnd(7)} ${f.file}:${f.line}:${f.column}  ${f.rule_id}  ${f.message}`);
    }
    console.log(report.status === "FAIL" ? "\nFAIL" : "\nPASS");
  }

  process.exit(report.status === "FAIL" ? 1 : 0);
}

// Only run as CLI when invoked directly (`node bin/scan.mjs`), not when
// imported (e.g. by a test or a future GitHub Action wrapper).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}
