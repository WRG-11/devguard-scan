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
import {
  closeSync,
  existsSync,
  fstatSync,
  openSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { statSync } from "node:fs";
import {
  scanFilesDetailed,
  buildReport,
  reportToSarif,
  applyAllowlist,
  DEFAULT_INCLUDE,
  DEFAULT_EXCLUDE,
  MAX_FILE_BYTES,
} from "../scan.js";

const ALWAYS_SKIP_DIRS = new Set([".git"]);

// Exit codes. 0/1 are the gate result; 2 means the gate never ran.
//
// Without a distinct code for the third case, a misconfigured invocation is
// reported as a clean scan: `node bin/scan.mjs ./typo` walked a directory that
// does not exist, found nothing, and exited 0. As a CI gate that is the worst
// possible failure mode -- a typo in the Action's `path:` input buys a green
// check forever, and nothing about the output looks wrong.
const EXIT_PASS = 0;
const EXIT_FINDINGS = 1;
const EXIT_USAGE = 2;

class UsageError extends Error {}

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
  --no-auto-allowlist  do NOT auto-discover <dir>/.wrg/allowlist.json; use only
                        an explicit --allowlist. Set this when scanning code you
                        do not control (a CI gate over a fork PR) so the scanned
                        tree cannot supply its own suppression rules.
  --max-file-bytes n   skip files larger than n bytes (default ${MAX_FILE_BYTES})
  --json               print the full JSON report instead of a text summary
  --sarif-output path  write a SARIF 2.1.0 report (findings stay redacted)
  -h, --help           show this help

Exit codes: 0 clean, 1 ERROR-severity finding(s) present, 2 the scan could not
run (bad arguments, missing scan root, unreadable allowlist).
Same rules, same include/exclude, same line/column as the browser UI and
the canonical wrg_devguard Python engine (see SECURITY.md).`);
}

const VALUE_FLAGS = new Set(["--include", "--exclude", "--allowlist", "--max-file-bytes", "--sarif-output"]);

export function parseArgs(argv) {
  const opts = {
    root: null,
    include: null,
    exclude: null,
    allowlist: null,
    autoAllowlist: true,
    maxFileBytes: MAX_FILE_BYTES,
    json: false,
    sarifOutput: null,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];

    // A flag that takes a value must actually have one. `--exclude` as the
    // final argument used to read argv[i+1] as undefined and die on
    // `.split(",")` with a raw stack trace.
    if (VALUE_FLAGS.has(a)) {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith("--")) {
        throw new UsageError(`${a} requires a value`);
      }
      i++;
      if (a === "--include") opts.include = splitPatterns(a, value);
      else if (a === "--exclude") opts.exclude = splitPatterns(a, value);
      else if (a === "--allowlist") opts.allowlist = value;
      else if (a === "--sarif-output") opts.sarifOutput = value;
      else opts.maxFileBytes = parsePositiveInt(a, value);
      continue;
    }

    if (a === "-h" || a === "--help") {
      opts.help = true;
      continue;
    }
    if (a === "--no-auto-allowlist") {
      opts.autoAllowlist = false;
      continue;
    }
    if (a === "--json") {
      opts.json = true;
      continue;
    }

    // Anything else used to fall through to `opts.root = a`, so a mistyped
    // flag silently became the scan root: `--jsonn` scanned a directory named
    // "--jsonn", found nothing, and exited 0. Same for a stray second
    // positional, which silently overrode the first.
    if (a.startsWith("-")) throw new UsageError(`unknown option: ${a}`);
    if (opts.root !== null) {
      throw new UsageError(`unexpected second directory argument: ${a} (already scanning ${opts.root})`);
    }
    opts.root = a;
  }
  if (opts.root === null) opts.root = ".";
  return opts;
}

function splitPatterns(flag, value) {
  const items = value.split(",").map((s) => s.trim()).filter(Boolean);
  if (items.length === 0) throw new UsageError(`${flag} was given no usable patterns: ${JSON.stringify(value)}`);
  return items;
}

function parsePositiveInt(flag, value) {
  // Number() over parseInt: parseInt("12abc") is 12, which would silently
  // accept a typo'd limit.
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) throw new UsageError(`${flag} expects a positive integer, got ${JSON.stringify(value)}`);
  return n;
}

// The scan root must exist and be a directory. Everything downstream tolerates
// unreadable paths by design (a vanished file must not abort a scan), which is
// exactly why the root itself needs an explicit check: without it the
// tolerance swallows the one error that invalidates the whole run.
export function assertScanRoot(root) {
  let st;
  try {
    st = statSync(root);
  } catch {
    throw new UsageError(`scan root does not exist or is not readable: ${root}`);
  }
  if (!st.isDirectory()) throw new UsageError(`scan root is not a directory: ${root}`);
}

export function loadAllowlist(allowlistArg, root, autoDiscover = true) {
  // An explicit --allowlist always wins. Otherwise fall back to
  // <root>/.wrg/allowlist.json ONLY when auto-discovery is on. That default
  // file lives inside the scanned tree, so a CI gate running over code it does
  // not control (a fork PR) must pass --no-auto-allowlist: else the scanned
  // repository could ship an allowlist rule that suppresses the very finding
  // the gate exists to catch. When auto-discovery is off and no explicit path
  // is given, there is simply no allowlist -- the safe default for a gate.
  const path = allowlistArg || (autoDiscover ? join(root, ".wrg", "allowlist.json") : null);
  if (!path || !existsSync(path)) return [];
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

export function runScan({ root, include, exclude, allowlistRules, maxFileBytes } = {}) {
  const inc = include || DEFAULT_INCLUDE;
  const exc = exclude || DEFAULT_EXCLUDE;
  const maxBytes = maxFileBytes || MAX_FILE_BYTES;

  const allPaths = [];
  collectAllFiles(root, allPaths);

  const files = [];
  const byteSizes = {}; // posix rel path -> size, for oversize paths only
  let skippedUnreadable = 0;
  for (const full of allPaths) {
    // Size-check and read the SAME open handle rather than the path twice.
    // stat(path) followed by readFile(path) is a time-of-check/time-of-use gap:
    // the file the guard measured need not be the file that is then read, so a
    // path that grows (or is swapped) in between is read past MAX_FILE_BYTES --
    // the one limit standing between the scanner and loading an arbitrarily
    // large file into memory. fstat on the descriptor closes the gap by
    // construction: it measures the object already opened.
    let fd;
    try {
      fd = openSync(full, "r");
      const st = fstatSync(fd);
      const rel = relative(root, full);
      if (st.size > maxBytes) {
        // Hand the engine an empty record plus the real size instead of
        // dropping the path here. The size guard still does its job (the bytes
        // are never read), but the file now passes through exclude/include
        // first, so a 5 MB bundle inside node_modules is counted as excluded
        // rather than reported as "skipped for size" -- a skipped-for-size
        // count is a prompt to go look, and it is worthless if it is mostly
        // vendored noise.
        byteSizes[rel.split(sep).join("/")] = st.size;
        files.push({ path: rel, text: "" });
        continue; // mirrors read_text_safely's size guard
      }
      const text = readFileSync(fd, "utf-8");
      files.push({ path: rel, text });
    } catch {
      /* vanished mid-scan / unreadable / binary -- skip, matches read_text_safely */
      skippedUnreadable++;
    } finally {
      // readFileSync(fd) does not close a caller-supplied descriptor
      if (fd !== undefined) closeSync(fd);
    }
  }

  const { findings: rawFindings, scanned, skippedOversize } = scanFilesDetailed(files, {
    include: inc,
    exclude: exc,
    maxFileBytes: maxBytes,
    byteSizes,
  });
  const { active, suppressed } = applyAllowlist(rawFindings, allowlistRules || []);
  return buildReport(active, root, suppressed.length, { scanned, skippedOversize, skippedUnreadable });
}

function main() {
  let opts;
  let allowlistRules;
  let report;
  try {
    opts = parseArgs(process.argv.slice(2));
    if (opts.help) {
      usage();
      process.exit(EXIT_PASS);
    }
    assertScanRoot(opts.root);
    allowlistRules = loadAllowlist(opts.allowlist, opts.root, opts.autoAllowlist);
    report = runScan({
      root: opts.root,
      include: opts.include,
      exclude: opts.exclude,
      allowlistRules,
      maxFileBytes: opts.maxFileBytes,
    });
  } catch (err) {
    // A configuration problem is not a clean scan. Exit 2 so a CI gate can
    // tell "nothing to report" from "nothing was scanned".
    console.error(`devguard-scan: ${err.message}`);
    console.error("run with --help for usage");
    process.exit(EXIT_USAGE);
  }

  if (opts.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    const { summary } = report;
    const suppressedNote = summary.suppressed > 0 ? `, ${summary.suppressed} suppressed` : "";
    console.log(
      `devguard-scan: ${summary.total_findings} finding(s) ` +
        `(${summary.error} error, ${summary.warning} warning${suppressedNote}) in ${opts.root}`,
    );
    // Always printed, including the zero case: "0 findings" alone cannot be
    // told apart from "0 files matched the include list".
    const skips = [];
    if (summary.skipped_oversize) skips.push(`${summary.skipped_oversize} skipped for size`);
    if (summary.skipped_unreadable) skips.push(`${summary.skipped_unreadable} unreadable`);
    console.log(`  ${summary.files_scanned} file(s) scanned${skips.length ? `, ${skips.join(", ")}` : ""}`);
    for (const f of report.findings) {
      console.log(`  ${f.severity.padEnd(7)} ${f.file}:${f.line}:${f.column}  ${f.rule_id}  ${f.message}`);
    }
    console.log(report.status === "FAIL" ? "\nFAIL" : "\nPASS");
  }

  if (opts.sarifOutput) {
    writeFileSync(opts.sarifOutput, JSON.stringify(reportToSarif(report), null, 2) + "\n", "utf-8");
  }

  process.exit(report.status === "FAIL" ? EXIT_FINDINGS : EXIT_PASS);
}

// Only run as CLI when invoked directly (`node bin/scan.mjs`), not when
// imported (e.g. by a test or a future GitHub Action wrapper).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}
