#!/usr/bin/env node
// Walk a directory the way wrg_devguard.secrets.scan_secrets does (rglob +
// include/exclude) using the SHARED browser engine (../scan.js), and emit the
// same JSON envelope as py_reference_dump.py so the two can be diffed
// finding-for-finding.
//
// Usage: node scripts/js_reference_dump.mjs <scan_root> <out.json>
//
// This is the Node side of the parity harness ONLY. The browser never touches
// the filesystem; this script exists so the identical scan engine can be run
// headless against the same fixtures the Python tool scans.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { scanFiles, buildReport } from "../scan.js";

function walk(root) {
  const out = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      const st = statSync(full);
      if (st.isDirectory()) stack.push(full);
      else if (st.isFile()) out.push(full);
    }
  }
  return out;
}

function main(argv) {
  const root = argv[2];
  const out = argv[3];
  if (!root || !out) {
    console.error("Usage: js_reference_dump.mjs <scan_root> <out.json>");
    return 2;
  }
  const files = walk(root).map((full) => ({
    path: relative(root, full).split(sep).join("/"),
    text: readFileSync(full, "utf-8"),
  }));
  const findings = scanFiles(files);
  const report = buildReport(findings, root);
  writeJson(out, report);
  console.log(`JS reference dump written to ${out} (${findings.length} findings)`);
  return 0;
}

import { writeFileSync } from "node:fs";
function writeJson(path, payload) {
  writeFileSync(path, JSON.stringify(payload, null, 2), "utf-8");
}

process.exit(main(process.argv));
