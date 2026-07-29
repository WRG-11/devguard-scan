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
//
// The walk mirrors read_text_safely rather than being the shortest thing that
// works: an unreadable directory, a file that vanishes between readdir and
// stat, and a file over the size cap must each be skipped the way the
// canonical tool skips it. bin/scan.mjs already does this; this script did
// not, which meant the harness could diverge from the engine it exists to
// measure -- an oversize file would be read and scanned here and correctly
// ignored on the Python side, and the parity run would report a difference
// that belongs to the harness.
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { buildReport, scanFiles, MAX_FILE_BYTES } from "../scan.js";

function walk(root) {
  const out = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let names;
    try {
      names = readdirSync(dir);
    } catch {
      continue; // unreadable directory -- skip, do not abort the dump
    }
    for (const name of names) {
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue; // vanished between readdir and stat
      }
      if (st.isDirectory()) stack.push(full);
      else if (st.isFile()) out.push({ full, size: st.size });
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

  const files = [];
  for (const { full, size } of walk(root)) {
    const path = relative(root, full).split(sep).join("/");
    if (size > MAX_FILE_BYTES) {
      // read_text_safely returns "" for oversize; hand the engine the same
      // empty record so include/exclude still runs and both sides agree.
      files.push({ path, text: "" });
      continue;
    }
    try {
      files.push({ path, text: readFileSync(full, "utf-8") });
    } catch {
      files.push({ path, text: "" }); // unreadable -> "", same as the Python side
    }
  }

  const findings = scanFiles(files);
  // No stats argument on purpose: py_reference_dump cannot measure
  // files_scanned without duplicating scan_secrets' own walk, so both
  // envelopes carry null there and the summaries stay comparable field for
  // field. A measured number on one side and a fabricated 0 on the other is
  // exactly the kind of difference a parity tool must not invent.
  const report = buildReport(findings, root);
  writeFileSync(out, JSON.stringify(report, null, 2), "utf-8");
  console.log(`JS reference dump written to ${out} (${findings.length} findings)`);
  return 0;
}

process.exit(main(process.argv));
