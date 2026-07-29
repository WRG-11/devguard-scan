#!/usr/bin/env node
// Guard for .gitattributes: every text file must be stored LF in the index.
//
// .gitattributes only takes effect for files that are added or renormalised
// after it lands. A file committed with CRLF before that (this repo had two:
// README.md and scripts/run_parity.ps1) keeps its stored EOLs until someone
// runs `git add --renormalize`. So the attribute alone is a claim; this is the
// check. Without it the failure is silent and only shows up later as a
// whole-file diff hiding a one-line change.
//
// Reads `git ls-files --eol`, whose i/ column is the INDEX encoding -- the
// thing that actually matters. The w/ column (working tree) is allowed to be
// CRLF: that is core.autocrlf doing its job on Windows.
//
// Usage: node scripts/eol_check.mjs      (exit 0 clean, 1 on any CRLF in index)
import { execFileSync } from "node:child_process";

const OUT = execFileSync("git", ["ls-files", "--eol"], { encoding: "utf-8" });

const offenders = [];
let text = 0;
for (const line of OUT.split("\n")) {
  if (!line.trim()) continue;
  // Format: "i/<eol>  w/<eol>  attr/<attrs>\t<path>"
  const [info, path] = line.split("\t");
  const index = (info.match(/i\/(\S+)/) || [])[1];
  if (index === "none") continue; // binary or empty -- no EOLs to get wrong
  text++;
  if (index !== "lf") offenders.push({ path, index });
}

for (const o of offenders) console.log(`FAIL  ${o.path}: index stores ${o.index}, expected lf`);

console.log(
  `eol check: ${text} text file(s), ${offenders.length} with non-lf index -- ` +
    `${offenders.length ? "FAIL" : "PASS"}`,
);
if (offenders.length) {
  console.log("fix: git add --renormalize . && git commit");
}
process.exit(offenders.length ? 1 : 0);
