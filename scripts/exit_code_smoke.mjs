#!/usr/bin/env node
// Exit codes, exercised across the real process boundary.
//
// cli_smoke.mjs imports runScan/parseArgs and asserts on their return values,
// which is the right way to test the logic and the wrong way to test a gate:
// what CI consumes is the exit code, and that is produced by main() -- code
// no in-process test touches. The two most dangerous behaviours this repo had
// (a non-existent scan root and a mistyped flag both exiting 0) lived exactly
// in that gap.
//
// Usage: node scripts/exit_code_smoke.mjs   (exit 0 = pass)
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "bin", "scan.mjs");
const FIXTURES = join(HERE, "..", "fixtures");

const EXIT_PASS = 0;
const EXIT_FINDINGS = 1;
const EXIT_USAGE = 2;

const clean = mkdtempSync(join(tmpdir(), "devguard-exitcode-clean-"));
writeFileSync(join(clean, "ok.py"), "print('nothing secret here')\n");

const cases = [
  {
    want: EXIT_FINDINGS,
    args: [FIXTURES],
    why: "corpus with ERROR findings fails the gate",
  },
  {
    want: EXIT_PASS,
    args: [clean],
    why: "a genuinely clean tree passes",
  },
  {
    want: EXIT_USAGE,
    args: [join(HERE, "..", "no-such-dir")],
    why: "a scan root that does not exist is not a clean tree",
  },
  {
    want: EXIT_USAGE,
    args: [CLI],
    why: "a file where a directory is expected",
  },
  {
    want: EXIT_USAGE,
    args: [".", "--jsonn"],
    why: "a mistyped flag must not be swallowed as the scan root",
  },
  {
    want: EXIT_USAGE,
    args: [".", "--exclude"],
    why: "a flag missing its value fails cleanly, not with a stack trace",
  },
  {
    want: EXIT_USAGE,
    args: [FIXTURES, "extra-positional"],
    why: "a stray second directory must not silently override the first",
  },
  {
    want: EXIT_USAGE,
    args: [FIXTURES, "--max-file-bytes", "-1"],
    why: "a nonsensical size cap is a configuration error",
  },
  {
    want: EXIT_PASS,
    args: ["--help"],
    why: "--help is not a failure",
  },
];

let ok = true;
for (const c of cases) {
  const res = spawnSync(process.execPath, [CLI, ...c.args], { encoding: "utf-8" });
  const got = res.status;
  const label = `exit ${got} for [${c.args.map((a) => a.replace(HERE, ".")).join(" ")}]`;
  if (got !== c.want) {
    ok = false;
    console.log(`FAIL  expected ${c.want}, got ${got} -- ${c.why}`);
    if (res.stderr) console.log(res.stderr.split("\n").map((l) => `        ${l}`).join("\n"));
  } else {
    console.log(`PASS  ${label} -- ${c.why}`);
  }
}

// A usage error must say something on stderr. Exit 2 with a silent process is
// a gate failure nobody can diagnose from a CI log.
{
  const res = spawnSync(process.execPath, [CLI, ".", "--nope"], { encoding: "utf-8" });
  const explained = /unknown option/.test(res.stderr || "");
  if (!explained) {
    ok = false;
    console.log(`FAIL  usage error printed nothing useful on stderr: ${JSON.stringify(res.stderr)}`);
  } else {
    console.log("PASS  usage errors explain themselves on stderr");
  }
}

rmSync(clean, { recursive: true, force: true });
console.log(ok ? "\nexit-code smoke: PASS" : "\nexit-code smoke: FAIL");
process.exit(ok ? 0 : 1);
