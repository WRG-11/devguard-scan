#!/usr/bin/env node
// Prove contract_check.mjs actually fails. A guard that has only ever been
// seen to pass is an assumption, and this one is the whole defence against the
// failure it was written for: the parity harness printed ALL GREEN for eight
// days while the published engine had stopped scanning `.env.local`.
//
// Each case writes a deliberately broken contract to a temp file, runs the
// real checker against it as a subprocess (the same entrypoint CI runs, not an
// internal function), and asserts it exits 1 with a message that names the
// problem. A checker that exits 1 for the wrong reason is not much better than
// one that exits 0.
//
// Usage: node scripts/contract_selftest.mjs   (exit 0 = pass)
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { contractDigest } from "./contract_digest.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CHECKER = join(HERE, "contract_check.mjs");
const REAL = join(HERE, "..", "parity", "contract.json");

const base = JSON.parse(readFileSync(REAL, "utf-8"));
const tmp = mkdtempSync(join(tmpdir(), "devguard-contract-selftest-"));

// Re-seal a mutated document so the digest check passes and the mutation is
// what actually gets caught. Without this every case would trip the digest
// check first and the individual comparisons would stay unproven.
function reseal(doc) {
  const { digest, ...core } = doc;
  return { ...core, digest: contractDigest(core) };
}

function clone() {
  return JSON.parse(JSON.stringify(base));
}

function run(doc, name) {
  const path = join(tmp, `${name}.json`);
  writeFileSync(path, JSON.stringify(doc, null, 2) + "\n");
  try {
    const stdout = execFileSync(process.execPath, [CHECKER, path], { encoding: "utf-8" });
    return { code: 0, out: stdout };
  } catch (err) {
    return { code: err.status, out: `${err.stdout || ""}${err.stderr || ""}` };
  }
}

const cases = [
  {
    name: "dropped-include-glob",
    why: "the exact 2026-07-21 divergence: a glob the canonical side has and this engine does not",
    mutate: (d) => {
      d.include.push("**/*.newext");
      return reseal(d);
    },
    expect: /missing pattern present in the contract: \*\*\/\*\.newext/,
  },
  {
    name: "extra-include-glob",
    why: "drift in the other direction: this engine scanning something the canonical tool does not",
    mutate: (d) => {
      d.include = d.include.filter((p) => p !== "**/*.cfg");
      return reseal(d);
    },
    expect: /pattern not in the contract: \*\*\/\*\.cfg/,
  },
  {
    name: "reordered-include",
    why: "same patterns, different order -- still a divergence from the canonical file",
    mutate: (d) => {
      d.include = [...d.include.slice(1), d.include[0]];
      return reseal(d);
    },
    expect: /different order/,
  },
  {
    name: "changed-regex",
    why: "a rule tightened or loosened on one side only",
    mutate: (d) => {
      d.rules[0].regex = "\\bsk-TOTALLY-DIFFERENT\\b";
      return reseal(d);
    },
    expect: /regex source differs/,
  },
  {
    name: "changed-severity",
    why: "an ERROR quietly demoted to WARNING changes whether the gate fails",
    mutate: (d) => {
      d.rules[0].severity = "WARNING";
      return reseal(d);
    },
    expect: /severity ERROR != WARNING/,
  },
  {
    name: "changed-message",
    why: "user-visible text is part of the contract the port claims to implement",
    mutate: (d) => {
      d.rules[0].message = "Something else entirely.";
      return reseal(d);
    },
    expect: /message differs/,
  },
  {
    name: "removed-rule",
    why: "a rule dropped from the canonical side must not linger here unnoticed",
    mutate: (d) => {
      d.rules = d.rules.slice(0, -1);
      return reseal(d);
    },
    expect: /rule ids or their order diverge/,
  },
  {
    name: "changed-max-file-bytes",
    why: "the size cap decides which files are looked at at all",
    mutate: (d) => {
      d.max_file_bytes = 4096;
      return reseal(d);
    },
    expect: /MAX_FILE_BYTES \d+ != 4096/,
  },
  {
    name: "hand-edited-digest",
    why: "the digest is what stops someone editing the contract to match the code",
    mutate: (d) => {
      d.include.push("**/*.newext"); // NOT resealed
      return d;
    },
    expect: /digest mismatch/,
  },
  {
    name: "unknown-contract-version",
    why: "a shape this checker does not know must be refused, not half-read",
    mutate: (d) => reseal({ ...d, contract_version: 99 }),
    expect: /contract_version 99 is not supported/,
  },
];

let ok = true;
for (const c of cases) {
  const { code, out } = run(c.mutate(clone()), c.name);
  const caught = code === 1 && c.expect.test(out);
  if (!caught) {
    ok = false;
    console.log(`FAIL  ${c.name}: exit ${code}, expected 1 with ${c.expect}`);
    console.log(out.split("\n").map((l) => `        ${l}`).join("\n"));
  } else {
    console.log(`PASS  ${c.name} -- ${c.why}`);
  }
}

// And the unmutated document must still pass, or every case above would
// "succeed" simply because the checker rejects everything.
{
  const { code } = run(base, "pristine");
  if (code !== 0) {
    ok = false;
    console.log(`FAIL  pristine contract should pass, exited ${code}`);
  } else {
    console.log("PASS  pristine contract still passes (the checker is not just always-fail)");
  }
}

rmSync(tmp, { recursive: true, force: true });
console.log(ok ? "\ncontract self-test: PASS" : "\ncontract self-test: FAIL");
process.exit(ok ? 0 : 1);
