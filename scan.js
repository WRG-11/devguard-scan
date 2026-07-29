// devguard-in-browser — secret-scan engine (JS port of wrg_devguard).
//
// PARITY SOURCE (READ-ONLY): wrg_devguard (private monorepo, not a
// standalone public repo -- see SECURITY.md scope note), src/wrg_devguard/
//   secrets.py  SECRET_RULES (L9-70), DEFAULT_INCLUDE (L72-86), scan_secrets (L89-134)
//   common.py   match_any (L42-52), line_col (L74-78)
//   policy.py   DEFAULT_EXCLUDE (L20-52)
//
// Verified byte-identical against the current monorepo source (2026-07-17):
// 9/9 findings + summary counts matched via
// `run_parity.ps1 -WrgDevguardSrc <monorepo>/wrg_devguard/src`.
//
// This module is dependency-free ES and runs UNCHANGED in the browser (UI) and
// in Node (parity harness). It performs NO I/O and NO network calls — callers
// hand it { path, text } records; it returns Finding records. The secret VALUE
// is never returned (snippet is always "[REDACTED]", matching secrets.py:107).

// --- SECRET_RULES — verbatim port of secrets.py:9-70 -----------------------
// Python compiles each with re.MULTILINE (secrets.py:98) → JS flag "m".
// Rule 6 (generic_secret_assignment) carries an inline (?i) flag in Python; JS
// has no inline flags, so the "(?i)" is stripped from the source and expressed
// as the "i" RegExp flag.
// None of the 10 patterns use ^/$ anchors, so "m" is a behavioural no-op here —
// it is kept only to mirror the Python compile flags 1:1.
export const SECRET_RULES = [
  {
    id: "openai_api_key",
    source: String.raw`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`,
    flags: "gm",
    severity: "ERROR",
    message: "Possible OpenAI API key found.",
  },
  {
    id: "github_token",
    source: String.raw`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`,
    flags: "gm",
    severity: "ERROR",
    message: "Possible GitHub token found.",
  },
  {
    id: "aws_access_key_id",
    source: String.raw`\bAKIA[0-9A-Z]{16}\b`,
    flags: "gm",
    severity: "ERROR",
    message: "Possible AWS Access Key ID found.",
  },
  {
    id: "slack_token",
    source: String.raw`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`,
    flags: "gm",
    severity: "ERROR",
    message: "Possible Slack token found.",
  },
  {
    id: "private_key_block",
    source: String.raw`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`,
    flags: "gm",
    severity: "ERROR",
    message: "Private key block found.",
  },
  {
    // Python: (?i)(api[_-]?key|...)...  → strip (?i), add "i" flag.
    // The rest of the source is kept BYTE-IDENTICAL to the Python original,
    // including the `\"` escapes inside the character classes, which JS does
    // not require but does accept with the same meaning. That makes the whole
    // port checkable by string comparison against parity/contract.json with
    // exactly one documented transform (the inline (?i)) instead of a
    // human deciding, per rule, whether two spellings are equivalent.
    id: "generic_secret_assignment",
    source: String.raw`(api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]`,
    flags: "gim",
    severity: "WARNING",
    message: "Potential hardcoded secret assignment.",
  },
  {
    id: "google_api_key",
    source: String.raw`\bAIza[0-9A-Za-z_\-]{35}\b`,
    flags: "gm",
    severity: "ERROR",
    message: "Possible Google API key found.",
  },
  {
    id: "stripe_secret_key",
    source: String.raw`\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b`,
    flags: "gm",
    severity: "ERROR",
    message: "Possible Stripe live secret key found.",
  },
  {
    id: "github_fine_grained_pat",
    source: String.raw`\bgithub_pat_[0-9A-Za-z_]{82}\b`,
    flags: "gm",
    severity: "ERROR",
    message: "Possible GitHub fine-grained personal access token found.",
  },
  {
    id: "slack_webhook_url",
    source: String.raw`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24,}`,
    flags: "gm",
    severity: "ERROR",
    message: "Possible Slack incoming-webhook URL found.",
  },
];

// --- DEFAULT_INCLUDE — verbatim port of secrets.py DEFAULT_INCLUDE ---------
// `**/*.env.*` and `**/*.cfg` were added upstream after this port's last
// hand-verification (2026-07-17) and were missing here until 2026-07-29. The
// gap was not cosmetic: `**/*.env` does not match `.env.local`, so the two
// highest-yield leak locations in a real tree -- `.env.local` / `.env.production`
// and `setup.cfg` / `tox.cfg` -- were skipped outright by the browser demo, the
// CLI and the Action alike. Measured on one directory before the fix:
// canonical Python 3 findings (including an AWS key in .env.local), this
// engine 1. The parity harness still reported ALL GREEN, because it compares
// the two engines' OUTPUT over a fixture corpus that contained neither
// extension -- see parity/contract.json + scripts/contract_check.mjs, which
// compare the LISTS themselves and would have failed on day one.
export const DEFAULT_INCLUDE = [
  "**/*.env",
  "**/*.env.*",
  "**/*.ini",
  "**/*.cfg",
  "**/*.json",
  "**/*.toml",
  "**/*.yaml",
  "**/*.yml",
  "**/*.txt",
  "**/*.md",
  "**/*.py",
  "**/*.js",
  "**/*.ts",
  "**/*.sh",
  "**/*.ps1",
];

// --- DEFAULT_EXCLUDE — verbatim port of policy.py:20-52 --------------------
export const DEFAULT_EXCLUDE = [
  "**/.git/**",
  "**/.venv/**",
  "**/venv/**",
  "**/node_modules/**",
  "**/__pycache__/**",
  "**/.pytest_cache/**",
  "**/tests/**",
  "**/testdata/**",
  "**/fixtures/**",
  "**/.tmp/**",
  ".tmp/**",
  "**/.tmp_pytest/**",
  ".tmp_pytest/**",
  "**/_tmp*/**",
  "_tmp*/**",
  "**/.cache/**",
  "**/site-packages/**",
  "**/.train_venv/**",
  "**/data/**",
  "**/runs/**",
  "**/artifacts/**",
  "artifacts/**",
  "**/dist/**",
  "**/build/**",
  "**/*.png",
  "**/*.jpg",
  "**/*.jpeg",
  "**/*.gif",
  "**/*.svg",
  "**/*.ico",
  "**/*.lock",
];

export const MAX_FILE_BYTES = 1_048_576; // secrets.py default max_file_bytes

// --- fnmatch.fnmatchcase equivalent ----------------------------------------
// Mirrors Python fnmatch: '*' matches any run INCLUDING '/', '?' any single
// char, '[...]' a character class; everything else is literal, and the match is
// anchored to the whole string.
//
// Matched directly rather than by building a RegExp from the pattern. The
// pattern is untrusted -- include/exclude arrive from the command line (and the
// GitHub Action's inputs), and an allowlist rule's `file` glob is read from
// <scanned-dir>/.wrg/allowlist.json, i.e. out of the very repository being
// scanned. Translating that to `^(?:...)$` turned each '*' into '.*', and a
// 22-character pattern of alternating stars backtracked long enough to hang the
// scan indefinitely (measured: 6 chars 0.2ms, 14 chars 237ms, 22 chars >25s --
// a scanner that a scanned repo can silence by supplying one glob). This
// two-pointer walk is O(len(str) x len(pattern)) with no backtracking blowup.
//
// Rewriting the translation also fixed two divergences from the Python contract
// this file is a port of, both found by differential-testing 2576 pattern/path
// pairs against fnmatchcase:
//   [^abc]  '^' is a LITERAL member in fnmatch (the set is {^,a,b,c}); only '!'
//           negates. Translating to a RegExp class made '^' negate, inverting
//           the result for every such pattern.
//   []]     a ']' in first position is a member, not the terminator. That was
//           parsed correctly but emitted as the RegExp class "[]]", which in
//           JavaScript is an EMPTY class followed by a literal ']' -- matching
//           nothing, where Python matches ']'.

// Parse a '[...]' class at pat[i] === '['. Returns null when unterminated, in
// which case the caller treats '[' as a literal (fnmatch does the same).
function parseCharClass(pat, i) {
  const n = pat.length;
  let j = i + 1;
  let negated = false;
  if (j < n && pat[j] === "!") {
    negated = true;
    j++;
  }
  const start = j;
  if (j < n && pat[j] === "]") j++; // leading ']' is a member, not the close
  while (j < n && pat[j] !== "]") j++;
  if (j >= n) return null;
  return { end: j + 1, negated, body: pat.slice(start, j) };
}

// Membership within a parsed class body. 'a-c' is a range; a '-' that is first
// or last is a literal. No backslash escaping -- fnmatch gives '\' no special
// meaning inside a class.
function classContains(body, ch) {
  for (let k = 0; k < body.length; k++) {
    if (body[k + 1] === "-" && k + 2 < body.length) {
      if (ch >= body[k] && ch <= body[k + 2]) return true;
      k += 2;
      continue;
    }
    if (body[k] === ch) return true;
  }
  return false;
}

function fnmatchTest(str, pattern) {
  const n = str.length;
  const m = pattern.length;
  let si = 0;
  let pi = 0;
  let starPi = -1; // pattern index of the last '*' seen
  let starSi = 0; // string index it was matched against
  while (si < n) {
    if (pi < m) {
      const c = pattern[pi];
      if (c === "*") {
        starPi = pi;
        starSi = si;
        pi++;
        continue;
      }
      if (c === "?") {
        pi++;
        si++;
        continue;
      }
      if (c === "[") {
        const cls = parseCharClass(pattern, pi);
        if (cls) {
          if (classContains(cls.body, str[si]) !== cls.negated) {
            pi = cls.end;
            si++;
            continue;
          }
        } else if (str[si] === "[") {
          pi++;
          si++;
          continue;
        }
      } else if (c === str[si]) {
        pi++;
        si++;
        continue;
      }
    }
    // no match here: give the last '*' one more character, else fail
    if (starPi >= 0) {
      starSi++;
      si = starSi;
      pi = starPi + 1;
      continue;
    }
    return false;
  }
  while (pi < m && pattern[pi] === "*") pi++;
  return pi === m;
}

// PurePosixPath.match equivalent (relative pattern → match from the right,
// component-wise, case-sensitive). Mirrors CPython pathlib: '**' is NOT
// recursive in match() — it behaves as an ordinary single-component glob.
function pathlibMatch(path, pattern) {
  const pathParts = path.split("/").filter(Boolean);
  const patParts = pattern.split("/").filter(Boolean);
  if (patParts.length === 0 || patParts.length > pathParts.length) return false;
  for (let k = 1; k <= patParts.length; k++) {
    const pat = patParts[patParts.length - k];
    const seg = pathParts[pathParts.length - k];
    if (!fnmatchTest(seg, pat)) return false;
  }
  return true;
}

// --- match_any — verbatim port of common.py:34-44 --------------------------
export function matchAny(path, patterns) {
  for (const pattern of patterns) {
    if (fnmatchTest(path, pattern)) return true; // fnmatch.fnmatch(path, pattern)
    if (pathlibMatch(path, pattern)) return true; // pp.match(pattern)
    if (pattern.startsWith("**/") && pathlibMatch(path, pattern.slice(3))) {
      return true; // pp.match(pattern[3:])
    }
  }
  return false;
}

// --- line_col — port of common.py line_col ---------------------------------
// `index` is a 0-based offset into `text`, and the two languages do not agree
// on what an offset counts: RegExp.exec gives UTF-16 code units, Python's
// match.start() gives code points. Anything outside the BMP -- an emoji, a
// musical symbol, most of the supplementary CJK block -- is two code units and
// one code point, so a line carrying one before the match reported a column
// two higher than the canonical tool for the same finding.
//
// This was previously documented as a known divergence and left alone on the
// grounds that fixtures and typical config are ASCII. That is true of the
// corpus and not of the input: a comment or a string above a leaked key is
// exactly where non-ASCII shows up, and a column that is silently wrong sends
// whoever is chasing the leak to the wrong character.
//
// The line number needs no such care: it counts newlines, and U+000A cannot
// appear as half of a surrogate pair, so both units give the same answer.
export function lineCol(text, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  const lineStart = text.lastIndexOf("\n", index - 1); // rfind("\n", 0, index)
  const from = lineStart === -1 ? 0 : lineStart + 1;
  // Python: column = index + 1 (first line) or index - line_start, both of
  // which are "code points since the start of the line, plus one".
  let column = 1;
  for (let i = from; i < index; i++) {
    const code = text.charCodeAt(i);
    const isTrailingSurrogate = code >= 0xdc00 && code <= 0xdfff;
    if (isTrailingSurrogate && i > from) {
      const prev = text.charCodeAt(i - 1);
      if (prev >= 0xd800 && prev <= 0xdbff) continue; // second half of one code point
    }
    column++;
  }
  return [line, column];
}

// UTF-8 byte length (mirror of os.stat().st_size for text content).
const _UTF8 = typeof TextEncoder !== "undefined" ? new TextEncoder() : null;
function byteLength(text) {
  if (_UTF8) return _UTF8.encode(text).length;
  // Node fallback (TextEncoder is global in modern Node, but be safe).
  return Buffer.byteLength(text, "utf-8");
}

// Scan a single text blob. Rule-outer / match-inner loop mirrors
// secrets.py:118-133 so the per-file finding order matches the Python tool.
export function scanText(text, file) {
  const findings = [];
  for (const rule of SECRET_RULES) {
    const re = new RegExp(rule.source, rule.flags);
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m.index === re.lastIndex) re.lastIndex++; // zero-width guard (defensive)
      const [line, column] = lineCol(text, m.index);
      findings.push({
        check: "scan-secrets",
        rule_id: rule.id,
        severity: rule.severity,
        message: rule.message,
        file,
        line,
        column,
        snippet: "[REDACTED]", // secrets.py:131 — value never retained
      });
    }
  }
  return findings;
}

// Scan a list of { path, text } records, applying include/exclude exactly as
// scan_secrets: skip excluded, require an include match, then skip oversize.
// File-outer order mirrors the Python rglob loop.
//
// Returns counts alongside the findings. A scanner reports absence of evidence,
// and absence of evidence is indistinguishable from "nothing was looked at" --
// a tree where every candidate was skipped for size, or where the include list
// matched nothing at all, produces exactly the same empty result as a clean
// tree. `scanned` makes the difference visible to the caller.
export function scanFilesDetailed(files, opts = {}) {
  const include = opts.include || DEFAULT_INCLUDE;
  const exclude = opts.exclude || DEFAULT_EXCLUDE;
  const maxBytes = opts.maxFileBytes || MAX_FILE_BYTES;
  const findings = [];
  let scanned = 0;
  let skippedOversize = 0;
  for (const { path, text } of files) {
    const rel = path.replace(/\\/g, "/");
    // Order follows secrets.py: exclude, then include, then the size guard
    // inside read_text_safely. Findings are identical whichever way round the
    // size check goes, but the counts are not -- checking size first would
    // report an excluded 5 MB node_modules bundle as "skipped for size".
    if (matchAny(rel, exclude)) continue;
    if (!matchAny(rel, include)) continue;
    if ((opts.byteSizes && opts.byteSizes[rel] > maxBytes) || byteLength(text) > maxBytes) {
      skippedOversize++; // read_text_safely returns "" for oversize -> skipped
      continue;
    }
    scanned++;
    if (!text) continue;
    for (const f of scanText(text, rel)) findings.push(f);
  }
  return { findings, scanned, skippedOversize };
}

// Backward-compatible thin wrapper: findings only.
export function scanFiles(files, opts = {}) {
  return scanFilesDetailed(files, opts).findings;
}

// --- allowlist — verbatim port of cli.py's _finding_matches_rule /
// _apply_allowlist (default source: <scan_root>/.wrg/allowlist.json,
// {"rules": [{check, rule_id, severity, file, snippet_contains, reason}]}).
// Every previously-shipped report hardcoded summary.suppressed to 0 --
// the canonical CLI's allowlist mechanism was never ported at all.
export function findingMatchesRule(finding, rule) {
  const check = rule.check;
  const ruleId = rule.rule_id;
  const severity = rule.severity;
  const filePattern = rule.file;
  const snippetContains = rule.snippet_contains;

  if (typeof check === "string" && check.trim() && finding.check !== check.trim()) return false;
  if (typeof ruleId === "string" && ruleId.trim() && finding.rule_id !== ruleId.trim()) return false;
  if (
    typeof severity === "string" &&
    severity.trim() &&
    finding.severity.toUpperCase() !== severity.trim().toUpperCase()
  ) {
    return false;
  }
  if (
    typeof filePattern === "string" &&
    filePattern.trim() &&
    !fnmatchTest(finding.file, filePattern.trim()) // fnmatch.fnmatch(finding.file, file_pattern)
  ) {
    return false;
  }
  if (
    typeof snippetContains === "string" &&
    snippetContains.trim() &&
    !finding.snippet.includes(snippetContains)
  ) {
    return false;
  }
  return true;
}

// Returns { active, suppressed } -- suppressed carries the same
// {finding, reason, rule} shape as the Python CLI's JSON output.
export function applyAllowlist(findings, allowlistRules) {
  if (!allowlistRules || allowlistRules.length === 0) return { active: findings, suppressed: [] };
  const active = [];
  const suppressed = [];
  for (const finding of findings) {
    const matchedRule = allowlistRules.find((rule) => findingMatchesRule(finding, rule));
    if (!matchedRule) {
      active.push(finding);
      continue;
    }
    suppressed.push({
      finding,
      reason: String(matchedRule.reason || "allowlisted"),
      rule: { check: matchedRule.check, rule_id: matchedRule.rule_id, file: matchedRule.file },
    });
  }
  return { active, suppressed };
}

// Build the same JSON envelope as the parity reference dumper.
//
// `stats` adds files_scanned / skipped_oversize / skipped_unreadable to the
// summary. These are additive fields: every previously-valid consumer keeps
// working, and a report that says `"files_scanned": 0` no longer looks like a
// clean tree. They default to null (not 0) when the caller does not supply
// them, so "not measured" stays distinguishable from "measured, and it was
// zero" -- reporting an unmeasured 0 would be the same lie in a new place.
export function buildReport(findings, scanRoot = ".", suppressedCount = 0, stats = {}) {
  const error = findings.filter((f) => f.severity.toUpperCase() === "ERROR").length;
  const warning = findings.filter((f) => f.severity.toUpperCase() === "WARNING").length;
  const num = (v) => (typeof v === "number" ? v : null);
  return {
    schema_version: "wrg_devguard.lib",
    command: "scan-secrets",
    scan_root: scanRoot,
    status: error > 0 ? "FAIL" : "PASS",
    summary: {
      total_findings: findings.length,
      error,
      warning,
      suppressed: suppressedCount,
      fail_on: "error",
      files_scanned: num(stats.scanned),
      skipped_oversize: num(stats.skippedOversize),
      skipped_unreadable: num(stats.skippedUnreadable),
    },
    findings,
  };
}
