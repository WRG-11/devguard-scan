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
    id: "generic_secret_assignment",
    source: String.raw`(api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*['"][^'"]{8,}['"]`,
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

// --- DEFAULT_INCLUDE — verbatim port of secrets.py:48-62 -------------------
export const DEFAULT_INCLUDE = [
  "**/*.env",
  "**/*.ini",
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

// --- fnmatch.translate equivalent ------------------------------------------
// Mirrors Python fnmatch: '*' -> '.*' (crosses '/'), '?' -> '.', '[...]' class,
// everything else escaped; full-string (anchored) match, DOTALL.
const _RE_SPECIAL = /[.+^${}()|\\]/g; // chars to escape outside a char class

function fnmatchToRegExp(pattern) {
  let out = "";
  let i = 0;
  const n = pattern.length;
  while (i < n) {
    const c = pattern[i];
    if (c === "*") {
      out += ".*";
      i++;
    } else if (c === "?") {
      out += ".";
      i++;
    } else if (c === "[") {
      let j = i + 1;
      if (j < n && (pattern[j] === "!" || pattern[j] === "^")) j++;
      if (j < n && pattern[j] === "]") j++;
      while (j < n && pattern[j] !== "]") j++;
      if (j >= n) {
        out += "\\["; // unterminated class -> literal '['
        i++;
      } else {
        let stuff = pattern.slice(i + 1, j).replace(/\\/g, "\\\\");
        if (stuff[0] === "!") stuff = "^" + stuff.slice(1);
        out += "[" + stuff + "]";
        i = j + 1;
      }
    } else {
      out += c.replace(_RE_SPECIAL, "\\$&");
      i++;
    }
  }
  return new RegExp("^(?:" + out + ")$", "s");
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
    if (!fnmatchToRegExp(pat).test(seg)) return false;
  }
  return true;
}

// --- match_any — verbatim port of common.py:34-44 --------------------------
export function matchAny(path, patterns) {
  for (const pattern of patterns) {
    if (fnmatchToRegExp(pattern).test(path)) return true; // fnmatch.fnmatch(path, pattern)
    if (pathlibMatch(path, pattern)) return true; // pp.match(pattern)
    if (pattern.startsWith("**/") && pathlibMatch(path, pattern.slice(3))) {
      return true; // pp.match(pattern[3:])
    }
  }
  return false;
}

// --- line_col — verbatim port of common.py:53-57 ---------------------------
// NOTE: index is a 0-based offset into `text`. In JS that offset is in UTF-16
// code units; Python counts code points. For ASCII content (all synthetic
// fixtures + typical config/source) these are identical.
export function lineCol(text, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  const lineStart = text.lastIndexOf("\n", index - 1); // rfind("\n", 0, index)
  const column = lineStart === -1 ? index + 1 : index - lineStart;
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
// scan_secrets (secrets.py:105-117): skip oversize, skip excluded, require an
// include match. File-outer order mirrors the Python rglob loop.
export function scanFiles(files, opts = {}) {
  const include = opts.include || DEFAULT_INCLUDE;
  const exclude = opts.exclude || DEFAULT_EXCLUDE;
  const maxBytes = opts.maxFileBytes || MAX_FILE_BYTES;
  const findings = [];
  for (const { path, text } of files) {
    const rel = path.replace(/\\/g, "/");
    if ((opts.byteSizes && opts.byteSizes[rel] > maxBytes) || byteLength(text) > maxBytes) {
      continue; // read_text_safely returns "" for oversize -> skipped
    }
    if (matchAny(rel, exclude)) continue;
    if (!matchAny(rel, include)) continue;
    if (!text) continue;
    for (const f of scanText(text, rel)) findings.push(f);
  }
  return findings;
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
    !fnmatchToRegExp(filePattern.trim()).test(finding.file) // fnmatch.fnmatch(finding.file, file_pattern)
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
export function buildReport(findings, scanRoot = ".", suppressedCount = 0) {
  const error = findings.filter((f) => f.severity.toUpperCase() === "ERROR").length;
  const warning = findings.filter((f) => f.severity.toUpperCase() === "WARNING").length;
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
    },
    findings,
  };
}
