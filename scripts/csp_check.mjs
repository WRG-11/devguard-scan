#!/usr/bin/env node
// The 0-byte-upload claim, checked two ways.
//
// 1. Statically: none of the files the browser loads may reference a network
//    API or an off-origin resource. This is the claim the README has always
//    made ("no fetch, XMLHttpRequest, WebSocket, sendBeacon, analytics, or
//    external CDN anywhere in the source") and it was verified by reading.
//    Reading does not survive the next edit.
//
// 2. Declaratively: index.html must ship a Content-Security-Policy that makes
//    the claim the browser's problem rather than the author's. A static check
//    only sees the code as written; CSP also covers what gets added later, and
//    turns a mistake into a visible violation instead of a silent request.
//
// Scope is deliberately the browser surface only -- index.html, theme.js,
// app.js, scan.js. scripts/ is the Node test harness: it spawns processes and
// reads files, which is not what the claim is about, and pretending otherwise
// would make the check noisy enough to be switched off.
//
// Usage: node scripts/csp_check.mjs   (exit 0 = pass)
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

const BROWSER_FILES = ["index.html", "theme.js", "app.js", "scan.js"];

// Each entry is [label, regex]. Word boundaries matter: `connect-src` in the
// policy itself must not be read as a network call, and neither must the
// prose in a comment explaining what is forbidden -- comments are stripped
// first for exactly that reason.
const NETWORK_APIS = [
  ["fetch(", /\bfetch\s*\(/],
  ["XMLHttpRequest", /\bXMLHttpRequest\b/],
  ["WebSocket", /\bWebSocket\b/],
  ["EventSource", /\bEventSource\b/],
  ["sendBeacon", /\bsendBeacon\b/],
  ["navigator.connection/serviceWorker", /\bnavigator\s*\.\s*(serviceWorker|sendBeacon)\b/],
  ["dynamic import()", /\bimport\s*\(/],
  ["off-origin src/href", /(?:src|href)\s*=\s*["']https?:\/\//i],
  ["protocol-relative url", /(?:src|href)\s*=\s*["']\/\//i],
];

const REQUIRED_DIRECTIVES = [
  ["default-src", "'none'"],
  ["script-src", "'self'"],
  ["connect-src", "'none'"],
  ["form-action", "'none'"],
  ["base-uri", "'none'"],
];

const failures = [];

// Strip comments and the CSP meta before scanning for API references: this
// file's own subject matter is those API names, and a check that trips on the
// documentation of what it forbids is a check nobody keeps.
function stripNonCode(text) {
  return text
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
}

for (const file of BROWSER_FILES) {
  const raw = readFileSync(join(ROOT, file), "utf-8");
  const code = stripNonCode(raw);
  for (const [label, re] of NETWORK_APIS) {
    if (re.test(code)) {
      const line = code.split("\n").findIndex((l) => re.test(l)) + 1;
      failures.push(`${file}:${line}: network capability referenced: ${label}`);
    }
  }
}

// --- CSP ------------------------------------------------------------------
const html = readFileSync(join(ROOT, "index.html"), "utf-8");
// The attribute delimiter has to be captured and back-referenced: CSP source
// expressions are themselves single-quoted ('none', 'self'), so a naive
// [^"']+ stops at the first quote inside the value and silently reports a
// policy of "default-src " -- a check that would fail on a correct policy.
const meta = html.match(
  /<meta\s+http-equiv=["']Content-Security-Policy["'][\s\S]*?content=(["'])([\s\S]*?)\1/i,
);
if (!meta) {
  failures.push("index.html: no Content-Security-Policy meta tag");
} else {
  const policy = meta[2];
  const directives = new Map(
    policy
      .split(";")
      .map((d) => d.trim())
      .filter(Boolean)
      .map((d) => {
        const [name, ...values] = d.split(/\s+/);
        return [name.toLowerCase(), values];
      }),
  );
  for (const [name, required] of REQUIRED_DIRECTIVES) {
    const values = directives.get(name);
    if (!values) {
      failures.push(`CSP: missing directive ${name}`);
    } else if (!values.includes(required)) {
      failures.push(`CSP: ${name} is "${values.join(" ")}", expected to include ${required}`);
    }
  }
  // 'unsafe-inline' in script-src would silently re-open inline event
  // handlers, which is the one thing the policy is here to close.
  const scriptSrc = directives.get("script-src") || [];
  if (scriptSrc.includes("'unsafe-inline'") || scriptSrc.includes("'unsafe-eval'")) {
    failures.push(`CSP: script-src must not allow ${scriptSrc.join(" ")}`);
  }
  // frame-ancestors is ignored in a meta policy; listing it reads like
  // protection that is not there.
  if (directives.has("frame-ancestors")) {
    failures.push("CSP: frame-ancestors has no effect in a <meta> policy -- remove it or set it as a header");
  }
}

// --- every local script the page loads must actually be there --------------
// `script-src 'self'` only helps if the 'self' files exist. The theme
// initialiser moved out of index.html to close 'unsafe-inline', which turned a
// guaranteed-present inline block into a file that a future move or a
// .gitignore rule could drop from the deployment, taking first-paint theming
// with it and leaving no error anywhere but the network tab.
{
  const scriptSrcs = [...html.matchAll(/<script[^>]*\bsrc=(["'])([^"']+)\1/gi)].map((m) => m[2]);
  if (scriptSrcs.length === 0) failures.push("index.html: no external scripts found -- did the parser break?");
  for (const src of scriptSrcs) {
    if (/^https?:\/\//i.test(src) || src.startsWith("//")) continue; // already flagged above
    try {
      readFileSync(join(ROOT, src));
    } catch {
      failures.push(`index.html references a script that does not exist: ${src}`);
    }
  }
}

for (const f of failures) console.log(`FAIL  ${f}`);
console.log(
  `csp + no-network check: ${BROWSER_FILES.length} browser files, ` +
    `${REQUIRED_DIRECTIVES.length} required directives -- ` +
    `${failures.length ? `${failures.length} problem(s), FAIL` : "PASS"}`,
);
process.exit(failures.length ? 1 : 0);
