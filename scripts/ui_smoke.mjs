#!/usr/bin/env node
// Headless UI-path smoke: stub just enough of the DOM to load app.js, simulate
// a paste + Scan click, and assert the rendered results table contains the
// finding with a [REDACTED] snippet and NEVER the raw secret value.
//
// This complements the parity harness (engine correctness) and the static
// 0-upload audit by proving the browser glue (app.js) wires intake → scan →
// render without leaking the secret into the DOM.
//
// Usage: node scripts/ui_smoke.mjs   (exit 0 = pass)

const SECRET = "sk-proj-AAAA1111BBBB2222CCCC3333DDDD";

// --- minimal DOM stub ------------------------------------------------------
function makeEl() {
  return {
    value: "",
    innerHTML: "",
    _listeners: {},
    classList: { add() {}, remove() {} },
    addEventListener(ev, fn) {
      (this._listeners[ev] ||= []).push(fn);
    },
    fire(ev, arg) {
      (this._listeners[ev] || []).forEach((fn) => fn(arg || { preventDefault() {} }));
    },
    appendChild() {},
    click() {
      this.fire("click");
    },
  };
}

const els = {
  text: makeEl(),
  fname: makeEl(),
  drop: makeEl(),
  filein: makeEl(),
  filelist: makeEl(),
  scan: makeEl(),
  clear: makeEl(),
  results: makeEl(),
};

globalThis.document = {
  readyState: "complete",
  getElementById: (id) => els[id],
  createElement: () => makeEl(),
  addEventListener() {},
};
globalThis.FileReader = class {};

els.fname.value = "secrets.env";
els.text.value = `OPENAI_API_KEY=${SECRET}\npassword = "hunter2hunter2"`;

await import("../app.js"); // init() runs on import (readyState=complete)
els.scan.fire("click"); // simulate Scan button

const html = els.results.innerHTML;
const checks = {
  "table rendered": html.includes("<table>"),
  "openai rule shown": html.includes("openai_api_key"),
  "generic rule shown": html.includes("generic_secret_assignment"),
  "[REDACTED] present": html.includes("[REDACTED]"),
  "raw secret ABSENT": !html.includes(SECRET),
  "password value ABSENT": !html.includes("hunter2hunter2"),
  "FAIL status pill": html.includes(">FAIL<"),
};

let ok = true;
for (const [k, v] of Object.entries(checks)) {
  console.log(`${v ? "PASS" : "FAIL"}  ${k}`);
  if (!v) ok = false;
}
console.log(ok ? "\nUI smoke: PASS" : "\nUI smoke: FAIL");
process.exit(ok ? 0 : 1);
