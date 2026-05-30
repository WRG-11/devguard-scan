// devguard-in-browser — UI glue. ALL scanning happens in scanFiles() (scan.js),
// which performs NO I/O and NO network calls. This file deliberately uses NO
// fetch / XMLHttpRequest / WebSocket / sendBeacon / dynamic remote import and
// loads NO external resource — every byte stays in the browser (0-byte upload).
import { scanFiles, buildReport } from "./scan.js";

const $ = (id) => document.getElementById(id);
const droppedFiles = []; // { path, text }

// --- file intake -----------------------------------------------------------
function readFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () =>
      resolve({ path: file.webkitRelativePath || file.name, text: String(reader.result) });
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file); // local read only — nothing is uploaded
  });
}

async function addFiles(fileList) {
  for (const file of fileList) {
    try {
      const rec = await readFile(file);
      // de-dupe by path
      const existing = droppedFiles.findIndex((f) => f.path === rec.path);
      if (existing >= 0) droppedFiles[existing] = rec;
      else droppedFiles.push(rec);
    } catch {
      /* unreadable / binary — skip silently */
    }
  }
  renderFileList();
}

function renderFileList() {
  const ul = $("filelist");
  ul.innerHTML = "";
  for (const f of droppedFiles) {
    const li = document.createElement("li");
    li.textContent = "📄 " + f.path;
    ul.appendChild(li);
  }
}

// --- scan + render ---------------------------------------------------------
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]),
  );
}

function runScan() {
  const inputs = [];
  const pasted = $("text").value;
  if (pasted.trim()) {
    inputs.push({ path: ($("fname").value || "pasted.txt").trim(), text: pasted });
  }
  for (const f of droppedFiles) inputs.push(f);

  const out = $("results");
  if (inputs.length === 0) {
    out.innerHTML = '<div class="panel empty">Nothing to scan — paste content or drop a file.</div>';
    return;
  }

  const findings = scanFiles(inputs);
  const report = buildReport(findings);
  renderResults(report);
}

function renderResults(report) {
  const { summary, findings, status } = report;
  const out = $("results");

  let html = '<div class="panel">';
  html += '<div class="summary">';
  if (summary.total_findings === 0) {
    html += '<span class="pill ok">CLEAN</span> No secrets detected.';
  } else {
    html += `<span class="pill ${status === "FAIL" ? "error" : "warning"}">${status}</span> `;
    html += `${summary.total_findings} finding(s): `;
    html += `<span class="pill error">${summary.error} error</span> `;
    html += `<span class="pill warning">${summary.warning} warning</span>`;
  }
  html += "</div>";

  if (findings.length > 0) {
    html += "<table><thead><tr>";
    html += "<th>#</th><th>rule</th><th>severity</th><th>file</th><th>line</th><th>col</th><th>snippet</th>";
    html += "</tr></thead><tbody>";
    findings.forEach((f, i) => {
      const sev = f.severity.toUpperCase();
      const cls = sev === "ERROR" ? "sev-error" : "sev-warning";
      html += "<tr>";
      html += `<td>${i + 1}</td>`;
      html += `<td>${escapeHtml(f.rule_id)}</td>`;
      html += `<td class="${cls}">${escapeHtml(sev)}</td>`;
      html += `<td>${escapeHtml(f.file)}</td>`;
      html += `<td>${f.line}</td>`;
      html += `<td>${f.column}</td>`;
      html += '<td class="redacted">[REDACTED]</td>';
      html += "</tr>";
    });
    html += "</tbody></table>";
  }
  html += "</div>";
  out.innerHTML = html;
}

// --- wiring ----------------------------------------------------------------
function init() {
  $("scan").addEventListener("click", runScan);
  $("clear").addEventListener("click", () => {
    $("text").value = "";
    droppedFiles.length = 0;
    renderFileList();
    $("results").innerHTML = "";
  });

  const drop = $("drop");
  const filein = $("filein");
  drop.addEventListener("click", () => filein.click());
  filein.addEventListener("change", (e) => addFiles(e.target.files));

  ["dragenter", "dragover"].forEach((ev) =>
    drop.addEventListener(ev, (e) => {
      e.preventDefault();
      drop.classList.add("over");
    }),
  );
  ["dragleave", "drop"].forEach((ev) =>
    drop.addEventListener(ev, (e) => {
      e.preventDefault();
      drop.classList.remove("over");
    }),
  );
  drop.addEventListener("drop", (e) => {
    if (e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files);
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
