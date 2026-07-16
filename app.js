// devguard-in-browser — UI glue. ALL scanning happens in scanFiles() (scan.js),
// which performs NO I/O and NO network calls. This file deliberately uses NO
// fetch / XMLHttpRequest / WebSocket / sendBeacon / dynamic remote import and
// loads NO external resource — every byte stays in the browser (0-byte upload).
import { scanFiles, buildReport } from "./scan.js";

const $ = (id) => document.getElementById(id);
const droppedFiles = []; // { path, text }

// --- file intake -----------------------------------------------------------
function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file); // local read only — nothing is uploaded
  });
}

function upsertDroppedFile(rec) {
  const existing = droppedFiles.findIndex((f) => f.path === rec.path);
  if (existing >= 0) droppedFiles[existing] = rec;
  else droppedFiles.push(rec);
}

async function addFiles(fileList) {
  for (const file of fileList) {
    try {
      const text = await readFileAsText(file);
      upsertDroppedFile({ path: file.webkitRelativePath || file.name, text });
    } catch {
      /* unreadable / binary — skip silently */
    }
  }
  renderFileList();
}

// --- directory-drop support (Chromium/WebKit DataTransferItem entries API) -
// Folder drag-and-drop only carries the top-level File objects via
// dataTransfer.files -- nested files inside a dropped directory never
// appear there. Reading the directory tree requires the (non-standard but
// widely supported) webkitGetAsEntry() + FileSystemDirectoryReader walk
// below. If the browser doesn't expose it, callers fall back to the flat
// dataTransfer.files list (individual file drops still work everywhere).

function entryToFile(entry) {
  return new Promise((resolve, reject) => entry.file(resolve, reject));
}

function readDirEntries(reader) {
  return new Promise((resolve, reject) => reader.readEntries(resolve, reject));
}

async function walkEntry(entry, out) {
  if (entry.isFile) {
    const file = await entryToFile(entry);
    // entry.fullPath is rooted at the dropped item ("/subdir/file.txt");
    // strip the leading slash to match webkitRelativePath's convention.
    out.push({ file, relPath: entry.fullPath.replace(/^\//, "") });
  } else if (entry.isDirectory) {
    const reader = entry.createReader();
    // readEntries() returns results in batches and does NOT guarantee a
    // complete listing in one call (documented Chromium quirk) -- keep
    // calling until it returns an empty array.
    let batch;
    do {
      batch = await readDirEntries(reader);
      for (const child of batch) await walkEntry(child, out);
    } while (batch.length > 0);
  }
}

async function addDroppedEntries(entries) {
  const collected = [];
  for (const entry of entries) {
    try {
      await walkEntry(entry, collected);
    } catch {
      /* unreadable entry — skip silently */
    }
  }
  for (const { file, relPath } of collected) {
    try {
      const text = await readFileAsText(file);
      upsertDroppedFile({ path: relPath || file.name, text });
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
    const items = e.dataTransfer && e.dataTransfer.items;
    if (items && items.length && typeof items[0].webkitGetAsEntry === "function") {
      const entries = [];
      for (const item of items) {
        const entry = item.webkitGetAsEntry();
        if (entry) entries.push(entry);
      }
      if (entries.length > 0) {
        addDroppedEntries(entries);
        return;
      }
    }
    // Fallback (no entries API, or none resolved): flat file list, no
    // directory recursion. Individual file drops still work everywhere.
    if (e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files);
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
