#!/usr/bin/env python3
"""Dump wrg_devguard.secrets.scan_secrets() findings as JSON for parity checks.

The wrg-devguard CLI redacts scan-secrets JSON output entirely (counts only, no
locations) as an OPSEC measure, so the CLI's --json-out is unusable for
finding-level parity. This helper calls the canonical detection library
directly (the SAME code the CLI uses) and emits the envelope the JS engine
produces, so browser-engine vs Python-tool can be diffed finding-for-finding.

The canonical source is maintainer-only: it lives in a private monorepo and is
not published as a standalone repo, so this script only runs for someone with
that checkout. (An earlier version of this line pointed at a public
"WRG-11/wrg-devguard" repository that does not exist -- the docs redaction pass
that removed that name elsewhere missed this file.)

Usage:
  PYTHONPATH=<monorepo-checkout>/apps/wrg_devguard/src       python py_reference_dump.py <root> <out.json>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from wrg_devguard.secrets import scan_secrets  # canonical parity source


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("Usage: py_reference_dump.py <scan_root> <out.json>", file=sys.stderr)
        return 2
    root, out = argv[1], argv[2]
    findings = scan_secrets(Path(root))
    error = sum(1 for f in findings if f.severity.upper() == "ERROR")
    warning = sum(1 for f in findings if f.severity.upper() == "WARNING")
    payload = {
        "schema_version": "wrg_devguard.lib",
        "command": "scan-secrets",
        "scan_root": root,
        "status": "FAIL" if error > 0 else "PASS",
        "summary": {
            "total_findings": len(findings),
            "error": error,
            "warning": warning,
            "suppressed": 0,
            "fail_on": "error",
            # Null, not 0: scan_secrets does its own walk and does not report
            # how many files it read, so these are genuinely not measured
            # here. The JS dumper leaves them null too, which keeps the two
            # summaries comparable field for field -- a measured number on one
            # side and an invented 0 on the other would show up as a parity
            # difference that belongs to the harness.
            "files_scanned": None,
            "skipped_oversize": None,
            "skipped_unreadable": None,
        },
        "findings": [
            {
                "check": f.check,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "message": f.message,
                "file": f.file,
                "line": f.line,
                "column": f.column,
                "snippet": "[REDACTED]",
            }
            for f in findings
        ],
    }
    Path(out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Python reference dump written to {out} ({len(findings)} findings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
