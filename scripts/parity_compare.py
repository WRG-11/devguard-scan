#!/usr/bin/env python3
"""Compare devguard-in-browser (JS) vs wrg-devguard (Python) scan-secrets reports.

Usage: parity_compare.py <js_report.json> <py_report.json>

Normalizes findings (posix paths, sorted by file/line/column/rule_id) and
ignores envelope fields that legitimately differ (scan_root). Exit 0 if the
finding sets + severity counts match, else 1.
"""
from __future__ import annotations

import json
import sys


def norm(path: str):
    data = json.load(open(path, encoding="utf-8"))
    findings = sorted(
        (
            f["file"].replace("\\", "/"),
            f["line"],
            f["column"],
            f["rule_id"],
            f["severity"],
            f["snippet"],
        )
        for f in data["findings"]
    )
    return data["summary"], findings


def main(argv: list[str]) -> int:
    js_path, py_path = argv[1], argv[2]
    js, jf = norm(js_path)
    ps, pf = norm(py_path)
    print(f"JS summary : {js}")
    print(f"PY summary : {ps}")
    print(f"JS findings: {len(jf)}   PY findings: {len(pf)}")
    identical = jf == pf
    counts_match = (
        js.get("total_findings") == ps.get("total_findings")
        and js.get("error") == ps.get("error")
        and js.get("warning") == ps.get("warning")
    )
    print(f"FINDINGS IDENTICAL : {identical}")
    print(f"SUMMARY COUNTS MATCH: {counts_match}")
    if not identical:
        print("--- JS only ---")
        for x in (x for x in jf if x not in pf):
            print("  ", x)
        print("--- PY only ---")
        for x in (x for x in pf if x not in jf):
            print("  ", x)
        return 1
    for x in jf:
        print("  MATCH", x)
    return 0 if (identical and counts_match) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
