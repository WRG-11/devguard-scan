#!/usr/bin/env python3
"""Oracle side of the glob differential harness.

scan.js's matchAny is documented as a verbatim port of the canonical Python
tool's common.py:

    fnmatch(path, pattern)
    or PurePosixPath(path).match(pattern)
    or (pattern.startswith("**/") and PurePosixPath(path).match(pattern[3:]))

so Python IS the contract. This emits {pattern, path, expected} triples that
scripts/glob_parity_check.mjs replays against the JS engine.

The scan-level parity harness (js_reference_dump / py_reference_dump /
parity_compare) only exercises whichever globs the DEFAULT include/exclude lists
happen to contain. This one sweeps the matcher itself, which is where two
divergences were hiding: '[^abc]' (in fnmatch '^' is a literal member, only '!'
negates) and '[]]' (a leading ']' is a member, not the terminator).

fnmatchcase, not fnmatch: fnmatch applies os.path.normcase first, so it is
case-insensitive on Windows and case-sensitive elsewhere. Using it here would
make the harness report the same JS code as correct or broken depending on which
OS ran it. The case-folding difference between the two implementations is real
and tracked separately; everything below is the platform-independent core.

Usage: python scripts/glob_corpus.py <out.json>
"""
from __future__ import annotations

import fnmatch
import json
import sys
from pathlib import PurePosixPath

PATTERNS = [
    # the tool's own real defaults
    "*.py", "*.js", "*.mjs", "*.ts", "*.json", "*.yml", "*.yaml", "*.toml",
    "*.env", ".env", ".env.*", "*.txt", "*.md", "*.rst", "*.cfg", "*.ini",
    "**/*.py", "**/node_modules/**", "**/.git/**", "node_modules", ".git",
    "*.lock", "*.min.js", "**/dist/**", "**/build/**",
    # structural edge cases
    "src/*.py", "src/**/*.py", "a/b/c.txt", "*", "**", "?", "??.py", "a?c",
    # character classes, both negation spellings and the ']'-first form
    "[abc].py", "[!abc].py", "[^abc].py", "[a-z]*.py", "file[0-9].txt",
    "[]].py", "[a-]x", "[[]y", "[!]a]z", "[abc", "[]",
    # regex metacharacters that MUST stay literal
    "a.b", "a+b", "a(b)c", "a|b", "a{2}", "a$b", "a^b", "back" + chr(92) + "slash",
    "dot.dot.py", "plus+.py", "paren(1).py",
    # multi-star shapes -- the ReDoS family the linear matcher exists for
    "*a*b*", "*a*a*a*b", "**/*a*/*b*", "*.*.*",
]

PATHS = [
    "x.py", "x.js", ".env", ".env.local", "a.b", "a+b", "a(b)c", "a|b",
    "a{2}", "a$b", "a^b", "back" + chr(92) + "slash", "abc", "a", "ab",
    "abc.py", "b.py", "^.py", "].py", "-x", "[y", "[abc", "[]",
    "file7.txt", "file77.txt", "aXc", "ac", "az", "]z",
    "src/x.py", "src/deep/x.py", "src/a/b/c/x.py", "a/b/c.txt", "c.txt",
    "node_modules/pkg/index.js", "x/node_modules/pkg/i.js", ".git/config",
    "dist/app.min.js", "build/out.js", "a/b/dist/x.js",
    "aaab", "aaaa", "dot.dot.py", "plus+.py", "paren(1).py",
    "", "x", "x/", "UPPER.PY", "sp ace.py",
]


def expected(path: str, pattern: str) -> bool:
    if fnmatch.fnmatchcase(path, pattern):
        return True
    try:
        if PurePosixPath(path).match(pattern):
            return True
    except ValueError:
        pass
    if pattern.startswith("**/"):
        try:
            if PurePosixPath(path).match(pattern[3:]):
                return True
        except ValueError:
            pass
    return False


def main() -> int:
    cases = [
        {"pattern": pat, "path": p, "expected": expected(p, pat)}
        for pat in PATTERNS
        for p in PATHS
    ]
    out = sys.argv[1] if len(sys.argv) > 1 else "glob_corpus.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(cases, fh, ensure_ascii=False)
    hits = sum(1 for c in cases if c["expected"])
    print(f"glob corpus: {len(cases)} cases "
          f"({len(PATTERNS)} patterns x {len(PATHS)} paths), "
          f"{hits} match / {len(cases) - hits} no-match -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
