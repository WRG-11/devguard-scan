# SYNTHETIC fixture (Pattern 34) — fake values only, no real credentials.
#
# Column reporting across the UTF-16 / code-point boundary. Each line below
# carries non-ASCII text BEFORE a fake key, so the reported column differs
# between the two engines unless the port counts code points the way Python
# does. The astral characters are the ones that matter: 'ş' is one UTF-16 unit
# and one code point, an emoji is two units and one code point.
#
# Kept in the corpus so the parity compare -- which diffs line AND column --
# fails if the counting ever regresses.
NOTE_BMP = "şğüöçİ sk-NOTREALbmpcolumncase1234567890AB"
NOTE_ASTRAL = "🔐🔐🔐 sk-NOTREALastralcolumncase1234567890"
NOTE_MIXED = "ş🔐ğ🔐 AKIAIOSFODNN7EXAMPLE"
