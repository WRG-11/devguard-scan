// Canonical digest of a contract document, shared by the checker and its
// self-test so both agree on what "the same document" means.
//
// Must match the Python exporter byte-for-byte:
//   json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
// JSON.stringify already emits those separators and leaves non-ASCII
// unescaped, so only key order has to be forced. Get this wrong and every run
// reports a hand-edit that never happened -- a check that cries wolf gets
// switched off, which is worse than not having it.
import { createHash } from "node:crypto";

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

// `core` is the contract WITHOUT its own digest field.
export function contractDigest(core) {
  return createHash("sha256").update(canonicalJson(core)).digest("hex");
}
