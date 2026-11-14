import { VALUE_PATTERNS, isDenylistedKey } from "../redact.js";
import type { Check, RawFinding } from "./types.js";
import { serverLabel } from "./types.js";

/** Values that are placeholders, not real secrets. */
function isPlaceholder(value: string): boolean {
  const v = value.trim();
  return v === "" || v === "CHANGE_ME" || /^\$\{[^}]*\}$/.test(v) || v === "example";
}

/**
 * Literal default inside `${VAR:-default}` (A1): the one place a placeholder
 * may hide a real secret (plan §4-A1). Returns null when absent/empty.
 */
function placeholderDefault(value: string): string | null {
  const m = /^\$\{[^:}]+:-(.*)\}$/.exec(value.trim());
  const g = m?.[1];
  return g && g.length > 0 ? g : null;
}

function hasSecretShape(value: string): boolean {
  return VALUE_PATTERNS.some(({ re }) => {
    re.lastIndex = 0;
    return re.test(value);
  });
}

interface StringLeaf {
  pointer: string;
  key: string;
  value: string;
}

/** Walk a server object collecting string leaves with pointer paths. */
function stringLeaves(serverIndex: number, node: unknown, base: string, out: StringLeaf[]): void {
  if (typeof node === "string") {
    const key = base.split(".").pop() ?? "";
    out.push({ pointer: base, key, value: node });
    return;
  }
  if (Array.isArray(node)) {
    node.forEach((v, j) => {
      stringLeaves(serverIndex, v, `${base}[${j}]`, out);
    });
    return;
  }
  if (node !== null && typeof node === "object") {
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      stringLeaves(serverIndex, v, `${base}.${k}`, out);
    }
  }
}

/** SEC-01: real secret values stored under denylisted config keys. */
export const envSecretsCheck: Check = {
  id: "SEC-01",
  requires: ["servers"],
  description: "No live secrets stored under credential config keys",
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      const leaves: StringLeaf[] = [];
      stringLeaves(i, server, `servers[${i}]`, leaves);
      for (const leaf of leaves) {
        const def = placeholderDefault(leaf.value);
        const liveValue = isPlaceholder(leaf.value) ? def : leaf.value;
        if (
          leaf.value.length >= 4 &&
          isDenylistedKey(leaf.key) &&
          liveValue !== null &&
          !isPlaceholder(liveValue)
        ) {
          // Evidence is the LOCATION only; the value never leaves this function.
          // The detail names the key, not the pointer — the pointer field (and
          // the summary renderer) carries the original-file location (A1).
          out.push({
            status: "fail",
            pointer: leaf.pointer,
            detail: `${serverLabel(i, (server as { name?: unknown }).name)} stores a live secret under key "${leaf.key}" (value withheld [REDACTED:${leaf.key}]); move it to a vault or environment reference`,
          });
        }
      }
    });
    return out;
  },
};

/** SEC-02: secret-shaped values anywhere in config, regardless of key name. */
export const valuePatternCheck: Check = {
  id: "SEC-02",
  requires: ["servers"],
  description: "No secret-shaped values anywhere in config",
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      const leaves: StringLeaf[] = [];
      stringLeaves(i, server, `servers[${i}]`, leaves);
      for (const leaf of leaves) {
        // Skip denylisted keys (SEC-01 owns those) to avoid double-reporting.
        if (isDenylistedKey(leaf.key)) continue;
        const def = placeholderDefault(leaf.value);
        const shapes = [leaf.value, def ?? ""].filter((v) => v.length >= 8);
        if (shapes.some((v) => hasSecretShape(v))) {
          out.push({
            status: "fail",
            pointer: leaf.pointer,
            detail: `${serverLabel(i, (server as { name?: unknown }).name)} has a secret-shaped value under key "${leaf.key}" (value withheld [REDACTED:pattern]); rotate and vault it`,
          });
        }
      }
    });
    return out;
  },
};
