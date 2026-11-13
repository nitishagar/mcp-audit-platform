import type { Check, RawFinding } from "./types.js";
import { serverLabel } from "./types.js";

/** Description fragments associated with tool-poisoning / prompt injection. */
export const POISON_PATTERNS: RegExp[] = [
  /ignore (all )?(previous|prior|earlier) instructions/i,
  /do not (tell|inform|show|reveal).*user/i,
  /~\/\.ssh/,
  /\/etc\/passwd/,
  /send .*to https?:\/\//i,
  /exfiltrat/i,
];

function paramCount(tool: { params?: unknown }): number {
  const p = tool.params;
  if (Array.isArray(p)) return p.length;
  if (p !== null && typeof p === "object") return Object.keys(p).length;
  return 0;
}

/** ARG-01: tools with excessive parameters (validation surface + token bloat). */
export const paramCountCheck: Check = {
  id: "ARG-01",
  description: "Tools declare at most 8 parameters",
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      const tools = Array.isArray(server.tools) ? server.tools : [];
      tools.forEach((tool, j) => {
        if (tool === null || typeof tool !== "object") return;
        const n = paramCount(tool);
        if (n > 8) {
          out.push({
            status: "fail",
            pointer: `servers[${i}].tools[${j}].params`,
            detail: `Tool "${String((tool as { name?: unknown }).name ?? j)}" on ${serverLabel(i, server.name)} declares ${n} parameters; shrink to ≤8 with server-side validation`,
          });
        }
      });
    });
    return out;
  },
};

/** ARG-02: tool descriptions containing poisoning/injection signals. */
export const descriptionPoisoningCheck: Check = {
  id: "ARG-02",
  description: "Tool descriptions contain no poisoning signals",
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      const tools = Array.isArray(server.tools) ? server.tools : [];
      tools.forEach((tool, j) => {
        if (tool === null || typeof tool !== "object") return;
        const desc = (tool as { description?: unknown }).description;
        if (typeof desc !== "string") return;
        const hit = POISON_PATTERNS.find((re) => {
          re.lastIndex = 0;
          return re.test(desc);
        });
        if (hit) {
          out.push({
            status: "fail",
            pointer: `servers[${i}].tools[${j}].description`,
            detail: `Tool "${String((tool as { name?: unknown }).name ?? j)}" on ${serverLabel(i, server.name)} matches poisoning pattern ${hit}; treat tool text as untrusted input`,
          });
        }
      });
    });
    return out;
  },
};
