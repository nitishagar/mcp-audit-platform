import type { Check, RawFinding } from "./types.js";
import { serverLabel, unassessableToolEntry } from "./types.js";

/** Named description signals associated with tool-poisoning / prompt injection. */
export const POISON_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "instruction-override", re: /ignore (all )?(previous|prior|earlier) instructions/i },
  { name: "user-deception", re: /do not (tell|inform|show|reveal)[\s\S]{0,200}user/i },
  { name: "credential-path", re: /~\/\.ssh/ },
  { name: "system-file-access", re: /\/etc\/passwd/ },
  { name: "external-exfiltration", re: /send [\s\S]{0,200}to https?:\/\//i },
  { name: "exfiltration-keyword", re: /exfiltrat/i },
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
  requires: ["tools"],
  description: "Tools declare at most 8 parameters",
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      const tools = Array.isArray(server.tools) ? server.tools : [];
      tools.forEach((tool, j) => {
        if (tool === null || typeof tool !== "object") {
          out.push(
            unassessableToolEntry(i, j, server.name, "tool entry is not an object; cannot assess"),
          );
          return;
        }
        if (typeof (tool as { name?: unknown }).name !== "string") {
          out.push(
            unassessableToolEntry(i, j, server.name, "tool entry has no name; cannot assess"),
          );
          return;
        }
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
  requires: ["tools"],
  description: "Tool descriptions contain no poisoning signals",
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      const tools = Array.isArray(server.tools) ? server.tools : [];
      tools.forEach((tool, j) => {
        if (tool === null || typeof tool !== "object") {
          out.push(
            unassessableToolEntry(i, j, server.name, "tool entry is not an object; cannot assess"),
          );
          return;
        }
        if (typeof (tool as { name?: unknown }).name !== "string") {
          out.push(
            unassessableToolEntry(i, j, server.name, "tool entry has no name; cannot assess"),
          );
          return;
        }
        const desc = (tool as { description?: unknown }).description;
        if (typeof desc !== "string") return;
        const hit = POISON_PATTERNS.find((p) => {
          p.re.lastIndex = 0;
          return p.re.test(desc);
        });
        if (hit) {
          out.push({
            status: "fail",
            pointer: `servers[${i}].tools[${j}].description`,
            detail: `Tool "${String((tool as { name?: unknown }).name ?? j)}" on ${serverLabel(i, server.name)} matches poisoning signal "${hit.name}"; treat tool text as untrusted input`,
          });
        }
      });
    });
    return out;
  },
};
