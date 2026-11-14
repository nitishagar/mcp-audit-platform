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
        const name = String((tool as { name?: unknown }).name);
        const surfaces: { pointer: string; text: string }[] = [];
        if (typeof desc === "string") {
          surfaces.push({ pointer: `servers[${i}].tools[${j}].description`, text: desc });
        }
        // A3a: poisoning hides in NESTED inputSchema property descriptions too.
        collectDescriptions(
          (tool as { inputSchema?: unknown }).inputSchema,
          `servers[${i}].tools[${j}].inputSchema`,
          surfaces,
        );
        for (const s of surfaces) {
          const hit = POISON_PATTERNS.find((p) => {
            p.re.lastIndex = 0;
            return p.re.test(s.text);
          });
          if (hit) {
            out.push({
              status: "fail",
              pointer: s.pointer,
              detail: `Tool "${name}" on ${serverLabel(i, server.name)} matches poisoning signal "${hit.name}"; treat tool text as untrusted input`,
            });
          }
        }
      });
    });
    return out;
  },
};

/** Recursively collect every `description` string under a JSON Schema. */
function collectDescriptions(
  node: unknown,
  base: string,
  out: { pointer: string; text: string }[],
): void {
  if (node === null || typeof node !== "object") return;
  const obj = node as Record<string, unknown>;
  if (typeof obj["description"] === "string") {
    out.push({ pointer: `${base}.description`, text: obj["description"] as string });
  }
  for (const [k, v] of Object.entries(obj)) {
    if (k === "description") continue;
    collectDescriptions(v, `${base}.${k}`, out);
  }
}

/**
 * A3a ARG-03 (new): tool schemas that accept arbitrary input — inputSchema
 * missing, additionalProperties not false, or path/command/url-like string
 * params with no pattern/maxLength/enum. LOW severity and AGGREGATED to one
 * finding per server (plan §9.2 noise rule): most real servers confine
 * server-side, so per-tool rows would be noise.
 */
const PATH_PARAM_RE = /path|file|dir|cmd|command|url|uri/i;

export const inputSchemaCheck: Check = {
  id: "ARG-03",
  requires: ["tools"],
  description: "Tool input schemas constrain their inputs",
  run: (config) => {
    const out: RawFinding[] = [];
    // Legacy native tools carry `params` name→type maps that cannot express
    // JSON-Schema constraints: ARG-03's subject does not apply to a server
    // whose tools have no inputSchema at all (not_applicable, never pass).
    const hasAnySchema = config.servers.some((server) => {
      const tools =
        server !== null && typeof server === "object" && Array.isArray(server.tools)
          ? server.tools
          : [];
      return tools.some(
        (tool) =>
          tool !== null &&
          typeof tool === "object" &&
          (tool as { inputSchema?: unknown }).inputSchema !== undefined,
      );
    });
    if (!hasAnySchema) return out;
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      const tools = Array.isArray(server.tools) ? server.tools : [];
      const looseTools: string[] = [];
      let seesPathParams = false;
      for (const tool of tools) {
        if (tool === null || typeof tool !== "object") continue;
        const t = tool as { name?: unknown; inputSchema?: unknown; params?: unknown };
        if (typeof t.name !== "string") continue;
        const schema =
          t.inputSchema !== null && typeof t.inputSchema === "object"
            ? (t.inputSchema as Record<string, unknown>)
            : null;
        if (!schema) {
          looseTools.push(t.name);
          continue;
        }
        if (schema["additionalProperties"] !== false) looseTools.push(t.name);
        const props = schema["properties"];
        if (props !== null && typeof props === "object") {
          for (const [pName, spec] of Object.entries(props as Record<string, unknown>)) {
            if (spec === null || typeof spec !== "object") continue;
            const s = spec as Record<string, unknown>;
            if (
              s["type"] === "string" &&
              PATH_PARAM_RE.test(pName) &&
              s["pattern"] === undefined &&
              s["maxLength"] === undefined &&
              s["enum"] === undefined
            ) {
              looseTools.push(t.name);
              if (/path|dir/i.test(pName)) seesPathParams = true;
              break; // one hit per tool is enough for the aggregate
            }
          }
        }
      }
      if (looseTools.length > 0) {
        const unique = [...new Set(looseTools)];
        const confinement = seesPathParams
          ? " Many filesystem servers confine paths server-side — verify the allowed-directory args (PRIV-03) rather than reading this as a definite gap."
          : "";
        out.push({
          status: "fail",
          pointer: `servers[${i}].tools`,
          detail: `${serverLabel(i, server.name)} tool schemas accept unconstrained input for: ${unique.join(", ")}${confinement}`,
        });
      }
    });
    return out;
  },
};
