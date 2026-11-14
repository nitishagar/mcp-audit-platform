import type { Check, RawFinding } from "./types.js";
import { serverLabel, unassessableToolEntry } from "./types.js";

/** Tool-name fragments that imply destructive capability. */
const DESTRUCTIVE = ["delete", "remove", "destroy", "exec", "shell", "write", "drop", "kill"];

function isDestructive(name: unknown): boolean {
  if (typeof name !== "string") return false;
  const lower = name.toLowerCase();
  return DESTRUCTIVE.some((d) => lower.includes(d));
}

/** PRIV-01: destructive tools require human approval gating. */
export const destructiveToolsCheck: Check = {
  id: "PRIV-01",
  description: "Destructive tools require approval gating",
  requires: ["tools"],
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
        if (
          isDestructive(tool.name) &&
          (tool as { requireApproval?: unknown }).requireApproval !== true
        ) {
          out.push({
            status: "fail",
            pointer: `servers[${i}].tools[${j}].requireApproval`,
            detail: `Tool "${String(tool.name)}" on ${serverLabel(i, server.name)} looks destructive but has no approval gate`,
          });
        }
      });
    });
    return out;
  },
};

/** PRIV-02: cap exposed tools per server (least privilege + context bloat). */
export const toolCountCheck: Check = {
  id: "PRIV-02",
  description: "Servers expose at most 20 tools (least privilege)",
  requires: ["tools"],
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      const tools = Array.isArray(server.tools) ? server.tools : [];
      if (tools.length > 20) {
        out.push({
          status: "fail",
          pointer: `servers[${i}].tools`,
          detail: `${serverLabel(i, server.name)} exposes ${tools.length} tools; scope to the task (≤20)`,
        });
      }
    });
    return out;
  },
};
