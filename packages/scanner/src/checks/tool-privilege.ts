import type { Check, RawFinding } from "./types.js";
import { serverLabel, unassessableToolEntry } from "./types.js";

/** Tool-name fragments that imply destructive capability (fallback only). */
const DESTRUCTIVE = ["delete", "remove", "destroy", "exec", "shell", "write", "drop", "kill"];

function nameLooksDestructive(name: unknown): boolean {
  if (typeof name !== "string") return false;
  const lower = name.toLowerCase();
  return DESTRUCTIVE.some((d) => lower.includes(d));
}

/**
 * A2 PRIV-01 destructive decision. Vendor `annotations` win (MCP spec,
 * verified in R5 §6): destructiveHint defaults TRUE when the tool is not
 * read-only, and is meaningless when readOnlyHint is true. Name heuristics
 * apply only when the tool carries no annotations.
 */
function isDestructive(tool: { name?: unknown; annotations?: unknown }): boolean {
  const ann =
    tool.annotations !== null && typeof tool.annotations === "object"
      ? (tool.annotations as Record<string, unknown>)
      : null;
  if (ann) {
    const readOnly = ann["readOnlyHint"] === true;
    if (readOnly) return false;
    if (ann["destructiveHint"] === false) return false;
    return true; // not read-only and no explicit non-destructive hint
  }
  return nameLooksDestructive(tool.name);
}

/**
 * PRIV-01 (A2): destructive tools need a human approval gate. Whether the
 * CLIENT prompts for approval is a client-side policy a config cannot prove
 * — that part is an honest unassessable row, not an assumed "no gate".
 */
export const destructiveToolsCheck: Check = {
  id: "PRIV-01",
  description: "Destructive tools are gated and reviewed",
  requires: ["tools"],
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      const tools = Array.isArray(server.tools) ? server.tools : [];
      let destructive = 0;
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
        const t = tool as { name: string; annotations?: unknown; requireApproval?: unknown };
        if (isDestructive(t)) {
          destructive++;
          if (t.requireApproval !== true) {
            out.push({
              status: "fail",
              pointer: `servers[${i}].tools[${j}].requireApproval`,
              detail: `Tool "${t.name}" on ${serverLabel(i, server.name)} is destructive (vendor annotation or name signal) with no approval gate in this config`,
            });
          }
        }
      });
      if (destructive > 0) {
        out.push({
          status: "unassessable",
          scope: "coverage",
          pointer: `servers[${i}]`,
          detail: `Approval prompting is a client-side policy setting; confirm ${serverLabel(i, server.name)} destructive tools (${destructive}) actually prompt before each call`,
        });
      }
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

/**
 * A2 PRIV-03 (new): a filesystem-type launch granting the filesystem ROOT —
 * "/", "~", "$HOME", or a drive root — exposes everything on the volume.
 */
const BROAD_PATHS = new Set(["/", "~", "$HOME", "$HOME/", "C:\\", "C:/", "c:\\", "c:/"]);

function isBroadPath(arg: string): boolean {
  const a = arg.trim();
  return BROAD_PATHS.has(a) || a === "$HOME" || /^[a-zA-Z]:[/\\]$/.test(a);
}

export const filesystemBreadthCheck: Check = {
  id: "PRIV-03",
  description: "Filesystem servers are not granted a filesystem root",
  requires: ["servers"],
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      const args = Array.isArray(server.args)
        ? (server.args as unknown[]).filter((a): a is string => typeof a === "string")
        : [];
      args.forEach((arg, j) => {
        if (isBroadPath(arg)) {
          out.push({
            status: "fail",
            pointer: `servers[${i}].args[${j}]`,
            detail: `${serverLabel(i, server.name)} grants \`${arg}\` (a filesystem root); scope the allowed directories to the project`,
          });
        }
      });
    });
    return out;
  },
};

/**
 * A2 PRIV-04 (new): container-privilege signals in docker launches —
 * --privileged, host networking, host-root bind mounts, docker.sock access.
 */
function dockerFlags(args: string[]): { flagIndex: number; what: string }[] {
  const hits: { flagIndex: number; what: string }[] = [];
  for (let j = 0; j < args.length; j++) {
    const a = args[j];
    if (a === "--privileged")
      hits.push({ flagIndex: j, what: "--privileged (full host device/cgroup access)" });
    if (a === "--network" || a === "--net") {
      const next = args[j + 1] ?? "";
      if (next === "host")
        hits.push({ flagIndex: j, what: "--network host (container shares the host network)" });
    }
    if (a === "-v" || a === "--volume") {
      const mount = args[j + 1];
      if (
        typeof mount === "string" &&
        (mount.startsWith("/:") || mount.startsWith("/var/run/docker.sock"))
      ) {
        hits.push({
          flagIndex: j + 1,
          what: mount.startsWith("/var/run/docker.sock")
            ? `-v ${mount} (container controls the host Docker daemon)`
            : `-v ${mount} (host filesystem root mounted)`,
        });
      }
    }
  }
  return hits;
}

export const containerPrivilegeCheck: Check = {
  id: "PRIV-04",
  description: "Docker launches carry no container-privilege escapes",
  requires: ["servers"],
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      const command = typeof server.command === "string" ? server.command : "";
      if (command.split("/").pop()?.toLowerCase() !== "docker") return;
      const args = Array.isArray(server.args)
        ? (server.args as unknown[]).filter((a): a is string => typeof a === "string")
        : [];
      for (const hit of dockerFlags(args)) {
        out.push({
          status: "fail",
          pointer: `servers[${i}].args[${hit.flagIndex}]`,
          detail: `${serverLabel(i, server.name)} docker launch uses ${hit.what}; drop the escape or scope it to the minimum the server needs`,
        });
      }
    });
    return out;
  },
};
