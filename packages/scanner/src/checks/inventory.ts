import type { Check, RawFinding } from "./types.js";
import { serverLabel } from "./types.js";

/**
 * A2 INV-01: the pinned-version question is answered from the LAUNCH COMMAND
 * for client configs (npx/uvx/docker-style refs), from the native `version`
 * field when present, and honestly "cannot derive" for local binaries.
 */
const LAUNCHERS = new Set(["npx", "pnpm", "bunx", "uvx", "pipx", "docker"]);

/** npm-style ref is pinned when the last @ (after any /) is a real version. */
function npmPinned(ref: string): boolean {
  const at = ref.lastIndexOf("@");
  if (at <= ref.lastIndexOf("/")) return false; // bare or @org/pkg — no version
  const v = ref.slice(at + 1).toLowerCase();
  return v.length > 0 && v !== "latest";
}

/** py-style ref is pinned on an ==, @, or >=/< spec. */
function pyPinned(ref: string): boolean {
  return /[=@<>]/.test(ref);
}

/** docker ref is pinned with a :tag (not :latest) or an @digest. */
function dockerPinned(ref: string): boolean {
  if (ref.lastIndexOf("@") > 0) return true; // digest pin
  const colon = ref.indexOf(":");
  if (colon <= ref.lastIndexOf("/")) return false; // no tag
  return ref.slice(colon + 1).toLowerCase() !== "latest";
}

function isFlag(arg: string): boolean {
  return arg.startsWith("-");
}

/** The FIRST non-flag arg of npx/uvx-style launches is the package spec;
 * everything after it is an argument to the launched server, not a ref. */
function scanLauncherArgs(args: string[], py: boolean): { index: number; ref: string } | null {
  for (let j = 0; j < args.length; j++) {
    const ref = args[j];
    if (ref === undefined || isFlag(ref)) continue;
    const pinned = py ? pyPinned(ref) : npmPinned(ref);
    return pinned ? null : { index: j, ref };
  }
  return null;
}

/** First non-flag arg after `docker run …` = the image ref. */
function dockerImage(args: string[]): { index: number; ref: string } | null {
  let seenRun = false;
  for (let j = 0; j < args.length; j++) {
    const a = args[j];
    if (a === undefined) return null;
    if (!seenRun) {
      if (a === "run") seenRun = true;
      continue;
    }
    if (isFlag(a)) {
      // skip -v / --volume value pairs where the next arg is the value
      if ((a === "-v" || a === "--volume" || a === "--mount") && j + 1 < args.length) j++;
      continue;
    }
    return { index: j, ref: a };
  }
  return null;
}

export const inventoryCheck: Check = {
  id: "INV-01",
  description: "Each MCP server runs a pinned, auditable version",
  requires: ["servers"],
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      if (typeof server.version === "string" && server.version.length > 0) return; // native pin
      const command = typeof server.command === "string" ? server.command : "";
      const launcher = command.split("/").pop()?.toLowerCase() ?? "";
      const args = Array.isArray(server.args)
        ? (server.args as unknown[]).filter((a): a is string => typeof a === "string")
        : [];
      if (LAUNCHERS.has(launcher) && args.length > 0) {
        const hit =
          launcher === "docker"
            ? (() => {
                const img = dockerImage(args);
                return img && !dockerPinned(img.ref) ? img : null;
              })()
            : scanLauncherArgs(args, launcher === "uvx" || launcher === "pipx");
        if (hit) {
          out.push({
            status: "fail",
            pointer: `servers[${i}].args[${hit.index}]`,
            detail: `${serverLabel(i, server.name)} launches \`${hit.ref}\` without a version pin; pin an exact version so the code can be audited against advisories`,
          });
        }
        return;
      }
      // Not a recognizable launcher: a local binary or script.
      out.push({
        status: "unassessable",
        pointer: `servers[${i}].command`,
        detail: `${serverLabel(i, server.name)} runs \`${command}\` — a pinned version cannot be derived from a local command; declare a native version or switch to a pinned registry launch`,
      });
    });
    return out;
  },
};
