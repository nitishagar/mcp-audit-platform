import type { Check, RawFinding } from "./types.js";
import { serverLabel } from "./types.js";

/**
 * A2 INV-01: the pinned-version question is answered from the LAUNCH COMMAND
 * for client configs, from the native `version` field when present, and
 * honestly "cannot derive" when the launch shape defeats decoding (red-team
 * round 1: a decode failure is coverage-unassessable, never a silent pass).
 */
const LAUNCHERS = new Set(["npx", "pnpm", "bunx", "uvx", "pipx", "docker"]);

/** Flags whose NEXT arg is a value (not the package/image). */
const LAUNCHER_VALUE_FLAGS = new Set(["-p", "--package", "--from", "--python", "--py"]);
const DOCKER_VALUE_FLAGS = new Set([
  "-p",
  "--publish",
  "-e",
  "--env",
  "--env-file",
  "--name",
  "-w",
  "--workdir",
  "-u",
  "--user",
  "--network",
  "--net",
  "-l",
  "--label",
  "-v",
  "--volume",
  "--mount",
  "-h",
  "--hostname",
  "--entrypoint",
]);

/**
 * Exact npm version pin: x.y.z(-prerelease)? — semver RANGES (^~>x), wildcards
 * (1.x, *), and dist-tags (latest/beta/next) float, so they are NOT pins
 * (red-team round 1: ranges/dist-tags were false pins).
 */
function npmPinned(ref: string): boolean {
  const at = ref.lastIndexOf("@");
  if (at <= ref.lastIndexOf("/")) return false; // bare or @org/pkg — no version
  return /^\d+\.\d+\.\d+(-[\w.]+)?$/.test(ref.slice(at + 1));
}

/** py-style ref is pinned on an == spec (>, <, @ are range-ish but bound). */
function pyPinned(ref: string): boolean {
  return /==/.test(ref);
}

/** docker pin = digest, or an exact numeric tag; movable tags are not pins. */
function dockerPinned(ref: string): boolean {
  const at = ref.lastIndexOf("@");
  if (at > 0) return true; // digest pin
  const slash = ref.lastIndexOf("/");
  const colon = ref.lastIndexOf(":");
  if (colon <= slash) return false; // no tag
  return /^\d+(\.\d+)*$/.test(ref.slice(colon + 1));
}

function isFlag(arg: string): boolean {
  return arg.startsWith("-");
}

type ImgRef = { index: number; ref: string };
type RefScan =
  | { kind: "unpinned"; index: number; ref: string }
  | { kind: "pinned" }
  | { kind: "none" };

/**
 * The FIRST non-flag arg of npx/uvx-style launches is the package spec;
 * everything after it is an argument to the launched server. Also decodes
 * -p/--package/--from (space and equals forms). Distinct kinds so the caller
 * never confuses "pinned" with "no decodable ref" (red-team round 1).
 */
function scanLauncherArgs(args: string[], py: boolean): RefScan {
  for (let j = 0; j < args.length; j++) {
    const a = args[j];
    if (a === undefined) continue;
    const eq = /^(--package|--from)=([\s\S]+)$/.exec(a);
    if (eq) {
      const ref = eq[2] ?? "";
      const pinned = py ? pyPinned(ref) : npmPinned(ref);
      return pinned ? { kind: "pinned" } : { kind: "unpinned", index: j, ref };
    }
    if (LAUNCHER_VALUE_FLAGS.has(a)) {
      const next = args[j + 1];
      if (next !== undefined && !isFlag(next)) {
        const pinned = py ? pyPinned(next) : npmPinned(next);
        return pinned ? { kind: "pinned" } : { kind: "unpinned", index: j + 1, ref: next };
      }
      continue;
    }
    if (isFlag(a)) continue;
    const pinned = py ? pyPinned(a) : npmPinned(a);
    return pinned ? { kind: "pinned" } : { kind: "unpinned", index: j, ref: a };
  }
  return { kind: "none" };
}

/** First non-flag arg after `docker run …` = the image ref (or null). */
function dockerImage(args: string[]): ImgRef | null {
  let seenRun = false;
  for (let j = 0; j < args.length; j++) {
    const a = args[j];
    if (a === undefined) return null;
    if (!seenRun) {
      if (a === "run") seenRun = true;
      continue;
    }
    const eq = /^(--\w[\w-]*)=/.exec(a);
    const eqFlag = eq?.[1];
    if (eqFlag !== undefined && DOCKER_VALUE_FLAGS.has(eqFlag)) continue; // equals-form value flag
    if (isFlag(a)) {
      if (DOCKER_VALUE_FLAGS.has(a) && j + 1 < args.length) j++;
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
      if (!LAUNCHERS.has(launcher)) {
        // Not a recognizable launcher: a local binary or script.
        out.push({
          status: "unassessable",
          pointer: `servers[${i}].command`,
          detail: `${serverLabel(i, server.name)} runs \`${command}\` — a pinned version cannot be derived from a local command; declare a native version or switch to a pinned registry launch`,
        });
        return;
      }
      if (launcher === "docker") {
        const img = dockerImage(args);
        if (!img) {
          out.push({
            status: "unassessable",
            scope: "coverage",
            pointer: `servers[${i}].args`,
            detail: `${serverLabel(i, server.name)} docker launch has no decodable image ref (docker compose or flag-only form); review the image pin manually`,
          });
          return;
        }
        if (!dockerPinned(img.ref)) {
          out.push({
            status: "fail",
            pointer: `servers[${i}].args[${img.index}]`,
            detail: `${serverLabel(i, server.name)} launches image \`${img.ref}\` without a digest or exact-version tag; floating tags change under you`,
          });
        }
        return;
      }
      const scan = scanLauncherArgs(
        launcher === "pipx" ? args.filter((a, k) => !(k === 0 && a === "run")) : args,
        launcher === "uvx" || launcher === "pipx",
      );
      if (scan.kind === "none") {
        out.push({
          status: "unassessable",
          scope: "coverage",
          pointer: `servers[${i}].args`,
          detail: `${serverLabel(i, server.name)} \`${launcher}\` launch carries no decodable package ref; review the pin manually`,
        });
        return;
      }
      if (scan.kind === "unpinned") {
        out.push({
          status: "fail",
          pointer: `servers[${i}].args[${scan.index}]`,
          detail: `${serverLabel(i, server.name)} launches \`${scan.ref}\` without an exact version pin; pin an exact version so the code can be audited against advisories`,
        });
      }
    });
    return out;
  },
};
