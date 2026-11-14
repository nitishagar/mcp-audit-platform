import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Check, RawFinding } from "./types.js";
import { serverLabel } from "./types.js";

/**
 * A5 SUP-01: match pinned launch refs against the BUNDLED advisory snapshot
 * (src/data/advisories.json, built at release time by
 * scripts/build-advisories.mjs from OSV.dev). Runtime stays network-free
 * (I2); the snapshot carries provenance and the CC-BY-4.0 attribution.
 */
interface AdvisoryRange {
  package: string;
  introduced: string;
  fixed: string | null;
  lastAffected: string | null;
}
interface Advisory {
  id: string;
  aliases: string[];
  summary: string;
  ranges: AdvisoryRange[];
  source: string;
}
interface Snapshot {
  fetched: string;
  advisories: Advisory[];
}

const here = dirname(fileURLToPath(import.meta.url));
const SNAPSHOT: Snapshot = JSON.parse(
  readFileSync(resolve(here, "../data/advisories.json"), "utf8"),
) as Snapshot;

/** Minimal semver-ish compare for dotted numeric versions (snapshot ranges). */
function cmp(a: string, b: string): number {
  const pa = a.split(/[.-]/).map((x) => (Number.isNaN(Number(x)) ? 0 : Number(x)));
  const pb = b.split(/[.-]/).map((x) => (Number.isNaN(Number(x)) ? 0 : Number(x)));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

function withinRange(version: string, range: AdvisoryRange): boolean {
  if (cmp(version, range.introduced) < 0) return false;
  if (range.fixed !== null) return cmp(version, range.fixed) < 0;
  if (range.lastAffected !== null) return cmp(version, range.lastAffected) <= 0;
  return true; // introduced, never fixed: affected forever
}

const LAUNCHERS = new Set(["npx", "pnpm", "bunx", "uvx", "pipx"]);

/**
 * Extract {package, version} pairs from a launch command. Same decoding
 * rules as INV-01 (first positional = package; -p/--package/--from are
 * repeatable; uvx/pipx use ==). Docker tags are not npm versions — skipped.
 */
function launchRefs(args: string[], py: boolean): { name: string; version: string | null }[] {
  const refs: { name: string; version: string | null }[] = [];
  const splitRef = (ref: string): { name: string; version: string | null } => {
    const at = ref.lastIndexOf("@");
    if (at > ref.lastIndexOf("/") && at > 0) {
      const v = ref.slice(at + 1);
      if (/^\d+(\.\d+)*$/.test(v)) return { name: ref.slice(0, at), version: v };
    }
    if (py && ref.includes("==")) {
      const idx = ref.indexOf("==");
      return { name: ref.slice(0, idx), version: ref.slice(idx + 2) || null };
    }
    return { name: ref, version: null };
  };
  for (let j = 0; j < args.length; j++) {
    const a = args[j];
    if (a === undefined) continue;
    const eq = /^(--package|--from)=([\s\S]+)$/.exec(a);
    if (eq) {
      refs.push(splitRef(eq[2] ?? ""));
      continue;
    }
    if (a === "-p" || a === "--package" || a === "--from") {
      const next = args[j + 1];
      if (next !== undefined && !next.startsWith("-")) {
        refs.push(splitRef(next));
        j++;
        continue;
      }
      continue;
    }
    if (a.startsWith("-")) continue;
    refs.push(splitRef(a));
    break; // first positional is the package; the rest are its arguments
  }
  return refs;
}

export const supplyChainCheck: Check = {
  id: "SUP-01",
  description: "Launched package versions carry no bundled advisories",
  requires: ["servers"],
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      const command = typeof server.command === "string" ? server.command : "";
      const launcher = command.split("/").pop()?.toLowerCase() ?? "";
      if (!LAUNCHERS.has(launcher)) return; // native version/docker are not npm refs
      const args = Array.isArray(server.args)
        ? (server.args as unknown[]).filter((a): a is string => typeof a === "string")
        : [];
      const py = launcher === "uvx" || launcher === "pipx";
      for (const { name, version } of launchRefs(args, py)) {
        const hits = SNAPSHOT.advisories.filter((a) =>
          a.ranges.some((r) => r.package === name && version !== null && withinRange(version, r)),
        );
        if (hits.length > 0 && version !== null) {
          const cves = [...new Set(hits.flatMap((h) => h.aliases))];
          out.push({
            status: "fail",
            pointer: `servers[${i}]`,
            detail: `${serverLabel(i, server.name)} launches ${name}@${version}, covered by bundled advisories (${hits.map((h) => h.id).join(", ")}); upgrade to a fixed version`,
            refs: [...cves, ...hits.map((h) => h.id)],
          });
        } else if (
          version === null &&
          SNAPSHOT.advisories.some((a) => a.ranges.some((r) => r.package === name))
        ) {
          out.push({
            status: "unassessable",
            pointer: `servers[${i}]`,
            detail: `${serverLabel(i, server.name)} launches ${name} without a pinned version; the bundled advisory snapshot cannot match a moving version`,
          });
        }
      }
    });
    return out;
  },
};
