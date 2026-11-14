#!/usr/bin/env node
/**
 * A5: build the offline advisory snapshot from OSV.dev (build-time only —
 * the scanner runtime stays network-free, I2). Curated watch-list of MCP
 * server packages; each query is package-only (all advisories for the
 * package, per google/osv.dev Discussion #1852), then we keep SEMVER-range
 * records for npm. Data license: GitHub Advisory Database records are
 * CC-BY-4.0 — attribution lives in src/data/advisories.json.
 *
 * Usage: node scripts/build-advisories.mjs
 */
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const PACKAGES = [
  "@modelcontextprotocol/server-filesystem",
  "@modelcontextprotocol/inspector",
  "mcp-remote",
];

const here = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(here, "../packages/scanner/src/data/advisories.json");

async function queryBatch(packages) {
  const res = await fetch("https://api.osv.dev/v1/querybatch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      queries: packages.map((name) => ({ package: { name, ecosystem: "npm" } })),
    }),
  });
  if (!res.ok) throw new Error(`OSV querybatch ${res.status}`);
  return res.json();
}

async function vuln(id) {
  const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
  if (!res.ok) throw new Error(`OSV vuln ${id} ${res.status}`);
  return res.json();
}

const batch = await queryBatch(PACKAGES);
const ids = new Set();
for (const r of batch.results ?? []) {
  for (const v of r.vulns ?? []) ids.add(v.id);
}
const advisories = [];
for (const id of [...ids].sort()) {
  const v = await vuln(id);
  const affected = (v.affected ?? [])
    .filter((a) => a.package?.ecosystem === "npm")
    .flatMap((a) =>
      (a.ranges ?? [])
        .filter((rg) => rg.type === "SEMVER")
        .map((rg) => ({
          package: a.package.name,
          introduced: (rg.events.find((e) => "introduced" in e) ?? {}).introduced ?? "0",
          fixed: (rg.events.find((e) => "fixed" in e) ?? {}).fixed ?? null,
          lastAffected: (rg.events.find((e) => "last_affected" in e) ?? {}).last_affected ?? null,
        })),
    );
  if (affected.length === 0) continue;
  advisories.push({
    id: v.id,
    aliases: v.aliases ?? [],
    summary: v.summary ?? "",
    cwes: v.database_specific?.cwe_ids ?? [],
    severity: v.database_specific?.severity ?? "",
    cvss: (v.severity ?? []).map((s) => ({ type: s.type, score: s.score })),
    ranges: affected,
    source: v.database_specific?.source ?? `https://api.osv.dev/v1/vulns/${v.id}`,
    published: v.published ?? null,
  });
}

const snapshot = {
  fetched: new Date().toISOString().slice(0, 10),
  via: "https://api.osv.dev/v1/querybatch (package-only queries, npm ecosystem)",
  watchList: PACKAGES,
  license:
    "Advisory data from the GitHub Advisory Database (via OSV.dev), CC-BY-4.0. " +
    "Attribution: github.com/github/advisory-database; per-record source links below.",
  advisories,
};
writeFileSync(OUT, `${JSON.stringify(snapshot, null, 2)}\n`);
console.log(`advisories: ${advisories.length} records -> ${OUT}`);
