#!/usr/bin/env node
/**
 * M-2 T2 step 4: diff a fresh capture against the committed golden fixture.
 * Compares facts (tool names, annotations, schema STRUCTURE — keys, required,
 * additionalProperties) and ignores description TEXT (the golden withholds
 * verbatim upstream text by license decision). A non-empty diff fails with a
 * readable report: either the vendor changed the server under a pinned
 * version, or the golden is stale — both are supply-chain signals.
 */
import { readFileSync } from "node:fs";

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}

const capture = JSON.parse(readFileSync(arg("capture"), "utf8"));
const golden = JSON.parse(readFileSync(arg("golden"), "utf8"));

/** Structural projection: names, annotations, schema shape — no text. */
function project(tools) {
  return tools.map((t) => ({
    name: t.name,
    annotations: t.annotations ?? null,
    schemaShape: shape(t.inputSchema ?? null),
  }));
}
function shape(node) {
  if (node === null || typeof node !== "object") return null;
  const out = {};
  for (const [k, v] of Object.entries(node)) {
    if (k === "description" || k === "$schema") continue;
    out[k] = v === null || typeof v !== "object" ? v : shape(v);
  }
  return out;
}

const a = project(capture.tools ?? []);
const b = project(golden.tools ?? []);
const diffs = [];
const namesA = new Map(a.map((t) => [t.name, t]));
const namesB = new Map(b.map((t) => [t.name, t]));
for (const [name, ta] of namesA) {
  const tb = namesB.get(name);
  if (!tb) diffs.push(`? tool "${name}" in capture but not in golden (new?)`);
  else if (JSON.stringify(ta) !== JSON.stringify(tb))
    diffs.push(`~ tool "${name}" annotations/schema drifted`);
}
for (const [name] of namesB)
  if (!namesA.has(name)) diffs.push(`- tool "${name}" gone from the live capture`);
if (a.length !== b.length)
  diffs.push(`tool count changed: capture ${a.length} vs golden ${b.length}`);

if (diffs.length > 0) {
  console.error(`MULE DRIFT DETECTED (${diffs.length}):`);
  for (const d of diffs) console.error(`  ${d}`);
  console.error("the golden fixture is stale OR the pinned server changed under us");
  process.exit(1);
}
console.log(`no drift: ${a.length} tools match the golden facts`);
