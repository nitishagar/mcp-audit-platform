#!/usr/bin/env node
// Ordered site build:
// 1. run the CURRENT scanner JSON emitter on the vulnerable fixture -> sample.json
// 2. render tiers + sample into the template -> dist/index.html
// 3. copy tokens.css, styles.css, app.js -> dist/
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const siteRoot = resolve(here, "..");
const scannerRoot = resolve(siteRoot, "../scanner");
const dist = resolve(siteRoot, "dist");

const cli = resolve(scannerRoot, "dist/cli.js");
const vulnerable = resolve(scannerRoot, "fixtures/vulnerable.json");

// Step 1: sample report from the live scanner (fails fast if scanner unbuilt).
// Exit 1 (findings present) is expected for the vulnerable fixture and still
// carries valid JSON on stdout; only exit 2 / spawn failure aborts the build.
let sampleJson;
try {
  sampleJson = execFileSync("node", [cli, "scan", vulnerable, "--format", "json"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
} catch (err) {
  if (err.status === 1 && typeof err.stdout === "string" && err.stdout.length > 0) {
    sampleJson = err.stdout;
  } else {
    console.error(
      `site build: scanner run failed (build @mcp-audit/scanner first): ${err.message}`,
    );
    process.exit(1);
  }
}
const sample = JSON.parse(sampleJson);
writeFileSync(resolve(siteRoot, "sample.json"), `${JSON.stringify(sample, null, 2)}\n`);

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const fails = sample.checks.flatMap((c) => c.findings.filter((f) => f.status === "fail"));
const rank = { critical: 0, high: 1, medium: 2, low: 3 };
fails.sort((a, b) => rank[a.severity] - rank[b.severity] || a.id.localeCompare(b.id));
const sampleRows = fails
  .map(
    (f) =>
      `<tr><td class="sev ${esc(f.severity)}">${esc(f.severity)}</td><td>${esc(f.checkId)}</td><td class="pointer">${esc(f.pointer)}</td><td>${esc(f.detail)}</td></tr>`,
  )
  .join("\n");
const sampleHtml = `<table class="sample-table">
<thead><tr><th>Severity</th><th>Check</th><th>Location</th><th>Finding</th></tr></thead>
<tbody>
${sampleRows}
</tbody>
</table>
<p class="muted">Framework: ${esc(sample.framework)} · ${fails.length} findings · exit 1</p>`;

// Step 2: tiers + sample into template.
const tiers = JSON.parse(readFileSync(resolve(siteRoot, "src/tiers.json"), "utf8"));
const tierCards = tiers
  .map(
    (t) => `<div class="tier">
<h3>${esc(t.name)}</h3>
<p class="price">${esc(t.price)}</p>
<p class="scope">${esc(t.scope)}</p>
<ul>
${t.deliverables.map((d) => `<li>${esc(d)}</li>`).join("\n")}
</ul>
<p class="turnaround">Turnaround: ${esc(t.turnaround)}</p>
</div>`,
  )
  .join("\n");
const template = readFileSync(resolve(siteRoot, "src/index.template.html"), "utf8");
if (!template.includes("<!--TIERS-->") || !template.includes("<!--SAMPLE-->")) {
  console.error("site build: template placeholders <!--TIERS--> / <!--SAMPLE--> missing");
  process.exit(1);
}
const html = template
  .replace("<!--TIERS-->", `<div class="tier-grid">\n${tierCards}\n</div>`)
  .replace("<!--SAMPLE-->", sampleHtml);

// Step 3: emit dist.
mkdirSync(dist, { recursive: true });
writeFileSync(resolve(dist, "index.html"), html);
for (const asset of ["tokens.css", "styles.css", "app.js"]) {
  copyFileSync(resolve(siteRoot, asset), resolve(dist, asset));
}
console.log(`site build: OK (${fails.length} sample findings, ${tiers.length} tiers)`);
