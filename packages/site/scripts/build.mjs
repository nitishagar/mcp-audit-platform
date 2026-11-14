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
    console.error(`site build: scanner run failed (build mcp-audit-scanner first): ${err.message}`);
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

// Step 1b: rule metadata + check ids from the scanner dist (C3 single source).
const scannerUrl = (mod) => `file://${resolve(scannerRoot, "dist", mod)}`;
const { RULES, CHECK_IDS: checkIds } = await import(scannerUrl("rules.js")).then(async (rules) => ({
  RULES: rules.RULES,
  CHECK_IDS: (await import(scannerUrl("checks/index.js"))).CHECK_IDS,
}));

// Step 2: tiers + sample into template.
const tiers = JSON.parse(readFileSync(resolve(siteRoot, "src/tiers.json"), "utf8"));
// I11: every deliverable string must have a mechanism entry in promises.json,
// and every tier must carry a CTA — a promise without a mechanism fails the build.
const promises = JSON.parse(readFileSync(resolve(siteRoot, "promises.json"), "utf8"));
for (const tier of tiers) {
  if (!tier.cta || typeof tier.cta.href !== "string" || tier.cta.href.length === 0) {
    console.error(`site build: tier "${tier.name}" has no cta object (I11)`);
    process.exit(1);
  }
  for (const d of tier.deliverables) {
    if (!(d in promises)) {
      console.error(
        `site build: deliverable "${d}" (${tier.name}) has no promises.json mechanism (I11)`,
      );
      process.exit(1);
    }
  }
}
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
<p><a class="cta" href="${esc(t.cta.href)}">${esc(t.cta.label)}</a></p>
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

// Step 4 (C3): rule pages, docs, changelog, report sample.
const page = (title, body) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · mcp-audit</title><link rel="stylesheet" href="styles.css"><link rel="stylesheet" href="tokens.css"></head>
<body><nav><a href="index.html">← mcp-audit</a></nav><main>${body}</main></body></html>
`;
const rulesDir = resolve(dist, "rules");
mkdirSync(rulesDir, { recursive: true });
writeFileSync(resolve(dist, "check-ids.json"), `${JSON.stringify(checkIds)}\n`);
for (const id of checkIds) {
  const meta = RULES[id];
  if (!meta) throw new Error(`site build: rules.ts has no metadata for ${id}`);
  writeFileSync(
    resolve(rulesDir, `${id}.html`),
    page(
      `${id} — ${meta.title}`,
      `<h1>${esc(id)} — ${esc(meta.title)}</h1>
<p class="muted">Effort: ${esc(meta.effort)}</p>
<h2>Why it matters</h2><p>${esc(meta.rationale)}</p>
<h2>How to fix</h2><p>${esc(meta.remediation)}</p>
<p class="muted">Static analysis only — not a pentest. Source of truth: scanner rules.ts.</p>`,
    ),
  );
}
const docsRows = checkIds
  .map(
    (id) =>
      `<tr><td><a href="rules/${id}.html">${esc(id)}</a></td><td>${esc(RULES[id]?.title ?? "")}</td></tr>`,
  )
  .join("\n");
writeFileSync(
  resolve(dist, "docs.html"),
  page(
    "Docs",
    `<h1>Docs</h1>
<h2>Supported inputs</h2>
<p>Claude Desktop/Code, Cursor, VS Code, Windsurf config files (auto-detected; <code>--client</code> overrides), the native <code>{"servers":[…]}</code> shape, and a tools/list snapshot via <code>--tools</code>.</p>
<h2>Exit codes</h2>
<p>0 clean (coverage gaps allowed) · 1 findings at/above <code>--fail-on</code> · 2 input-unassessable or write error.</p>
<h2>Checks</h2>
<table><thead><tr><th>Check</th><th>Title</th></tr></thead><tbody>${docsRows}</tbody></table>
<p class="muted">Full CLI reference: <code>mcp-audit --help</code> and the scanner README on GitHub.</p>`,
  ),
);
const contactHtml = page(
  "Contact",
  `<h1>Request a review</h1>
<p>Pick a tier on the <a href="index.html#tiers">pricing section</a>, then request it here. Checkout and email intake arrive with the domain decision; until then the request path is a GitHub issue — never include config contents or secrets in an issue.</p>
<h2 id="snapshot">Snapshot — $490</h2>
<p>Run the free scanner, then <a href="https://github.com/nitishagar/mcp-audit-platform/issues" rel="noopener" target="_blank">open a Snapshot request issue</a> titled "Snapshot request". The operator replies with the intake details and the redacted <code>audit.json</code> hand-off, reviews it by hand, and returns the report pack (same-day SLA applies to business hours).</p>
<h2 id="deep-audit">Deep Audit — $1,900</h2>
<p><a href="https://github.com/nitishagar/mcp-audit-platform/issues" rel="noopener" target="_blank">Open a Deep Audit request issue</a> titled "Deep Audit request". The operator confirms scope (up to 15 servers), schedules the kickoff, and runs the 5-day plan with 2 retests inside 60 days.</p>
<p class="muted">Both tiers: the only artifact the operator needs is the redacted <code>audit.json</code> the scanner produces — your raw configs stay on your machine.</p>`,
);
writeFileSync(resolve(dist, "contact.html"), contactHtml);
const changelog = readFileSync(resolve(siteRoot, "../../CHANGELOG.md"), "utf8");
writeFileSync(
  resolve(dist, "changelog.html"),
  page("Changelog", `<h1>Changelog</h1><pre class="changelog">${esc(changelog)}</pre>`),
);
// Step 5 (C4): browser bundle of the pure audit surface (esbuild, ESM).
const esbuild = await import("esbuild");
await esbuild.build({
  entryPoints: [resolve(scannerRoot, "src/entry-browser.ts")],
  outfile: resolve(dist, "scan.js"),
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  minify: false,
  legalComments: "none",
  logLevel: "silent",
});

// Report sample: full standalone A6 report of the vulnerable fixture.
const sampleReport = execFileSync(
  "node",
  [cli, "report", resolve(siteRoot, "sample.json"), "--format", "html"],
  { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
);
writeFileSync(resolve(dist, "report-sample.html"), sampleReport);
copyFileSync(resolve(siteRoot, "src/scan.html"), resolve(dist, "scan.html"));
copyFileSync(resolve(siteRoot, "_headers"), resolve(dist, "_headers"));
const scanUi = await esbuild.build({
  entryPoints: [resolve(siteRoot, "src/scan-ui.mjs")],
  outfile: resolve(dist, "scan-ui.js"),
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  minify: false,
  logLevel: "silent",
});
console.log(
  `site build: OK (${fails.length} sample findings, ${tiers.length} tiers, ${checkIds.length} rule pages)`,
);
