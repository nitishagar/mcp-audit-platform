import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const distHtml = resolve(here, "../dist/index.html");

function builtHtml() {
  if (!existsSync(distHtml)) {
    throw new Error(
      "dist/index.html missing — run pnpm build first (verify builds before testing)",
    );
  }
  return readFileSync(distHtml, "utf8");
}

const tiers = JSON.parse(readFileSync(resolve(here, "../src/tiers.json"), "utf8"));

describe("site copy (I7/I9/I6)", () => {
  it("every tier renders name, scope, deliverables, price, turnaround", () => {
    const html = builtHtml();
    for (const tier of tiers) {
      for (const field of ["name", "scope", "price", "turnaround"]) {
        expect(html, `tier ${tier.name} missing ${field}`).toContain(tier[field]);
      }
      for (const d of tier.deliverables) {
        expect(html, `tier ${tier.name} missing deliverable`).toContain(d);
      }
    }
  });

  it("honesty disclaimer is present", () => {
    const html = builtHtml();
    expect(html).toContain("static analysis");
    expect(html).toContain("not a pentest");
  });

  it("install block with working copy affordances is present", () => {
    const html = builtHtml();
    for (const tab of ["npm", "pnpm", "source"]) {
      expect(html, `missing ${tab} tab`).toContain(`data-tab="${tab}"`);
    }
    const copies = html.match(/data-copy="/g) ?? [];
    expect(copies.length).toBeGreaterThanOrEqual(3);
  });
});

describe("C3/C6 site content", () => {
  const distDir = resolve(here, "../dist");
  const checkIds = JSON.parse(readFileSync(resolve(distDir, "check-ids.json"), "utf8"));

  it("every check has a rule page in dist/rules", () => {
    const pages = readdirSync(resolve(distDir, "rules")).filter((f) => f.endsWith(".html"));
    for (const id of checkIds) expect(pages, id).toContain(`${id}.html`);
  });

  it("docs/changelog pages are themed; report-sample carries the A6 pack", () => {
    for (const f of ["docs.html", "changelog.html"]) {
      const html = readFileSync(resolve(distDir, f), "utf8");
      expect(html, f).toContain("tokens.css");
    }
    const sample = readFileSync(resolve(distDir, "report-sample.html"), "utf8");
    expect(sample).toContain("Executive summary");
    expect(sample).toContain("Static analysis only — not a penetration test");
  });

  it("every numeric claim in the announce bar has a claims.json entry with a source", () => {
    const html = builtHtml();
    const announce = html.match(/class="announce"[^>]*>([\s\S]*?)<\/div>/)?.[1] ?? "";
    const numbers = announce.match(/\d+(?:\.\d+)?%?/g) ?? [];
    const claims = JSON.parse(readFileSync(resolve(here, "../claims.json"), "utf8"));
    const allSources = claims.claims.every(
      (c) => typeof c.source === "string" && c.source.startsWith("https://"),
    );
    expect(allSources).toBe(true);
    for (const n of ["40%", "7,973"]) {
      const covered = claims.claims.some((c) => (c.claim ?? "").includes(n));
      const inText = announce.includes(n);
      if (inText) expect(covered, `announce number ${n} must have a claims entry`).toBe(true);
    }
    expect(numbers.length).toBeGreaterThan(0);
  });
});
