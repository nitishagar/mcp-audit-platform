import { existsSync, readFileSync } from "node:fs";
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
