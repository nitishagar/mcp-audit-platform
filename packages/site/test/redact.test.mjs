import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
// Scanner must be built first (site build depends on it; verify builds before testing).
import { isDenylistedKey } from "../../scanner/dist/redact.js";

const here = dirname(fileURLToPath(import.meta.url));

function stringLeaves(node, out) {
  if (typeof node === "string") {
    out.push(node);
    return;
  }
  if (Array.isArray(node)) {
    node.forEach((v) => {
      stringLeaves(v, out);
    });
    return;
  }
  if (node !== null && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (typeof v === "string") {
        if (isDenylistedKey(k)) out.push(v);
      } else {
        stringLeaves(v, out);
      }
    }
  }
}

describe("sample-report redaction (I4 HTML surface)", () => {
  it("vulnerable fixture secret values are absent from built HTML", () => {
    const distHtml = resolve(here, "../dist/index.html");
    if (!existsSync(distHtml)) {
      throw new Error("dist/index.html missing — run pnpm build first");
    }
    const html = readFileSync(distHtml, "utf8");
    // Non-vacuous: the sample table must be rendered.
    expect(html).toContain("sample-table");
    const vulnerable = JSON.parse(
      readFileSync(resolve(here, "../../scanner/fixtures/vulnerable.json"), "utf8"),
    );
    const secrets = [];
    stringLeaves(vulnerable, secrets);
    expect(secrets.length).toBeGreaterThan(0);
    for (const secret of new Set(secrets)) {
      expect(html, `leaked ${secret.slice(0, 12)}…`).not.toContain(secret);
    }
  });
});
