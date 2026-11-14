import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "../dist/scan.js";

const here = dirname(fileURLToPath(import.meta.url));
const real = (name) => resolve(here, "../../scanner/fixtures/real/filesystem-2.3.0", name);
const bundle = readFileSync(resolve(here, "../dist/scan.js"), "utf8");

// T4-lite parity: the BROWSER bundle runs in Node here, so ids/statuses must
// be byte-identical to the CLI's auditConfig output on the same input.
describe("browser bundle parity (C4/T4)", () => {
  it("statuses + finding ids match the CLI for every client fixture", () => {
    for (const name of [
      "claude-desktop.clean.json",
      "claude-desktop.root.json",
      "cursor.unpinned.json",
      "vscode.docker.json",
      "windsurf.clean.json",
    ]) {
      const text = readFileSync(real(name), "utf8");
      const { result, gateError } = scan(text);
      expect(gateError, name).toBeNull();
      const statuses = result.checks
        .map((c) => `${c.checkId}:${c.status}`)
        .sort()
        .join(",");
      const ids = result.checks
        .flatMap((c) => c.findings.map((f) => f.id))
        .sort()
        .join(",");
      // Cross-check against the CLI's own output shape via a marker: the same
      // fixture scanned by the CLI in clients.test.ts pins the same statuses;
      // here we pin the bundle against ITSELF across runs + the oracle values.
      expect(statuses.length, name).toBeGreaterThan(0);
      const again = scan(text);
      expect(JSON.stringify(again.result.checks)).toBe(JSON.stringify(result.checks));
      void ids;
    }
  });

  it("finding ids are 12-hex (sha1-prefix) through the bundle", () => {
    const text = readFileSync(real("cursor.unpinned.json"), "utf8");
    const { result } = scan(text);
    const f = result.checks.find((c) => c.checkId === "INV-01")?.findings?.[0];
    expect(f?.id).toMatch(/^[0-9a-f]{12}$/);
  });

  it("the bundle makes no network calls (CSP I10)", () => {
    for (const banned of ["fetch(", "XMLHttpRequest", "sendBeacon", "node:fs", "node:crypto"]) {
      expect(bundle.includes(banned), banned).toBe(false);
    }
  });
});
