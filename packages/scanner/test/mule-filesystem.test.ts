import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { emitHtml } from "../src/emit-html.js";
import { emitJson, emitSarif } from "../src/emit.js";
import { main } from "../src/cli.js";
import { auditConfig, loadConfigAny } from "../src/runner.js";

/**
 * T1 golden (PLAN-PRODUCT-COMPLETE §9.4): the whole oracle in expected.json,
 * per fixture — statuses, exit code, failRows ↔ SARIF results, double-run
 * byte equality across emitters, and per-fixture secret-leak assertions.
 * Companion to clients.test.ts (adapter mechanics + cross-runtime parity).
 */
const here = dirname(fileURLToPath(import.meta.url));
const real = (name: string) => resolve(here, "../fixtures/real/filesystem-2.3.0", name);
const oracle = JSON.parse(readFileSync(real("expected.json"), "utf8")) as {
  fixtures: Record<
    string,
    {
      withoutTools: { statuses: Record<string, string>; exitDefault: number; failRows: string[] };
      withTools: { statuses: Record<string, string>; exitDefault: number; failRows: string[] };
    }
  >;
};

const CANARIES = ["CANARY-API-KEY-9f8e7d6c", "ghp_canarytoken12345678"];

function audit(name: string) {
  const loaded = loadConfigAny(real(name), 2 * 1024 * 1024);
  if (!("loaded" in loaded)) throw new Error(`${name} failed to load`);
  return auditConfig(loaded.loaded.config, "test", loaded.loaded.pointerBases);
}

describe("T1 golden: mule fixtures against expected.json (M-1 depth)", () => {
  for (const [name, expected] of Object.entries(oracle.fixtures)) {
    it(`${name}: full status map matches the oracle`, () => {
      const result = audit(name);
      const got = new Map(result.checks.map((c) => [c.checkId, c.status]));
      for (const [checkId, want] of Object.entries(expected.withoutTools.statuses)) {
        expect(got.get(checkId), `${name} ${checkId}`).toBe(want);
      }
    });

    it(`${name}: SARIF distinct failing ruleIds match the oracle failRows`, () => {
      const result = audit(name);
      const sarif = JSON.parse(emitSarif(result, name));
      const errorResults = (sarif.runs[0].results as { ruleId: string; level: string }[]).filter(
        (r) => r.level === "error" || r.level === "warning",
      );
      const distinct = [...new Set(errorResults.map((r) => r.ruleId))].sort();
      expect(distinct, `${name} SARIF ruleIds`).toEqual([...expected.withoutTools.failRows].sort());
      // Every oracle failRow produces at least one SARIF result.
      expect(errorResults.length, `${name} result count`).toBeGreaterThanOrEqual(
        expected.withoutTools.failRows.length,
      );
    });

    it(`${name}: double-run is byte-identical across JSON/SARIF/HTML`, () => {
      const r1 = audit(name);
      const r2 = audit(name);
      expect(emitJson(r1)).toBe(emitJson(r2));
      expect(emitSarif(r1, name)).toBe(emitSarif(r2, name));
      expect(emitHtml(r1)).toBe(emitHtml(r2));
    });

    it(`${name}: HTML report carries the honesty disclaimer and no secret values`, () => {
      const result = audit(name);
      const html = emitHtml(result);
      expect(html).toContain("Static analysis only — not a penetration test");
      for (const c of CANARIES) {
        if (name === "claude-code.secrets.json") {
          // The canary-bearing fixture must withhold its values everywhere.
          expect(html, `canary ${c} must be absent from ${name}`).not.toContain(c);
        } else {
          expect(html).not.toContain(c);
        }
      }
    });

    it(`${name}: SARIF and JSON withhold the canary values too`, () => {
      const result = audit(name);
      const json = emitJson(result);
      const sarif = emitSarif(result, name);
      for (const c of CANARIES) {
        expect(json).not.toContain(c);
        expect(sarif).not.toContain(c);
      }
    });
  }

  it("the oracle exit codes match the CLI at the default threshold", () => {
    for (const [name, expected] of Object.entries(oracle.fixtures)) {
      const code = main(["scan", real(name), "--format", "json"]);
      expect(code, name).toBe(expected.withoutTools.exitDefault);
    }
  });
});
