import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CHECK_IDS } from "../src/checks/index.js";
import { emitSarif } from "../src/emit.js";
import { auditConfig, gateFailureResult } from "../src/runner.js";

const here = dirname(fileURLToPath(import.meta.url));
const vulnerable = JSON.parse(readFileSync(resolve(here, "../fixtures/vulnerable.json"), "utf8"));

describe("SARIF output (I5)", () => {
  it("contains the fields code-scanning consumers require", () => {
    const sarif = JSON.parse(emitSarif(auditConfig(structuredClone(vulnerable), "0.1.0")));
    expect(sarif.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
    expect(sarif.version).toBe("2.1.0");
    const driver = sarif.runs[0].tool.driver;
    expect(driver.name).toBe("mcp-audit");
    expect(driver.version).toBe("0.1.0");
    expect(driver.rules.map((r: { id: string }) => r.id).sort()).toEqual([...CHECK_IDS].sort());
  });

  it("links every result to its rule", () => {
    const sarif = JSON.parse(emitSarif(auditConfig(structuredClone(vulnerable), "0.1.0")));
    const results = sarif.runs[0].results as { ruleId: string }[];
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) expect(CHECK_IDS).toContain(r.ruleId);
  });

  it("reports unassessable checks instead of dropping them", () => {
    const sarif = JSON.parse(emitSarif(gateFailureResult("bad input", "0.1.0")));
    const results = sarif.runs[0].results as { properties: { status?: string } }[];
    expect(results).toHaveLength(CHECK_IDS.length);
    expect(results.every((r) => r.properties.status === "unassessable")).toBe(true);
  });
});
