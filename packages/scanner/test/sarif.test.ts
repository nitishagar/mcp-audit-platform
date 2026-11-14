import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CHECK_IDS } from "../src/checks/index.js";
import { emitSarif } from "../src/emit.js";
import { auditConfig, gateFailureResult, loadConfig } from "../src/runner.js";

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
    expect(
      sarif.runs[0].results.every((r: { properties: { scope?: string } }) =>
        ["input", "coverage", undefined].includes(r.properties.scope),
      ),
    ).toBe(true);
    expect(driver.rules.map((r: { id: string }) => r.id).sort()).toEqual([...CHECK_IDS].sort());
    expect(
      driver.rules.every(
        (r: { helpUri: string }) =>
          r.helpUri === "https://github.com/nitishagar/mcp-audit-platform#check-coverage-i8",
      ),
    ).toBe(true);
    expect(driver.rules.every((r: { help: { text: string } }) => r.help.text.length > 0)).toBe(
      true,
    );
    // help.text comes from rules.ts remediation (single source, review item 3)
    expect(
      driver.rules.some((r: { help: { text: string } }) => r.help.text.startsWith("Fix: ")),
    ).toBe(true);
  });

  it("carries the ingestion contract on every result", () => {
    const result = auditConfig(structuredClone(vulnerable), "0.1.0");
    const sarif = JSON.parse(emitSarif(result, "mcp.json"));
    const results = sarif.runs[0].results as {
      level: string;
      message: { text: string };
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: string };
            region: Record<string, number>;
          };
        },
      ];
      partialFingerprints: { primaryLocationLineHash: string };
      properties: { pointer: string };
    }[];
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      expect(r.level === "error" || r.level === "warning" || r.level === "note").toBe(true);
      expect(r.message.text.length).toBeGreaterThan(0);
      const loc = r.locations[0].physicalLocation;
      expect(loc.artifactLocation.uri).toBe("mcp.json");
      expect(loc.region).toEqual({ startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 });
      expect(r.partialFingerprints.primaryLocationLineHash).toMatch(/^[0-9a-f]{12}$/);
      expect(r.properties.pointer.length).toBeGreaterThan(0);
    }
  });

  it("links every result to its rule", () => {
    const sarif = JSON.parse(emitSarif(auditConfig(structuredClone(vulnerable), "0.1.0")));
    const results = sarif.runs[0].results as { ruleId: string }[];
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) expect(CHECK_IDS).toContain(r.ruleId);
  });

  it("reports unassessable checks instead of dropping them", () => {
    const sarif = JSON.parse(emitSarif(gateFailureResult("bad input", "0.1.0")));
    const results = sarif.runs[0].results as {
      properties: { status?: string; scope?: string };
    }[];
    expect(results).toHaveLength(CHECK_IDS.length);
    expect(results.every((r) => r.properties.status === "unassessable")).toBe(true);
    expect(results.every((r) => r.properties.scope === "input")).toBe(true);
  });

  it("coverage-unassessable results carry scope and not_applicable emits no result (A0)", () => {
    const loaded = loadConfig(resolve(here, "../fixtures/no-tools.json"), 2 * 1024 * 1024);
    if (!("config" in loaded)) throw new Error("no-tools fixture failed to load");
    const result = auditConfig(loaded.config, "0.1.0");
    const sarif = JSON.parse(emitSarif(result, "no-tools.json"));
    const results = sarif.runs[0].results as {
      ruleId: string;
      properties: { status?: string; scope?: string };
    }[];
    const byId = new Map(results.map((r) => [r.ruleId, r]));
    // Tool checks: note-level results with scope "coverage".
    for (const id of ["PRIV-01", "ARG-02"]) {
      expect(byId.get(id)?.properties.scope, id).toBe("coverage");
      expect(byId.get(id)?.properties.status, id).toBe("unassessable");
    }
    // not_applicable checks emit no result at all.
    for (const id of ["AUTH-01", "AUTH-02", "AUTH-03"]) {
      expect(byId.has(id), id).toBe(false);
    }
  });
});
