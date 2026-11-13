import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { emitJson, emitSarif } from "../src/emit.js";
import { auditConfig } from "../src/runner.js";

const here = dirname(fileURLToPath(import.meta.url));
const vulnerable = JSON.parse(readFileSync(resolve(here, "../fixtures/vulnerable.json"), "utf8"));

describe("determinism (I2)", () => {
  it("double-run JSON output is byte-identical", () => {
    const a = emitJson(auditConfig(structuredClone(vulnerable), "test"));
    const b = emitJson(auditConfig(structuredClone(vulnerable), "test"));
    expect(a).toBe(b);
  });

  it("double-run SARIF output is byte-identical", () => {
    const a = emitSarif(auditConfig(structuredClone(vulnerable), "test"));
    const b = emitSarif(auditConfig(structuredClone(vulnerable), "test"));
    expect(a).toBe(b);
  });

  it("finding ids are stable across runs", () => {
    const ids = (v: unknown) =>
      auditConfig(v as never, "test")
        .checks.flatMap((c) => c.findings)
        .map((f) => f.id);
    expect(ids(structuredClone(vulnerable))).toEqual(ids(structuredClone(vulnerable)));
  });
});
