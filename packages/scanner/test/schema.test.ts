import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { emitJson } from "../src/emit.js";
import { auditConfig, gateFailureResult, loadConfig } from "../src/runner.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => resolve(here, "../fixtures", name);
const schema = JSON.parse(readFileSync(resolve(here, "../audit.schema.json"), "utf8"));

// ajv ships CJS-only dists; under NodeNext ESM the default-import interop
// mis-types the constructor, so load it through require with an explicit type.
type Ajv2020Ctor = typeof import("ajv/dist/2020.js")["default"];
const nodeRequire = createRequire(import.meta.url);
const Ajv2020 = nodeRequire("ajv/dist/2020.js") as unknown as Ajv2020Ctor;

const validator = new Ajv2020({ allErrors: true }).compile(schema);

/** Every status-bearing fixture: gate failures + full audits. */
const AUDIT_FIXTURES = [
  "clean.json",
  "vulnerable.json",
  "canary.json",
  "below-threshold.json",
  "mixed.json",
  "no-tools.json",
];

function validate(name: string, json: string) {
  const ok = validator(JSON.parse(json));
  if (!ok) {
    const errors = validator.errors ?? [];
    const detail = errors
      .map((e: { instancePath: string; message?: string }) => `${e.instancePath} ${e.message}`)
      .join("; ");
    throw new Error(`${name} violates audit.schema.json: ${detail}`);
  }
  expect(ok).toBe(true);
}

describe("audit.schema.json (A0)", () => {
  it("every fixture's JSON output validates", () => {
    for (const name of AUDIT_FIXTURES) {
      const loaded = loadConfig(fixture(name), 2 * 1024 * 1024);
      if ("error" in loaded) throw new Error(`${name} failed to load`);
      validate(name, emitJson(auditConfig(loaded.config, "0.0.0")));
    }
  });

  it("gate-failure output validates (scope: input on every check)", () => {
    validate("gate-failure", emitJson(gateFailureResult("bad input", "0.0.0")));
    const result = gateFailureResult("bad input", "0.0.0");
    expect(result.schemaVersion).toBeDefined();
    expect(result.checks.every((c) => c.scope === "input")).toBe(true);
  });

  it("a hand-crafted result with a bare unassessable check (no scope) is rejected", () => {
    const broken = gateFailureResult("x", "0.0.0");
    // biome-ignore lint/suspicious/noExplicitAny: schema-violation probe
    const mutated = structuredClone(broken) as unknown as Record<string, unknown>;
    const checks = mutated.checks as { scope?: unknown }[];
    const first = checks[0];
    if (!first) throw new Error("gate result has no checks");
    delete first.scope;
    expect(validator(mutated)).toBe(false);
  });
});
