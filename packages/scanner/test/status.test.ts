import { mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CHECKS } from "../src/checks/index.js";
import { loadConfig, auditConfig, gateFailureResult } from "../src/runner.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => resolve(here, "../fixtures", name);

describe("input-validation gate", () => {
  it("rejects malformed JSON", () => {
    const loaded = loadConfig(fixture("corrupt.json"), 2 * 1024 * 1024);
    expect("error" in loaded && loaded.error.kind).toBe("parse");
  });

  it("rejects empty {}", () => {
    const empty = loadConfig(fixture("empty.json"), 2 * 1024 * 1024);
    expect("error" in empty && empty.error.kind).toBe("shape");
  });

  it("rejects missing/invalid servers shapes", () => {
    const dir = mkdtempSync(join(tmpdir(), "shape-"));
    const cases: [string, string][] = [
      ["empty-array", '{"servers": []}'],
      ["wrong-type", '{"servers": "x"}'],
      ["missing-key", '{"foo": 1}'],
      ["top-array", "[]"],
    ];
    for (const [name, body] of cases) {
      const path = join(dir, `${name}.json`);
      writeFileSync(path, body);
      const loaded = loadConfig(path, 2 * 1024 * 1024);
      expect("error" in loaded && loaded.error.kind, name).toBe("shape");
    }
  });

  it("rejects oversize input", () => {
    const loaded = loadConfig(fixture("clean.json"), 10);
    expect("error" in loaded && loaded.error.kind).toBe("oversize");
  });

  it("accepts well-formed configs", () => {
    const loaded = loadConfig(fixture("clean.json"), 2 * 1024 * 1024);
    expect("config" in loaded).toBe(true);
  });

  it("refuses symlinks without reading the target (F1b)", () => {
    const dir = mkdtempSync(join(tmpdir(), "f1b-"));
    const victim = join(dir, "victim.txt");
    writeFileSync(victim, "PLAINTEXT-BOOTY-12345");
    const link = join(dir, "link.json");
    symlinkSync(victim, link);
    const loaded = loadConfig(link, 2 * 1024 * 1024);
    expect("error" in loaded).toBe(true);
    if ("error" in loaded) {
      expect(loaded.error.message).toContain("symlink");
      expect(loaded.error.message).not.toContain("PLAINTEXT-BOOTY-12345");
    }
  });
});

describe("check statuses (I1)", () => {
  it("clean fixture: every check passes or is not_applicable, zero findings", () => {
    const loaded = loadConfig(fixture("clean.json"), 2 * 1024 * 1024);
    if (!("config" in loaded)) throw new Error("clean fixture failed to load");
    const result = auditConfig(loaded.config, "test");
    // clean.json is stdio-only: AUTH-* are not_applicable, everything else passes.
    expect(result.checks.every((c) => c.status === "pass" || c.status === "not_applicable")).toBe(
      true,
    );
    expect(
      result.checks.filter((c) => c.status === "not_applicable").map((c) => c.checkId),
    ).toEqual(["AUTH-01", "AUTH-02", "AUTH-03"]);
    expect(result.checks.flatMap((c) => c.findings)).toHaveLength(0);
  });

  it("no tool schemas: tool checks are coverage-unassessable, never pass (A0/E2)", () => {
    const loaded = loadConfig(fixture("no-tools.json"), 2 * 1024 * 1024);
    if (!("config" in loaded)) throw new Error("no-tools fixture failed to load");
    const result = auditConfig(loaded.config, "test");
    const byId = new Map(result.checks.map((c) => [c.checkId, c]));
    for (const id of ["PRIV-01", "PRIV-02", "ARG-01", "ARG-02"]) {
      const c = byId.get(id);
      expect(c?.status, id).toBe("unassessable");
      expect(c?.scope, id).toBe("coverage");
      expect(c?.findings.length, id).toBeGreaterThan(0);
    }
    // stdio-only: AUTH-* not_applicable (distinct from pass).
    for (const id of ["AUTH-01", "AUTH-02", "AUTH-03"]) {
      expect(byId.get(id)?.status, id).toBe("not_applicable");
      expect(byId.get(id)?.findings, id).toHaveLength(0);
    }
    // Well-formed non-tool checks still pass.
    expect(byId.get("INV-01")?.status).toBe("pass");
    expect(byId.get("LOG-01")?.status).toBe("pass");
  });

  it("malformed server entry (no transport keys) is input-scoped, not coverage (A0)", () => {
    const raw = JSON.parse(readFileSync(fixture("mixed.json"), "utf8"));
    const result = auditConfig(raw, "test");
    expect(result.checks.every((c) => c.status === "unassessable" && c.scope === "input")).toBe(
      true,
    );
    expect(result.checks.every((c) => c.findings.every((f) => f.scope === "input"))).toBe(true);
  });

  it("vulnerable fixture: fails include criticals with framework refs", () => {
    const raw = JSON.parse(readFileSync(fixture("vulnerable.json"), "utf8"));
    const result = auditConfig(raw, "test");
    const fails = result.checks.flatMap((c) => c.findings.filter((f) => f.status === "fail"));
    expect(fails.length).toBeGreaterThan(0);
    expect(fails.some((f) => f.severity === "critical")).toBe(true);
    expect(fails.every((f) => f.frameworkRefs.length > 0)).toBe(true);
    // Every finding traces to an executed check with evidence (I1).
    expect(fails.every((f) => f.checkId && f.pointer && f.detail)).toBe(true);
  });

  it("gate failure: every check unassessable (input scope), zero pass", () => {
    const result = gateFailureResult("not valid JSON", "test");
    expect(result.checks).toHaveLength(CHECKS.length);
    expect(result.checks.every((c) => c.status === "unassessable" && c.scope === "input")).toBe(
      true,
    );
    expect(result.checks.some((c) => c.status === "pass")).toBe(false);
  });
});

describe("junk tool entries (A0 red-team fix)", () => {
  const junkCases: [string, unknown][] = [
    ["null entry", [null]],
    ["bare object entry", [{}]],
    ["mixed junk and real", [null, { name: "read_file", description: "Reads." }]],
  ];
  for (const [label, tools] of junkCases) {
    it(`tools with ${label} never yield a tool-check pass (I1)`, () => {
      const raw = {
        servers: [
          {
            name: "x",
            transport: "stdio",
            command: "c",
            version: "1",
            auditLog: true,
            tools,
          },
        ],
      };
      const result = auditConfig(raw as never, "test");
      const byId = new Map(result.checks.map((c) => [c.checkId, c]));
      for (const id of ["PRIV-01", "ARG-01", "ARG-02"]) {
        const c = byId.get(id);
        expect(c?.status, `${id} ${label}`).toBe("unassessable");
        expect(c?.scope, `${id} ${label}`).toBe("coverage");
      }
    });
  }
});
