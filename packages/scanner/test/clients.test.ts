import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { emitJson, emitSummary } from "../src/emit.js";
import { main } from "../src/cli.js";
import { auditConfig, loadConfigAny } from "../src/runner.js";

const here = dirname(fileURLToPath(import.meta.url));
const real = (name: string) => resolve(here, "../fixtures/real/filesystem-2.3.0", name);

const CANARIES = ["CANARY-API-KEY-9f8e7d6c", "ghp_canarytoken12345678"];

/** A1 acceptance: findings point at the ORIGINAL file — every pointer's
 * parent prefix must exist in the fixture (missing-version fails point at
 * where the field would be). */
function assertPointerPrefixes(original: unknown, pointer: string): void {
  const parts = pointer.split(".");
  // Walk from the full pointer up to its first resolvable ancestor.
  for (let cut = parts.length; cut > 0; cut--) {
    let node: unknown = original;
    const path = parts.slice(0, cut).join(".");
    let ok = true;
    for (const seg of path.split(".")) {
      const m = /^([^[\]]+)\[(\d+)\]$/.exec(seg);
      const key = m?.[1];
      const idx = m?.[2];
      if (key !== undefined && idx !== undefined) {
        node = (node as Record<string, unknown>)?.[key];
        node = Array.isArray(node) ? node[Number(idx)] : undefined;
      } else {
        node = (node as Record<string, unknown>)?.[seg];
      }
      if (node === undefined) {
        ok = false;
        break;
      }
    }
    if (ok) return; // some ancestor resolves — pointer is anchored in the file
  }
  throw new Error(`pointer ${pointer} resolves to nothing in the original fixture`);
}

const CLIENT_FIXTURES = [
  "claude-desktop.clean.json",
  "claude-desktop.root.json",
  "cursor.unpinned.json",
  "vscode.docker.json",
  "claude-code.secrets.json",
  "windsurf.clean.json",
];

describe("client fixtures through the CLI path (A1)", () => {
  it("every client fixture loads, audits, and points into the original file", () => {
    for (const name of CLIENT_FIXTURES) {
      const path = real(name);
      const loaded = loadConfigAny(path, 2 * 1024 * 1024);
      expect("loaded" in loaded, name).toBe(true);
      if (!("loaded" in loaded)) throw new Error(name);
      const original = JSON.parse(readFileSync(path, "utf8"));
      const result = auditConfig(loaded.loaded.config, "test", loaded.loaded.pointerBases);
      for (const f of result.checks.flatMap((c) => c.findings)) {
        expect(f.pointer, `${name}: ${f.checkId}`).not.toMatch(/^servers\[\d+\]/);
        // Global locations (bare "servers", gate "config") are not file-anchored.
        if (f.pointer !== "servers" && f.pointer !== "config") {
          assertPointerPrefixes(original, f.pointer);
        }
      }
      // Determinism: double audit is byte-identical.
      const again = auditConfig(
        JSON.parse(JSON.stringify(loaded.loaded.config)),
        "test",
        loaded.loaded.pointerBases,
      );
      expect(emitJson(result)).toBe(emitJson(again));
    }
  });

  it("secrets fixture: SEC-01 fires on env and the canary never leaks", () => {
    const path = real("claude-code.secrets.json");
    const loaded = loadConfigAny(path, 2 * 1024 * 1024);
    if (!("loaded" in loaded)) throw new Error("fixture failed to load");
    const result = auditConfig(loaded.loaded.config, "test", loaded.loaded.pointerBases);
    const sec01 = result.checks.find((c) => c.checkId === "SEC-01");
    expect(sec01?.status).toBe("fail");
    const pointers = sec01?.findings.map((f) => f.pointer) ?? [];
    expect(pointers).toContain("mcpServers.fs-secrets.env.GITHUB_PERSONAL_ACCESS_TOKEN");
    // The ${FS_TOKEN:-default} literal default is scanned, not skipped.
    expect(pointers).toContain("mcpServers.fs-secrets.env.FS_TOKEN");
    const surfaces = [emitJson(result), emitSummary(result)].join("\n");
    for (const canary of CANARIES) expect(surfaces).not.toContain(canary);
  });

  it("secrets fixture exit codes: SEC-01 (high) → 0 at default, 1 at --fail-on high", () => {
    expect(main(["scan", real("claude-code.secrets.json"), "--format", "json"])).toBe(0);
    expect(
      main(["scan", real("claude-code.secrets.json"), "--format", "json", "--fail-on", "high"]),
    ).toBe(1);
  });

  it("windsurf and claude-desktop clean configs normalize to the same verdicts", () => {
    const verdicts = (name: string) => {
      const loaded = loadConfigAny(real(name), 2 * 1024 * 1024);
      if (!("loaded" in loaded)) throw new Error(name);
      const result = auditConfig(loaded.loaded.config, "test", loaded.loaded.pointerBases);
      return result.checks.map((c) => `${c.checkId}:${c.status}`).join(",");
    };
    expect(verdicts("windsurf.clean.json")).toBe(verdicts("claude-desktop.clean.json"));
  });
});

describe("mule oracle: config-derived rows (A2 subset of expected.json)", () => {
  const oracle = JSON.parse(readFileSync(real("expected.json"), "utf8")) as {
    fixtures: Record<
      string,
      { withoutTools: { statuses: Record<string, string>; exitDefault: number } }
    >;
  };
  // Checks whose verdicts derive purely from config fields — the A2 subset.
  const CONFIG_DERIVED = [
    "INV-01",
    "AUTH-01",
    "AUTH-02",
    "AUTH-03",
    "AUTH-04",
    "LOG-01",
    "PRIV-03",
    "PRIV-04",
    "SEC-01",
    "SEC-02",
  ];

  for (const [name, expected] of Object.entries(oracle.fixtures)) {
    it(`${name}: config-derived rows match the oracle`, () => {
      const loaded = loadConfigAny(real(name), 2 * 1024 * 1024);
      if (!("loaded" in loaded)) throw new Error(`${name} failed to load`);
      const result = auditConfig(loaded.loaded.config, "test", loaded.loaded.pointerBases);
      const got = statusesOf(result);
      for (const id of CONFIG_DERIVED) {
        expect(got.get(id), `${name} ${id}`).toBe(expected.withoutTools.statuses[id]);
      }
    });
  }
});

function statusesOf(result: ReturnType<typeof auditConfig>): Map<string, string> {
  return new Map(result.checks.map((c) => [c.checkId, c.status]));
}
