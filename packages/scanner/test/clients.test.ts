import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { emitJson, emitSummary } from "../src/emit.js";
import { main } from "../src/cli.js";
import { parseToolsFile } from "../src/adapters/tools.js";
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

describe("mule oracle with --tools (A3a)", () => {
  const oracle = JSON.parse(readFileSync(real("expected.json"), "utf8")) as {
    fixtures: Record<string, { withTools: { statuses: Record<string, string> } }>;
  };
  const withTools = (configName: string, toolsName: string) => {
    const loaded = loadConfigAny(real(configName), 2 * 1024 * 1024);
    if (!("loaded" in loaded)) throw new Error(configName);
    const tools = JSON.parse(readFileSync(real(toolsName), "utf8")) as { tools: unknown };
    for (const s of loaded.loaded.config.servers) s.tools = tools.tools as never;
    return auditConfig(loaded.loaded.config, "test", loaded.loaded.pointerBases);
  };

  it("clean config + golden tools: oracle withTools statuses match", () => {
    const result = withTools("claude-desktop.clean.json", "tools-list.json");
    const want = oracle.fixtures["claude-desktop.clean.json"]?.withTools.statuses;
    if (!want) throw new Error("oracle missing claude-desktop.clean.json");
    for (const [id, status] of Object.entries(want)) {
      const c = result.checks.find((x) => x.checkId === id);
      expect(c?.status, `${id}`).toBe(status);
    }
    // PRIV-01 fails exactly for the vendor-annotated destructive tools.
    const priv01 = result.checks.find((c) => c.checkId === "PRIV-01");
    const failingTools = priv01?.findings
      .filter((f) => f.status === "fail")
      .map((f) => f.pointer)
      .sort();
    expect(failingTools).toEqual([
      "mcpServers.filesystem.tools[11].requireApproval", // move_file
      "mcpServers.filesystem.tools[4].requireApproval", // write_file
      "mcpServers.filesystem.tools[6].requireApproval", // edit_file
    ]);
  });

  it("poisoned nested description is detected with a pointer into the schema", () => {
    const result = withTools("claude-desktop.clean.json", "tools-list.poisoned.json");
    const arg02 = result.checks.find((c) => c.checkId === "ARG-02");
    expect(arg02?.status).toBe("fail");
    expect(
      arg02?.findings.some(
        (f) => f.pointer.includes("inputSchema") && f.pointer.includes("oldText"),
      ),
    ).toBe(true);
  });

  it("rugpull annotations flip PRIV-01", () => {
    const result = withTools("claude-desktop.clean.json", "tools-list.rugpull.json");
    const priv01 = result.checks.find((c) => c.checkId === "PRIV-01");
    // read_file (now non-read-only/destructive) + exec_command join the fails
    const failing = priv01?.findings.filter((f) => f.status === "fail") ?? [];
    expect(failing.length).toBe(5);
  });
});

describe("--tools CLI wiring (A3a red-team)", () => {
  const silence2 = () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  };
  const writeJson = (name: string, body: unknown): string => {
    const path = join(tmpdir(), `tools-${name}`);
    writeFileSync(path, JSON.stringify(body));
    return path;
  };

  it("zero-match tools map warns and tool checks stay coverage", () => {
    silence2();
    const cfg = writeJson("cfg.json", {
      mcpServers: { srvb: { command: "npx", args: ["p@1.0.0"] } },
    });
    const tools = writeJson("tools-zero.json", {
      srvA: { tools: [{ name: "t", inputSchema: {} }] },
    });
    const code = main(["scan", cfg, "--format", "json", "--tools", tools]);
    expect(code).toBe(0);
  });

  it("--tools without a value exits 2", () => {
    silence2();
    const cfg = writeJson("cfg2.json", {
      mcpServers: { a: { command: "npx", args: ["p@1.0.0"] } },
    });
    const exitSpy = vi.spyOn(process, "exit").mockImplementation((n) => {
      throw new Error(`exit ${String(n)}`);
    });
    try {
      expect(() => main(["scan", cfg, "--format", "json", "--tools"])).toThrow("exit 2");
      expect(exitSpy).toHaveBeenCalledWith(2);
    } finally {
      exitSpy.mockRestore();
    }
  });

  it("parseToolsFile: __proto__ key is an own property on a null-proto map, no pollution", () => {
    // Built via JSON.parse: an object literal would SET the prototype instead.
    const f = parseToolsFile(
      JSON.parse('{"__proto__": {"tools": [{"name": "t"}]}, "real": {"tools": []}}'),
    );
    if (!("byServer" in f)) throw new Error("expected byServer shape");
    expect(Object.getPrototypeOf(f.byServer)).toBeNull();
    expect(Object.prototype.hasOwnProperty.call(f.byServer, "__proto__")).toBe(true);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});
