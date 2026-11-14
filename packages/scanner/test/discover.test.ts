import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { discoverConfigs } from "../src/adapters/discover.js";
import { main } from "../src/cli.js";
import { auditConfig } from "../src/runner.js";

const HOME = mkdtempSync(join(tmpdir(), "discover-home-"));
const afterAll: (() => void)[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const fn of afterAll.splice(0)) fn();
});

function silence() {
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(process.stdout, "write").mockImplementation(() => true);
}

/** Seed fake client configs into a fake HOME (plan A4 test shape). */
function seed(files: Record<string, unknown>): string {
  for (const [rel, body] of Object.entries(files)) {
    const path = join(HOME, rel);
    mkdirSync(join(path, ".."), { recursive: true });
    writeFileSync(path, JSON.stringify(body));
  }
  return HOME;
}

describe("--discover merges well-known configs deterministically (A4)", () => {
  it("merges multiple sources with per-file servers, sorted by path", () => {
    const base = seed({
      ".claude.json": {
        projects: { "/w/a": { mcpServers: { fs: { command: "npx", args: ["-y", "pkg@1.0.0"] } } } },
      },
    });
    const rootDir = mkdtempSync(join(tmpdir(), "discover-root-"));
    mkdirSync(join(rootDir, ".cursor"), { recursive: true });
    writeFileSync(
      join(rootDir, ".cursor/mcp.json"),
      JSON.stringify({
        mcpServers: {
          git: { url: "https://git.example.com/mcp", headers: { Authorization: "r" } },
        },
      }),
    );
    const d = discoverConfigs(2 * 1024 * 1024, { home: base, root: rootDir });
    expect(d.sources.map((s) => s.format).sort()).toEqual(["claude-code", "cursor"]);
    expect(d.config.servers).toHaveLength(2);
    expect(d.warnings).toEqual([]);
    // Deterministic: same input -> byte-identical server order (path sort).
    const d2 = discoverConfigs(2 * 1024 * 1024, { home: base, root: rootDir });
    expect(d.config.servers.map((s) => s.name)).toEqual(d2.config.servers.map((s) => s.name));
  });

  it("missing files are silent; unreadable ones warn with the path only", () => {
    const base = seed({
      ".cursor/mcp.json": { mcpServers: { fs: { command: "c" } } },
    });
    // A non-JSON file at a well-known path (windsurf path left absent = silent).
    writeFileSync(join(base, ".claude.json"), "not json {");
    const d = discoverConfigs(2 * 1024 * 1024, { home: base, root: base });
    expect(d.warnings).toHaveLength(1);
    expect(d.warnings[0]).toContain(".claude.json");
    expect(d.warnings[0]).not.toContain("not json"); // content never echoed (I4)
  });

  it("INV-02: same server name with differing definitions fails (shadowing)", () => {
    const base = seed({
      ".cursor/mcp.json": {
        mcpServers: { fs: { command: "npx", args: ["-y", "pkg@1.0.0"] } },
      },
    });
    // claude-desktop.json is not a well-known path; attach via a project file:
    writeFileSync(
      join(base, ".mcp.json"),
      JSON.stringify({ mcpServers: { fs: { command: "npx", args: ["-y", "pkg@2.0.0"] } } }),
    );
    const d = discoverConfigs(2 * 1024 * 1024, { home: base, root: base });
    const result = ((): Map<string, string> => {
      const r = auditConfig(
        d.config,
        "test",
        d.config.servers.map((s) => s._pointerBase),
      );
      return new Map(r.checks.map((c) => [c.checkId, c.status]));
    })();
    expect(result.get("INV-02")).toBe("fail");
  });

  it("INV-02: identical definitions across files pass", () => {
    const base = seed({
      ".cursor/mcp.json": { mcpServers: { fs: { command: "npx", args: ["-y", "pkg@1.0.0"] } } },
      ".mcp.json": { mcpServers: { fs: { command: "npx", args: ["-y", "pkg@1.0.0"] } } },
    });
    const d = discoverConfigs(2 * 1024 * 1024, { home: base, root: base });
    const r = auditConfig(
      d.config,
      "test",
      d.config.servers.map((s) => s._pointerBase),
    );
    const inv02 = r.checks.find((c) => c.checkId === "INV-02");
    expect(inv02?.status).toBe("pass");
  });
});

describe("--discover CLI (A4)", () => {
  it("runs and emits sources in the JSON output", () => {
    const base = seed({
      ".cursor/mcp.json": { mcpServers: { fs: { command: "npx", args: ["-y", "pkg@1.0.0"] } } },
    });
    silence();
    process.env["MCP_AUDIT_DISCOVER_DIR"] = base;
    afterAll.push(() => delete process.env["MCP_AUDIT_DISCOVER_DIR"]);
    const chunks: string[] = [];
    vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
      chunks.push(String(chunk));
      return true;
    }) as never);
    const code = main(["scan", "--discover", "--format", "json"]);
    expect(code).toBe(0);
    const parsed = JSON.parse(chunks.join("")) as { sources?: { format: string }[] };
    expect(parsed.sources?.some((s) => s.format === "cursor")).toBe(true);
  });

  it("--discover rejects a config path", () => {
    silence();
    const exitSpy = vi.spyOn(process, "exit").mockImplementation((n) => {
      throw new Error(`exit ${String(n)}`);
    });
    try {
      expect(() => main(["scan", "--discover", "some.json"])).toThrow("exit 2");
    } finally {
      exitSpy.mockRestore();
    }
  });
});
