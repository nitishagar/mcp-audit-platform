import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { detectFormat, FormatError, normalizeFile } from "../src/adapters/index.js";
import { auditConfig, loadConfigAny } from "../src/runner.js";

const claude = {
  mcpServers: {
    filesystem: {
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem@2.3.0", "/tmp"],
    },
  },
};
const windsurf = {
  mcpServers: { remote: { serverUrl: "https://api.example.com/mcp", headers: { "X-Key": "v" } } },
};
const vscode = {
  inputs: [{ type: "promptString", id: "k", description: "key", password: true }],
  servers: { local: { type: "stdio", command: "uvx", args: ["pkg"] } },
};
const claudeCode = {
  projects: { "/home/dev/app": { mcpServers: { fs: { command: "npx", args: ["-y", "pkg"] } } } },
  mcpServers: { globalfs: { url: "https://api.example.com/mcp" } },
};

describe("format detection (A1)", () => {
  it("detects mcpServers / vscode servers / native servers / claude-code projects", () => {
    expect(detectFormat(claude)).toBe("mcp-servers");
    expect(detectFormat(vscode)).toBe("vscode");
    expect(detectFormat({ servers: [{ name: "x" }] })).toBe("native");
    expect(detectFormat(claudeCode)).toBe("mcp-servers"); // mcpServers wins; projects handled by claude-code path
  });

  it("rejects unknown shapes with a supported list", () => {
    expect(() => detectFormat({ foo: 1 })).toThrow(FormatError);
    expect(() => detectFormat([1, 2])).toThrow(FormatError);
    try {
      detectFormat({ foo: 1 });
    } catch (err) {
      expect((err as FormatError).message).toContain("servers{…}");
    }
  });
});

describe("normalization (A1)", () => {
  it("claude-desktop shape: name from key, stdio from command, pointer base", () => {
    const { config, format } = normalizeFile(claude);
    expect(format).toBe("mcp-servers");
    const s = config.servers[0];
    if (!s) throw new Error("no servers");
    expect(s.name).toBe("filesystem");
    expect(s.transport).toBe("stdio");
    expect(s._pointerBase).toBe("mcpServers.filesystem");
    expect(JSON.stringify(s.args)).toContain("@modelcontextprotocol/server-filesystem@2.3.0");
  });

  it("windsurf serverUrl → url + http; headers carried; type omitted (R5)", () => {
    const { config } = normalizeFile(windsurf, "windsurf");
    const s = config.servers[0];
    if (!s) throw new Error("no servers");
    expect(s.transport).toBe("http");
    expect(s.url).toBe("https://api.example.com/mcp");
    expect(s.headers).toEqual({ "X-Key": "v" });
  });

  it("vscode: servers object + inputs passthrough", () => {
    const { config, format } = normalizeFile(vscode);
    expect(format).toBe("vscode");
    const s = config.servers[0];
    if (!s) throw new Error("no servers");
    expect(s.transport).toBe("stdio");
    expect(s._pointerBase).toBe("servers.local");
  });

  it("claude-code: per-project expansion with quoted pointer bases", () => {
    const { config } = normalizeFile(claudeCode, "claude-code");
    const bases = config.servers.map((s) => s._pointerBase);
    expect(bases).toContain('projects["/home/dev/app"].mcpServers.fs');
    expect(bases).toContain("mcpServers.globalfs");
    expect(config.servers.find((s) => s.name === "globalfs")?.transport).toBe("http");
  });

  it("native format is identity-preserving", () => {
    const { config, format } = normalizeFile({ servers: [{ name: "x", command: "c" }] });
    expect(format).toBe("native");
    const s = config.servers[0];
    if (!s) throw new Error("no servers");
    expect(s.name).toBe("x");
    expect(s._pointerBase).toBe("servers[0]");
  });

  it("--client mismatch is a clean error, never a guess", () => {
    expect(() => normalizeFile(claude, "vscode")).toThrow(FormatError);
    expect(() => normalizeFile(claude, "bogus" as never)).toThrow(FormatError);
  });

  it("entries with no transport signal are carried through → audit is input-unassessable", () => {
    const { config } = normalizeFile({ mcpServers: { ghost: { description: "nothing" } } });
    expect(config.servers).toHaveLength(1); // carried, not dropped
    const result = auditConfig(
      config,
      "test",
      config.servers.map((s) => s._pointerBase),
    );
    expect(result.checks.every((c) => c.status === "unassessable" && c.scope === "input")).toBe(
      true,
    );
  });
});

describe("loadConfigAny (A1)", () => {
  it("unknown shape → shape error listing supported formats", () => {
    const path = join(mkdtempSync(join(tmpdir(), "fmt-")), "x.json");
    writeFileSync(path, '{"foo": 1}');
    const bad = loadConfigAny(path, 2 * 1024 * 1024);
    expect("error" in bad && bad.error.kind).toBe("shape");
    if ("error" in bad) expect(bad.error.message).toContain("mcpServers");
  });
});
