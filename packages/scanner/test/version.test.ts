import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { main } from "../src/cli.js";

const here = dirname(fileURLToPath(import.meta.url));
// test/../package.json = packages/scanner/package.json (the single source).
const pkg = JSON.parse(readFileSync(resolve(here, "../package.json"), "utf8")) as {
  version: string;
};

describe("version single-source (B1, review item 1)", () => {
  it("--version prints the manifest version", () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => logs.push(String(a[0])));
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((n: number) => {
      throw new Error(`exit ${String(n)}`);
    }) as never);
    try {
      expect(() => main(["--version"])).toThrow("exit 0");
    } finally {
      exitSpy.mockRestore();
    }
    expect(logs.join("")).toContain(`mcp-audit ${pkg.version}`);
  });

  it("summary toolVersion equals the manifest version (never the 0.0.0 fallback)", () => {
    const chunks: string[] = [];
    vi.spyOn(process.stdout, "write").mockImplementation(((c: unknown) => {
      chunks.push(String(c));
      return true;
    }) as never);
    const fixture = resolve(here, "../fixtures/no-tools.json");
    const code = main(["scan", fixture, "--format", "summary"]);
    vi.restoreAllMocks();
    expect(code).toBe(0);
    const out = chunks.join("");
    expect(out).toContain(`Tool: mcp-audit ${pkg.version}`);
    expect(out).not.toContain("0.0.0");
  });

  it("--help carries the manifest version", () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => logs.push(String(a[0])));
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((n: number) => {
      throw new Error(`exit ${String(n)}`);
    }) as never);
    try {
      expect(() => main(["--help"])).toThrow("exit 0");
    } finally {
      exitSpy.mockRestore();
    }
    expect(logs.join("")).toContain(`mcp-audit ${pkg.version}`);
    vi.restoreAllMocks();
  });
});
