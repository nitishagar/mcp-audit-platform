import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { main } from "../src/cli.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => resolve(here, "../fixtures", name);

afterEach(() => {
  vi.restoreAllMocks();
});

function silence() {
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(process.stdout, "write").mockImplementation(() => true);
}

describe("CLI exit codes", () => {
  it("clean.json → 0 with zero findings", () => {
    silence();
    const code = main(["scan", fixture("clean.json"), "--format", "json"]);
    expect(code).toBe(0);
  });

  it("below-threshold with --fail-on high → 0", () => {
    silence();
    const code = main([
      "scan",
      fixture("below-threshold.json"),
      "--format",
      "json",
      "--fail-on",
      "high",
    ]);
    expect(code).toBe(0);
  });

  it("vulnerable with --fail-on critical → 1", () => {
    silence();
    const code = main([
      "scan",
      fixture("vulnerable.json"),
      "--format",
      "json",
      "--fail-on",
      "critical",
    ]);
    expect(code).toBe(1);
  });

  it("vulnerable with no --fail-on → 1 (default critical)", () => {
    silence();
    const code = main(["scan", fixture("vulnerable.json"), "--format", "json"]);
    expect(code).toBe(1);
  });

  it("corrupt and empty → 2", () => {
    silence();
    expect(main(["scan", fixture("corrupt.json"), "--format", "json"])).toBe(2);
    expect(main(["scan", fixture("empty.json"), "--format", "json"])).toBe(2);
  });

  it("mixed (critical + unassessable) → 2 by precedence", () => {
    silence();
    const code = main(["scan", fixture("mixed.json"), "--format", "json", "--fail-on", "critical"]);
    expect(code).toBe(2);
  });

  it("--format all writes audit.json, audit.sarif, summary.md", () => {
    silence();
    const outDir = mkdtempSync(join(tmpdir(), "audit-"));
    const code = main([
      "scan",
      fixture("vulnerable.json"),
      "--format",
      "all",
      "--out-dir",
      outDir,
      "--fail-on",
      "critical",
    ]);
    expect(code).toBe(1);
    for (const name of ["audit.json", "audit.sarif", "summary.md"]) {
      const path = join(outDir, name);
      expect(existsSync(path), `missing ${name}`).toBe(true);
      expect(readFileSync(path, "utf8").length).toBeGreaterThan(0);
    }
    // JSON artifact parses and carries framework + findings.
    const parsed = JSON.parse(readFileSync(join(outDir, "audit.json"), "utf8"));
    expect(parsed.framework).toContain("OWASP MCP Top 10");
    expect(parsed.checks.length).toBeGreaterThan(0);
  });
});
