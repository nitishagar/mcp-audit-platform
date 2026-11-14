import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
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

  it("no-tools fixture → 0 (coverage gaps do not fail; A0)", () => {
    silence();
    expect(main(["scan", fixture("no-tools.json"), "--format", "json"])).toBe(0);
  });

  it("no-tools fixture with --strict → 2 (coverage treated as failure)", () => {
    silence();
    expect(main(["scan", fixture("no-tools.json"), "--format", "json", "--strict"])).toBe(2);
  });

  it("clean fixture with --strict → 2 (legacy params cannot be schema-assessed: ARG-03 coverage)", () => {
    silence();
    expect(main(["scan", fixture("clean.json"), "--format", "json", "--strict"])).toBe(2);
  });

  it("oversize input → 2 at CLI level", () => {
    silence();
    const code = main(["scan", fixture("clean.json"), "--format", "json", "--max-bytes", "10"]);
    expect(code).toBe(2);
  });

  it("unwritable --out-dir → 2", () => {
    silence();
    const blocker = join(mkdtempSync(join(tmpdir(), "w-")), "file");
    writeFileSync(blocker, "x");
    const code = main(["scan", fixture("clean.json"), "--format", "all", "--out-dir", blocker]);
    expect(code).toBe(2);
  });

  it("mid-write failure → 2 with partial files removed", () => {
    silence();
    const outDir = mkdtempSync(join(tmpdir(), "w-"));
    // audit.sarif as a directory makes the second write fail after audit.json lands.
    mkdirSync(join(outDir, "audit.sarif"));
    const code = main(["scan", fixture("clean.json"), "--format", "all", "--out-dir", outDir]);
    expect(code).toBe(2);
    expect(existsSync(join(outDir, "audit.json"))).toBe(false);
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
