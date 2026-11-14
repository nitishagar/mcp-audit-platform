import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { emitHtml } from "../src/emit-html.js";
import { emitJson } from "../src/emit.js";
import { main } from "../src/cli.js";
import { auditConfig, loadConfig } from "../src/runner.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => resolve(here, "../fixtures", name);

const canaries = [
  "CANARY-API-KEY-9f8e7d6c",
  "https://hooks.slack.com/services/CANARY/WEBHOOK/VALUE",
  "CANARYPEM-BODY-1234",
  "ghp_canarytoken12345678",
  "AKIAIOSFODNN7CANARY01",
];

describe("HTML report (A6)", () => {
  it("renders the full pack with cover, exec summary, checklist, appendix", () => {
    const loaded = loadConfig(fixture("vulnerable.json"), 2 * 1024 * 1024);
    if (!("config" in loaded)) throw new Error("vulnerable fixture failed to load");
    const html = emitHtml(auditConfig(loaded.config, "0.1.0"));
    for (const marker of [
      "Executive summary",
      "Prioritized fix checklist",
      "Technical findings",
      "Appendix: what static analysis could not assess",
      "Methodology",
      "Static analysis only — not a penetration test",
    ]) {
      expect(html, marker).toContain(marker);
    }
  });

  it("canary secrets never appear in the HTML report (I4)", () => {
    const loaded = loadConfig(fixture("canary.json"), 2 * 1024 * 1024);
    if (!("config" in loaded)) throw new Error("canary fixture failed to load");
    const html = emitHtml(auditConfig(loaded.config, "0.1.0"));
    for (const c of canaries) expect(html).not.toContain(c);
  });

  it("a hostile tool name cannot inject markup (XSS-escaped)", () => {
    const result = auditConfig(
      {
        servers: [
          {
            name: "<script>alert(1)</script>",
            transport: "stdio",
            command: "c",
            version: "1",
            auditLog: true,
            tools: [{ name: "delete_x<img src=x onerror=alert(2)>", params: {} }],
          },
        ],
      },
      "test",
    );
    const html = emitHtml(result);
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("delete_x<img");
    expect(html).toContain("delete_x&lt;img");
  });

  it("`report` re-render is byte-equal to the direct scan --format html", () => {
    const loaded = loadConfig(fixture("vulnerable.json"), 2 * 1024 * 1024);
    if (!("config" in loaded)) throw new Error("vulnerable fixture failed to load");
    const direct = emitHtml(auditConfig(loaded.config, "0.1.0"));
    // Round-trip through the JSON artifact like the operator flow does.
    const json = emitJson(auditConfig(loaded.config, "0.1.0"));
    const tmp = join(mkdtempSync(join(tmpdir(), "html-report-")), "audit.json");
    writeFileSync(tmp, json);
    const parsed = JSON.parse(readFileSync(tmp, "utf8")) as never;
    const rerender = emitHtml(parsed);
    expect(rerender).toBe(direct);
  });

  it("report subcommand rejects a non-audit file", () => {
    const out: string[] = [];
    const errSpy = vi
      .spyOn(console, "error")
      .mockImplementation((...a: unknown[]) => out.push(String(a[0])));
    const code = main(["report", fixture("clean.json"), "--format", "html"]);
    errSpy.mockRestore();
    expect(code).toBe(2);
    expect(out.join(" ")).toContain("not an audit.json");
  });
});

describe("A6 red-team: report re-render trust boundary", () => {
  it("a hostile audit.json with canary details is re-redacted in the HTML", () => {
    const hostile = {
      tool: "mcp-audit",
      toolVersion: "0.0.9",
      framework: "OWASP MCP Top 10 v2025-beta",
      idScheme: "v1",
      schemaVersion: "2.0",
      checks: [
        {
          checkId: "SEC-01",
          status: "fail",
          findings: [
            {
              id: "aaaaaaaaaaaa",
              checkId: "SEC-01",
              status: "fail",
              severity: "high",
              pointer: "servers[0]",
              detail: "live secret ghp_canarytoken12345678 stored in config",
              frameworkRefs: ["x"],
            },
          ],
        },
      ],
      warnings: ["leak attempt ghp_canarytoken12345678"],
    };
    const tmp = join(mkdtempSync(join(tmpdir(), "hostile-")), "audit.json");
    writeFileSync(tmp, JSON.stringify(hostile));
    const out: string[] = [];
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(process.stdout, "write").mockImplementation(((c: unknown) => {
      out.push(String(c));
      return true;
    }) as never);
    const code = main(["report", tmp, "--format", "html"]);
    errSpy.mockRestore();
    expect(code).toBe(0);
    const html = out.join("");
    expect(html).not.toContain("ghp_canarytoken12345678");
    expect(html).not.toContain("CANARY-API-KEY-9f8e7d6c"); // unshaped text is NOT redacted (by design)
    expect(html).toContain("[REDACTED:pattern]");
    void 0;
  });

  it("a forged severity attribute cannot inject markup", () => {
    const forged = {
      tool: "mcp-audit",
      toolVersion: "0.0.9",
      framework: "f",
      idScheme: "v1",
      schemaVersion: "2.0",
      checks: [
        {
          checkId: "SEC-01",
          status: "fail",
          findings: [
            {
              id: "bbbbbbbbbbbb",
              checkId: "SEC-01",
              status: "fail",
              severity: 'critical"><img src=x onerror=alert(1)>',
              pointer: "p",
              detail: "d",
              frameworkRefs: [],
            },
          ],
        },
      ],
      warnings: [],
    };
    const tmp = join(mkdtempSync(join(tmpdir(), "forge-")), "audit.json");
    writeFileSync(tmp, JSON.stringify(forged));
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const code = main(["report", tmp, "--format", "html"]);
    errSpy.mockRestore();
    expect(code).toBe(2); // severity enum validation rejects it
  });
});
