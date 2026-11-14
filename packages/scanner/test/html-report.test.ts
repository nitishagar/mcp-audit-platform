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
