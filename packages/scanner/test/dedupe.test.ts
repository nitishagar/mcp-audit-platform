import { describe, expect, it } from "vitest";
import { auditConfig, dedupeTools } from "../src/runner.js";

function dupeConfig() {
  return {
    servers: [
      {
        name: "d",
        transport: "stdio",
        command: "c",
        version: "1",
        auditLog: true,
        tools: [
          { name: "delete_x", params: {} },
          { name: "delete_x", params: {} },
          { name: "ping", params: {} },
        ],
      },
    ],
  };
}

describe("tool dedupe (plan: first wins + one warning)", () => {
  it("folds duplicate tools by (server, name), first wins", () => {
    const { config, warnings } = dedupeTools(dupeConfig());
    const names = (config.servers[0] as { tools: { name: string }[] }).tools.map((t) => t.name);
    expect(names).toEqual(["delete_x", "ping"]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('duplicate tool "delete_x"');
  });

  it("audit emits one fail + one approval-coverage row plus one warning for duplicates", () => {
    const result = auditConfig(dupeConfig(), "test");
    const priv = result.checks.find((c) => c.checkId === "PRIV-01");
    expect(priv?.findings).toHaveLength(2); // 1 fail (delete_x) + 1 approval-coverage row (A2)
    expect(priv?.findings.filter((f) => f.status === "fail")).toHaveLength(1);
    expect(result.warnings).toHaveLength(1);
  });

  it("no warnings when tools are unique", () => {
    const { warnings } = dedupeTools({
      servers: [{ name: "d", tools: [{ name: "a" }, { name: "b" }] }],
    });
    expect(warnings).toHaveLength(0);
  });

  it("secret-shaped tool names are redacted in warnings (F2)", () => {
    const token = "ghp_abcdefghij12345678";
    const { warnings } = dedupeTools({
      servers: [{ name: "s", tools: [{ name: token }, { name: token }] }],
    });
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).not.toContain(token);
    expect(warnings[0]).toContain("[REDACTED:pattern]");
  });
});
