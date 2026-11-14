import { describe, expect, it } from "vitest";
import { CHECK_IDS } from "../src/checks/index.js";
import { filesystemBreadthCheck } from "../src/checks/tool-privilege.js";
import { auditLogCheck } from "../src/checks/logging.js";
import {
  localhostBindingCheck,
  originValidationCheck,
  remoteAuthCheck,
  tlsCheck,
} from "../src/checks/transport-auth.js";
import { containerPrivilegeCheck, destructiveToolsCheck } from "../src/checks/tool-privilege.js";
import { inventoryCheck } from "../src/checks/inventory.js";
import { auditConfig } from "../src/runner.js";

/** A2: table-driven derivation cases — ≥2 pass and ≥2 fail per changed check. */
function statuses(result: ReturnType<typeof auditConfig>): Map<string, string> {
  return new Map(result.checks.map((c) => [c.checkId, c.status]));
}

describe("INV-01 derives pinning from the launch command (A2)", () => {
  const cases: {
    name: string;
    server: Record<string, unknown>;
    want: "pass" | "fail" | "unassessable";
  }[] = [
    {
      name: "npx pinned",
      server: { command: "npx", args: ["-y", "pkg@1.2.3", "/data"] },
      want: "pass",
    },
    {
      name: "npx scoped pinned",
      server: { command: "npx", args: ["-y", "@org/pkg@2.0.0"] },
      want: "pass",
    },
    { name: "npx unpinned", server: { command: "npx", args: ["-y", "pkg"] }, want: "fail" },
    { name: "npx @latest", server: { command: "npx", args: ["-y", "pkg@latest"] }, want: "fail" },
    { name: "uvx pinned", server: { command: "uvx", args: ["pkg==1.4"] }, want: "pass" },
    { name: "uvx unpinned", server: { command: "uvx", args: ["pkg"] }, want: "fail" },
    {
      name: "docker tagged",
      server: { command: "docker", args: ["run", "-i", "img:1.25"] },
      want: "pass",
    },
    {
      name: "docker digest",
      server: { command: "docker", args: ["run", "img@sha256:abc"] },
      want: "pass",
    },
    {
      name: "docker untagged",
      server: { command: "docker", args: ["run", "-i", "--rm", "org/img"] },
      want: "fail",
    },
    { name: "local binary", server: { command: "billing-mcp", args: [] }, want: "unassessable" },
    {
      name: "native version wins",
      server: { command: "npx", args: ["pkg"], version: "9.9.9" },
      want: "pass",
    },
  ];
  for (const c of cases) {
    it(c.name, () => {
      const result = auditConfig({ servers: [c.server] }, "test");
      expect(statuses(result).get("INV-01")).toBe(c.want);
    });
  }
});

describe("LOG-01 is coverage on client configs (A2)", () => {
  const cases: {
    name: string;
    server: Record<string, unknown>;
    want: "pass" | "fail" | "unassessable";
  }[] = [
    { name: "native true", server: { name: "x", auditLog: true }, want: "pass" },
    { name: "native false is evidence", server: { name: "x", auditLog: false }, want: "fail" },
    { name: "client config: no field", server: { name: "x" }, want: "unassessable" },
  ];
  for (const c of cases) {
    it(c.name, () => {
      const out = auditLogCheck.run({ servers: [c.server] });
      const rows = out.filter((r) => r.pointer.startsWith("servers[0]"));
      expect(rows.length > 0 ? "fail-or-unassessable" : "pass").toBe(
        c.want === "pass" ? "pass" : "fail-or-unassessable",
      );
      if (c.want !== "pass") {
        expect(rows[0]?.status).toBe(c.want);
      }
    });
  }
});

describe("AUTH-01 reads real credential signals (A2)", () => {
  const base = { name: "r", transport: "http", url: "https://api.example.com" };
  const cases: {
    name: string;
    server: Record<string, unknown>;
    want: "pass" | "fail";
  }[] = [
    {
      name: "Authorization header present",
      server: { ...base, headers: { Authorization: "Bearer ${TOKEN}" } },
      want: "pass",
    },
    {
      name: "api-key header present",
      server: { ...base, headers: { "X-Api-Key": "ref" } },
      want: "pass",
    },
    { name: "no headers", server: { ...base }, want: "fail" },
    {
      name: "auth.type none only",
      server: { ...base, auth: { type: "none" } },
      want: "fail",
    },
    {
      name: "auth.type oauth",
      server: { ...base, auth: { type: "oauth" } },
      want: "pass",
    },
    {
      name: "cursor static oauth",
      server: { ...base, auth: { CLIENT_ID: "id" } },
      want: "pass",
    },
  ];
  for (const c of cases) {
    it(c.name, () => {
      const out = remoteAuthCheck.run({ servers: [c.server] });
      expect(out.some((r) => r.status === "fail")).toBe(c.want === "fail");
      expect(out.some((r) => r.status === "unassessable")).toBe(false);
    });
  }
});

describe("AUTH-03 stops failing client configs (A2)", () => {
  it("no native originValidation → coverage-unassessable, never fail", () => {
    const out = originValidationCheck.run({
      servers: [{ name: "r", transport: "http", url: "https://api.example.com" }],
    });
    expect(out).toHaveLength(1);
    expect(out[0]?.status).toBe("unassessable");
  });
  it("native true → pass (no rows); native false → fail", () => {
    const pass = originValidationCheck.run({
      servers: [{ name: "r", transport: "http", url: "https://a.example", originValidation: true }],
    });
    expect(pass).toHaveLength(0);
    const fail = originValidationCheck.run({
      servers: [
        { name: "r", transport: "http", url: "https://a.example", originValidation: false },
      ],
    });
    expect(fail[0]?.status).toBe("fail");
  });
});

describe("AUTH-04 TLS (new, A2)", () => {
  const cases: { name: string; url: string; want: "pass" | "fail" }[] = [
    { name: "https remote", url: "https://api.example.com/mcp", want: "pass" },
    { name: "plain http remote", url: "http://api.example.com/mcp", want: "fail" },
    { name: "loopback http is AUTH-02's", url: "http://localhost:3000/mcp", want: "pass" },
    { name: "0.0.0.0 http", url: "http://0.0.0.0:8080/mcp", want: "pass" },
  ];
  for (const c of cases) {
    it(c.name, () => {
      const out = tlsCheck.run({ servers: [{ name: "r", transport: "http", url: c.url }] });
      expect(out.some((r) => r.status === "fail")).toBe(c.want === "fail");
    });
  }
});

describe("PRIV-01 prefers vendor annotations (A2, spec semantics)", () => {
  const ann = (v: Record<string, unknown>) => ({ name: "t", annotations: v, params: {} });
  it("destructiveHint true → fail; readOnlyHint true → pass", () => {
    const failOut = destructiveToolsCheck.run({
      servers: [{ name: "x", tools: [ann({ readOnlyHint: false, destructiveHint: true })] }],
    });
    expect(failOut.some((r) => r.status === "fail")).toBe(true);
    const passOut = destructiveToolsCheck.run({
      servers: [{ name: "x", tools: [ann({ readOnlyHint: true, destructiveHint: true })] }],
    });
    expect(passOut.some((r) => r.status === "fail")).toBe(false);
  });
  it("non-destructive additive hints → pass", () => {
    const out = destructiveToolsCheck.run({
      servers: [{ name: "x", tools: [ann({ readOnlyHint: false, destructiveHint: false })] }],
    });
    expect(out.some((r) => r.status === "fail")).toBe(false);
  });
  it("unannotated write/delete name → fail; unannotated read name → pass", () => {
    const failOut = destructiveToolsCheck.run({
      servers: [{ name: "x", tools: [{ name: "delete_x", params: {} }] }],
    });
    expect(failOut.some((r) => r.status === "fail")).toBe(true);
    const passOut = destructiveToolsCheck.run({
      servers: [{ name: "x", tools: [{ name: "read_file", params: {} }] }],
    });
    expect(passOut.some((r) => r.status === "fail")).toBe(false);
  });
  it("approval part is coverage, asserted per destructive server", () => {
    const out = destructiveToolsCheck.run({
      servers: [{ name: "x", tools: [{ name: "delete_x", params: {} }] }],
    });
    expect(out.some((r) => r.status === "unassessable" && r.scope === "coverage")).toBe(true);
  });
});

describe("PRIV-03/PRIV-04 (new, A2)", () => {
  it("PRIV-03: / and ~ grants fail; scoped dirs pass", () => {
    const failOut = filesystemBreadthCheck.run({
      servers: [
        { name: "a", command: "npx", args: ["-y", "pkg@1.0", "/"] },
        { name: "b", command: "npx", args: ["-y", "pkg@1.0", "~"] },
      ],
    });
    expect(failOut.filter((r) => r.status === "fail")).toHaveLength(2);
    const passOut = filesystemBreadthCheck.run({
      servers: [{ name: "a", command: "npx", args: ["-y", "pkg@1.0", "/home/dev/app"] }],
    });
    expect(passOut).toHaveLength(0);
  });
  it("PRIV-04: privileged/sock/host-root fail critical; plain docker passes", () => {
    const failOut = containerPrivilegeCheck.run({
      servers: [
        { name: "a", command: "docker", args: ["run", "-i", "--privileged", "img:1"] },
        { name: "b", command: "docker", args: ["run", "-v", "/var/run/docker.sock", "img:1"] },
        { name: "c", command: "docker", args: ["run", "-v", "/:/projects", "img:1"] },
        { name: "d", command: "docker", args: ["run", "--network", "host", "img:1"] },
      ],
    });
    expect(failOut.filter((r) => r.status === "fail")).toHaveLength(4);
    const passOut = containerPrivilegeCheck.run({
      servers: [
        { name: "e", command: "docker", args: ["run", "-i", "--rm", "-v", "/tmp:/w", "img:1"] },
      ],
    });
    expect(passOut).toHaveLength(0);
  });
});

describe("A2 registry invariants", () => {
  it("new checks are registered exactly once", () => {
    for (const id of ["AUTH-04", "PRIV-03", "PRIV-04"]) {
      expect(CHECK_IDS.filter((x) => x === id)).toHaveLength(1);
    }
  });
  it("localhostBindingCheck unchanged on normalized url (A2 plan)", () => {
    const out = localhostBindingCheck.run({
      servers: [{ name: "r", transport: "http", url: "http://0.0.0.0:8080" }],
    });
    expect(out[0]?.status).toBe("fail");
  });
});
