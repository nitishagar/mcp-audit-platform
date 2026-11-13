import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CHECK_IDS } from "../src/checks/index.js";
import { SEVERITY_MAP } from "../src/severity-map.js";

/** Consensus categories from the converged published checklists (I8). */
const CONSENSUS = [
  "MCP01 Token Mismanagement & Secret Exposure",
  "MCP02 Privilege Escalation via Scope Creep",
  "MCP03 Tool Poisoning",
  "MCP04 Software Supply Chain",
  "MCP05 Command Injection & Execution",
  "MCP07 Insufficient Authentication",
  "MCP08 Lack of Audit and Telemetry",
];

describe("category coverage (I8)", () => {
  it("every consensus category has at least one check", () => {
    const covered = new Set(Object.values(SEVERITY_MAP).map((e) => e.category));
    for (const cat of CONSENSUS) {
      expect(covered, `no check covers ${cat}`).toContain(cat);
    }
  });

  it("every checkId has a severity entry", () => {
    for (const id of CHECK_IDS) expect(SEVERITY_MAP[id]).toBeDefined();
  });
});

describe("offline core (I2)", () => {
  it("scanner src imports no network modules", () => {
    const hits: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const p = resolve(dir, entry.name);
        if (entry.isDirectory()) walk(p);
        else if (entry.name.endsWith(".ts")) {
          const content = readFileSync(p, "utf8");
          for (const banned of ["fetch(", "node:http", "axios", "undici", "node:https"]) {
            if (content.includes(banned)) hits.push(`${p}: ${banned}`);
          }
        }
      }
    };
    walk(resolve(dirname(fileURLToPath(import.meta.url)), "../src"));
    expect(hits).toEqual([]);
  });
});
