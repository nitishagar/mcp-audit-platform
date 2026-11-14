import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { sha1Hex } from "../src/core/sha1.js";
import { auditConfig } from "../src/runner.js";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const vectors: [string, string][] = [
  ["", "da39a3ee5e6b4b0d3255bfef95601890afd80709"],
  ["abc", "a9993e364706816aba3e25717850c26c9cd0d89d"],
  ["The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"],
  ["mcp-audit|servers[0]|x".repeat(500), ""],
];

describe("pure SHA-1 (C4)", () => {
  for (const [input, want] of vectors) {
    it(`matches node:crypto for ${input.slice(0, 40).length > 40 ? "long" : JSON.stringify(input.slice(0, 20))}`, () => {
      const expected = want || createHash("sha1").update(input).digest("hex");
      expect(sha1Hex(input)).toBe(expected);
    });
  }

  it("finding ids are identical whether computed via sha1Hex or node:crypto", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const vulnerable = JSON.parse(
      readFileSync(resolve(here, "../fixtures/vulnerable.json"), "utf8"),
    );
    const result = auditConfig(vulnerable, "test");
    for (const f of result.checks.flatMap((c) => c.findings)) {
      const viaNode = createHash("sha1")
        .update(`${f.checkId}|${f.pointer}|${f.detail.trim().replace(/\s+/g, " ")}`)
        .digest("hex")
        .slice(0, 12);
      expect(f.id, f.pointer).toBe(viaNode);
    }
  });
});
