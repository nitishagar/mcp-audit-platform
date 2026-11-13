import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { HELP } from "../src/cli.js";

const here = dirname(fileURLToPath(import.meta.url));

describe("honesty disclaimer (I9, tool side)", () => {
  it("CLI --help carries the static-analysis disclaimer", () => {
    expect(HELP).toContain("Static analysis only");
    expect(HELP).toContain("not a penetration test");
  });

  it("scanner and root READMEs carry the disclaimer", () => {
    for (const path of [resolve(here, "../README.md"), resolve(here, "../../../README.md")]) {
      const content = readFileSync(path, "utf8");
      expect(content, path).toContain("Static analysis only");
      expect(content, path).toMatch(/not a penetest|not a penetration test/);
    }
  });
});
