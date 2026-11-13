import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const css = readFileSync(resolve(here, "../tokens.css"), "utf8");
const oracle = JSON.parse(readFileSync(resolve(here, "../vendor/pi-web-tokens.json"), "utf8"));

function parseBlock(cssText, startMarker) {
  const start = cssText.indexOf(startMarker);
  const end = cssText.indexOf("}", start);
  const block = cssText.slice(start, end);
  const vars = {};
  for (const m of block.matchAll(/--([a-z-]+):\s*([^;]+);/g)) {
    vars[m[1]] = m[2].replace(/\s+/g, " ").trim();
  }
  return vars;
}

const norm = (s) => String(s).replace(/\s+/g, " ").trim();

describe("theme tokens (I6)", () => {
  it("dark vars equal the vendored pi.dev values", () => {
    const dark = parseBlock(css, ":root {");
    for (const [k, v] of Object.entries(oracle.dark)) {
      expect(dark[k], `--${k} drifted from pi.dev`).toBe(norm(v));
    }
  });

  it("light vars equal the vendored pi.dev values", () => {
    const light = parseBlock(css, ':root[data-theme="light"] {');
    for (const [k, v] of Object.entries(oracle.light)) {
      expect(light[k], `--${k} drifted from pi.dev`).toBe(norm(v));
    }
  });

  it("font stacks equal the vendored pi.dev values", () => {
    const dark = parseBlock(css, ":root {");
    for (const [k, v] of Object.entries(oracle.fonts)) {
      expect(dark[k], `--${k} drifted from pi.dev`).toBe(norm(v));
    }
  });

  it("both themes define the identical var set", () => {
    const dark = Object.keys(parseBlock(css, ":root {")).sort();
    const light = Object.keys(parseBlock(css, ':root[data-theme="light"] {')).sort();
    expect(light).toEqual(dark);
  });
});
