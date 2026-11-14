import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const script = resolve(here, "../../../scripts/mule-capture.mjs");

function runCapture(sandbox: string): { out: string; code: number } {
  let out = "";
  let code = 0;
  try {
    out = execFileSync(
      process.execPath,
      [
        script,
        "--prefix",
        resolve(here, "../../../"),
        "--sandbox",
        sandbox,
        "--out",
        join(mkdtempSync(join(tmpdir(), "guard-")), "c.json"),
      ],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    code = 0;
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string; message?: string };
    code = e.status ?? 1;
    out = `${e.stdout ?? ""}${e.stderr ?? ""}${e.message ?? ""}`;
  }
  return { out, code };
}

describe("mule-capture sandbox guard (§9.5, M-2)", () => {
  it("refuses a sandbox outside os.tmpdir()", () => {
    const { out, code } = runCapture("/etc");
    expect(code).not.toBe(0);
    expect(out).toContain("refusing");
    expect(out).toContain("os.tmpdir");
  });

  it("refuses a missing sandbox dir", () => {
    const { out, code } = runCapture(join(tmpdir(), "definitely-missing-mule-dir"));
    expect(code).not.toBe(0);
    expect(out).toContain("does not exist");
  });

  it("accepts a sandbox under tmpdir (proceeds past the guard)", () => {
    const sandbox = mkdtempSync(join(tmpdir(), "mule-ok-"));
    const { out, code } = runCapture(sandbox);
    // No server installed in this prefix -> it fails AFTER the guard, on the
    // entry lookup, never before (proves the guard passed).
    expect(out).not.toContain("refusing");
    expect(code).not.toBe(0); // fails on missing server entry, as expected here
  });
});
