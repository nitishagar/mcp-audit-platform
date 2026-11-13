import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { emitJson, emitSarif, emitSummary } from "../src/emit.js";
import { isDenylistedKey, redactString, redactValue } from "../src/redact.js";
import { auditConfig, loadConfig } from "../src/runner.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => resolve(here, "../fixtures", name);

/** Every secret value planted in canary.json / corrupt.json. */
const CANARIES = [
  "CANARY-API-KEY-9f8e7d6c",
  "https://hooks.slack.com/services/CANARY/WEBHOOK/VALUE",
  "CANARYPEM-BODY-1234",
  "ghp_canarytoken12345678",
  "AKIAIOSFODNN7CANARY01",
];
const CORRUPT_SECRET = "https://hooks.slack.com/services/T000/B000/CORRUPTSEED";

describe("redaction (I4)", () => {
  it("zero canary values in JSON, SARIF, and summary outputs", () => {
    const raw = JSON.parse(readFileSync(fixture("canary.json"), "utf8"));
    const result = auditConfig(raw, "test");
    const outputs = [emitJson(result), emitSarif(result), emitSummary(result)];
    for (const canary of CANARIES) {
      for (const out of outputs) {
        expect(out, `leaked ${canary}`).not.toContain(canary);
      }
    }
    // …but the locations are still reported.
    const json = outputs[0] as string;
    expect(json).toContain("api_key");
    expect(json).toContain("[REDACTED:");
  });

  it("zero corrupt-fixture secret in the parse-error (stderr) message", () => {
    const loaded = loadConfig(fixture("corrupt.json"), 2 * 1024 * 1024);
    expect("error" in loaded).toBe(true);
    if ("error" in loaded) {
      expect(loaded.error.message).not.toContain(CORRUPT_SECRET);
      expect(loaded.error.message).toContain("[REDACTED:pattern]");
    }
  });

  it("redactValue replaces denylisted keys wholesale and scrubs shapes", () => {
    expect(redactValue("api_key", "live-value-1")).toBe("[REDACTED:api_key]");
    expect(redactValue("auth_token", "live-value-2")).toBe("[REDACTED:auth_token]");
    expect(redactString("key sk-ant-secretvalue99 here")).toBe("key [REDACTED:pattern] here");
    expect(redactValue("notes", "nothing secret")).toBe("nothing secret");
  });

  it("innocent keys containing denylist substrings are not secrets (F1)", () => {
    // `author` contains `auth` — substring matching would false-positive here.
    expect(isDenylistedKey("author")).toBe(false);
    expect(isDenylistedKey("authentication")).toBe(false);
    expect(isDenylistedKey("authorized_by")).toBe(false);
    const config = {
      servers: [
        {
          name: "t",
          transport: "stdio",
          command: "c",
          version: "1",
          auditLog: true,
          author: "Alice Cooper",
          tools: [],
        },
      ],
    };
    const result = auditConfig(config, "test");
    const sec01 = result.checks.find((c) => c.checkId === "SEC-01");
    expect(sec01?.status).toBe("pass");
  });

  it("segment-aware matching still catches compound credential keys", () => {
    for (const key of [
      "api_key",
      "apiKey",
      "auth_token",
      "webhook_url",
      "clientSecret",
      "bearer",
      "private_key",
      "privateKey",
      "access_key",
      "accessKey",
    ]) {
      expect(isDenylistedKey(key), key).toBe(true);
    }
  });
});
