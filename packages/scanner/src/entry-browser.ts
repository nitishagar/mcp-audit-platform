/**
 * C4 browser entry: the pure audit surface with NO node builtins.
 * Exports used by the site bundle (dist/scan.js): scanString parses a
 * config-file text and returns the AuditResult OBJECT; renderReport renders
 * the A6 HTML pack from it. Finding ids are byte-identical across runtimes
 * (pure SHA-1 in core/sha1.ts — pinned in test/core-id.test.ts).
 */
import { auditConfig, type AuditResult } from "./audit.js";
import { FormatError, normalizeFile } from "./adapters/index.js";
import { redactString } from "./redact.js";
import { emitHtml } from "./emit-html.js";

export interface BrowserScan {
  result: AuditResult | null;
  gateError: string | null;
}

export function scan(source: string): BrowserScan {
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    return { result: null, gateError: "input is not valid JSON" };
  }
  try {
    // Full adapter path: mcpServers family, VS Code, claude-code, native —
    // identical verdicts to the CLI (parity pinned in scan-parity.test.mjs).
    const { config, format, warnings } = normalizeFile(parsed);
    const pointerBases = config.servers.map((s) => s._pointerBase);
    const result = auditConfig(config, `browser (${format})`, pointerBases, warnings);
    return { result, gateError: null };
  } catch (err) {
    if (err instanceof FormatError) {
      return { result: null, gateError: redactString(err.message) };
    }
    throw err;
  }
}

export function renderReport(result: AuditResult): string {
  return emitHtml(result);
}

export function redactForDisplay(s: string): string {
  return redactString(s);
}

/** Summary text (mirrors emitSummary's counts line minus the node-only emitter). */
export function summaryCounts(result: AuditResult): string {
  const fails = result.checks.flatMap((c) => c.findings.filter((f) => f.status === "fail"));
  const passed = result.checks.filter((c) => c.status === "pass").length;
  const cov = result.checks.filter(
    (c) => c.status === "unassessable" && c.scope === "coverage",
  ).length;
  const na = result.checks.filter((c) => c.status === "not_applicable").length;
  return `${passed} passed, ${fails.length} finding(s), ${cov} not determinable, ${na} not applicable`;
}
