import { readFileSync, statSync } from "node:fs";
import { CHECKS } from "./checks/index.js";
import { FRAMEWORK, severityFor } from "./severity-map.js";
import {
  type CheckResult,
  type CheckStatus,
  ID_SCHEME,
  type McpConfig,
  makeFinding,
} from "./schema.js";
import { redactString } from "./redact.js";

export const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;

export interface AuditResult {
  tool: string;
  toolVersion: string;
  framework: string;
  idScheme: string;
  /** Per-check outcomes, in registry order. */
  checks: CheckResult[];
  warnings: string[];
}

export interface LoadError {
  kind: "oversize" | "parse" | "shape";
  /** Already redacted, safe for stderr. */
  message: string;
}

/** Input-validation gate: object with a non-empty servers array. */
export function validateShape(parsed: unknown): parsed is McpConfig {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return false;
  const servers = (parsed as { servers?: unknown }).servers;
  return Array.isArray(servers) && servers.length > 0;
}

export function loadConfig(
  path: string,
  maxBytes: number,
): { config: McpConfig } | { error: LoadError } {
  let size: number;
  try {
    size = statSync(path).size;
  } catch {
    return { error: { kind: "parse", message: `cannot read ${path}` } };
  }
  if (size > maxBytes) {
    return {
      error: {
        kind: "oversize",
        message: `${path} is ${size} bytes (cap ${maxBytes}); raise --max-bytes to scan it`,
      },
    };
  }
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return { error: { kind: "parse", message: `cannot read ${path}` } };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Never echo raw input: even the snippet is redacted (H2 teeth).
    const snippet = redactString(raw.slice(0, 200));
    return { error: { kind: "parse", message: `${path} is not valid JSON: ${snippet}` } };
  }
  if (!validateShape(parsed)) {
    return {
      error: {
        kind: "shape",
        message: `${path} must be a JSON object with a non-empty "servers" array`,
      },
    };
  }
  return { config: parsed };
}

/** Build an AuditResult for a config that passed the gate. */
export function auditConfig(config: McpConfig, toolVersion: string): AuditResult {
  const checks: CheckResult[] = CHECKS.map((check) => {
    let status: CheckStatus = "pass";
    try {
      const raw = check.run(config);
      if (raw.length > 0) {
        status = raw.some((r) => r.status === "fail") ? "fail" : "unassessable";
        const findings = raw.map((r) => {
          const resolved = severityFor(check.id);
          return makeFinding(
            check.id,
            r.status,
            resolved.severity,
            r.pointer,
            redactString(r.detail),
            [`${FRAMEWORK}: ${resolved.category}`, ...resolved.cveRefs],
            resolved.unmapped,
          );
        });
        // Canonical order: sort by (checkId, pointer).
        findings.sort((a, b) => a.pointer.localeCompare(b.pointer));
        return { checkId: check.id, status, findings };
      }
      return { checkId: check.id, status, findings: [] };
    } catch (err) {
      // Catch-and-convert: a throwing check is unassessable, never silent.
      const resolved = severityFor(check.id);
      const detail = redactString(
        `check ${check.id} errored during execution: ${err instanceof Error ? err.message : String(err)}`,
      );
      return {
        checkId: check.id,
        status: "unassessable" as const,
        findings: [
          makeFinding(
            check.id,
            "unassessable",
            resolved.severity,
            "servers",
            detail,
            [`${FRAMEWORK}: ${resolved.category}`],
            resolved.unmapped,
          ),
        ],
      };
    }
  });

  // Deterministic dedupe by (checkId, pointer): first wins, one warning.
  const seen = new Set<string>();
  const warnings: string[] = [];
  for (const result of checks) {
    result.findings = result.findings.filter((f) => {
      const key = `${f.checkId}|${f.pointer}`;
      if (seen.has(key)) {
        warnings.push(`duplicate finding suppressed: ${key} (first wins)`);
        return false;
      }
      seen.add(key);
      return true;
    });
    if (result.findings.length === 0) result.status = "pass";
  }

  return {
    tool: "mcp-audit",
    toolVersion,
    framework: FRAMEWORK,
    idScheme: ID_SCHEME,
    checks,
    warnings,
  };
}

/** Gate-failure result: every check unassessable, zero pass (I1). */
export function gateFailureResult(reason: string, toolVersion: string): AuditResult {
  const checks: CheckResult[] = CHECKS.map((check) => {
    const resolved = severityFor(check.id);
    return {
      checkId: check.id,
      status: "unassessable" as const,
      findings: [
        makeFinding(
          check.id,
          "unassessable",
          resolved.severity,
          "config",
          redactString(reason),
          [`${FRAMEWORK}: ${resolved.category}`],
          resolved.unmapped,
        ),
      ],
    };
  });
  return {
    tool: "mcp-audit",
    toolVersion,
    framework: FRAMEWORK,
    idScheme: ID_SCHEME,
    checks,
    warnings: [],
  };
}
