import { createHash } from "node:crypto";

export const ID_SCHEME = "v1" as const;

export type Severity = "critical" | "high" | "medium" | "low";
export type CheckStatus = "pass" | "fail" | "unassessable" | "not_applicable";
/**
 * Why a check is unassessable (spec amendment, PLAN-PRODUCT-COMPLETE §1):
 * - "input": the input itself could not be read/understood (gate failure,
 *   malformed server entry, or the check threw). Exit-code effect (2).
 * - "coverage": the property cannot be determined from this input type.
 *   Reported, never pass (I1), no exit-code effect (--strict opts into 2).
 */
export type UnassessableScope = "input" | "coverage";

/** Result schema version. Bumped when status/output semantics change; ids are v1. */
export const SCHEMA_VERSION = "2.0" as const;

export const SEVERITY_RANK: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/** A single audit finding. `detail` must already be redacted at construction. */
export interface Finding {
  /** Stable id: sha1(checkId|pointer|normalizedDetail)[0:12], non-security use. */
  id: string;
  checkId: string;
  status: Exclude<CheckStatus, "pass" | "not_applicable">;
  severity: Severity;
  /** JSON-pointer-ish location, e.g. servers[0].auth. Never contains values. */
  pointer: string;
  /** Human-readable, redacted. Never contains secret values. */
  detail: string;
  frameworkRefs: string[];
  unmapped?: boolean;
  /** Present on unassessable findings: why we could not assess. */
  scope?: UnassessableScope;
}

export interface CheckResult {
  checkId: string;
  status: CheckStatus;
  /** Present when status is "unassessable": why (see UnassessableScope). */
  scope?: UnassessableScope;
  findings: Finding[];
}

/** Loose input shape; the runner validates the minimal gate before checks. */
export interface McpConfig {
  servers: McpServer[];
}

export interface McpServer {
  name?: string;
  transport?: string;
  command?: string;
  url?: string;
  bind?: string;
  version?: string;
  auth?: { type?: string };
  originValidation?: boolean;
  auditLog?: boolean;
  tools?: McpTool[];
  [key: string]: unknown;
}

export interface McpTool {
  name?: string;
  description?: string;
  params?: Record<string, unknown> | unknown[];
  requireApproval?: boolean;
  [key: string]: unknown;
}

export function stableFindingId(checkId: string, pointer: string, detail: string): string {
  const normalized = detail.trim().replace(/\s+/g, " ");
  return createHash("sha1")
    .update(`${checkId}|${pointer}|${normalized}`)
    .digest("hex")
    .slice(0, 12);
}

export function makeFinding(
  checkId: string,
  status: Exclude<CheckStatus, "pass" | "not_applicable">,
  severity: Severity,
  pointer: string,
  detail: string,
  frameworkRefs: string[],
  unmapped = false,
  scope?: UnassessableScope,
): Finding {
  return {
    id: stableFindingId(checkId, pointer, detail),
    checkId,
    status,
    severity,
    pointer,
    detail,
    frameworkRefs,
    ...(unmapped ? { unmapped: true as const } : {}),
    ...(scope ? { scope } : {}),
  };
}
