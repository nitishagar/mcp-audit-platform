import { createHash } from "node:crypto";

export const ID_SCHEME = "v1" as const;

export type Severity = "critical" | "high" | "medium" | "low";
export type CheckStatus = "pass" | "fail" | "unassessable";

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
  status: Exclude<CheckStatus, "pass">;
  severity: Severity;
  /** JSON-pointer-ish location, e.g. servers[0].auth. Never contains values. */
  pointer: string;
  /** Human-readable, redacted. Never contains secret values. */
  detail: string;
  frameworkRefs: string[];
  unmapped?: boolean;
}

export interface CheckResult {
  checkId: string;
  status: CheckStatus;
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
  status: Exclude<CheckStatus, "pass">,
  severity: Severity,
  pointer: string,
  detail: string,
  frameworkRefs: string[],
  unmapped = false,
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
  };
}
