import type { Severity } from "./schema.js";

/** Pinned framework vocabulary. Beta wording may move; the pin records what we mapped. */
export const FRAMEWORK = "OWASP MCP Top 10 v2025-beta" as const;

export interface SeverityEntry {
  category: string;
  severity: Severity;
  /** Informational CVE refs from research; severity derives from category only (B8). */
  cveRefs: string[];
}

/** Per-check severity mapping. Checks missing here default to medium + unmapped. */
export const SEVERITY_MAP: Record<string, SeverityEntry> = {
  "INV-01": {
    category: "MCP04 Software Supply Chain Attacks & Dependency Tampering",
    severity: "medium",
    cveRefs: [],
  },
  "AUTH-01": {
    category: "MCP07 Insufficient Authentication & Authorization",
    severity: "high",
    cveRefs: [],
  },
  "AUTH-02": {
    category: "MCP07 Insufficient Authentication & Authorization",
    severity: "high",
    cveRefs: [],
  },
  "AUTH-03": {
    category: "MCP07 Insufficient Authentication & Authorization",
    severity: "high",
    cveRefs: ["CVE-2025-49596"],
  },
  "AUTH-04": {
    category: "MCP07 Insufficient Authentication & Authorization",
    severity: "high",
    cveRefs: [],
  },
  "PRIV-01": {
    category: "MCP02 Privilege Escalation via Scope Creep",
    severity: "high",
    cveRefs: [],
  },
  "PRIV-02": {
    category: "MCP02 Privilege Escalation via Scope Creep",
    severity: "medium",
    cveRefs: [],
  },
  "PRIV-03": {
    category: "MCP02 Privilege Escalation via Scope Creep",
    severity: "high",
    cveRefs: [],
  },
  "PRIV-04": {
    category: "MCP02 Privilege Escalation via Scope Creep",
    severity: "critical",
    cveRefs: [],
  },
  "ARG-01": { category: "MCP05 Command Injection & Execution", severity: "medium", cveRefs: [] },
  "ARG-02": {
    category: "MCP03 Tool Poisoning",
    severity: "critical",
    cveRefs: ["CVE-2025-54136"],
  },
  "SEC-01": {
    category: "MCP01 Token Mismanagement & Secret Exposure",
    severity: "high",
    cveRefs: [],
  },
  "SEC-02": {
    category: "MCP01 Token Mismanagement & Secret Exposure",
    severity: "critical",
    cveRefs: [],
  },
  "LOG-01": { category: "MCP08 Lack of Audit and Telemetry", severity: "medium", cveRefs: [] },
};

export interface ResolvedSeverity extends SeverityEntry {
  unmapped: boolean;
}

export function severityFor(checkId: string): ResolvedSeverity {
  const entry = SEVERITY_MAP[checkId];
  if (entry) return { ...entry, unmapped: false };
  return { category: "unmapped", severity: "medium", cveRefs: [], unmapped: true };
}
