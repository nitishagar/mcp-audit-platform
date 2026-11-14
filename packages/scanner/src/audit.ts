import { CHECKS } from "./checks/index.js";
import { FRAMEWORK, severityFor } from "./severity-map.js";
import {
  type CheckResult,
  type CheckStatus,
  ID_SCHEME,
  type McpConfig,
  type McpServer,
  SCHEMA_VERSION,
  type UnassessableScope,
  makeFinding,
} from "./schema.js";
import { redactString } from "./redact.js";

export const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;

export interface AuditResult {
  tool: string;
  toolVersion: string;
  framework: string;
  idScheme: string;
  /** Result schema version (bumped when status/output semantics change). */
  schemaVersion: string;
  /** Per-check outcomes, in registry order. */
  checks: CheckResult[];
  warnings: string[];
  /** Present in --discover mode: every well-known file that contributed. */
  sources?: { file: string; format: string; servers: number }[];
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

/**
 * Plan-literal dedupe: fold duplicate tool entries per server by (server, tool
 * name), first wins. Unnamed tools are never folded. Returns the folded config
 * plus one warning per suppressed duplicate.
 */
export function dedupeTools(config: McpConfig): { config: McpConfig; warnings: string[] } {
  const warnings: string[] = [];
  const servers = config.servers.map((server, i) => {
    if (server === null || typeof server !== "object") return server;
    if (!Array.isArray(server.tools)) return server;
    const seen = new Set<string>();
    const tools = [];
    for (const tool of server.tools) {
      const name =
        tool !== null && typeof tool === "object" ? (tool as { name?: unknown }).name : undefined;
      if (typeof name !== "string" || !seen.has(name)) {
        if (typeof name === "string") seen.add(name);
        tools.push(tool);
      } else {
        // Tool names are attacker-influenced: route through redaction (F2).
        warnings.push(
          redactString(`duplicate tool "${name}" on servers[${i}] ignored (first wins)`),
        );
      }
    }
    return { ...server, tools };
  });
  return { config: { servers }, warnings };
}

/**
 * A server entry the runner cannot classify at all (none of the transport-
 * identifying keys present) is malformed input, not an assessable server:
 * checks over it would vacuously pass or invent verdicts (A0/E2/E3).
 */
function isClassifiableServer(server: unknown): boolean {
  if (server === null || typeof server !== "object") return false;
  const s = server as McpServer;
  return ["command", "url", "serverUrl", "type", "transport"].some(
    (k) => typeof s[k] === "string" && (s[k] as string).length > 0,
  );
}

function firstMalformedServerIndex(config: McpConfig): number {
  return config.servers.findIndex((s) => !isClassifiableServer(s));
}

/** A remote server per the current classification (url/transport based). */
function isRemoteServer(server: McpServer): boolean {
  if (server.transport === "http" || server.transport === "https") return true;
  return typeof server.url === "string" && /^https?:\/\//i.test(server.url);
}

function hasToolsSomewhere(config: McpConfig): boolean {
  // Only object-shaped entries count as "tool schemas supplied" (A0 red-team
  // fix): a tools array of junk must not turn coverage-unassessable into pass.
  return config.servers.some(
    (s) =>
      s !== null &&
      typeof s === "object" &&
      Array.isArray(s.tools) &&
      s.tools.some((t) => t !== null && typeof t === "object"),
  );
}

/** A1: rewrite `servers[i]` prefixes to the adapter-recorded original path. */
function translatePointer(pointer: string, bases: string[] | undefined): string {
  if (!bases) return pointer;
  const m = /^servers\[(\d+)\](.*)$/.exec(pointer);
  if (!m) return pointer;
  const base = bases[Number(m[1])];
  return base === undefined ? pointer : `${base}${m[2]}`;
}

/** Every check unassessable with scope "input" (gate/malformed paths). */
function unassessableAll(
  toolVersion: string,
  reason: string,
  pointer: string,
): { result: AuditResult } {
  const checks: CheckResult[] = CHECKS.map((check) => {
    const resolved = severityFor(check.id);
    return {
      checkId: check.id,
      status: "unassessable" as const,
      scope: "input" as const,
      findings: [
        makeFinding(
          check.id,
          "unassessable",
          resolved.severity,
          pointer,
          redactString(reason),
          [`${FRAMEWORK}: ${resolved.category}`],
          resolved.unmapped,
          "input",
        ),
      ],
    };
  });
  return {
    result: {
      tool: "mcp-audit",
      toolVersion,
      framework: FRAMEWORK,
      idScheme: ID_SCHEME,
      schemaVersion: SCHEMA_VERSION,
      checks,
      warnings: [],
    },
  };
}

function coverageUnassessable(check: { id: string }, reason: string): CheckResult {
  const resolved = severityFor(check.id);
  return {
    checkId: check.id,
    status: "unassessable",
    scope: "coverage",
    findings: [
      makeFinding(
        check.id,
        "unassessable",
        resolved.severity,
        "servers",
        redactString(reason),
        [`${FRAMEWORK}: ${resolved.category}`],
        resolved.unmapped,
        "coverage",
      ),
    ],
  };
}

/**
 * Build an AuditResult for a config that passed the gate.
 *
 * A0 anti-vacuous-pass rules:
 * - a server entry classifiable as none of stdio/remote is malformed input →
 *   every check unassessable with scope "input" (exit 2);
 * - a check whose `requires` includes "tools" with no tool schemas anywhere →
 *   unassessable with scope "coverage" (reported, no exit effect);
 * - a check whose `requires` includes "remote" with no remote server →
 *   "not_applicable" (distinct from pass, no findings, no exit effect).
 */
export function auditConfig(
  config: McpConfig,
  toolVersion: string,
  pointerBases?: string[],
  adapterWarnings?: string[],
): AuditResult {
  const malformed = firstMalformedServerIndex(config);
  if (malformed >= 0) {
    return unassessableAll(
      toolVersion,
      `servers[${malformed}] declares none of command/url/serverUrl/type/transport; malformed server entry`,
      "servers",
    ).result;
  }
  if (config.servers.length === 0) {
    // A1 red-team residual: an adapter may deliver zero servers (all skipped
    // with warnings) — that is an input problem, never a vacuous all-pass.
    return unassessableAll(toolVersion, "no server entries found in the input", "config").result;
  }
  const folded = dedupeTools(config);
  const toolsAvailable = hasToolsSomewhere(folded.config);
  const remotePresent = folded.config.servers.some((s) => isRemoteServer(s));
  const checks: CheckResult[] = CHECKS.map((check) => {
    // Applicability gate: a check without its inputs never says "pass".
    if (check.requires.includes("tools") && !toolsAvailable) {
      return coverageUnassessable(
        check,
        "no tool schemas supplied (pass --tools or use native format with tools[])",
      );
    }
    if (check.requires.includes("remote") && !remotePresent) {
      return { checkId: check.id, status: "not_applicable", findings: [] };
    }
    let status: CheckStatus = "pass";
    try {
      const raw = check.run(folded.config);
      if (raw.length > 0) {
        status = raw.some((r) => r.status === "fail") ? "fail" : "unassessable";
        const resolved = severityFor(check.id);
        const findings = raw.map((r) =>
          makeFinding(
            check.id,
            r.status,
            resolved.severity,
            // A1 red-team Medium 2: translate to the original-file location
            // BEFORE redaction so attacker-named pointer bases are scrubbed.
            redactString(translatePointer(r.pointer, pointerBases)),
            redactString(r.detail),
            [`${FRAMEWORK}: ${resolved.category}`, ...resolved.cveRefs, ...(r.refs ?? [])],
            resolved.unmapped,
            // Check-returned unassessable rows are coverage-scoped unless the
            // check declares otherwise (A2 sets per-row scope explicitly).
            r.status === "unassessable" ? (r.scope ?? "coverage") : undefined,
          ),
        );
        // Canonical order: sort by (checkId, pointer).
        findings.sort((a, b) => a.pointer.localeCompare(b.pointer));
        return {
          checkId: check.id,
          status,
          ...(status === "unassessable" ? { scope: "coverage" as const } : {}),
          findings,
        };
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
        scope: "input" as const,
        findings: [
          makeFinding(
            check.id,
            "unassessable",
            resolved.severity,
            "servers",
            detail,
            [`${FRAMEWORK}: ${resolved.category}`],
            resolved.unmapped,
            "input",
          ),
        ],
      };
    }
  });

  return {
    tool: "mcp-audit",
    toolVersion,
    framework: FRAMEWORK,
    idScheme: ID_SCHEME,
    schemaVersion: SCHEMA_VERSION,
    checks,
    warnings: [...folded.warnings, ...(adapterWarnings ?? [])],
  };
}

/**
 * A4 zero-found result (M-3): --discover on a machine where no client config
 * exists audits nothing — every check is not_applicable and the run exits 0
 * (a CI-friendly "nothing to audit"), never a vacuous pass. The caller
 * decides between this (absent files, zero warnings) and gateFailureResult
 * (files present but unreadable — still exit 2).
 */
export function notApplicableAll(
  toolVersion: string,
  warnings: string[],
  sources: { file: string; format: string; servers: number }[] = [],
): AuditResult {
  const checks: CheckResult[] = CHECKS.map((check) => ({
    checkId: check.id,
    status: "not_applicable",
    findings: [],
  }));
  return {
    tool: "mcp-audit",
    toolVersion,
    framework: FRAMEWORK,
    idScheme: ID_SCHEME,
    schemaVersion: SCHEMA_VERSION,
    checks,
    warnings,
    sources,
  };
}

/** Gate-failure result: every check unassessable (scope "input"), zero pass (I1). */
export function gateFailureResult(reason: string, toolVersion: string): AuditResult {
  return unassessableAll(toolVersion, reason, "config").result;
}
