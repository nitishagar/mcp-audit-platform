import { lstatSync, readFileSync } from "node:fs";
import { FormatError, normalizeFile } from "./adapters/index.js";
import type { ClientFormat, NormalizedConfig } from "./adapters/types.js";
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

/** Read+parse a JSON file with the F1b/F1 guards (symlinks, FIFOs, cap, no echo). */
export function readJsonFile(
  path: string,
  maxBytes: number,
): { parsed: unknown } | { error: LoadError } {
  let stat: { size: number; isSymbolicLink: () => boolean; isFile: () => boolean };
  try {
    stat = lstatSync(path);
  } catch {
    return { error: { kind: "parse", message: `cannot read ${path}` } };
  }
  // Refuse symlinks (F1b: arbitrary-file-prefix disclosure) and non-regular
  // files (FIFOs hang the read; devices lie about size).
  if (stat.isSymbolicLink()) {
    return { error: { kind: "parse", message: `${path} is a symlink; refusing to scan` } };
  }
  if (!stat.isFile()) {
    return { error: { kind: "parse", message: `${path} is not a regular file; refusing to scan` } };
  }
  const size = stat.size;
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
  } catch (err) {
    // Never echo raw input: key-context secrets survive pattern scrubbing (F1).
    // Only the parser's error position (a number, never input) is reported.
    const position = /position (\d+)/.exec(err instanceof Error ? err.message : "")?.[1];
    const where = position !== undefined ? ` at position ${position}` : "";
    return { error: { kind: "parse", message: `${path} is not valid JSON${where}` } };
  }
  return { parsed };
}

/** Native-shape loader (fixtures/back-compat): read + strict servers[] gate. */
export function loadConfig(
  path: string,
  maxBytes: number,
): { config: McpConfig } | { error: LoadError } {
  const loaded = readJsonFile(path, maxBytes);
  if ("error" in loaded) return loaded;
  if (!validateShape(loaded.parsed)) {
    return {
      error: {
        kind: "shape",
        message: `${path} must be a JSON object with a non-empty "servers" array`,
      },
    };
  }
  return { config: loaded.parsed as McpConfig };
}

export interface LoadedAudit {
  config: NormalizedConfig;
  pointerBases: string[];
  format: ClientFormat;
  /** Adapter-level warnings (e.g. skipped malformed Claude Code projects). */
  adapterWarnings: string[];
}

/**
 * A1 loader: read any supported client format (or native) and normalize it.
 * Unknown shapes are a clean exit-2 with the supported list — never a guess.
 */
export function loadConfigAny(
  path: string,
  maxBytes: number,
  client?: ClientFormat,
): { loaded: LoadedAudit } | { error: LoadError } {
  const file = readJsonFile(path, maxBytes);
  if ("error" in file) return file;
  try {
    const { config, format, warnings } = normalizeFile(file.parsed, client);
    return {
      loaded: {
        config,
        format,
        pointerBases: config.servers.map((s) => s._pointerBase),
        adapterWarnings: warnings,
      },
    };
  } catch (err) {
    if (err instanceof FormatError) {
      return { error: { kind: "shape", message: redactString(`${path}: ${err.message}`) } };
    }
    throw err;
  }
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

/** A1: rewrite `servers[i]` prefixes to the adapter-recorded original path. */
function translatePointer(pointer: string, bases: string[] | undefined): string {
  if (!bases) return pointer;
  const m = /^servers\[(\d+)\](.*)$/.exec(pointer);
  if (!m) return pointer;
  const base = bases[Number(m[1])];
  return base === undefined ? pointer : `${base}${m[2]}`;
}

function firstMalformedServerIndex(config: McpConfig): number {
  return config.servers.findIndex((s) => !isClassifiableServer(s));
}

/** A remote server per the current classification (url/transport based). */
function isRemoteServer(server: McpServer): boolean {
  if (server.transport === "http" || server.transport === "https") return true;
  return typeof server.url === "string" && /^https?:\/\//.test(server.url);
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
  if (malformed < 0 && config.servers.length === 0) {
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

/** Gate-failure result: every check unassessable (scope "input"), zero pass (I1). */
export function gateFailureResult(reason: string, toolVersion: string): AuditResult {
  return unassessableAll(toolVersion, reason, "config").result;
}
