#!/usr/bin/env node
/**
 * mcp-audit CLI: deterministic offline static audit of MCP configs.
 * Static analysis only — not a penetration test; never probes live systems.
 */
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { type Format, emit } from "./emit.js";
import { emitHtml } from "./emit-html.js";
import { redactString } from "./redact.js";
import {
  DEFAULT_MAX_BYTES,
  type AuditResult,
  auditConfig,
  gateFailureResult,
  loadConfigAny,
  notApplicableAll,
  readJsonFile,
} from "./runner.js";
import { discoverConfigs } from "./adapters/discover.js";
import { parseToolsFile } from "./adapters/tools.js";
import { CLIENT_FORMATS, type ClientFormat } from "./adapters/types.js";
import { SEVERITY_RANK, type Severity } from "./schema.js";

/**
 * B1: single source of truth for the tool version — the package manifest.
 * dist/cli.js -> ../../package.json resolves to packages/scanner/package.json.
 */
const VERSION = (() => {
  try {
    const pkgPath = resolve(dirname(fileURLToPath(import.meta.url)), "../../package.json");
    return (JSON.parse(readFileSync(pkgPath, "utf8")) as { version: string }).version;
  } catch {
    return "0.0.0";
  }
})();

export const HELP = `mcp-audit ${VERSION} — static MCP / AI agent config audit

Usage:
  mcp-audit scan <config.json> [--format json|sarif|summary|all]
    [--out-dir <dir>] [--fail-on critical|high|medium|low] [--max-bytes <n>]
    [--strict] [--client claude-desktop|claude-code|cursor|vscode|windsurf|native]
  mcp-audit report <audit.json> [--format html]   # re-render a saved audit
    [--tools tools-list.json]  # replaces any native tools[] on matched servers
  mcp-audit scan --discover    # audit every well-known client config in one run

Formats: a single format writes to stdout; "all" writes audit.json,
audit.sarif, report.html and summary.md into --out-dir (default ./audit-out).

Input: auto-detects the client format (mcpServers{…}, VS Code servers{…},
Claude Code ~/.claude.json, native servers[…]); --client overrides.
Findings point at the original file locations.

Exit codes: 0 clean (coverage gaps allowed) · 1 findings at/above
--fail-on (default critical) · 2 input-unassessable (unreadable input,
malformed server entry, or a check error) or a write error. Checks whose
subject cannot be determined from this input type are reported as "not
determinable" with no exit effect; pass --strict to treat those as 2.

Static analysis only — not a penetration test. It never probes live
systems or runs attacks.`;

interface Options {
  format: Format | "all";
  outDir: string;
  failOn: Severity;
  maxBytes: number;
  strict: boolean;
  client?: ClientFormat;
  toolsPath?: string;
  discover: boolean;
  reportMode?: boolean;
}

function parseArgs(argv: string[]): { configPath: string; options: Options } {
  const options: Options = {
    format: "summary",
    outDir: "./audit-out",
    failOn: "critical",
    maxBytes: DEFAULT_MAX_BYTES,
    strict: false,
    discover: false,
  };
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    if (arg === "--help" || arg === "-h") {
      console.log(HELP);
      process.exit(0);
    }
    if (arg === "--format") options.format = (argv[++i] ?? "") as Options["format"];
    else if (arg === "--out-dir") options.outDir = argv[++i] ?? options.outDir;
    else if (arg === "--fail-on") options.failOn = (argv[++i] ?? "") as Severity;
    else if (arg === "--max-bytes") options.maxBytes = Number(argv[++i] ?? Number.NaN);
    else if (arg === "--strict") options.strict = true;
    else if (arg === "--discover") options.discover = true;
    else if (arg === "--tools") {
      const v = argv[++i];
      if (v === undefined) {
        console.error("--tools requires a file path");
        process.exit(2);
      }
      options.toolsPath = v;
    } else if (arg === "--client") {
      const v = argv[++i] ?? "";
      if (!CLIENT_FORMATS.includes(v as ClientFormat)) {
        console.error(`unsupported --client ${v}; supported: ${CLIENT_FORMATS.join(", ")}`);
        process.exit(2);
      }
      options.client = v as ClientFormat;
    } else if (arg.startsWith("--")) {
      console.error(`unknown flag: ${arg}\n${HELP}`);
      process.exit(2);
    } else positional.push(arg);
  }
  if (positional[0] === "report") {
    options.reportMode = true;
    if (typeof positional[1] !== "string") {
      console.error(HELP);
      process.exit(2);
    }
    return { configPath: positional[1], options };
  }
  if (positional[0] !== "scan") {
    console.error(HELP);
    process.exit(2);
  }
  if (options.discover && typeof positional[1] === "string") {
    console.error("--discover takes no config path; it scans the well-known client configs");
    process.exit(2);
  }
  if (!options.discover && typeof positional[1] !== "string") {
    console.error(HELP);
    process.exit(2);
  }
  if (!["json", "sarif", "summary", "html", "all"].includes(options.format)) {
    console.error(`invalid --format: ${options.format}\n${HELP}`);
    process.exit(2);
  }
  if (!(options.failOn in SEVERITY_RANK)) {
    console.error(`invalid --fail-on: ${options.failOn}\n${HELP}`);
    process.exit(2);
  }
  if (!Number.isInteger(options.maxBytes) || options.maxBytes <= 0) {
    console.error(`invalid --max-bytes: ${argv.join(" ")}\n${HELP}`);
    process.exit(2);
  }
  // --discover mode has no config path; the audit runs over well-known files.
  const configPath = options.discover ? "" : (positional[1] as string);
  return { configPath, options };
}

function exitCode(result: AuditResult, failOn: Severity, strict: boolean): number {
  const findings = result.checks.flatMap((c) => c.findings);
  // Total order (A0): input-unassessable → 2; findings ≥ threshold → 1;
  // coverage-unassessable has no effect (--strict opts into 2); else 0.
  if (result.checks.some((c) => c.status === "unassessable" && c.scope === "input")) return 2;
  if (
    findings.some((f) => f.status === "fail" && SEVERITY_RANK[f.severity] >= SEVERITY_RANK[failOn])
  )
    return 1;
  if (strict && result.checks.some((c) => c.status === "unassessable" && c.scope === "coverage"))
    return 2;
  return 0;
}

function writeAll(outDir: string, result: AuditResult, sourcePath: string): void {
  const dir = resolve(outDir);
  mkdirSync(dir, { recursive: true });
  const files: [string, Format][] = [
    ["audit.json", "json"],
    ["audit.sarif", "sarif"],
    ["report.html", "html"],
    ["summary.md", "summary"],
  ];
  const written: string[] = [];
  try {
    for (const [name, format] of files) {
      const path = resolve(dir, name);
      writeFileSync(path, emit(result, format, sourcePath), "utf8");
      written.push(path);
    }
  } catch (err) {
    for (const p of written) rmSync(p, { force: true });
    throw err;
  }
}

/** A4: audit every well-known client config in one deterministic run. */
function runDiscover(options: Options): number {
  const d = discoverConfigs(options.maxBytes);
  // M-3 decision: zero configs found (no files, no warnings) is "nothing to
  // audit" — not_applicable + exit 0, so --discover cannot fail a CI build on
  // an empty runner. Files PRESENT but unreadable still carry warnings and
  // keep the input-unassessable exit 2 (the A1 residual guard).
  const zeroFound = d.config.servers.length === 0 && d.warnings.length === 0;
  const bases = d.config.servers.map((s) => {
    const f = (s as { _sourceFile?: string })._sourceFile ?? "";
    return f ? `${f}::${s._pointerBase}` : s._pointerBase;
  });
  const result = zeroFound
    ? notApplicableAll(VERSION, ["no client configs found on this machine"], d.sources)
    : auditConfig(d.config, VERSION, bases, d.warnings);
  result.sources = d.sources;
  if (options.format === "all") {
    try {
      writeAll(options.outDir, result, "discovered-configs");
    } catch (err) {
      console.error(
        `mcp-audit: cannot write ${options.outDir}: ${err instanceof Error ? err.message : err}`,
      );
      return 2;
    }
    console.log(emit(result, "summary"));
  } else {
    process.stdout.write(emit(result, options.format));
  }
  return exitCode(result, options.failOn, options.strict);
}

/** A6: re-render a saved audit.json (the Snapshot fulfilment path). */
function runReport(auditPath: string, options: Options): number {
  const file = readJsonFile(auditPath, options.maxBytes);
  if ("error" in file) {
    console.error(`mcp-audit: ${file.error.message}`);
    return 2;
  }
  const parsed = file.parsed as Partial<AuditResult>;
  // Full shape validation: a hostile audit.json must exit 2 cleanly, never
  // crash the renderer or smuggle markup into a buyer deliverable (M2).
  const SEVERITIES = new Set(["critical", "high", "medium", "low"]);
  const valid = (() => {
    if (parsed === null || typeof parsed !== "object") return false;
    if (typeof parsed.tool !== "string" || typeof parsed.toolVersion !== "string") return false;
    if (typeof parsed.framework !== "string" || typeof parsed.idScheme !== "string") return false;
    if (!Array.isArray(parsed.checks) || !Array.isArray(parsed.warnings)) return false;
    if (parsed.warnings.some((w) => typeof w !== "string")) return false;
    for (const c of parsed.checks) {
      if (c === null || typeof c !== "object") return false;
      const cr = c as unknown as Record<string, unknown>;
      if (typeof cr["checkId"] !== "string" || !Array.isArray(cr["findings"])) return false;
      if (!["pass", "fail", "unassessable", "not_applicable"].includes(String(cr["status"])))
        return false;
      for (const f of cr["findings"] as unknown[]) {
        if (f === null || typeof f !== "object") return false;
        const fr = f as Record<string, unknown>;
        if (typeof fr["id"] !== "string" || typeof fr["checkId"] !== "string") return false;
        if (!["fail", "unassessable"].includes(String(fr["status"]))) return false;
        if (!SEVERITIES.has(String(fr["severity"]))) return false;
        if (typeof fr["pointer"] !== "string" || typeof fr["detail"] !== "string") return false;
        if (!Array.isArray(fr["frameworkRefs"])) return false;
        if ((fr["frameworkRefs"] as unknown[]).some((x) => typeof x !== "string")) return false;
      }
    }
    return true;
  })();
  if (!valid) {
    console.error(`mcp-audit: ${auditPath} is not an audit.json produced by mcp-audit scan`);
    return 2;
  }
  const result = parsed as AuditResult;
  // I4 trust boundary: the file's provenance (scanner version, integrity) is
  // unknown — re-run redaction over every carried string before rendering.
  result.warnings = result.warnings.map((w) => redactString(w));
  for (const c of result.checks as unknown as {
    findings: { pointer: string; detail: string }[];
  }[]) {
    for (const f of c.findings) {
      f.pointer = redactString(f.pointer);
      f.detail = redactString(f.detail);
    }
  }
  const html = options.format === "all" ? emitHtml(result) : emit(result, options.format);
  process.stdout.write(html);
  return 0;
}

export function main(argv: string[]): number {
  const { configPath, options } = parseArgs(argv);
  if (options.reportMode) {
    return runReport(configPath, options);
  }
  if (options.discover) {
    return runDiscover(options);
  }
  const loaded = loadConfigAny(configPath, options.maxBytes, options.client);
  let toolsError: string | null = null;
  if ("loaded" in loaded && options.toolsPath) {
    try {
      const file = readJsonFile(options.toolsPath, options.maxBytes);
      if ("error" in file) {
        toolsError = file.error.message;
      } else {
        const f = parseToolsFile(file.parsed);
        if ("single" in f) {
          const named = loaded.loaded.config.servers.filter((s) => typeof s.name === "string");
          if (named.length !== 1) {
            toolsError = `tools file is single-server but the config has ${named.length} named servers; use a name-keyed tools map`;
          } else {
            (named[0] as { tools?: unknown }).tools = f.single;
          }
        } else {
          let matched = 0;
          for (const s of loaded.loaded.config.servers) {
            // Null-prototype map + Array.isArray guard: a "__proto__" key in
            // the tools file must never reach the prototype chain (Low 3).
            const match = (f.byServer as Record<string, unknown>)[String(s.name)];
            if (Array.isArray(match)) {
              s.tools = match;
              matched++;
            }
          }
          if (matched === 0) {
            toolsError = "no server in the config matches any name in the tools map";
          } else if (matched < loaded.loaded.config.servers.length) {
            toolsError = `tools attached for ${matched} of ${loaded.loaded.config.servers.length} servers`;
          }
        }
      }
    } catch (err) {
      toolsError = err instanceof Error ? err.message : String(err);
    }
  }
  const result =
    "error" in loaded
      ? gateFailureResult(loaded.error.message, VERSION)
      : auditConfig(
          loaded.loaded.config,
          VERSION,
          loaded.loaded.pointerBases,
          loaded.loaded.adapterWarnings,
        );
  if (toolsError) {
    // Tool-file problems never abort the config audit; they surface as warnings.
    result.warnings.push(redactString(`--tools: ${toolsError}`));
  }
  if ("error" in loaded) {
    console.error(`mcp-audit: ${loaded.error.message}`);
  }

  if (options.format === "all") {
    try {
      // I4: the source path lands in exported artifacts, so it gets the same
      // redaction as every other output string.
      writeAll(options.outDir, result, redactString(configPath));
    } catch (err) {
      console.error(
        `mcp-audit: cannot write ${options.outDir}: ${err instanceof Error ? err.message : err}`,
      );
      return 2;
    }
    console.log(emit(result, "summary"));
  } else {
    process.stdout.write(emit(result, options.format, redactString(configPath)));
  }
  return exitCode(result, options.failOn, options.strict);
}

// Only run when executed directly (importable for tests without side effects).
const invokedAs = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedAs === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}
