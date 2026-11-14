#!/usr/bin/env node
/**
 * mcp-audit CLI: deterministic offline static audit of MCP configs.
 * Static analysis only — not a penetration test; never probes live systems.
 */
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { type Format, emit } from "./emit.js";
import { redactString } from "./redact.js";
import {
  DEFAULT_MAX_BYTES,
  type AuditResult,
  auditConfig,
  gateFailureResult,
  loadConfigAny,
  readJsonFile,
} from "./runner.js";
import { parseToolsFile } from "./adapters/tools.js";
import { CLIENT_FORMATS, type ClientFormat } from "./adapters/types.js";
import { SEVERITY_RANK, type Severity } from "./schema.js";

const VERSION = "0.1.0";

export const HELP = `mcp-audit ${VERSION} — static MCP / AI agent config audit

Usage:
  mcp-audit scan <config.json> [--format json|sarif|summary|all]
    [--out-dir <dir>] [--fail-on critical|high|medium|low] [--max-bytes <n>]
    [--strict] [--client claude-desktop|claude-code|cursor|vscode|windsurf|native]
    [--tools tools-list.json]

Formats: a single format writes to stdout; "all" writes audit.json,
audit.sarif and summary.md into --out-dir (default ./audit-out).

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
}

function parseArgs(argv: string[]): { configPath: string; options: Options } {
  const options: Options = {
    format: "summary",
    outDir: "./audit-out",
    failOn: "critical",
    maxBytes: DEFAULT_MAX_BYTES,
    strict: false,
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
    else if (arg === "--tools") options.toolsPath = argv[++i] ?? "";
    else if (arg === "--client") {
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
  if (positional[0] !== "scan" || typeof positional[1] !== "string") {
    console.error(HELP);
    process.exit(2);
  }
  if (!["json", "sarif", "summary", "all"].includes(options.format)) {
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
  return { configPath: positional[1], options };
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

export function main(argv: string[]): number {
  const { configPath, options } = parseArgs(argv);
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
          for (const s of loaded.loaded.config.servers) {
            const match = f.byServer[String(s.name)];
            if (match !== undefined) s.tools = match;
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
