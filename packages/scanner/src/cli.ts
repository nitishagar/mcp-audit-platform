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
  loadConfig,
} from "./runner.js";
import { SEVERITY_RANK, type Severity } from "./schema.js";

const VERSION = "0.1.0";

export const HELP = `mcp-audit ${VERSION} — static MCP / AI agent config audit

Usage:
  mcp-audit scan <config.json> [--format json|sarif|summary|all]
    [--out-dir <dir>] [--fail-on critical|high|medium|low] [--max-bytes <n>]

Formats: a single format writes to stdout; "all" writes audit.json,
audit.sarif and summary.md into --out-dir (default ./audit-out).

Exit codes: 0 clean · 1 findings at/above --fail-on (default critical) ·
2 unassessable input or write error (takes precedence over 1).

Static analysis only — not a penetration test. It never probes live
systems or runs attacks.`;

interface Options {
  format: Format | "all";
  outDir: string;
  failOn: Severity;
  maxBytes: number;
}

function parseArgs(argv: string[]): { configPath: string; options: Options } {
  const options: Options = {
    format: "summary",
    outDir: "./audit-out",
    failOn: "critical",
    maxBytes: DEFAULT_MAX_BYTES,
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
    else if (arg.startsWith("--")) {
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

function exitCode(result: AuditResult, failOn: Severity): number {
  const fails = result.checks.flatMap((c) => c.findings);
  // Total order: any unassessable → 2; else ≥ threshold → 1; else 0.
  if (fails.some((f) => f.status === "unassessable")) return 2;
  if (fails.some((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[failOn])) return 1;
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
  const loaded = loadConfig(configPath, options.maxBytes);
  const result =
    "error" in loaded
      ? gateFailureResult(loaded.error.message, VERSION)
      : auditConfig(loaded.config, VERSION);
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
  return exitCode(result, options.failOn);
}

// Only run when executed directly (importable for tests without side effects).
const invokedAs = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedAs === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}
