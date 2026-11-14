import { lstatSync, readFileSync } from "node:fs";
import { FormatError, normalizeFile } from "./adapters/index.js";
import type { ClientFormat, NormalizedConfig } from "./adapters/types.js";
import { redactString } from "./redact.js";
import { DEFAULT_MAX_BYTES, type AuditResult, type LoadError, validateShape } from "./audit.js";
import { type McpConfig, type McpServer } from "./schema.js";

export { auditConfig, gateFailureResult, dedupeTools, DEFAULT_MAX_BYTES } from "./audit.js";
export type { AuditResult, LoadError } from "./audit.js";

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
