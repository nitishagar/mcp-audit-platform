import { redactString } from "../redact.js";
import type { ClientFormat, NormalizedConfig, NormalizedServer } from "./types.js";
import { CLIENT_FORMATS } from "./types.js";

/**
 * Transport normalization (plan §4-A1): `type` if present (streamable-http →
 * http), else a URL key → http, else a launch command → stdio. R5 verified:
 * Cursor/Windsurf omit `type` on remote entries; Claude Code requires it
 * there — we classify by what the file shows, never guess beyond it.
 */
function transportOf(entry: Record<string, unknown>): "stdio" | "http" | "sse" | "unknown" {
  const type = entry["type"];
  if (typeof type === "string" && type.length > 0) {
    if (type === "stdio") return "stdio";
    if (type === "http" || type === "streamable-http") return "http";
    if (type === "sse") return "sse";
    if (type === "ws") return "http"; // WebSocket carries http-style url/headers
    return "unknown";
  }
  if (typeof entry["url"] === "string" || typeof entry["serverUrl"] === "string") return "http";
  if (typeof entry["command"] === "string") return "stdio";
  return "unknown";
}

interface RawEntry {
  pointerBase: string;
  name: string;
  entry: Record<string, unknown>;
}

/**
 * Normalize one mcpServers/servers-style entry (the shape family shared by
 * Claude Desktop, Claude Code, Cursor, and Windsurf per R5). Keys it reads:
 * type/command/args/env/url/serverUrl/headers/tools. Everything else in the
 * entry is carried through untouched so checks can see it, but adapters
 * never echo unknown keys into findings.
 */
function normalizeEntry(raw: RawEntry): NormalizedServer | null {
  const { entry } = raw;
  if (entry === null || typeof entry !== "object") return null;
  const transport = transportOf(entry);
  if (transport === "unknown") return null;
  const out: Record<string, unknown> = { ...entry, transport };
  const url = entry["serverUrl"] ?? entry["url"];
  if (typeof url === "string") out["url"] = url;
  return { ...(out as unknown as NormalizedServer), _pointerBase: raw.pointerBase, name: raw.name };
}

/** mcpServers-family: `{"mcpServers": {"<name>": {…}}}` (claude/cursor/windsurf). */
function normalizeMcpServersObject(
  group: Record<string, unknown>,
  base: string,
): NormalizedServer[] {
  const out: NormalizedServer[] = [];
  for (const [name, entry] of Object.entries(group)) {
    const s = normalizeEntry({
      pointerBase: `${base}.${name}`,
      name,
      entry: entry as Record<string, unknown>,
    });
    // Unclassifiable entries are carried through raw so the runner's
    // malformed pre-pass makes the audit input-unassessable — never a
    // silent partial drop (A0 red-team lesson applied to adapters).
    out.push(
      s ??
        ({
          ...((entry ?? {}) as object),
          _pointerBase: `${base}.${name}`,
          name,
        } as NormalizedServer),
    );
  }
  return out;
}

/** VS Code editor format: `{"servers": {"<name>": {…}}, "inputs"?}` (R5 §4). */
function normalizeVscode(parsed: Record<string, unknown>): NormalizedConfig | null {
  const group = parsed["servers"];
  if (group === null || typeof group !== "object" || Array.isArray(group)) return null;
  const servers: NormalizedServer[] = [];
  for (const [name, entry] of Object.entries(group as Record<string, unknown>)) {
    const s = normalizeEntry({
      pointerBase: `servers.${name}`,
      name,
      entry: entry as Record<string, unknown>,
    });
    servers.push(
      s ??
        ({
          ...((entry ?? {}) as object),
          _pointerBase: `servers.${name}`,
          name,
        } as NormalizedServer),
    );
  }
  if (servers.length === 0) return null;
  return { servers };
}

/** Claude Code `~/.claude.json`: top-level + per-project mcpServers (R5 §2). */
function normalizeClaudeCode(
  parsed: Record<string, unknown>,
): { config: NormalizedConfig; warnings: string[] } | null {
  const servers: NormalizedServer[] = [];
  const warnings: string[] = [];
  const top = parsed["mcpServers"];
  if (top !== null && typeof top === "object" && !Array.isArray(top)) {
    servers.push(...normalizeMcpServersObject(top as Record<string, unknown>, "mcpServers"));
  }
  const projects = parsed["projects"];
  if (projects !== null && typeof projects === "object" && !Array.isArray(projects)) {
    for (const [path, body] of Object.entries(projects as Record<string, unknown>)) {
      const group =
        body !== null && typeof body === "object"
          ? (body as Record<string, unknown>)["mcpServers"]
          : null;
      if (group === null || typeof group !== "object" || Array.isArray(group)) {
        // Never a silent drop: the skip is surfaced as a warning (path only).
        warnings.push(
          redactString(`projects[${JSON.stringify(path)}].mcpServers is not an object; skipped`),
        );
        continue;
      }
      // Pointer base quotes the project path — it is a file path, not a secret.
      servers.push(
        ...normalizeMcpServersObject(
          group as Record<string, unknown>,
          `projects[${JSON.stringify(path)}].mcpServers`,
        ),
      );
    }
  }
  if (servers.length === 0 && warnings.length === 0) return null;
  return { config: { servers }, warnings };
}

/** Native scanner format: `{"servers": [{name, …}]}` (fixtures/back-compat). */
function normalizeNative(parsed: Record<string, unknown>): NormalizedConfig | null {
  const arr = parsed["servers"];
  if (!Array.isArray(arr) || arr.length === 0) return null;
  const servers: NormalizedServer[] = [];
  arr.forEach((entry, i) => {
    const name =
      typeof (entry as { name?: unknown })?.name === "string"
        ? (entry as { name: string }).name
        : `server[${i}]`;
    const carried = { ...entry, _pointerBase: `servers[${i}]`, name } as NormalizedServer;
    if (entry === null || typeof entry !== "object") {
      servers.push(carried);
      return;
    }
    const e = entry as Record<string, unknown>;
    const transport = transportOf(e);
    if (transport === "unknown") {
      servers.push(carried);
      return;
    }
    servers.push({
      ...(e as unknown as NormalizedServer),
      transport,
      _pointerBase: `servers[${i}]`,
      name,
    });
  });
  if (servers.length === 0) return null;
  return { servers };
}

export class FormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FormatError";
  }
}

/**
 * Auto-detect the format from top-level keys, or honor an explicit
 * `--client` choice (mismatch → FormatError → exit 2; never guess).
 */
export function detectFormat(parsed: unknown): ClientFormat {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new FormatError("not a JSON object");
  }
  const keys = Object.keys(parsed as Record<string, unknown>);
  const p = parsed as Record<string, unknown>;
  // ~/.claude.json mixes top-level mcpServers AND projects[].mcpServers — the
  // claude-code normalizer handles both; detecting it first avoids a silent
  // partial audit of project-scoped servers (A1 red-team Medium 1).
  const projects = p["projects"];
  if (projects !== null && typeof projects === "object" && !Array.isArray(projects)) {
    return "claude-code";
  }
  if (keys.includes("mcpServers")) return "mcp-servers";
  if (keys.includes("servers")) {
    return Array.isArray(p["servers"]) ? "native" : "vscode";
  }
  throw new FormatError(
    "unsupported shape: expected one of mcpServers{…} (Claude Desktop/Code, Cursor, Windsurf), " +
      "servers{…} (VS Code), servers[…] (native), or a Claude Code ~/.claude.json (projects{…})",
  );
}

/**
 * Normalize a parsed config file into the audit shape. `client` narrows or
 * overrides detection when the caller knows the file's origin.
 */
export function normalizeFile(
  parsed: unknown,
  client?: ClientFormat,
): { config: NormalizedConfig; format: ClientFormat; warnings: string[] } {
  if (client !== undefined && !CLIENT_FORMATS.includes(client)) {
    throw new FormatError(
      `unsupported --client ${client}; supported: ${CLIENT_FORMATS.join(", ")}`,
    );
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new FormatError("config must be a JSON object");
  }
  const p = parsed as Record<string, unknown>;
  const format = client ?? detectFormat(p);
  let config: NormalizedConfig | null = null;
  let warnings: string[] = [];
  switch (format) {
    case "mcp-servers":
    case "claude-desktop":
    case "cursor":
    case "windsurf": {
      const group = p["mcpServers"];
      if (group === null || typeof group !== "object" || Array.isArray(group)) {
        throw new FormatError(`--client ${format} requires a top-level "mcpServers" object`);
      }
      config = {
        servers: normalizeMcpServersObject(group as Record<string, unknown>, "mcpServers"),
      };
      break;
    }
    case "claude-code": {
      const cc = normalizeClaudeCode(p);
      if (cc) {
        config = cc.config;
        warnings = cc.warnings;
      }
      break;
    }
    case "vscode":
      config = normalizeVscode(p);
      break;
    case "native":
      config = normalizeNative(p);
      break;
  }
  if (!config || (config.servers.length === 0 && warnings.length === 0)) {
    throw new FormatError(
      `no MCP server entries found for format ${format} (mcpServers/servers empty or missing)`,
    );
  }
  return { config, format, warnings };
}
