import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

/** Test/ops seam: override the home and project roots for discovery. */
export interface DiscoverRoots {
  home: string;
  root: string;
}

export function discoveryRoots(): DiscoverRoots {
  const dir = process.env["MCP_AUDIT_DISCOVER_DIR"];
  if (dir !== undefined && dir.length > 0) {
    return { home: dir, root: dir };
  }
  return { home: homedir(), root: process.cwd() };
}
import type { ClientFormat, NormalizedConfig, NormalizedServer } from "./types.js";
import { normalizeFile } from "./index.js";
import { redactString } from "../redact.js";

/**
 * A4 discovery (plan §4-A4): read-only scan of the well-known client config
 * paths. Missing files are skipped silently; unreadable ones surface as
 * warnings (path only, never content). Paths verified against vendor docs
 * in research R5 — notably Claude Desktop has NO documented Linux path.
 */
export interface DiscoveredFile {
  path: string;
  format: ClientFormat;
  /** How the file was addressed (for the sources list). */
  label: string;
}

export function wellKnownPaths(roots: DiscoverRoots = discoveryRoots()): DiscoveredFile[] {
  const paths: DiscoveredFile[] = [];
  const home = (rel: string): string => join(roots.home, rel);
  const root = (rel: string): string => {
    const p = join(roots.root, rel);
    return isAbsolute(rel) ? resolve(rel) : p;
  };
  const add = (path: string, format: ClientFormat, label: string): void => {
    paths.push({ path, format, label });
  };
  // Claude Code: user/local scopes live in ~/.claude.json (R5 §2).
  add(home(".claude.json"), "claude-code", "claude-code (user/local scopes)");
  // Project-level .mcp.json (project root).
  add(root(".mcp.json"), "mcp-servers", "claude-code (project .mcp.json)");
  // Cursor: global + project (R5 §3).
  add(home(join(".cursor", "mcp.json")), "cursor", "cursor (global)");
  add(root(join(".cursor", "mcp.json")), "cursor", "cursor (project)");
  // VS Code: workspace file (R5 §4 — no documented user-level path).
  add(root(join(".vscode", "mcp.json")), "vscode", "vscode (workspace)");
  // Windsurf (R5 §5).
  add(home(join(".codeium", "windsurf", "mcp_config.json")), "windsurf", "windsurf");
  // Claude Desktop: macOS and Windows only — no Linux build exists (R5 §1).
  if (process.platform === "darwin") {
    add(
      home(join("Library", "Application Support", "Claude", "claude_desktop_config.json")),
      "claude-desktop",
      "claude-desktop",
    );
  }
  if (process.platform === "win32" && process.env.APPDATA) {
    add(
      join(process.env.APPDATA, "Claude", "claude_desktop_config.json"),
      "claude-desktop",
      "claude-desktop",
    );
  }
  // Deterministic regardless of filesystem enumeration order (plan A4).
  return paths.sort((a, b) => a.path.localeCompare(b.path));
}

export interface DiscoverResult {
  config: NormalizedConfig;
  sources: { file: string; format: ClientFormat; servers: number }[];
  warnings: string[];
}

/** Read one file's config (read-only; refuses symlinks like the main gate). */
function readOne(
  file: DiscoveredFile,
  maxBytes: number,
):
  | { servers: NormalizedServer[]; source: { file: string; format: ClientFormat; servers: number } }
  | { warning: string }
  | null {
  if (!existsSync(file.path)) return null; // missing = silent skip (plan A4)
  let stat;
  try {
    stat = statSync(file.path);
  } catch {
    return { warning: redactString(`cannot stat ${file.path}; skipped`) };
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    return { warning: redactString(`${file.path} is not a regular file; skipped`) };
  }
  if (stat.size > maxBytes) {
    return {
      warning: redactString(`${file.path} exceeds the size cap; skipped (raise --max-bytes)`),
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file.path, "utf8"));
  } catch {
    return { warning: redactString(`${file.path} is not valid JSON; skipped`) };
  }
  try {
    const { config } = normalizeFile(parsed, file.format);
    for (const s of config.servers) {
      (s as { _sourceFile?: string })._sourceFile = file.path;
    }
    return {
      servers: config.servers,
      source: { file: file.path, format: file.format, servers: config.servers.length },
    };
  } catch {
    return { warning: redactString(`${file.path} has no assessable MCP entries; skipped`) };
  }
}

/**
 * Merge every well-known config into one normalized config. Each carried
 * server keeps `_sourceFile` so INV-02 (shadow/drift across clients) and the
 * sources[] list can reason per file.
 */
export function discoverConfigs(
  maxBytes: number,
  roots: DiscoverRoots = discoveryRoots(),
): DiscoverResult {
  const servers: NormalizedServer[] = [];
  const sources: { file: string; format: ClientFormat; servers: number }[] = [];
  const warnings: string[] = [];
  for (const file of wellKnownPaths(roots)) {
    const r = readOne(file, maxBytes);
    if (r === null) continue;
    if ("warning" in r) {
      warnings.push(r.warning);
      continue;
    }
    servers.push(...r.servers);
    sources.push(r.source);
  }
  // Canonical order: by source file, then pointer base (determinism, plan A4).
  servers.sort(
    (a, b) =>
      ((a as { _sourceFile?: string })._sourceFile ?? "").localeCompare(
        (b as { _sourceFile?: string })._sourceFile ?? "",
      ) || a._pointerBase.localeCompare(b._pointerBase),
  );
  return { config: { servers }, sources, warnings };
}
