import type { McpConfig, McpServer } from "../schema.js";

/**
 * A1: adapters turn real client config files into the normalized shape the
 * checks run over, while findings keep pointing at the ORIGINAL file
 * location (plan §4-A1). `_pointerBase` is the original JSON path of the
 * server entry (e.g. `mcpServers.filesystem`); the runner rewrites
 * `servers[i]` prefixes to it after checks run.
 */
export type NormalizedServer = McpServer & { _pointerBase: string };

export type NormalizedConfig = {
  servers: NormalizedServer[];
} & McpConfig;

/** Which client file this config came from (drives format quirks). */
export type ClientFormat =
  | "claude-desktop"
  | "claude-code"
  | "cursor"
  | "vscode"
  | "windsurf"
  | "native"
  | "mcp-servers";

export const CLIENT_FORMATS: readonly ClientFormat[] = [
  "claude-desktop",
  "claude-code",
  "cursor",
  "vscode",
  "windsurf",
  "native",
  "mcp-servers",
];

export interface SourceRef {
  file: string;
  format: ClientFormat;
  servers: number;
}

/** Record an adapter-normalized server. Pointer base never contains values. */
function serverFrom(
  pointerBase: string,
  name: string,
  fields: Partial<McpServer>,
): NormalizedServer {
  return { ...fields, name, _pointerBase: pointerBase } as NormalizedServer;
}

export { serverFrom };
