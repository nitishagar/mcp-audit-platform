import type { McpTool } from "../schema.js";

/**
 * A3a: a `tools/list` snapshot file. Two shapes (plan §4-A3a):
 * - single: `{tools: [...]}` (optionally with serverInfo/protocol/nextCursor
 *   around it — the mule capture shape);
 * - multi: `{"<serverName>": {"tools": [...]}}`.
 * Tools are normalized: `inputSchema.properties` becomes `params` (ARG-01
 * counts them), `inputSchema` and `annotations` are carried verbatim (ARG-02
 * nested scan, PRIV-01 spec semantics). Unknown keys are preserved.
 */
export type ToolsFile = { single: McpTool[] } | { byServer: Record<string, McpTool[]> };

function normalizeTools(raw: unknown): McpTool[] {
  if (!Array.isArray(raw)) return [];
  const out: McpTool[] = [];
  for (const t of raw) {
    if (t === null || typeof t !== "object") {
      // Junk entries are carried so the tool checks report them unassessable.
      out.push(t as McpTool);
      continue;
    }
    const tool = t as Record<string, unknown>;
    const inputSchema = tool["inputSchema"];
    const params =
      inputSchema !== null &&
      typeof inputSchema === "object" &&
      !Array.isArray(inputSchema) &&
      (inputSchema as Record<string, unknown>)["properties"] !== null &&
      typeof (inputSchema as Record<string, unknown>)["properties"] === "object"
        ? ((inputSchema as Record<string, unknown>)["properties"] as Record<string, unknown>)
        : {};
    out.push({ ...(tool as McpTool), params });
  }
  return out;
}

export function parseToolsFile(parsed: unknown): ToolsFile {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TypeError("tools file must be a JSON object");
  }
  const p = parsed as Record<string, unknown>;
  if (Array.isArray(p["tools"])) {
    return { single: normalizeTools(p["tools"]) };
  }
  const byServer: Record<string, McpTool[]> = {};
  let found = false;
  for (const [name, body] of Object.entries(p)) {
    if (
      body !== null &&
      typeof body === "object" &&
      Array.isArray((body as Record<string, unknown>)["tools"])
    ) {
      byServer[name] = normalizeTools((body as Record<string, unknown>)["tools"]);
      found = true;
    }
  }
  if (found) return { byServer };
  throw new TypeError('tools file must be {"tools":[…]} or {"<serverName>":{"tools":[…]}}');
}
