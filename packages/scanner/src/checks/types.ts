import type { CheckStatus, McpConfig } from "../schema.js";

/** Raw check output; the runner resolves severity, ids, and sorting. */
export interface RawFinding {
  status: Exclude<CheckStatus, "pass">;
  /** Location pointer only — never a value. */
  pointer: string;
  /** Must already be redacted by the check (no secret values). */
  detail: string;
}

export interface Check {
  id: string;
  /** One-line description for the coverage table and SARIF rules. */
  description: string;
  run: (config: McpConfig) => RawFinding[];
}

export function serverLabel(index: number, name: unknown): string {
  return typeof name === "string" && name.length > 0 ? name : `server[${index}]`;
}
