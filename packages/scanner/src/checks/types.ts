import type { CheckStatus, McpConfig } from "../schema.js";

/** Raw check output; the runner resolves severity, ids, and sorting. */
export interface RawFinding {
  status: Exclude<CheckStatus, "pass" | "not_applicable">;
  /** Location pointer only — never a value. */
  pointer: string;
  /** Must already be redacted by the check (no secret values). */
  detail: string;
  /**
   * Why this row is unassessable (A0). Defaults to "coverage": the property
   * cannot be determined from this input. The runner overrides to "input"
   * for gate/malformed/throw paths.
   */
  scope?: "input" | "coverage";
}

/** What a check needs from the config to say anything at all. */
export type RequiresKey = "servers" | "tools" | "remote";

export interface Check {
  id: string;
  /** One-line description for the coverage table and SARIF rules. */
  description: string;
  /**
   * Applicability declaration (A0, anti-vacuous-pass): "tools" = at least one
   * server supplies tool schemas, else the check is coverage-unassessable;
   * "remote" = at least one remote server, else the check is not_applicable.
   * "servers" is guaranteed by the input gate.
   */
  requires: RequiresKey[];
  run: (config: McpConfig) => RawFinding[];
}

export function serverLabel(index: number, name: unknown): string {
  return typeof name === "string" && name.length > 0 ? name : `server[${index}]`;
}

/**
 * Honest-unassessable row for a tool entry that cannot be assessed (A0
 * red-team fix): junk entries must never be silently skipped into a pass.
 */
export function unassessableToolEntry(
  serverIndex: number,
  toolIndex: number,
  serverName: unknown,
  reason: string,
): RawFinding {
  return {
    status: "unassessable",
    pointer: `servers[${serverIndex}].tools[${toolIndex}]`,
    detail: `${serverLabel(serverIndex, serverName)} tool entry ${toolIndex}: ${reason}`,
  };
}
