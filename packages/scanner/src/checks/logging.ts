import type { Check, RawFinding } from "./types.js";
import { serverLabel } from "./types.js";

/**
 * LOG-01 (A2): audit logging is a SERVER-side property. A client config can
 * never show it, so absence of the native field is coverage-unassessable —
 * failing every client-configured server was an invented verdict (plan E3).
 * An explicit native `auditLog: false` is evidence, and fails.
 */
export const auditLogCheck: Check = {
  id: "LOG-01",
  description: "Each server keeps an audit log of tool calls",
  requires: ["servers"],
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      const flag = (server as { auditLog?: unknown }).auditLog;
      if (flag === undefined) {
        out.push({
          status: "unassessable",
          pointer: `servers[${i}]`,
          detail: `${serverLabel(i, server.name)} audit logging is server-side and not determinable from this input; supply native "auditLog" or review the server's logging manually`,
        });
        return;
      }
      if (flag !== true) {
        out.push({
          status: "fail",
          pointer: `servers[${i}].auditLog`,
          detail: `${serverLabel(i, server.name)} declares no audit log; log every tool call with identity and arguments`,
        });
      }
    });
    return out;
  },
};
