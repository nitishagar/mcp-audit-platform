import type { Check } from "./types.js";
import { serverLabel } from "./types.js";

/** LOG-01: every server records an audit trail of tool calls. */
export const auditLogCheck: Check = {
  id: "LOG-01",
  description: "Each server keeps an audit log of tool calls",
  run: (config) => {
    const out: { status: "fail"; pointer: string; detail: string }[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      if (server.auditLog !== true) {
        out.push({
          status: "fail",
          pointer: `servers[${i}].auditLog`,
          detail: `${serverLabel(i, server.name)} has no audit log; log every tool call with identity and arguments`,
        });
      }
    });
    return out;
  },
};
