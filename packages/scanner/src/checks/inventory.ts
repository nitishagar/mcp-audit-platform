import type { Check } from "./types.js";
import { serverLabel } from "./types.js";

/** INV-01: every server pins a version (supply-chain: unpinned = un-auditable). */
export const inventoryCheck: Check = {
  id: "INV-01",
  description: "Each MCP server declares a pinned version",
  run: (config) => {
    const out: { status: "fail"; pointer: string; detail: string }[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      if (typeof server.version !== "string" || server.version.length === 0) {
        out.push({
          status: "fail",
          pointer: `servers[${i}].version`,
          detail: `${serverLabel(i, server.name)} has no pinned version; unpinned servers cannot be audited against known CVEs`,
        });
      }
    });
    return out;
  },
};
