import type { Check, RawFinding } from "./types.js";
import { serverLabel } from "./types.js";

/**
 * A4 INV-02 (new): the same server name defined with DIFFERING launch
 * definitions across files/projects — a shadowing/drift signal (MCP09).
 * Same name + identical definition is fine; same name + different command,
 * args, url, or headers means which definition actually runs depends on
 * client precedence the operator may not expect.
 */
function definitionKey(server: Record<string, unknown>): string {
  return JSON.stringify({
    command: server["command"] ?? null,
    args: server["args"] ?? null,
    url: server["url"] ?? server["serverUrl"] ?? null,
    headers: server["headers"] ?? null,
  });
}

export const shadowDriftCheck: Check = {
  id: "INV-02",
  description: "Same-named servers agree on their definition everywhere",
  requires: ["servers"],
  run: (config) => {
    const out: RawFinding[] = [];
    const byName = new Map<
      string,
      { key: string; index: number; server: Record<string, unknown> }
    >();
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      const s = server as Record<string, unknown>;
      const name = typeof s["name"] === "string" && s["name"].length > 0 ? s["name"] : null;
      if (!name) return;
      const key = definitionKey(s);
      const seen = byName.get(name);
      if (seen === undefined) {
        byName.set(name, { key, index: i, server: s });
        return;
      }
      if (seen.key !== key) {
        out.push({
          status: "fail",
          pointer: `servers[${i}].name`,
          detail: `${serverLabel(i, s["name"])} is defined more than once with different commands/urls (shadowing: which one runs depends on client precedence)`,
        });
      }
    });
    return out;
  },
};
