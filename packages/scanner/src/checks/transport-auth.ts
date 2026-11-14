import type { Check, RawFinding } from "./types.js";
import { serverLabel } from "./types.js";

function isRemote(server: { transport?: unknown; url?: unknown }): boolean {
  if (server.transport === "http" || server.transport === "https") return true;
  return typeof server.url === "string" && /^https?:\/\//.test(server.url);
}

function transportUnknown(server: { transport?: unknown; url?: unknown }): boolean {
  return server.transport === undefined && server.url === undefined;
}

/**
 * AUTH-01: remote servers require authentication. Unknown transport cannot be
 * assessed (honest unassessable, never a guessed PASS).
 */
export const remoteAuthCheck: Check = {
  id: "AUTH-01",
  description: "Remote (HTTP) servers require authentication",
  requires: ["remote"],
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      if (transportUnknown(server)) {
        out.push({
          status: "unassessable",
          pointer: `servers[${i}].transport`,
          detail: `${serverLabel(i, server.name)} declares neither transport nor url; auth posture cannot be assessed`,
        });
        return;
      }
      if (!isRemote(server)) return;
      const t = server.auth?.type;
      if (t === undefined || t === "none") {
        out.push({
          status: "fail",
          pointer: `servers[${i}].auth`,
          detail: `${serverLabel(i, server.name)} is remote with no authentication configured`,
        });
      }
    });
    return out;
  },
};

/** AUTH-02: local HTTP servers must not bind 0.0.0.0 (DNS-rebinding surface). */
export const localhostBindingCheck: Check = {
  id: "AUTH-02",
  description: "Local HTTP servers bind localhost only, not 0.0.0.0",
  requires: ["remote"],
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      if (transportUnknown(server)) {
        out.push({
          status: "unassessable",
          pointer: `servers[${i}].transport`,
          detail: `${serverLabel(i, server.name)} declares neither transport nor url; bind posture cannot be assessed`,
        });
        return;
      }
      const bind = server.bind;
      const url = server.url;
      const bindsAll =
        bind === "0.0.0.0" || (typeof url === "string" && /https?:\/\/0\.0\.0\.0/.test(url));
      if (bindsAll) {
        out.push({
          status: "fail",
          pointer: `servers[${i}].${bind === "0.0.0.0" ? "bind" : "url"}`,
          detail: `${serverLabel(i, server.name)} listens on 0.0.0.0; bind 127.0.0.1 to shrink DNS-rebinding exposure`,
        });
      }
    });
    return out;
  },
};

/** AUTH-03: HTTP servers must validate the Origin header (spec 2025-06-18). */
export const originValidationCheck: Check = {
  id: "AUTH-03",
  description: "HTTP servers validate the Origin header",
  requires: ["remote"],
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      if (transportUnknown(server)) {
        out.push({
          status: "unassessable",
          pointer: `servers[${i}].transport`,
          detail: `${serverLabel(i, server.name)} declares neither transport nor url; Origin policy cannot be assessed`,
        });
        return;
      }
      if (!isRemote(server)) return;
      if (server.originValidation !== true) {
        out.push({
          status: "fail",
          pointer: `servers[${i}].originValidation`,
          detail: `${serverLabel(i, server.name)} does not validate the Origin header (DNS-rebinding risk)`,
        });
      }
    });
    return out;
  },
};
