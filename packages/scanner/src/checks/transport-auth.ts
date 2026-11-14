import type { Check, RawFinding } from "./types.js";
import { serverLabel } from "./types.js";

function isRemote(server: { transport?: unknown; url?: unknown }): boolean {
  if (server.transport === "http" || server.transport === "https") return true;
  return typeof server.url === "string" && /^https?:\/\//i.test(server.url);
}

function transportUnknown(server: { transport?: unknown; url?: unknown }): boolean {
  return server.transport === undefined && server.url === undefined;
}

/**
 * A2 AUTH-01: auth is PRESENT if the config carries any client-side
 * credential signal (plan §4-A2, verified shapes in R5):
 * - an Authorization header, or a header named like api-key / token / auth;
 * - a placeholder reference in such a header (a reference exists; its
   resolution at runtime is NOT verified);
 * - native `auth` with type ≠ none, or Cursor/VS Code static-OAuth objects.
 * OAuth discovered at connect time is invisible statically — the finding
 * wording says so instead of asserting none exists.
 */
function clientAuthSignal(server: Record<string, unknown>): boolean {
  const headers = server["headers"];
  if (headers !== null && typeof headers === "object") {
    for (const [name, value] of Object.entries(headers as Record<string, unknown>)) {
      if (!/^authorization$/i.test(name) && !/(api[-_]?key|token|auth)/i.test(name)) continue;
      if (typeof value !== "string" || value.trim() === "") continue;
      return true; // a real value or a ${…} reference both count
    }
  }
  const auth = server["auth"];
  if (auth !== null && typeof auth === "object") {
    const t = (auth as Record<string, unknown>)["type"];
    // Claude Code auth.type; Cursor static-OAuth (non-empty CLIENT_ID present).
    if (
      (typeof t === "string" && t.length > 0 && t !== "none") ||
      "CLIENT_ID" in (auth as object)
    ) {
      const cid = (auth as Record<string, unknown>)["CLIENT_ID"];
      if (typeof cid !== "string" || cid.length > 0) return true;
    }
  }
  return false;
}

export const remoteAuthCheck: Check = {
  id: "AUTH-01",
  description: "Remote (HTTP) servers carry client-side credentials",
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
      if (!clientAuthSignal(server as Record<string, unknown>)) {
        out.push({
          status: "fail",
          pointer: `servers[${i}].headers`,
          detail: `${serverLabel(i, server.name)} is remote with no client-side credentials configured; if the server uses OAuth discovery at connect time, record that as reviewed`,
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

/**
 * A2 AUTH-03: Origin validation is a SERVER-side property, never visible in
 * a client config — absence of the native field is coverage-unassessable
 * (stop failing every remote server, plan E3). CVE ref stays (informational).
 */
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
      const flag = (server as { originValidation?: unknown }).originValidation;
      if (flag === undefined) {
        out.push({
          status: "unassessable",
          pointer: `servers[${i}]`,
          detail: `${serverLabel(i, server.name)} Origin validation is a server-side property and not determinable from this input; review the server's Origin/Host header policy (see CVE-2025-49596)`,
        });
        return;
      }
      if (flag !== true) {
        out.push({
          status: "fail",
          pointer: `servers[${i}].originValidation`,
          detail: `${serverLabel(i, server.name)} declares originValidation: false; validate the Origin header (DNS-rebinding risk, see CVE-2025-49596)`,
        });
      }
    });
    return out;
  },
};

/**
 * A2 AUTH-04 (new): a remote server reached over plain http:// to a
 * non-loopback host sends credentials in cleartext.
 */
const LOOPBACK = /^(localhost|127\.0\.0\.1|\[::1\]|::1|0\.0\.0\.0)(:\d+)?$/i;

export const tlsCheck: Check = {
  id: "AUTH-04",
  description: "Remote http:// URLs use TLS (https) except on loopback",
  requires: ["remote"],
  run: (config) => {
    const out: RawFinding[] = [];
    config.servers.forEach((server, i) => {
      if (server === null || typeof server !== "object") return;
      if (transportUnknown(server)) return;
      const url = typeof server.url === "string" ? server.url : "";
      if (!/^http:\/\//i.test(url)) return;
      let host: string | null = null;
      try {
        host = new URL(url).hostname;
      } catch {
        host = null;
      }
      if (host === null) {
        out.push({
          status: "unassessable",
          pointer: `servers[${i}].url`,
          detail: `${serverLabel(i, server.name)} has an unparseable http:// url; TLS posture cannot be assessed`,
        });
        return;
      }
      if (LOOPBACK.test(host)) return; // local http is AUTH-02's concern
      out.push({
        status: "fail",
        pointer: `servers[${i}].url`,
        detail: `${serverLabel(i, server.name)} is reached over plain http:// to ${host}; use https:// so credentials and tool traffic are not sent in cleartext`,
      });
    });
    return out;
  },
};
