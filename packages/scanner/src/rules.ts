/**
 * A6: single source of per-rule metadata — consumed by the SARIF emitter
 * (help.text), the HTML report (rationale/remediation), and the site rule
 * pages (C3). Keep each entry factual and remediation-first; copy-guard
 * applies to these strings (I9: static analysis only, never pentest claims).
 */
export interface RuleMeta {
  id: string;
  title: string;
  rationale: string;
  remediation: string;
  effort: "quick" | "moderate" | "deep";
}

export const RULES: Record<string, RuleMeta> = {
  "INV-01": {
    id: "INV-01",
    title: "Run pinned versions",
    rationale:
      "A launch without an exact version pin resolves to whatever the registry serves today, so the code that runs on your machine can change between scans and cannot be audited against advisories.",
    remediation:
      "Pin the exact version in the launch (pkg@1.2.3, ==1.2.3 for uvx/pipx, or a digest/exact tag for docker) and record upgrade reviews.",
    effort: "quick",
  },
  "INV-02": {
    id: "INV-02",
    title: "One definition per server name",
    rationale:
      "The same server name defined with different commands in different clients is shadowing: which definition actually runs depends on client precedence that is easy to get wrong.",
    remediation:
      "Keep a single source of truth per server name; remove or rename the drifted duplicate and diff the definitions intentionally.",
    effort: "quick",
  },
  "AUTH-01": {
    id: "AUTH-01",
    title: "Remote servers carry credentials",
    rationale:
      "A remote MCP server reachable with no client-side credentials exposes its tools to whoever can reach the endpoint (measurement studies found ~40% of live remote servers in this state).",
    remediation:
      "Configure an Authorization header or the client's OAuth flow for every remote server; if the server uses OAuth discovery, record that decision as reviewed.",
    effort: "quick",
  },
  "AUTH-02": {
    id: "AUTH-02",
    title: "Bind local servers to localhost",
    rationale:
      "A server bound to 0.0.0.0 accepts connections from any interface, widening the DNS-rebinding surface against a tool-execution endpoint.",
    remediation: "Bind to 127.0.0.1 and keep the port local.",
    effort: "quick",
  },
  "AUTH-03": {
    id: "AUTH-03",
    title: "Validate the Origin header",
    rationale:
      "Without Origin/Host validation, a malicious webpage can drive a local MCP server via DNS rebinding (the mechanism behind CVE-2025-49596 in MCP Inspector).",
    remediation:
      "Enable the server's Origin/Host allow-list; if you run a server with documented server-side confinement, verify it during setup.",
    effort: "moderate",
  },
  "AUTH-04": {
    id: "AUTH-04",
    title: "Use TLS for remote servers",
    rationale:
      "Plain http:// to a non-loopback host sends credentials and tool traffic in cleartext across networks you do not control.",
    remediation: "Switch the server URL to https://; keep plain http for loopback dev only.",
    effort: "quick",
  },
  "PRIV-01": {
    id: "PRIV-01",
    title: "Gate destructive tools",
    rationale:
      "Vendor annotations (destructiveHint) or the tool name signal that a tool can overwrite or destroy state; without an approval step, one prompt injection away from execution is data loss.",
    remediation:
      "Enable your client's approval prompting for destructive tools and review the tool list after every server update.",
    effort: "quick",
  },
  "PRIV-02": {
    id: "PRIV-02",
    title: "Limit exposed tools",
    rationale:
      "Every exposed tool widens the context an attacker can steer and the surface a prompt injection can reach.",
    remediation: "Enable only the tools the task needs; drop catch-all servers.",
    effort: "moderate",
  },
  "PRIV-03": {
    id: "PRIV-03",
    title: "Scope filesystem grants",
    rationale:
      "A filesystem server granted /, ~, or a drive root turns any tool-call confusion into whole-volume read/write.",
    remediation:
      "Pass the narrowest project directories as allowed-directory args and keep scratch work in a temp sandbox.",
    effort: "quick",
  },
  "PRIV-04": {
    id: "PRIV-04",
    title: "Avoid container privilege escapes",
    rationale:
      "--privileged, host networking, host-root bind mounts, or docker.sock access make the container effectively the host.",
    remediation: "Drop the escape; mount only the project directory read-only where possible.",
    effort: "moderate",
  },
  "ARG-01": {
    id: "ARG-01",
    title: "Keep tool parameter counts small",
    rationale:
      "Many-parameter tools are both a larger validation surface and context bloat that degrades the model's tool choice.",
    remediation:
      "Split tools with more than 8 parameters or accept an object parameter with a schema.",
    effort: "moderate",
  },
  "ARG-02": {
    id: "ARG-02",
    title: "No poisoning signals in tool text",
    rationale:
      "Tool descriptions and schema descriptions are untrusted text the model reads; injection phrasing there steers the agent toward exfiltration or system files.",
    remediation:
      "Treat tool text as data: remove injection phrasing from the server, and prefer vendors that document their tool text.",
    effort: "moderate",
  },
  "ARG-03": {
    id: "ARG-03",
    title: "Constrain tool inputs",
    rationale:
      "Schemas that accept arbitrary strings for path/command/url parameters let bad callers steer the server; constraints document intent and bound damage.",
    remediation:
      "Set additionalProperties:false and add pattern/maxLength/enum to path-like parameters; verify server-side confinement separately (PRIV-03).",
    effort: "deep",
  },
  "SEC-01": {
    id: "SEC-01",
    title: "No live secrets under credential keys",
    rationale:
      "Config files are copied, synced, and committed; a live API key under a credential key is one dotfile sync away from public.",
    remediation: "Move secrets to a vault or the OS keychain and reference them by variable.",
    effort: "quick",
  },
  "SEC-02": {
    id: "SEC-02",
    title: "No secret-shaped values anywhere",
    rationale:
      "Values that match known token shapes (API keys, PATs, webhooks, PEM blocks) are secrets even when the key name is innocent.",
    remediation:
      "Rotate the exposed value and move it to a secret store; keep only references in configs.",
    effort: "quick",
  },
  "LOG-01": {
    id: "LOG-01",
    title: "Keep an audit log of tool calls",
    rationale:
      "Without a per-call record (who called what, with which arguments) you cannot investigate a suspicious tool execution after the fact.",
    remediation:
      "Enable the server's audit logging or route calls through a client that logs; verify it records identity and arguments.",
    effort: "moderate",
  },
  "SUP-01": {
    id: "SUP-01",
    title: "Upgrade versions covered by advisories",
    rationale:
      "The pinned version matches a published advisory for that package; running it keeps a known vulnerability in the launch path.",
    remediation:
      "Upgrade to the first fixed version named by the advisory and re-scan; check the advisory source link for details.",
    effort: "quick",
  },
};

export function ruleMeta(id: string): RuleMeta | undefined {
  return RULES[id];
}
