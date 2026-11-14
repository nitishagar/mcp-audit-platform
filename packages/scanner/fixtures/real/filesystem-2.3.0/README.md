# Real-MCP test mule: `@modelcontextprotocol/server-filesystem@2.3.0`

Ground-truth fixture set (PLAN-PRODUCT-COMPLETE §9). Everything here is
**config text and captured interface facts** — scanned, never executed.

## Provenance

- `tools-list.json` was captured live on 2026-11-14 by running the pinned
  npm package `@modelcontextprotocol/server-filesystem@2.3.0` in a temp
  sandbox and sending MCP `initialize` + `tools/list` over stdio
  (16 tools, protocol `2025-06-18`, `serverInfo.name` =
  "secure-filesystem-server"). Raw capture: bundle
  `research/2026-11-14-mule-filesystem-2.3.0-tools-list.json`.
- Tool names, `annotations`, `title`, and JSON Schemas (facts/interfaces)
  are committed **verbatim**. Verbatim description **strings are withheld**
  (replaced by a marker) because the upstream license is a multi-license
  transition file (Apache-2.0 primary for new code, MIT for legacy
  contributions, CC-BY-4.0 docs) — attribution posture per
  `research/2026-11-14-R5-client-formats.md` §7. Poisoning tests therefore
  use `tools-list.poisoned.json` (our own injected text) instead of upstream
  text. If the user prefers verbatim descriptions later, satisfying the
  MIT notice + Apache-2.0 §4 attribution conditions is required.
- Upstream: https://github.com/modelcontextprotocol/servers (Apache-2.0/MIT
  transition; MIT block copyright "Model Context Protocol a Series of LF
  Projects, LLC").

## Files

| File | Purpose |
|---|---|
| `tools-list.json` | Golden `tools/list` capture (descriptions withheld). Input for `--tools` (A3a). |
| `tools-list.poisoned.json` | Golden + one injected poisoning string in a **nested** `inputSchema` property description (`edit_file.edits.items.properties.oldText`). Proves ARG-02 scans nested descriptions. |
| `tools-list.rugpull.json` | Golden with `read_file` flipped to non-read-only/destructive and a new `exec_command` tool — input for the future tool-drift check (INV-03). |
| `claude-desktop.clean.json` | Claude Desktop shape, pinned, scoped dir. |
| `claude-desktop.root.json` | Args `/` and `~` — PRIV-03 (filesystem breadth) oracle. |
| `cursor.unpinned.json` | Cursor shape, unpinned + `@latest` — INV-01 derivation oracle. |
| `vscode.docker.json` | VS Code shape, `docker run --privileged -v /:/…` — PRIV-04 + INV-01 oracle. |
| `claude-code.secrets.json` | `.mcp.json` shape with a canary token in `env` and a `${FS_TOKEN:-<canary>}` default — SEC-01/02 + placeholder-default handling. |
| `windsurf.clean.json` | Windsurf shape; must normalize identically to `claude-desktop.clean.json` (adapter parity). |
| `expected.json` | Oracle: per fixture, expected `{checkId → status}` + exit at default threshold, with and without `--tools`. **Pending A1/A2/A3a** — the M-1 test (`test/mule-filesystem.test.ts`) iterates it; those rows are red until the named items land. |

## Safety rules (§9.5)

- These files are **never executed** — the `/`, `~`, `--privileged`, and
  `docker.sock`-style args are config text scanned by the CLI.
- The mule server itself is only ever run by the `mule-live` CI job, pinned,
  `--ignore-scripts`, in a temp sandbox, env scrubbed to PATH.
