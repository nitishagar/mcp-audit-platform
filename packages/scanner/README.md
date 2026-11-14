# mcp-audit-scanner

Deterministic offline static audit of MCP server / AI agent configs.
Emits JSON, SARIF 2.1.0, and a Markdown summary. Zero runtime dependencies.

Static analysis only — not a penetration test. It never probes live systems
or runs attacks.

## Usage

```sh
pnpm build
node dist/cli.js scan <config.json> --format all --out-dir ./audit-out --fail-on critical
echo "exit=$?"
```

Exit codes: `0` clean · `1` findings at/above `--fail-on` (default `critical`)
· `2` unassessable input or write error (takes precedence over `1`).

Single formats (`json`, `sarif`, `summary`, `html`) write to stdout; `all`
writes `audit.json`, `audit.sarif`, `report.html`, `summary.md` into
`--out-dir`. The HTML report is the print-ready pack (board summary,
prioritized fix checklist, methodology appendix) — see `report`.

## Supported inputs (A1)

The scanner auto-detects the input format; `--client <format>` overrides
(mismatch is a clean exit 2, never a guess). Findings point at the
original file locations.

| Format | Shape |
|---|---|
| Claude Desktop / Code / Cursor / Windsurf | `{"mcpServers": {"<name>": {command,args,env \| url,headers \| serverUrl,…}}}` |
| Claude Code `~/.claude.json` | top-level `mcpServers` + `projects["<path>"].mcpServers` |
| VS Code | `{"servers": {"<name>": {type,command,args,env \| url,headers}}, "inputs"?}` |
| Native | `{"servers": [{name, transport, command/url, version, auditLog, tools}]}` |

`${VAR}` / `${VAR:-default}` / `${env:VAR}` / `${input:id}` are references,
not secrets — but a `${VAR:-default}` with a literal secret default is
scanned. Tool schemas come from a native `tools[]` or the `--tools`
tools/list file, which REPLACES any native `tools[]` on the matched
server(s); without schemas, tool checks report "not determinable".

## Install

The npm registry package is `mcp-audit-scanner` (the `mcp-audit` name is an
unrelated package). The CLI command it installs is `mcp-audit`:

```sh
npm install -g mcp-audit-scanner && mcp-audit scan mcp.json
```

Until the first publish lands, run from source:

```sh
git clone https://github.com/nitishagar/mcp-audit-platform
cd mcp-audit-platform && pnpm install && pnpm build
node packages/scanner/dist/cli.js scan /path/to/your/mcp.json
```

## Use in CI (GitHub Action)

Once the npm package is published, wire the scanner into CI:

```yaml
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # only needed for upload-sarif
    steps:
      - uses: actions/checkout@v4
      - uses: nitishagar/mcp-audit-platform@v1
        with:
          config: mcp.json
          fail-on: high
          upload-sarif: "true"
```

SARIF uploads to GitHub code scanning are free for public repos; private
repos need GitHub Advanced Security. Before the first publish, run the
scanner from source instead (clone + `pnpm build`, then
`node packages/scanner/dist/cli.js …`).

## Report subcommand

Re-render a saved audit.json (the Snapshot fulfilment path):

```sh
mcp-audit report audit.json --format html > report.html
```

## Publish (maintainers)

```sh
pnpm --filter mcp-audit-scanner build   # dist/ must exist: files=["dist"]
cd packages/scanner && npm publish
```

`files: ["dist"]` overrides the gitignored `dist/`, so the published tarball
carries the bin. Do not skip the build step before publishing.

## Input shape

```json
{
  "servers": [
    {
      "name": "billing",
      "transport": "stdio",
      "command": "billing-mcp",
      "version": "1.4.0",
      "auditLog": true,
      "tools": [{ "name": "read_invoice", "description": "...", "params": {} }]
    }
  ]
}
```

Remote servers add `url`, `auth: { "type": "oauth" }`, `originValidation: true`.

## Check coverage (I8)

| Check | Consensus category | Severity |
|---|---|---|
| INV-01 pinned version (derived from the launch command) | MCP04 Software Supply Chain Attacks & Dependency Tampering | medium |
| SUP-01 bundled-advisory match (offline OSV snapshot) | MCP04 Software Supply Chain Attacks & Dependency Tampering | medium |
| AUTH-01 remote server carries client-side credentials | MCP07 Insufficient Authentication & Authorization | high |
| AUTH-02 localhost-only bind | MCP07 Insufficient Authentication & Authorization | high |
| AUTH-03 Origin validation (server-side; coverage gap on client configs) | MCP07 Insufficient Authentication & Authorization | high |
| AUTH-04 remote http:// uses TLS | MCP07 Insufficient Authentication & Authorization | high |
| PRIV-01 destructive tools gated + reviewed | MCP02 Privilege Escalation via Scope Creep | high |
| PRIV-02 ≤20 tools | MCP02 Privilege Escalation via Scope Creep | medium |
| PRIV-03 no filesystem-root grants | MCP02 Privilege Escalation via Scope Creep | high |
| PRIV-04 no container-privilege escapes | MCP02 Privilege Escalation via Scope Creep | critical |
| ARG-01 ≤8 params | MCP05 Command Injection & Execution | medium |
| ARG-02 no poisoning signals (incl. nested schema descriptions) | MCP03 Tool Poisoning | critical |
| ARG-03 tool schemas constrain inputs (aggregated) | MCP05 Command Injection & Execution | low |
| SEC-01 no live secrets in config | MCP01 Token Mismanagement & Secret Exposure | high |
| SEC-02 no secret-shaped values | MCP01 Token Mismanagement & Secret Exposure | critical |
| LOG-01 audit log present (server-side; coverage gap on client configs) | MCP08 Lack of Audit and Telemetry | medium |

Severity mapping: `src/severity-map.ts`, pinned to OWASP MCP Top 10 v2025-beta.

Official categories not covered by static config analysis in v1: MCP06 Intent
Flow Subversion, MCP09 Shadow MCP Servers, MCP10 Context Injection &
Over-Sharing — these concern runtime context/intent behavior.
