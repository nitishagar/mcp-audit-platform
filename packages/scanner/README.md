# @mcp-audit/scanner

Deterministic offline static audit of MCP server / AI agent configs.
Emits JSON, SARIF 2.1.0, and a Markdown summary. Zero runtime dependencies.

Static analysis only — not a penetration test. It does not probe or exploit
live systems.

## Usage

```sh
pnpm build
node dist/cli.js scan <config.json> --format all --out-dir ./audit-out --fail-on critical
echo "exit=$?"
```

Exit codes: `0` clean · `1` findings at/above `--fail-on` (default `critical`)
· `2` unassessable input or write error (takes precedence over `1`).

Single formats (`json`, `sarif`, `summary`) write to stdout; `all` writes
`audit.json`, `audit.sarif`, `summary.md` into `--out-dir`.

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
| INV-01 pinned version | MCP04 Software Supply Chain | medium |
| AUTH-01 remote auth required | MCP07 Insufficient Authentication | critical |
| AUTH-02 localhost-only bind | MCP07 Insufficient Authentication | high |
| AUTH-03 Origin validation | MCP07 Insufficient Authentication | high |
| PRIV-01 destructive-tool approval | MCP02 Privilege Escalation via Scope Creep | high |
| PRIV-02 ≤20 tools | MCP02 Privilege Escalation via Scope Creep | medium |
| ARG-01 ≤8 params | MCP05 Command Injection & Execution | medium |
| ARG-02 no poisoning signals | MCP03 Tool Poisoning | critical |
| SEC-01 no live secrets in config | MCP01 Token Mismanagement & Secret Exposure | high |
| SEC-02 no secret-shaped values | MCP01 Token Mismanagement & Secret Exposure | critical |
| LOG-01 audit log present | MCP08 Lack of Audit and Telemetry | medium |

Severity mapping: `src/severity-map.ts`, pinned to OWASP MCP Top 10 v2025-beta.
