# mcp-audit-platform

Productised MCP / AI agent security audits for startups: a free deterministic
offline scanner plus a pi.dev-themed marketing/product site with fixed tiers.

Static analysis only — not a penetration test. See each package README.

## Layout

- `packages/scanner` — `mcp-audit` CLI: audits MCP config JSON + tool schemas,
  emits JSON / SARIF / Markdown summary. Offline, deterministic.
- `packages/site` — static pi.dev-themed site (tiers, sample report, install).

## Develop

```sh
git clone https://github.com/nitishagar/mcp-audit-platform
cd mcp-audit-platform
pnpm install
pnpm verify   # typecheck + lint + build + test + copy-guard
```

## Disclaimer

This project performs static configuration analysis. It is not a penetration
test; it never probes live systems or runs attacks.
