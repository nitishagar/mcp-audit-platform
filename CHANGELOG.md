# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
SemVer. Release tags live on GitHub Releases (see `.github/workflows/release.yml`).

## [Unreleased]

### Added
- Real client-config adapters (Claude Desktop/Code, Cursor, VS Code, Windsurf) with
  original-file pointers; `--client` override; `--discover` multi-config mode.
- Checks re-derived from real fields: INV-01 launch pinning, AUTH-01 credential
  signals, AUTH-03 server-side coverage split, AUTH-04 TLS, PRIV-01 vendor
  annotations, PRIV-03 filesystem breadth, PRIV-04 container escapes.
- `--tools` tools/list import; ARG-03 aggregated schema-strictness check; ARG-02
  nested-description scanning.
- Bundled OSV advisory snapshot (`SUP-01`) with build-time refresh script.
- `INV-02` shadow/drift check for `--discover`.
- Print-ready HTML report (`--format html`, `mcp-audit report`) with executive
  summary, prioritized fix checklist, and methodology appendix.
- Composite GitHub Action (`action.yml`) with SARIF upload recipe.
- CI: `pnpm verify` gate, CodeQL, Dependabot, action selftest with SARIF upload
  on main; advisory-staleness warning.

### Changed
- Status semantics v2.0: `unassessable` split into input/coverage scope;
  `not_applicable` status; `--strict` flag; no vacuous passes (tool checks
  without schemas are coverage-unassessable, never pass).
- Scanner package prepared for npm publish as `mcp-audit-scanner`.
- SARIF: region, partialFingerprints, file-path artifactLocation, note level.

### Security
- MIT LICENSE added; redaction hardened across adapters, HTML report, and
  the report re-render trust boundary.
