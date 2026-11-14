# Security Policy

## Reporting a vulnerability

Open a GitHub security advisory via **Report a vulnerability** on this
repository. (An email address will be published once the product domain is
chosen — tracking: PLAN-PRODUCT-COMPLETE D-1.)

Please include: affected component (scanner / site / action), the input file
or request that triggers the issue, and the expected vs actual behavior.

## Scope

- `packages/scanner` — config parsing, adapters, checks, emitters (the
  scanner processes untrusted config files; secret handling is invariant I4).
- `packages/site` — static site build and copy.
- GitHub Actions workflows.

## What we do NOT claim

The scanner is static analysis only — it never probes, attacks, or tests
live systems. Reports about a *target* system belong to that system's owner,
not this project.
