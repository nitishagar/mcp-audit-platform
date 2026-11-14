# Branch protection (one-time, maintainer)

The CI gate is only as good as the branch that requires it. Run once as an
admin (or via the UI: Settings → Branches → Add rule):

```sh
gh api -X PUT repos/nitishagar/mcp-audit-platform/branches/main/protection \
  --input - <<'JSON'
{
  "required_status_checks": {"strict": true, "contexts": ["verify", "selftest", "analyze"]},
  "enforce_admins": false,
  "required_pull_request_reviews": {"required_approving_review_count": 0},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

`verify` is the CI job name in .github/workflows/ci.yml. Note the required
context name must match the job id (GitHub reports it as `verify`).
