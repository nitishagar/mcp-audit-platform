import { CHECKS } from "./checks/index.js";
import { ruleMeta } from "./rules.js";
import { emitHtml } from "./emit-html.js";
import type { AuditResult } from "./runner.js";
import { SEVERITY_RANK } from "./schema.js";

export type Format = "json" | "sarif" | "summary" | "html";

function allFailFindings(result: AuditResult) {
  return result.checks.flatMap((c) => c.findings.filter((f) => f.status === "fail"));
}

/** Unassessable findings from ALL checks (a fail-status check can still carry
 * unassessable rows; I1 forbids dropping them from the human surface). */
function allUnassessable(result: AuditResult) {
  return result.checks.flatMap((c) =>
    c.findings
      .filter((f) => f.status === "unassessable")
      .map((f) => ({ finding: f, scope: f.scope ?? c.scope })),
  );
}

function allNotApplicable(result: AuditResult) {
  return result.checks.filter((c) => c.status === "not_applicable");
}

/** Canonical JSON: key order fixed by construction, findings pre-sorted. */
export function emitJson(result: AuditResult): string {
  return `${JSON.stringify(result, null, 2)}\n`;
}

const SARIF_LEVEL: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};

/** SARIF 2.1.0 with the fields code-scanning consumers require.
 * `sourcePath` is the scanned config file path; when omitted (bare library
 * calls), `artifactLocation.uri` falls back to the finding's JSON pointer,
 * which stays schema-valid. CLI callers always pass the real path. */
export function emitSarif(result: AuditResult, sourcePath?: string): string {
  // rules.ts is the single source for rule help (C3): short text = the check
  // description, full/help = the rationale + remediation. helpUri anchors the
  // README coverage table (the stable public docs until the site domain lands).
  const rules = CHECKS.map((c) => {
    const meta = ruleMeta(c.id);
    return {
      id: c.id,
      name: c.id,
      shortDescription: { text: c.description },
      fullDescription: { text: meta ? `${meta.rationale}` : c.description },
      help: { text: meta ? `Fix: ${meta.remediation}` : c.description },
      helpUri: "https://github.com/nitishagar/mcp-audit-platform#check-coverage-i8",
    };
  });
  const locations = (f: { pointer: string }) => [
    {
      physicalLocation: {
        artifactLocation: { uri: sourcePath ?? f.pointer },
        // Config files have no line-anchored region; a 1-line region is the
        // honest minimum code-scanning consumers require.
        region: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 },
      },
    },
  ];
  const results = [
    ...allFailFindings(result).map((f) => ({
      ruleId: f.checkId,
      level: SARIF_LEVEL[f.severity] ?? "warning",
      message: { text: `[${f.id}] ${f.detail}` },
      locations: locations(f),
      partialFingerprints: { primaryLocationLineHash: f.id },
      properties: { severity: f.severity, pointer: f.pointer, frameworkRefs: f.frameworkRefs },
    })),
    // Unassessable checks are reported, never dropped (I1). Level "note":
    // GitHub documents only error/warning/note and surfaces "none" as open alerts.
    // not_applicable checks emit no result by design.
    ...allUnassessable(result).map(({ finding: f, scope }) => ({
      ruleId: f.checkId,
      level: "note",
      message: { text: `[${f.id}] UNASSESSABLE: ${f.detail}` },
      locations: locations(f),
      partialFingerprints: { primaryLocationLineHash: f.id },
      properties: {
        severity: f.severity,
        status: "unassessable",
        ...(scope ? { scope } : {}),
        pointer: f.pointer,
        frameworkRefs: f.frameworkRefs,
      },
    })),
  ];
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: result.tool, version: result.toolVersion, rules } },
        results,
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

/** Human-readable Markdown summary. */
export function emitSummary(result: AuditResult): string {
  const fails = allFailFindings(result).sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.id.localeCompare(b.id),
  );
  const inputUnass = allUnassessable(result).filter((x) => x.scope === "input");
  const coverageUnass = allUnassessable(result).filter((x) => x.scope === "coverage");
  const notApplicable = allNotApplicable(result);
  const passed = result.checks.filter((c) => c.status === "pass").length;
  const lines = [
    `# mcp-audit summary`,
    ``,
    `Tool: ${result.tool} ${result.toolVersion} · Framework: ${result.framework}`,
    ``,
    `Checks: ${passed} passed, ${fails.length} finding(s), ${inputUnass.length} input-unassessable, ${coverageUnass.length} not determinable, ${notApplicable.length} not applicable.`,
    ``,
  ];
  if (result.sources && result.sources.length > 0) {
    lines.push(`## Sources`, ``);
    for (const s of result.sources) lines.push(`- ${s.file} (${s.format}, ${s.servers} server(s))`);
    lines.push(``);
  }
  if (fails.length > 0) {
    lines.push(`## Findings`, ``);
    for (const f of fails) {
      lines.push(`- **[${f.severity}] ${f.checkId}** (${f.id}) at \`${f.pointer}\``);
      lines.push(`  ${f.detail}`);
      lines.push(`  Refs: ${f.frameworkRefs.join(", ")}`);
    }
    lines.push(``);
  }
  if (inputUnass.length > 0) {
    lines.push(`## Unassessable (input errors)`, ``);
    for (const { finding: f } of inputUnass) {
      lines.push(`- **${f.checkId}** (${f.id}) at \`${f.pointer}\`: ${f.detail}`);
    }
    lines.push(``);
  }
  if (coverageUnass.length > 0) {
    lines.push(`## Not determinable from this input`, ``);
    for (const { finding: f } of coverageUnass) {
      lines.push(`- **${f.checkId}** (${f.id}) at \`${f.pointer}\`: ${f.detail}`);
    }
    lines.push(``);
  }
  if (result.warnings.length > 0) {
    lines.push(`## Warnings`, ``);
    for (const w of result.warnings) lines.push(`- ${w}`);
    lines.push(``);
  }
  lines.push(`_Static analysis only — not a penetration test._`, ``);
  return lines.join("\n");
}

export function emit(result: AuditResult, format: Format, sourcePath?: string): string {
  if (format === "sarif") return emitSarif(result, sourcePath);
  if (format === "summary") return emitSummary(result);
  if (format === "html") return emitHtml(result);
  return emitJson(result);
}
