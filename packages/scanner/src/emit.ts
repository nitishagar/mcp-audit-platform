import { CHECKS } from "./checks/index.js";
import type { AuditResult } from "./runner.js";
import { SEVERITY_RANK } from "./schema.js";

export type Format = "json" | "sarif" | "summary";

function allFailFindings(result: AuditResult) {
  return result.checks.flatMap((c) => c.findings.filter((f) => f.status === "fail"));
}

function allUnassessable(result: AuditResult) {
  return result.checks.flatMap((c) => c.findings.filter((f) => f.status === "unassessable"));
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

/** SARIF 2.1.0 with the fields code-scanning consumers require. */
export function emitSarif(result: AuditResult): string {
  const rules = CHECKS.map((c) => ({
    id: c.id,
    name: c.id,
    shortDescription: { text: c.description },
    fullDescription: { text: c.description },
    helpUri: "https://github.com/nitishagar/mcp-audit-platform",
  }));
  const results = [
    ...allFailFindings(result).map((f) => ({
      ruleId: f.checkId,
      level: SARIF_LEVEL[f.severity] ?? "warning",
      message: { text: `[${f.id}] ${f.detail}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: f.pointer } } }],
      properties: { severity: f.severity, frameworkRefs: f.frameworkRefs },
    })),
    // Unassessable checks are reported, never dropped (I1).
    ...allUnassessable(result).map((f) => ({
      ruleId: f.checkId,
      level: "none",
      message: { text: `[${f.id}] UNASSESSABLE: ${f.detail}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: f.pointer } } }],
      properties: { severity: f.severity, status: "unassessable", frameworkRefs: f.frameworkRefs },
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
  const unass = allUnassessable(result);
  const passed = result.checks.filter((c) => c.status === "pass").length;
  const lines = [
    `# mcp-audit summary`,
    ``,
    `Tool: ${result.tool} ${result.toolVersion} · Framework: ${result.framework}`,
    ``,
    `Checks: ${passed} passed, ${fails.length} finding(s), ${unass.length} unassessable.`,
    ``,
  ];
  if (fails.length > 0) {
    lines.push(`## Findings`, ``);
    for (const f of fails) {
      lines.push(`- **[${f.severity}] ${f.checkId}** (${f.id}) at \`${f.pointer}\``);
      lines.push(`  ${f.detail}`);
      lines.push(`  Refs: ${f.frameworkRefs.join(", ")}`);
    }
    lines.push(``);
  }
  if (unass.length > 0) {
    lines.push(`## Unassessable`, ``);
    for (const f of unass) {
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

export function emit(result: AuditResult, format: Format): string {
  if (format === "sarif") return emitSarif(result);
  if (format === "summary") return emitSummary(result);
  return emitJson(result);
}
