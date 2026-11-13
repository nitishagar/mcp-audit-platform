import { describe, expect, it } from "vitest";
import { CHECK_IDS } from "../src/checks/index.js";
import { FRAMEWORK, SEVERITY_MAP, severityFor } from "../src/severity-map.js";

describe("severity map (I3)", () => {
  it("pins the OWASP MCP Top 10 beta framework", () => {
    expect(FRAMEWORK).toBe("OWASP MCP Top 10 v2025-beta");
  });

  it("maps every registered checkId", () => {
    for (const id of CHECK_IDS) {
      expect(SEVERITY_MAP[id], `missing map entry for ${id}`).toBeDefined();
    }
  });

  it("carries CVE refs where research ties a CVE", () => {
    expect(severityFor("AUTH-03").cveRefs).toContain("CVE-2025-49596");
    expect(severityFor("ARG-02").cveRefs).toContain("CVE-2025-54136");
  });

  it("defaults unknown checks to medium + unmapped flag, never silent", () => {
    const resolved = severityFor("NOPE-99");
    expect(resolved.severity).toBe("medium");
    expect(resolved.unmapped).toBe(true);
  });
});
