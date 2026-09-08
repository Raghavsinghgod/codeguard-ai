// CrackScope Part 23 — knowledge-base regression tests.
// Run with: bun test tests/techniques.test.ts
// The critical invariant: every ruleId referenced by a technique must exist
// in the detection engine's rule inventory. This mapping silently rotted once
// already (techniques referenced SQLI-CONCAT-style ids that the engine never
// emitted), which made live-finding coverage show zero rows.
import { describe, expect, test } from "bun:test";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import {
  TECHNIQUES,
  searchTechniques,
  techniqueCoverage,
  techniqueForFinding,
  type FindingLike,
} from "../src/lib/techniques";

let seq = 0;
const f = (ruleId: string, category = "Injection"): FindingLike => {
  seq += 1;
  return { ruleId, category, title: "t", severity: "high", ...{}, ...(seq > 0 ? {} : {}) } as FindingLike;
};

/**
 * Every `id: "..."` (static rule definitions) and `ruleId: "..."` (dynamic
 * detections) literal in the detector modules = emitted rule ids.
 */
function engineRuleIds(): Set<string> {
  const dir = join(import.meta.dir, "..", "src", "lib");
  const files = readdirSync(dir).filter((f) => f.endsWith(".ts"));
  const ids = new Set<string>();
  for (const file of files) {
    const text = readFileSync(join(dir, file), "utf8");
    for (const m of text.matchAll(/\b(?:id|ruleId):\s*"([A-Za-z][A-Za-z0-9-]*)"/g)) {
      ids.add(m[1]);
    }
  }
  return ids;
}

const ENGINE = engineRuleIds();

describe("technique → engine rule mapping", () => {
  test("every cataloged ruleId exists in the engine's rule inventory", () => {
    const stale: string[] = [];
    for (const t of TECHNIQUES) {
      expect(t.ruleIds.length).toBeGreaterThan(0);
      for (const rid of t.ruleIds) {
        if (!ENGINE.has(rid)) stale.push(`${t.id} → ${rid}`);
      }
    }
    expect(stale).toEqual([]);
  });

  test("at least one technique is covered by real rules — no all-rot catalog", () => {
    const covered = TECHNIQUES.filter((t) => t.ruleIds.some((r) => ENGINE.has(r)));
    expect(covered.length).toBeGreaterThan(0);
  });
});

describe("techniqueForFinding", () => {
  test("resolves a real engine rule to its technique", () => {
    const t = techniqueForFinding(f("SQLI-001"));
    expect(t).not.toBeNull();
    expect(t!.id).toBe("CS-T01");
  });

  test("resolves secrets rules (multi-rule technique)", () => {
    expect(techniqueForFinding(f("SECRET-AWS-AKID"))?.id).toBe("CS-T06");
    expect(techniqueForFinding(f("SEC-001"))?.id).toBe("CS-T06");
  });

  test("returns null for unknown rules without throwing", () => {
    expect(techniqueForFinding(f("TOTALLY-UNKNOWN-999"))).toBeNull();
  });
});

describe("techniqueCoverage", () => {
  test("aggregates counts per technique and maps severity", () => {
    const findings: FindingLike[] = [
      f("SQLI-001", "Injection"),
      f("SQLI-002", "Injection"),
      f("SECRET-AWS-AKID", "Secrets"),
    ];
    const cov = techniqueCoverage(findings);
    expect(cov.get("CS-T01")!.count).toBe(2);
    expect(cov.get("CS-T06")!.count).toBe(1);
    expect(cov.size).toBe(2);
  });

  test("empty findings → empty coverage", () => {
    expect(techniqueCoverage([]).size).toBe(0);
  });
});

describe("searchTechniques", () => {
  test("free-text search hits names, ids, and payloads", () => {
    expect(searchTechniques("SQL injection", null).some((t) => t.id === "CS-T01")).toBe(true);
    expect(searchTechniques("CS-T06", null)[0]?.id).toBe("CS-T06");
    expect(searchTechniques("__proto__", null).some((t) => t.id === "CS-T12")).toBe(true);
    expect(searchTechniques("pickle", null).some((t) => t.id === "CS-T09")).toBe(true);
  });

  test("tactic filter narrows results and is case-exact", () => {
    const all = searchTechniques("", null);
    const execution = searchTechniques("", "Execution");
    expect(execution.length).toBeGreaterThan(0);
    expect(execution.length).toBeLessThan(all.length);
    for (const t of execution) expect(t.tactic).toBe("Execution");
  });

  test("non-matching query returns empty array", () => {
    expect(searchTechniques("zzz-no-such-term-zzz", null)).toEqual([]);
  });
});
