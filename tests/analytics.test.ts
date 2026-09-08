// CrackScope Part 24 — risk-analytics tests.
// Run with: bun test tests/analytics.test.ts
import { describe, expect, test } from "bun:test";

import {
  heatmap,
  languageBreakdown,
  languageOf,
  mttrStats,
  postureSummary,
  trendSeries,
} from "../src/lib/analytics";
import type { Finding, Severity } from "../src/lib/scanner";

const DAY = 24 * 60 * 60 * 1000;

let seq = 0;
function finding(
  ruleId: string,
  severity: Severity,
  file = "a.js",
  line = 1,
): Finding {
  seq += 1;
  return {
    ruleId,
    title: `${ruleId} title`,
    severity,
    category: "Injection",
    owasp: "A03:2021 – Injection",
    file,
    line,
    snippet: "x",
    description: "d",
    remediation: "r",
    payload: "p",
    ...(seq > 0 ? {} : {}),
  } as Finding;
}

function scan(
  id: string,
  createdAt: number,
  findings: Finding[],
  score = 80,
): {
  _id: string;
  name: string;
  createdAt: number;
  score: number;
  grade: string;
  findings: Finding[];
} {
  return { _id: id, name: id, createdAt, score, grade: "B", findings };
}

describe("trendSeries", () => {
  test("returns chronological points regardless of input order", () => {
    const t = trendSeries([
      scan("new", 3000, [finding("SQLI-001", "critical")], 60),
      scan("old", 1000, [finding("SQLI-001", "critical"), finding("XSS-001", "high")], 40),
      scan("mid", 2000, [], 70),
    ]);
    expect(t.map((p) => p.createdAt)).toEqual([1000, 2000, 3000]);
    expect(t[0].total).toBe(2);
    expect(t[0].high).toBe(1);
    expect(t[1].total).toBe(0);
    expect(t[2].critical).toBe(1);
  });

  test("empty history → empty series", () => {
    expect(trendSeries([])).toEqual([]);
  });
});

describe("heatmap", () => {
  test("counts per category×severity and sorts categories by total", () => {
    const h = heatmap([
      finding("A", "critical", "a.js"),
      finding("A", "critical", "a.js", 2),
      finding("B", "low", "b.js"),
    ]);
    expect(h.categories[0]).toBe("Injection");
    expect(h.cells.get("Injection|critical")).toBe(2);
    expect(h.cells.get("Injection|low")).toBe(1);
    expect(h.maxCell).toBe(2);
    expect(h.total).toBe(3);
  });

  test("missing cell lookups default to undefined → 0 in UI", () => {
    const h = heatmap([finding("A", "critical")]);
    expect(h.cells.get("Injection|info")).toBeUndefined();
  });

  test("empty findings → no categories", () => {
    const h = heatmap([]);
    expect(h.categories).toEqual([]);
    expect(h.maxCell).toBe(0);
  });
});

describe("languageOf / languageBreakdown", () => {
  test("maps extensions and special filenames", () => {
    expect(languageOf("src/app.tsx")).toBe("TypeScript");
    expect(languageOf("server.py")).toBe("Python");
    expect(languageOf("Dockerfile")).toBe("Docker");
    expect(languageOf("infra/main.tf")).toBe("Terraform/IaC");
    expect(languageOf("mystery.zzz")).toBe("Other");
  });

  test("breakdown aggregates findings, criticals, highs per language", () => {
    const langs = languageBreakdown([
      finding("A", "critical", "s.js"),
      finding("B", "high", "s.js", 2),
      finding("C", "low", "p.py", 3),
    ]);
    const js = langs.find((l) => l.language === "JavaScript")!;
    const py = langs.find((l) => l.language === "Python")!;
    expect(js.findings).toBe(2);
    expect(js.critical).toBe(1);
    expect(js.high).toBe(1);
    expect(py.findings).toBe(1);
    expect(langs[0].findings).toBeGreaterThanOrEqual(langs[langs.length - 1].findings);
  });
});

describe("mttrStats", () => {
  test("computes mean time from first seen to disappearance", () => {
    const f = finding("SQLI-001", "critical");
    const m = mttrStats([
      scan("s1", 0 * DAY, [f]),
      scan("s2", 5 * DAY, []),
    ]);
    expect(m.samples).toBe(1);
    expect(m.meanDays).toBe(5);
    expect(m.bySeverity.critical).toBe(5);
    expect(m.slowest[0]?.days).toBe(5);
    expect(m.slowest[0]?.ruleId).toBe("SQLI-001");
  });

  test("still-open findings are not counted as fixed", () => {
    const m = mttrStats([scan("s1", 0, [finding("XSS-001", "high")])]);
    expect(m.samples).toBe(0);
    expect(m.meanDays).toBeNull();
    expect(m.bySeverity.high).toBeNull();
  });

  test("reappearing finding produces two fix samples (disappear→fix, return→new)", () => {
    const a = finding("A", "medium");
    const b = finding("A", "medium"); // same rule/file/line → same key
    const m = mttrStats([
      scan("s1", 0 * DAY, [a]),
      scan("s2", 2 * DAY, []), // fixed after 2d
      scan("s3", 3 * DAY, [b]), // reintroduced
      scan("s4", 10 * DAY, []), // fixed again after 7d
    ]);
    expect(m.samples).toBe(2);
    expect(m.meanDays).toBe(4.5);
  });

  test("empty history → null MTTR, no crash", () => {
    const m = mttrStats([]);
    expect(m.meanDays).toBeNull();
    expect(m.slowest).toEqual([]);
  });

  test("key includes line: fixing one of two same-rule lines counts once", () => {
    const l1 = finding("CMD-001", "high", "f.js", 10);
    const l2 = finding("CMD-001", "high", "f.js", 20);
    const m = mttrStats([
      scan("s1", 0, [l1, l2]),
      scan("s2", 1 * DAY, [l2]), // only line 10 fixed
    ]);
    expect(m.samples).toBe(1);
  });
});

describe("postureSummary", () => {
  test("derives latest scan, score trend, and open counts", () => {
    const p = postureSummary(
      [
        scan("old", 0, [finding("A", "critical")], 50),
        scan("new", DAY, [finding("B", "high")], 70),
      ],
      0,
    );
    expect(p.scans).toBe(2);
    expect(p.latest?._id).toBe("new");
    expect(p.scoreTrend).toBe(20);
    expect(p.openCritical).toBe(0);
    expect(p.openHigh).toBe(1);
    expect(p.triagedPct).toBe(0);
  });

  test("triage percentage counts closed rows vs latest findings", () => {
    const p = postureSummary(
      [scan("s", 0, [finding("A", "low"), finding("B", "low", "b.js", 2)], 90)],
      1,
    );
    expect(p.triagedPct).toBe(50);
  });

  test("single scan → null score trend, not NaN", () => {
    const p = postureSummary([scan("only", 0, [], 75)], 0);
    expect(p.scoreTrend).toBeNull();
    expect(p.triagedPct).toBeNull(); // zero findings → null, not 0/0 NaN
  });

  test("empty history → safe defaults", () => {
    const p = postureSummary([], 0);
    expect(p.latest).toBeNull();
    expect(p.openCritical).toBe(0);
    expect(p.scoreTrend).toBeNull();
  });
});
