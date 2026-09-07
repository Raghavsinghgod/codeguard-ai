// CrackScope Part 12 — scan history & diffing.
// Compares two ScanResults by finding key ("ruleId|file|line"), classifies
// new / fixed / persistent findings, and derives remediation-velocity stats
// across a scan history. Pure TypeScript.
import type { Finding, ScanResult, Severity } from "./scanner";

export interface ScanDiff {
  scoreDelta: number; // current - previous (positive = improvement)
  gradeFrom: string;
  gradeTo: string;
  added: Finding[]; // present now, absent before — regressions
  fixed: Finding[]; // present before, absent now — remediated
  persistent: number;
  verdict: "improved" | "regressed" | "mixed" | "unchanged";
}

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function keyOf(f: Finding): string {
  return `${f.ruleId}|${f.file}|${f.line}`;
}

export function diffScanResults(prev: ScanResult, curr: ScanResult): ScanDiff {
  const prevKeys = new Map(prev.findings.map((f) => [keyOf(f), f]));
  const currKeys = new Map(curr.findings.map((f) => [keyOf(f), f]));

  const added = curr.findings.filter((f) => !prevKeys.has(keyOf(f)));
  const fixed = prev.findings.filter((f) => !currKeys.has(keyOf(f)));
  const persistent = curr.findings.filter((f) => prevKeys.has(keyOf(f))).length;

  const scoreDelta = curr.score - prev.score;
  const worst = (fs: Finding[]): Severity | null =>
    fs.length === 0 ? null : fs.slice().sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))[0].severity;

  const addedWorst = worst(added);
  const fixedWorst = worst(fixed);

  let verdict: ScanDiff["verdict"];
  const meaningful = (s: Severity | null) => s === "critical" || s === "high";
  if (added.length === 0 && fixed.length === 0) {
    verdict = "unchanged";
  } else if (meaningful(addedWorst) && !meaningful(fixedWorst)) {
    verdict = "regressed";
  } else if (meaningful(fixedWorst) && !meaningful(addedWorst)) {
    verdict = "improved";
  } else if (fixed.length > added.length) {
    verdict = "improved";
  } else if (added.length > fixed.length) {
    verdict = "regressed";
  } else {
    verdict = "mixed";
  }
  // A significant score swing is decisive even when counts tie.
  if (Math.abs(scoreDelta) >= 10 && verdict === "mixed") {
    verdict = scoreDelta > 0 ? "improved" : "regressed";
  }

  return {
    scoreDelta,
    gradeFrom: prev.grade,
    gradeTo: curr.grade,
    added: added.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)),
    fixed: fixed.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)),
    persistent,
    verdict,
  };
}

// ---------- history trend / remediation velocity ----------

export interface TrendPoint {
  scanId: string;
  name: string;
  createdAt: number;
  score: number;
  added: number;
  fixed: number;
}

export interface VelocityStats {
  points: TrendPoint[]; // chronological (oldest first)
  totalFixed: number;
  totalAdded: number;
  netPerScan: number; // average net change in finding count per scan
  verdict: "improving" | "degrading" | "flat";
}

export function velocityStats(
  scans: Array<{ _id: string; name: string; createdAt: number; score: number; findings: Finding[] }>,
): VelocityStats {
  // Input is typically newest-first; make it chronological.
  const chrono = [...scans].sort((a, b) => a.createdAt - b.createdAt);
  const points: TrendPoint[] = [];
  let totalFixed = 0;
  let totalAdded = 0;

  for (let i = 0; i < chrono.length; i++) {
    const curr = chrono[i];
    let added = 0;
    let fixed = 0;
    if (i > 0) {
      const prevKeys = new Set(chrono[i - 1].findings.map(keyOf));
      const currKeys = new Set(curr.findings.map(keyOf));
      added = curr.findings.filter((f) => !prevKeys.has(keyOf(f))).length;
      fixed = chrono[i - 1].findings.filter((f) => !currKeys.has(keyOf(f))).length;
      totalFixed += fixed;
      totalAdded += added;
    }
    points.push({
      scanId: curr._id,
      name: curr.name,
      createdAt: curr.createdAt,
      score: curr.score,
      added,
      fixed,
    });
  }

  const transitions = Math.max(points.length - 1, 1);
  const netPerScan = Math.round(((totalAdded - totalFixed) / transitions) * 10) / 10;

  return {
    points,
    totalFixed,
    totalAdded,
    netPerScan,
    verdict: totalFixed === 0 && totalAdded === 0 ? "flat" : netPerScan < 0 ? "improving" : netPerScan > 0 ? "degrading" : "flat",
  };
}
