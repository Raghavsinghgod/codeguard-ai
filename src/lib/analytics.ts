// CrackScope Part 24 — risk analytics.
// Pure TypeScript aggregations over scan history: score/severity trends,
// category × severity heatmap, language breakdown, and MTTR (mean time to
// remediate, derived from when findings first appear and later disappear).
import type { Finding, ScanResult, Severity } from "./scanner";

export interface HistoryScan {
  _id: string;
  name: string;
  createdAt: number;
  score: number;
  grade: string;
  findings: Finding[];
}

// ---------- score & severity trend ----------

export interface TrendSeriesPoint {
  createdAt: number;
  name: string;
  score: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

/** Chronological trend series across scan history (oldest first). */
export function trendSeries(scans: HistoryScan[]): TrendSeriesPoint[] {
  return [...scans]
    .sort((a, b) => a.createdAt - b.createdAt)
    .map((s) => ({
      createdAt: s.createdAt,
      name: s.name,
      score: s.score,
      critical: countSev(s.findings, "critical"),
      high: countSev(s.findings, "high"),
      medium: countSev(s.findings, "medium"),
      low: countSev(s.findings, "low"),
      total: s.findings.length,
    }));
}

export function countSev(findings: Finding[], sev: Severity): number {
  return findings.filter((f) => f.severity === sev).length;
}

// ---------- category × severity heatmap ----------

export interface HeatmapCell {
  category: string;
  severity: Severity;
  count: number;
}

export interface HeatmapData {
  categories: string[]; // sorted by total findings desc
  severities: Severity[];
  cells: Map<string, number>; // key: `${category}|${severity}`
  maxCell: number;
  total: number;
}

export function heatmap(findings: Finding[]): HeatmapData {
  const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
  const cells = new Map<string, number>();
  const totals = new Map<string, number>();
  let maxCell = 0;
  for (const f of findings) {
    const key = `${f.category}|${f.severity}`;
    const next = (cells.get(key) ?? 0) + 1;
    cells.set(key, next);
    if (next > maxCell) maxCell = next;
    totals.set(f.category, (totals.get(f.category) ?? 0) + 1);
  }
  const categories = [...totals.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([c]) => c);
  return {
    categories,
    severities,
    cells,
    maxCell,
    total: findings.length,
  };
}

// ---------- language breakdown ----------

const EXT_LANGUAGE: Record<string, string> = {
  js: "JavaScript",
  jsx: "JavaScript",
  mjs: "JavaScript",
  cjs: "JavaScript",
  ts: "TypeScript",
  tsx: "TypeScript",
  py: "Python",
  rb: "Ruby",
  go: "Go",
  rs: "Rust",
  java: "Java",
  kt: "Kotlin",
  php: "PHP",
  cs: "C#",
  c: "C",
  h: "C",
  cpp: "C++",
  cc: "C++",
  hpp: "C++",
  swift: "Swift",
  sh: "Shell",
  bash: "Shell",
  sql: "SQL",
  yml: "YAML/IaC",
  yaml: "YAML/IaC",
  json: "Config/Data",
  toml: "Config/Data",
  dockerfile: "Docker",
};

export function languageOf(file: string): string {
  const lower = file.toLowerCase();
  if (lower.includes("dockerfile")) return "Docker";
  if (lower.includes("terraform") || lower.endsWith(".tf")) return "Terraform/IaC";
  const ext = lower.includes(".") ? lower.split(".").pop()! : "";
  return EXT_LANGUAGE[ext] ?? "Other";
}

export interface LanguageStat {
  language: string;
  findings: number;
  critical: number;
  high: number;
}

export function languageBreakdown(findings: Finding[]): LanguageStat[] {
  const map = new Map<string, LanguageStat>();
  for (const f of findings) {
    const lang = languageOf(f.file);
    const stat = map.get(lang) ?? { language: lang, findings: 0, critical: 0, high: 0 };
    stat.findings += 1;
    if (f.severity === "critical") stat.critical += 1;
    if (f.severity === "high") stat.high += 1;
    map.set(lang, stat);
  }
  return [...map.values()].sort((a, b) => b.findings - a.findings);
}

// ---------- MTTR (mean time to remediate) ----------

const DAY_MS = 24 * 60 * 60 * 1000;

export interface MttrStats {
  /** Overall mean remediation time in days; null when no fixes observed. */
  meanDays: number | null;
  samples: number;
  /** MTTR per severity in days (null where no fixes observed for that level). */
  bySeverity: Record<Severity, number | null>;
  /** Worst (longest-lived) fixed findings, newest first. */
  slowest: Array<{ key: string; ruleId: string; title: string; severity: Severity; days: number }>;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function keyOf(f: Finding): string {
  return `${f.ruleId}|${f.file}|${f.line}`;
}

/**
 * MTTR from scan history: for each finding that disappears between two
 * consecutive scans, its remediation time = fix-scan time − first-seen time.
 * Findings still present are open (not counted).
 */
export function mttrStats(scans: HistoryScan[]): MttrStats {
  const chrono = [...scans].sort((a, b) => a.createdAt - b.createdAt);
  const firstSeen = new Map<string, { createdAt: number; finding: Finding }>();

  const durations: Array<{ days: number; finding: Finding }> = [];

  for (const s of chrono) {
    const keys = new Set(s.findings.map(keyOf));
    // Findings from earlier scans that are gone now → fixed at s.createdAt.
    for (const [key, meta] of firstSeen) {
      if (!keys.has(key)) {
        durations.push({ days: (s.createdAt - meta.createdAt) / DAY_MS, finding: meta.finding });
        firstSeen.delete(key);
      }
    }
    for (const f of s.findings) {
      const key = keyOf(f);
      if (!firstSeen.has(key)) firstSeen.set(key, { createdAt: s.createdAt, finding: f });
    }
  }

  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, null])) as Record<Severity, number | null>;
  const sums = Object.fromEntries(SEVERITIES.map((s) => [s, { total: 0, n: 0 }])) as Record<
    Severity,
    { total: number; n: number }
  >;

  for (const d of durations) {
    sums[d.finding.severity].total += d.days;
    sums[d.finding.severity].n += 1;
  }
  for (const sev of SEVERITIES) {
    const { total, n } = sums[sev];
    bySeverity[sev] = n === 0 ? null : Math.round((total / n) * 10) / 10;
  }

  const meanDays =
    durations.length === 0
      ? null
      : Math.round((durations.reduce((acc, d) => acc + d.days, 0) / durations.length) * 10) / 10;

  const slowest = [...durations]
    .sort((a, b) => b.days - a.days)
    .slice(0, 5)
    .map(({ days, finding }) => ({
      key: keyOf(finding),
      ruleId: finding.ruleId,
      title: finding.title,
      severity: finding.severity,
      days: Math.round(days * 10) / 10,
    }));

  return { meanDays, samples: durations.length, bySeverity, slowest };
}

// ---------- risk posture summary ----------

export interface PostureSummary {
  scans: number;
  latest: HistoryScan | null;
  scoreTrend: number | null; // latest − oldest score
  openCritical: number;
  openHigh: number;
  triagedPct: number | null; // % of latest findings marked false_positive/accepted_risk
}

export function postureSummary(scans: HistoryScan[], triageClosed: number): PostureSummary {
  const chrono = [...scans].sort((a, b) => a.createdAt - b.createdAt);
  const latest = chrono[chrono.length - 1] ?? null;
  const scoreTrend =
    chrono.length >= 2 ? chrono[chrono.length - 1].score - chrono[0].score : null;
  return {
    scans: chrono.length,
    latest,
    scoreTrend,
    openCritical: latest ? countSev(latest.findings, "critical") : 0,
    openHigh: latest ? countSev(latest.findings, "high") : 0,
    triagedPct:
      latest && latest.findings.length > 0
        ? Math.round((triageClosed / latest.findings.length) * 100)
        : null,
  };
}

export type { ScanResult };
