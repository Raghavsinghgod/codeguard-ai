// CrackScope Part 20 — export module.
// CSV and JSON exports of a scan result, alongside the Markdown/HTML
// exports that already live in report.ts. CSV is client/audit-tool
// friendly (one row per finding); JSON is the full machine-readable
// artifact including score, counts, surface map, and pipeline gate.

import type { Finding, ScanResult } from "./scanner";
import { safeFileName } from "./report";

function csvEscape(value: string): string {
  if (/[",\n\r]/.test(value)) return `"${value.replace(/"/g, '""')}"`;
  return value;
}

const CSV_COLUMNS: (keyof Finding)[] = [
  "ruleId",
  "severity",
  "category",
  "title",
  "file",
  "line",
  "owasp",
  "description",
  "remediation",
  "payload",
  "snippet",
];

/** One row per finding; cells are escaped and multi-line fields quoted. */
export function buildCsvReport(result: ScanResult): string {
  const header = ["rule", "severity", "category", "title", "file", "line", "owasp", "description", "remediation", "attack", "snippet"].join(",");
  const rows = result.findings.map((f) =>
    CSV_COLUMNS.map((k) => csvEscape(String(f[k] ?? ""))).join(","),
  );
  return [header, ...rows].join("\r\n");
}

/** Full machine-readable artifact: result + CVSS-style vectors per finding. */
export function buildJsonReport(name: string, result: ScanResult): string {
  return JSON.stringify(
    {
      tool: "CrackScope",
      reportVersion: 1,
      generatedAt: new Date().toISOString(),
      scanName: name,
      score: result.score,
      grade: result.grade,
      scope: {
        files: result.filesScanned,
        lines: result.linesScanned,
        languages: result.languages,
      },
      counts: result.counts,
      durationMs: result.durationMs,
      pipelineGate: result.pipelineGate ?? null,
      surface: result.surface ?? null,
      findings: result.findings,
    },
    null,
    2,
  );
}

function download(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportCsv(name: string, result: ScanResult) {
  download(buildCsvReport(result), `crackscope-findings-${safeFileName(name)}.csv`, "text/csv");
}

export function exportJson(name: string, result: ScanResult) {
  download(buildJsonReport(name, result), `crackscope-report-${safeFileName(name)}.json`, "application/json");
}
