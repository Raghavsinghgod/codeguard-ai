// CrackScope Part 8 — AI deep analysis.
// Shared between the Convex action (which calls the LLM) and the client UI.
// Pure TypeScript, no runtime deps: the prompt builder and the lenient JSON
// parser work on both sides of the wire.

// NOTE: relative import — this module is also compiled by the Convex
// tsconfig (via src/convex/ai.ts), which does not resolve the "@/" alias.
import type { Finding, ScanResult } from "./scanner";

export type AiVerdict = "confirmed" | "likely" | "suspicious";

export interface AiVerdictItem {
  key: string; // "ruleId|file|line" matching a finding
  verdict: AiVerdict;
  exploitability: string; // "trivial" | "easy" | "moderate" | "hard"
  note: string;
}

export interface AiBusinessFlaw {
  title: string;
  detail: string;
  affected: string;
}

export interface DeepAnalysis {
  narrative: string[]; // plain-English exploitation narrative
  businessLogicFlaws: AiBusinessFlaw[];
  verdicts: AiVerdictItem[];
  fixPriorities: string[];
}

export function verdictKey(f: Finding): string {
  return `${f.ruleId}|${f.file}|${f.line}`;
}

export function findingByKey(result: ScanResult, key: string): Finding | undefined {
  return result.findings.find((f) => verdictKey(f) === key);
}

// ---------- prompt ----------

export function buildAnalysisPrompt(name: string, result: ScanResult): { system: string; user: string } {
  const system = [
    "You are a senior red-team lead reviewing an automated security scan report.",
    "Reason about the findings like a pentester: exploitability, attack chains across findings,",
    "business-logic weaknesses the static rules cannot see, and what to fix first.",
    "Be concrete and technical. Never invent findings that are not in the provided list.",
    "Respond with STRICT JSON only, no markdown fences, matching exactly this shape:",
    '{"narrative": string[], "businessLogicFlaws": [{"title": string, "detail": string, "affected": string}],',
    ' "verdicts": [{"key": string, "verdict": "confirmed"|"likely"|"suspicious", "exploitability": string, "note": string}],',
    ' "fixPriorities": string[]}',
    "Rules: narrative = 3-5 paragraphs telling the exploitation story end-to-end.",
    'verdicts[].key must be EXACTLY a "ruleId|file|line" key from the findings list (verdict the most important 5-10 findings).',
    "fixPriorities = 3-6 ordered remediation steps, most urgent first.",
    "businessLogicFlaws = 0-3 plausible business-logic/abuse concerns inferred from the code patterns (mark them clearly as hypotheses).",
  ].join("\n");

  const findingsForPrompt = result.findings.slice(0, 20).map((f) => ({
    key: verdictKey(f),
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    category: f.category,
    location: `${f.file}:${f.line}`,
    snippet: f.snippet.slice(0, 160),
    description: f.description.slice(0, 240),
  }));

  const user = JSON.stringify({
    scan: name,
    securityScore: result.score,
    grade: result.grade,
    filesScanned: result.filesScanned,
    linesScanned: result.linesScanned,
    counts: result.counts,
    findings: findingsForPrompt,
    truncated: result.findings.length > 20,
  });

  return { system, user };
}

// ---------- lenient response parsing ----------

function asStringArray(value: unknown, max: number): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === "string" && v.trim().length > 0).slice(0, max);
}

function pickVerdict(value: unknown): AiVerdict | null {
  return value === "confirmed" || value === "likely" || value === "suspicious" ? value : null;
}

export function parseDeepAnalysis(raw: string): DeepAnalysis {
  let parsed: unknown = null;
  try {
    // Models sometimes wrap JSON in fences despite instructions.
    const cleaned = raw.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
    parsed = JSON.parse(cleaned);
  } catch {
    const start = raw.indexOf("{");
    const end = raw.lastIndexOf("}");
    if (start >= 0 && end > start) {
      try {
        parsed = JSON.parse(raw.slice(start, end + 1));
      } catch {
        parsed = null;
      }
    }
  }

  const obj = (parsed ?? {}) as Record<string, unknown>;

  const narrative = asStringArray(obj.narrative, 6);
  const fixPriorities = asStringArray(obj.fixPriorities, 8);

  const businessLogicFlaws: AiBusinessFlaw[] = Array.isArray(obj.businessLogicFlaws)
    ? (obj.businessLogicFlaws as Record<string, unknown>[])
        .filter((f) => typeof f?.title === "string")
        .slice(0, 4)
        .map((f) => ({
          title: String(f.title),
          detail: typeof f.detail === "string" ? f.detail : "",
          affected: typeof f.affected === "string" ? f.affected : "",
        }))
    : [];

  const verdicts: AiVerdictItem[] = Array.isArray(obj.verdicts)
    ? (obj.verdicts as Record<string, unknown>[])
        .filter((v) => typeof v?.key === "string" && pickVerdict(v?.verdict) !== null)
        .slice(0, 15)
        .map((v) => ({
          key: String(v.key),
          verdict: pickVerdict(v.verdict)!,
          exploitability: typeof v.exploitability === "string" ? v.exploitability : "unknown",
          note: typeof v.note === "string" ? v.note : "",
        }))
    : [];

  return { narrative, businessLogicFlaws, verdicts, fixPriorities };
}
