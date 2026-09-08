import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { useMutation, useQuery } from "convex/react";
import { EyeOff } from "lucide-react";
import {
  ChevronDown,
  Download,
  FileText,
  ShieldCheck,
  Swords,
  Wrench,
} from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { SimulationLab } from "@/components/SimulationLab";
import { ComplianceView } from "@/components/ComplianceView";
import { StrixAgents, StrixModeSelector } from "@/components/StrixAgents";
import { runStrixAgents, SCAN_BUDGETS, type ScanMode, type StrixRun } from "@/lib/strix";
import { cweFor } from "@/lib/compliance";
import { DIFFICULTY_CHIP, hardeningFor, hardeningPlan } from "@/lib/hardening";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";
import { TriageBar, TRIAGE_BADGE, type TriageState } from "@/components/TriageBar";
import { verdictKey } from "@/lib/ai";
import type { ScanResult, Severity, Finding } from "@/lib/scanner";
import {
  cvssFor,
  executiveSummary,
  exportMarkdown,
  exportPdf,
  riskRating,
} from "@/lib/report";

export const SEVERITY_STYLE: Record<Severity, { dot: string; text: string; chip: string }> = {
  critical: {
    dot: "bg-destructive",
    text: "text-destructive",
    chip: "border-destructive/40 bg-destructive/10 text-destructive",
  },
  high: {
    dot: "bg-[oklch(0.75_0.15_55)]",
    text: "text-[oklch(0.78_0.14_55)]",
    chip: "border-[oklch(0.75_0.15_55)]/40 bg-[oklch(0.75_0.15_55)]/10 text-[oklch(0.8_0.13_55)]",
  },
  medium: {
    dot: "bg-[oklch(0.8_0.16_85)]",
    text: "text-[oklch(0.82_0.15_85)]",
    chip: "border-[oklch(0.8_0.16_85)]/40 bg-[oklch(0.8_0.16_85)]/10 text-[oklch(0.84_0.14_85)]",
  },
  low: {
    dot: "bg-[oklch(0.75_0.12_220)]",
    text: "text-[oklch(0.78_0.11_220)]",
    chip: "border-[oklch(0.75_0.12_220)]/40 bg-[oklch(0.75_0.12_220)]/10 text-[oklch(0.8_0.1_220)]",
  },
  info: {
    dot: "bg-muted-foreground/60",
    text: "text-muted-foreground",
    chip: "border-border bg-muted text-muted-foreground",
  },
};

const GRADE_COLOR: Record<string, string> = {
  A: "text-primary",
  B: "text-[oklch(0.78_0.11_220)]",
  C: "text-[oklch(0.82_0.14_85)]",
  D: "text-[oklch(0.8_0.13_55)]",
  F: "text-destructive",
};

function ScoreRing({ score, grade }: { score: number; grade: string }) {
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const stroke =
    score >= 75 ? "oklch(0.78 0.13 168)" : score >= 50 ? "oklch(0.8 0.16 85)" : "oklch(0.66 0.19 25)";
  return (
    <div className="relative flex size-[132px] items-center justify-center">
      <svg className="size-full -rotate-90" viewBox="0 0 132 132">
        <circle cx="66" cy="66" r={radius} fill="none" stroke="oklch(1 0 0 / 8%)" strokeWidth="9" />
        <motion.circle
          cx="66"
          cy="66"
          r={radius}
          fill="none"
          stroke={stroke}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.1, ease: "easeOut", delay: 0.2 }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-3xl font-semibold tracking-tight">{score}</span>
        <span className={`text-sm font-semibold ${GRADE_COLOR[grade] ?? "text-muted-foreground"}`}>
          grade {grade}
        </span>
      </div>
    </div>
  );
}

function FixGuide({ finding }: { finding: Finding }) {
  const guide = hardeningFor(finding);
  return (
    <div className="rounded-lg border border-[oklch(0.78_0.13_168)]/30 bg-[oklch(0.78_0.13_168)]/5 p-3.5">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <p className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-widest text-[oklch(0.72_0.14_168)]">
          <Wrench className="size-3.5" /> Fix guide
        </p>
        <Badge variant="outline" className={`rounded-full capitalize ${DIFFICULTY_CHIP[guide.difficulty]}`}>
          {guide.difficulty}
        </Badge>
        <span className="font-mono text-[11px] text-muted-foreground">est. {guide.effort}</span>
      </div>
      <ol className="space-y-1.5">
        {guide.steps.map((step, i) => (
          <li key={i} className="flex items-start gap-2 text-sm leading-6">
            <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-[oklch(0.72_0.14_168)]" />
            <span className="text-foreground/90">{step}</span>
          </li>
        ))}
      </ol>
      {guide.before && guide.after && (
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          <div>
            <p className="mb-1 font-mono text-[10px] uppercase tracking-widest text-destructive/80">Before</p>
            <pre className="overflow-x-auto rounded-lg border border-destructive/25 bg-secondary/60 p-2.5 font-mono text-xs leading-5 line-through decoration-destructive/50">
              {guide.before}
            </pre>
          </div>
          <div>
            <p className="mb-1 font-mono text-[10px] uppercase tracking-widest text-primary">After</p>
            <pre className="overflow-x-auto rounded-lg border border-primary/25 bg-secondary/60 p-2.5 font-mono text-xs leading-5">
              {guide.after}
            </pre>
          </div>
        </div>
      )}
      <p className="mt-2.5 text-xs leading-5 text-muted-foreground">
        <span className="font-medium text-foreground/80">Verify:</span> {guide.verify}
      </p>
    </div>
  );
}

function HardeningPlanCard({ result }: { result: ScanResult }) {
  const plan = hardeningPlan(result);
  if (plan.items.length === 0) return null;
  const quickWins = plan.counts.trivial + plan.counts.easy;
  return (
    <div>
      <div className="mb-4 flex items-center gap-3">
        <h3 className="text-lg font-semibold tracking-tight">Hardening plan</h3>
        <Separator className="flex-1" />
        <span className="font-mono text-xs text-muted-foreground">
          {plan.items.length} fix{plan.items.length === 1 ? "" : "es"} · {quickWins} quick win
          {quickWins === 1 ? "" : "s"}
        </span>
      </div>
      <Card className="border-border/60 bg-card/70">
        <CardContent className="p-0">
          {plan.items.map((item, i) => (
            <div
              key={item.ruleId}
              className={`flex flex-wrap items-center gap-3 px-5 py-3.5 ${
                i > 0 ? "border-t border-border/50" : ""
              }`}
            >
              <span className="w-6 shrink-0 text-center font-mono text-sm text-muted-foreground">{i + 1}</span>
              <span className={`size-2 shrink-0 rounded-full ${SEVERITY_STYLE[item.severity].dot}`} />
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{item.title}</p>
                <p className="truncate font-mono text-xs text-muted-foreground">
                  {item.ruleId} · {item.occurrences} location{item.occurrences === 1 ? "" : "s"} ·{" "}
                  {item.files.join(", ")} · est. {item.effort}
                </p>
              </div>
              <Badge variant="outline" className={`shrink-0 rounded-full capitalize ${DIFFICULTY_CHIP[item.difficulty]}`}>
                {item.difficulty}
              </Badge>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

function FindingCard({
  finding,
  index,
  triage,
  triageDisabled,
  onTriage,
}: {
  finding: Finding;
  index: number;
  triage: TriageState;
  triageDisabled: boolean;
  onTriage: (patch: Partial<TriageState>) => void;
}) {
  const [open, setOpen] = useState(index < 3);
  const [labOpen, setLabOpen] = useState(false);
  const style = SEVERITY_STYLE[finding.severity];
  const triagedBadge = triage.status !== "open" ? TRIAGE_BADGE[triage.status] : null;
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: Math.min(index * 0.05, 0.4) }}
    >
      <Card className="border-border/60 bg-card/70">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="flex w-full items-center gap-3 px-5 py-4 text-left"
        >
          <span className={`size-2 shrink-0 rounded-full ${style.dot}`} />
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">{finding.title}</p>
            <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground">
              {finding.file}:{finding.line} · {finding.ruleId} · {finding.category}
            </p>
          </div>
          <Badge variant="outline" className={`shrink-0 rounded-full capitalize ${style.chip}`}>
            {finding.severity}
          </Badge>
          {triagedBadge && (
            <Badge variant="outline" className={`shrink-0 rounded-full text-[11px] ${triagedBadge.chip}`}>
              {triagedBadge.label}
            </Badge>
          )}
          <Badge variant="outline" className="hidden shrink-0 rounded-full font-mono text-[11px] text-muted-foreground md:inline-flex">
            {cvssFor(finding).score} · CVSS-style
          </Badge>
          <ChevronDown
            className={`size-4 shrink-0 text-muted-foreground transition-transform ${open ? "rotate-180" : ""}`}
          />
        </button>
        {open && (
          <div className="space-y-4 border-t border-border/50 px-5 py-4">
            <p className="text-sm leading-6 text-muted-foreground">{finding.description}</p>
            <div>
              <p className="mb-1.5 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
                Detected code · {finding.owasp}
                {cweFor(finding.ruleId) ? ` · ${cweFor(finding.ruleId)!.id}` : ""}
              </p>
              <pre className="overflow-x-auto rounded-lg border border-border/60 bg-secondary/60 p-3 font-mono text-xs leading-5">
                {finding.snippet}
              </pre>
            </div>
            <div className="rounded-lg border border-destructive/25 bg-destructive/5 p-3.5">
              <p className="mb-1.5 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-widest text-destructive">
                <Swords className="size-3.5" /> Simulated attack
              </p>
              <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-xs leading-5 text-foreground/90">
                {finding.payload}
              </pre>
            </div>
            <div className="rounded-lg border border-primary/25 bg-primary/5 p-3.5">
              <p className="mb-1.5 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-widest text-primary">
                <ShieldCheck className="size-3.5" /> Remediation
              </p>
              <p className="text-sm leading-6 text-foreground/90">{finding.remediation}</p>
            </div>
            <FixGuide finding={finding} />
            <TriageBar disabled={triageDisabled} state={triage} onPatch={onTriage} />
            <div className="flex justify-end">
              <Button size="sm" className="gap-2 rounded-full scan-glow" onClick={() => setLabOpen(true)}>
                <Swords className="size-4" /> Try to crack
              </Button>
            </div>
          </div>
        )}
      </Card>
      <Dialog open={labOpen} onOpenChange={setLabOpen}>
        <DialogContent className="max-h-[85vh] max-w-3xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Swords className="size-4 text-primary" /> Attack simulation lab
            </DialogTitle>
            <DialogDescription>
              Step through the exploit chain for this finding in a sandbox. Everything below is a
              local simulation — no requests are sent anywhere.
            </DialogDescription>
          </DialogHeader>
          <SimulationLab finding={finding} />
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}

export interface ScanReportData {
  name: string;
  result: ScanResult;
  /** Convex scan row id — enables the Part 11 triage workflow when present. */
  id?: Id<"scans"> | null;
}

export function ScanReport({ data }: { data: ScanReportData }) {
  const { name, result } = data;
  const scanId = data.id ?? null;
  const setTriage = useMutation(api.scans.setTriage);
  const triageRows = useQuery(
    api.scans.listTriage,
    scanId ? { scanId } : "skip",
  );
  const triageMap = useMemo(() => {
    const map = new Map<string, TriageState>();
    for (const row of triageRows ?? []) {
      map.set(row.key, { status: row.status, note: row.note, owner: row.owner });
    }
    return map;
  }, [triageRows]);
  const [hideFp, setHideFp] = useState(false);
  const [strixMode, setStrixMode] = useState<ScanMode>("standard");
  const strixRun: StrixRun | null = useMemo(
    () => (result.findings.length > 0 ? runStrixAgents(actionableResult, { mode: strixMode }) : null),
    [result, strixMode, triageMap],
  );

  const onTriage = (key: string, patch: Partial<TriageState>) => {
    if (!scanId) return;
    const current = triageMap.get(key) ?? { status: "open" as const };
    const next = { ...current, ...patch };
    triageMap.set(key, next);
    setTriage({
      scanId,
      key,
      status: next.status,
      note: next.note || undefined,
      owner: next.owner || undefined,
    }).catch(() => toast.error("Could not save triage state"));
  };

  const isFp = (f: Finding) => (triageMap.get(verdictKey(f))?.status ?? "open") === "false_positive";
  const fpCount = result.findings.filter(isFp).length;
  const visibleFindings = hideFp ? result.findings.filter((f) => !isFp(f)) : result.findings;
  const actionableResult = useMemo(
    () => ({ ...result, findings: result.findings.filter((f) => !isFp(f)) }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [result, triageMap],
  );
  const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
  const rating = riskRating(result);
  const summary = executiveSummary(result);

  const handlePdf = () => {
    const opened = exportPdf(name, result);
    if (!opened) {
      toast.info("Pop-up blocked — downloaded the report as HTML instead. Open it and print to PDF.");
    }
  };

  return (
    <div className="space-y-6">
      <Card className="border-border/60 bg-card/70">
        <CardContent className="flex flex-col gap-8 p-6 sm:flex-row sm:items-center">
          <div className="flex items-center gap-6">
            <ScoreRing score={result.score} grade={result.grade} />
            <div className="space-y-1.5">
              <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                Security score
              </p>
              <p className="font-medium">{name}</p>
              <p className="text-sm text-muted-foreground">
                {result.filesScanned} file{result.filesScanned === 1 ? "" : "s"} ·{" "}
                {result.linesScanned.toLocaleString()} lines ·{" "}
                {result.languages.join(", ") || "unknown"}
              </p>
              <p className="text-xs text-muted-foreground">
                {result.findings.length} finding{result.findings.length === 1 ? "" : "s"} ·
                simulated in {result.durationMs}ms
              </p>
              <Badge
                variant="outline"
                className={`rounded-full capitalize ${
                  rating === "Critical" || rating === "High"
                    ? SEVERITY_STYLE[rating === "Critical" ? "critical" : "high"].chip
                    : rating === "Moderate"
                      ? SEVERITY_STYLE.medium.chip
                      : SEVERITY_STYLE.low.chip
                }`}
              >
                risk rating: {rating}
              </Badge>
            </div>
          </div>
          <div className="flex flex-1 flex-wrap items-center justify-start gap-2.5 sm:justify-end">
            {severities.map((sev) => (
              <div
                key={sev}
                className={`rounded-full border px-3.5 py-1.5 text-sm font-medium capitalize ${SEVERITY_STYLE[sev].chip}`}
              >
                {result.counts[sev]} {sev}
              </div>
            ))}
          </div>
          <div className="flex shrink-0 flex-col gap-2">
            <Button variant="outline" onClick={() => exportMarkdown(name, result)} className="gap-2 rounded-full">
              <Download className="size-4" /> Export .md
            </Button>
            <Button variant="outline" onClick={handlePdf} className="gap-2 rounded-full">
              <FileText className="size-4" /> Export PDF
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card className="border-border/60 bg-card/70">
        <CardContent className="p-6">
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Executive summary
          </p>
          <div className="mt-2 space-y-2.5">
            {summary.map((p, i) => (
              <p key={i} className="text-sm leading-6 text-muted-foreground">
                {p}
              </p>
            ))}
          </div>
        </CardContent>
      </Card>

      {strixRun && (
        <div>
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <h3 className="text-lg font-semibold tracking-tight">Strix agent team</h3>
            <Separator className="hidden flex-1 md:block" />
            <span className="font-mono text-xs text-muted-foreground">
              autonomous multi-agent red team · real PoCs, not false positives
            </span>
            <StrixModeSelector mode={strixMode} onMode={setStrixMode} />
          </div>
          <StrixAgents run={strixRun} mode={strixMode} />
        </div>
      )}

      <div>
        <div className="mb-4 flex items-center gap-3">
          <h3 className="text-lg font-semibold tracking-tight">OWASP & CWE compliance</h3>
          <Separator className="flex-1" />
        </div>
        <ComplianceView result={result} />
      </div>

      <HardeningPlanCard result={actionableResult} />

      <div>
        <div className="mb-4 flex items-center gap-3">
          <h3 className="text-lg font-semibold tracking-tight">Findings</h3>
          <Separator className="flex-1" />
          <span className="font-mono text-xs text-muted-foreground">
            {visibleFindings.length} actionable
            {fpCount > 0 ? ` · ${fpCount} false positive${fpCount === 1 ? "" : "s"}` : ""}
          </span>
          {fpCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className={`h-7 gap-1.5 rounded-full text-xs ${hideFp ? "text-primary" : "text-muted-foreground"}`}
              onClick={() => setHideFp((v) => !v)}
            >
              <EyeOff className="size-3.5" /> {hideFp ? "Show" : "Hide"} false positives
            </Button>
          )}
        </div>
        {result.findings.length === 0 ? (
          <Card className="border-primary/30 bg-primary/5">
            <CardContent className="flex items-center gap-4 p-6">
              <ShieldCheck className="size-8 shrink-0 text-primary" />
              <div>
                <p className="font-medium">No exploitable weaknesses found</p>
                <p className="mt-1 text-sm text-muted-foreground">
                  All attack stages came back clean on this submission. Keep re-scanning as the
                  code changes.
                </p>
              </div>
            </CardContent>
          </Card>
        ) : visibleFindings.length === 0 ? (
          <Card className="border-border/60 bg-card/60">
            <CardContent className="py-10 text-center">
              <p className="text-sm text-muted-foreground">
                All findings are triaged as false positives. Toggle visibility above to review them.
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-3">
            {visibleFindings.map((f, i) => (
              <FindingCard
                key={`${f.ruleId}-${f.file}-${f.line}-${i}`}
                finding={f}
                index={i}
                triage={triageMap.get(verdictKey(f)) ?? { status: "open" }}
                triageDisabled={!scanId}
                onTriage={(patch) => onTriage(verdictKey(f), patch)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
