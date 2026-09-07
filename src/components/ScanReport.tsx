import { useState } from "react";
import { motion } from "framer-motion";
import {
  ChevronDown,
  Download,
  ShieldCheck,
  Swords,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import type { ScanResult, Severity, Finding } from "@/lib/scanner";
import { buildMarkdownReport } from "@/lib/scanner";

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

function FindingCard({ finding, index }: { finding: Finding; index: number }) {
  const [open, setOpen] = useState(index < 3);
  const style = SEVERITY_STYLE[finding.severity];
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
          </div>
        )}
      </Card>
    </motion.div>
  );
}

export interface ScanReportData {
  name: string;
  result: ScanResult;
}

export function ScanReport({ data }: { data: ScanReportData }) {
  const { name, result } = data;
  const severities: Severity[] = ["critical", "high", "medium", "low", "info"];

  const download = () => {
    const blob = new Blob([buildMarkdownReport(name, result)], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `crackscope-report-${name.replace(/\W+/g, "-").toLowerCase()}.md`;
    a.click();
    URL.revokeObjectURL(url);
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
          <Button variant="outline" onClick={download} className="gap-2 shrink-0 rounded-full">
            <Download className="size-4" /> Export .md
          </Button>
        </CardContent>
      </Card>

      <div>
        <div className="mb-4 flex items-center gap-3">
          <h3 className="text-lg font-semibold tracking-tight">Findings</h3>
          <Separator className="flex-1" />
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
        ) : (
          <div className="space-y-3">
            {result.findings.map((f, i) => (
              <FindingCard key={`${f.ruleId}-${f.file}-${f.line}-${i}`} finding={f} index={i} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
