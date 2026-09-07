import { useState } from "react";
import { motion } from "framer-motion";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  ChevronDown,
  Download,
  Crosshair,
  FileCode2,
  Wrench,
  ShieldAlert,
} from "lucide-react";
import {
  SEVERITY_ORDER,
  reportToMarkdown,
  type ScanReport,
  type Severity,
} from "@/lib/scanner";
import { cn } from "@/lib/utils";

const SEVERITY_STYLES: Record<Severity, { badge: string; dot: string; label: string }> = {
  critical: { badge: "bg-red-500/15 text-red-400 border-red-500/30", dot: "bg-red-400", label: "Critical" },
  high: { badge: "bg-orange-500/15 text-orange-400 border-orange-500/30", dot: "bg-orange-400", label: "High" },
  medium: { badge: "bg-amber-500/15 text-amber-400 border-amber-500/30", dot: "bg-amber-400", label: "Medium" },
  low: { badge: "bg-sky-500/15 text-sky-400 border-sky-500/30", dot: "bg-sky-400", label: "Low" },
  info: { badge: "bg-slate-500/15 text-slate-400 border-slate-500/30", dot: "bg-slate-400", label: "Info" },
};

function scoreColor(score: number) {
  if (score >= 75) return "text-primary";
  if (score >= 50) return "text-amber-400";
  return "text-red-400";
}

function ScoreDial({ score, grade }: { score: number; grade: string }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score));
  return (
    <div className="relative flex size-[136px] shrink-0 items-center justify-center">
      <svg viewBox="0 0 128 128" className="size-full -rotate-90">
        <circle cx="64" cy="64" r={r} fill="none" strokeWidth="10" className="stroke-muted" />
        <motion.circle
          cx="64"
          cy="64"
          r={r}
          fill="none"
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={c}
          initial={{ strokeDashoffset: c }}
          animate={{ strokeDashoffset: c - (c * pct) / 100 }}
          transition={{ duration: 1, ease: "easeOut" }}
          className={cn(
            score >= 75 ? "stroke-primary" : score >= 50 ? "stroke-amber-400" : "stroke-red-400",
          )}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={cn("text-3xl font-semibold tabular-nums", scoreColor(score))}>{score}</span>
        <span className="text-xs text-muted-foreground">grade {grade}</span>
      </div>
    </div>
  );
}

export function ScanReportView({ report }: { report: ScanReport }) {
  const [openIdx, setOpenIdx] = useState<number | null>(report.findings.length ? 0 : null);
  const total = report.findings.length;

  const exportReport = () => {
    const blob = new Blob([reportToMarkdown(report)], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `crackscope-report-${report.name.replace(/[^a-z0-9-]+/gi, "-").toLowerCase()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Summary */}
      <Card className="border-border/70 shadow-sm">
        <CardContent className="flex flex-col items-center gap-6 p-6 sm:flex-row sm:gap-8">
          <ScoreDial score={report.score} grade={report.grade} />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="truncate text-lg font-semibold">{report.name}</h3>
                <p className="mt-0.5 text-sm text-muted-foreground">
                  {report.filesScanned} file{report.filesScanned === 1 ? "" : "s"} ·{" "}
                  {report.linesScanned.toLocaleString()} lines · {total} finding
                  {total === 1 ? "" : "s"}
                </p>
              </div>
              <Button variant="outline" size="sm" className="cursor-pointer gap-1.5" onClick={exportReport}>
                <Download className="size-3.5" /> Export report
              </Button>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              {SEVERITY_ORDER.map((sev) => (
                <Badge key={sev} variant="outline" className={cn("gap-1.5", SEVERITY_STYLES[sev].badge)}>
                  <span className={cn("size-1.5 rounded-full", SEVERITY_STYLES[sev].dot)} />
                  {SEVERITY_STYLES[sev].label} · {report.counts[sev]}
                </Badge>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Findings */}
      {total === 0 ? (
        <Card className="border-border/70 shadow-sm">
          <CardContent className="flex items-center gap-3 p-6 text-sm text-muted-foreground">
            <ShieldAlert className="size-5 text-primary" />
            The Part 1 engine found no vulnerable patterns. AST-based taint tracking and deeper
            detectors arrive in Part 3 — treat this as a pass of the heuristic battery only.
          </CardContent>
        </Card>
      ) : (
        <div className="flex flex-col gap-3">
          {report.findings.map((f, i) => {
            const open = openIdx === i;
            const s = SEVERITY_STYLES[f.severity];
            return (
              <motion.div
                key={`${f.ruleId}-${f.file}-${f.line}-${i}`}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: Math.min(i * 0.05, 0.4) }}
              >
                <Card
                  className={cn(
                    "cursor-pointer border-border/70 shadow-sm transition-colors hover:border-border",
                    open && "border-primary/30",
                  )}
                  onClick={() => setOpenIdx(open ? null : i)}
                >
                  <CardHeader className="p-4">
                    <div className="flex items-start gap-3">
                      <span className={cn("mt-2 size-2 shrink-0 rounded-full", s.dot)} />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant="outline" className={cn("text-[11px]", s.badge)}>
                            {s.label}
                          </Badge>
                          <CardTitle className="text-sm font-semibold">{f.title}</CardTitle>
                          <span className="font-mono text-[11px] text-muted-foreground">{f.ruleId}</span>
                        </div>
                        <p className="mt-1.5 flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
                          <FileCode2 className="size-3.5 shrink-0" />
                          {f.file}:{f.line}
                          <span className="text-border">|</span>
                          {f.owasp}
                        </p>
                      </div>
                      <ChevronDown
                        className={cn("mt-1 size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-180")}
                      />
                    </div>
                  </CardHeader>
                  {open && (
                    <CardContent className="border-t border-border/60 p-4 pt-4">
                      <pre className="overflow-x-auto rounded-lg bg-secondary p-3 font-mono text-xs leading-5 text-foreground/90">
                        {f.snippet}
                      </pre>
                      <p className="mt-4 text-sm leading-6 text-muted-foreground">{f.description}</p>

                      <div className="mt-4 rounded-xl border border-red-500/25 bg-red-500/5 p-4">
                        <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-red-400">
                          <Crosshair className="size-3.5" /> Simulated attack
                        </p>
                        <p className="mt-2 font-mono text-[13px] leading-6 text-foreground/90">{f.payload}</p>
                      </div>

                      <div className="mt-3 rounded-xl border border-primary/25 bg-primary/5 p-4">
                        <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-primary">
                          <Wrench className="size-3.5" /> Remediation
                        </p>
                        <p className="mt-2 text-sm leading-6 text-foreground/90">{f.remediation}</p>
                      </div>
                    </CardContent>
                  )}
                </Card>
              </motion.div>
            );
          })}
        </div>
      )}
    </div>
  );
}
