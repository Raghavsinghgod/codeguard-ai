// CrackScope Part 12 — scan comparison view.
// Renders the diff produced by lib/diff between two saved scans.
import { motion } from "framer-motion";
import { ArrowDownRight, ArrowRight, ArrowUpRight, Minus } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { SEVERITY_STYLE } from "@/components/ScanReport";
import type { ScanDiff } from "@/lib/diff";
import type { Finding, ScanResult } from "@/lib/scanner";
import { Button } from "@/components/ui/button";

const VERDICT_CHIP: Record<ScanDiff["verdict"], { chip: string; label: string }> = {
  improved: { chip: "border-primary/30 bg-primary/10 text-primary", label: "security improved" },
  regressed: { chip: "border-destructive/40 bg-destructive/10 text-destructive", label: "security regressed" },
  mixed: { chip: "border-[oklch(0.8_0.16_85)]/40 bg-[oklch(0.8_0.16_85)]/10 text-[oklch(0.82_0.14_85)]", label: "mixed changes" },
  unchanged: { chip: "border-border bg-muted text-muted-foreground", label: "no changes" },
};

function FindingRow({ finding }: { finding: Finding }) {
  const style = SEVERITY_STYLE[finding.severity];
  return (
    <div className="flex items-center gap-2.5 rounded-lg border border-border/60 bg-secondary/40 px-3 py-2">
      <span className={`size-2 shrink-0 rounded-full ${style.dot}`} />
      <div className="min-w-0 flex-1">
        <p className="truncate text-xs font-medium">{finding.title}</p>
        <p className="truncate font-mono text-[11px] text-muted-foreground">
          {finding.ruleId} · {finding.file}:{finding.line}
        </p>
      </div>
      <Badge variant="outline" className={`shrink-0 rounded-full text-[11px] capitalize ${style.chip}`}>
        {finding.severity}
      </Badge>
    </div>
  );
}

function FindingColumn({
  title,
  findings,
  tone,
  emptyText,
}: {
  title: string;
  findings: Finding[];
  tone: "new" | "fixed";
  emptyText: string;
}) {
  return (
    <div className="min-w-0 flex-1 space-y-2">
      <p
        className={`font-mono text-[11px] uppercase tracking-widest ${tone === "new" ? "text-destructive" : "text-primary"}`}
      >
        {title} ({findings.length})
      </p>
      {findings.length === 0 ? (
        <p className="rounded-lg border border-dashed border-border/70 px-3 py-4 text-center text-xs text-muted-foreground">
          {emptyText}
        </p>
      ) : (
        <div className="max-h-72 space-y-2 overflow-y-auto pr-1">
          {findings.map((f, i) => (
            <FindingRow key={`${f.ruleId}-${f.file}-${f.line}-${i}`} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}

export function DiffView({
  baselineName,
  baseline,
  currentName,
  current,
  diff,
  onClose,
}: {
  baselineName: string;
  baseline: ScanResult;
  currentName: string;
  current: ScanResult;
  diff: ScanDiff;
  onClose: () => void;
}) {
  const verdict = VERDICT_CHIP[diff.verdict];
  const improved = diff.scoreDelta > 0;
  const flat = diff.scoreDelta === 0;
  const DeltaIcon = flat ? Minus : improved ? ArrowUpRight : ArrowDownRight;
  const deltaColor = flat ? "text-muted-foreground" : improved ? "text-primary" : "text-destructive";

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.25 }}>
      <Card className="border-border/60 bg-card/70">
        <CardContent className="space-y-5 p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="min-w-0">
              <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                Part 12 · Scan comparison
              </p>
              <p className="mt-0.5 truncate text-sm">
                <span className="font-medium">{baselineName}</span>
                <span className="mx-2 inline-flex translate-y-0.5 items-center text-muted-foreground">
                  <ArrowRight className="size-3.5" />
                </span>
                <span className="font-medium">{currentName}</span>
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className={`rounded-full ${verdict.chip}`}>
                {verdict.label}
              </Badge>
              <Button variant="ghost" size="sm" className="h-7 rounded-full text-xs text-muted-foreground" onClick={onClose}>
                Close
              </Button>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-6 rounded-xl border border-border/60 bg-secondary/40 px-5 py-4">
            <div className="flex items-center gap-2">
              <span className="text-2xl font-semibold tracking-tight">{baseline.score}</span>
              <span className="text-xs text-muted-foreground">grade {diff.gradeFrom}</span>
            </div>
            <div className={`flex items-center gap-1 font-mono text-sm font-semibold ${deltaColor}`}>
              <DeltaIcon className="size-4" />
              {flat ? "no score change" : `${improved ? "+" : ""}${diff.scoreDelta} pts → ${current.score}`}
            </div>
            <span className="font-mono text-xs text-muted-foreground">
              {diff.persistent} finding{diff.persistent === 1 ? "" : "s"} still present
            </span>
          </div>

          <div className="flex flex-col gap-5 md:flex-row">
            <FindingColumn
              title="New findings"
              findings={diff.added}
              tone="new"
              emptyText="Nothing new — no regressions introduced."
            />
            <FindingColumn
              title="Fixed since baseline"
              findings={diff.fixed}
              tone="fixed"
              emptyText="Nothing fixed in this window yet."
            />
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
