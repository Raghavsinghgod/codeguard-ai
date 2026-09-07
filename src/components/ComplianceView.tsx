// CrackScope Part 9 — OWASP Top 10 & CWE compliance view.
// Renders the coverage model from lib/compliance for a scan result.
import { motion } from "framer-motion";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { SEVERITY_STYLE } from "@/components/ScanReport";
import type { Risk } from "@/lib/compliance";
import { buildCompliance } from "@/lib/compliance";
import type { ScanResult } from "@/lib/scanner";
import { CheckCircle2, CircleDashed, ListChecks } from "lucide-react";

const RISK_CHIP: Record<Risk, string> = {
  Critical: "border-destructive/40 bg-destructive/10 text-destructive",
  High: "border-[oklch(0.75_0.15_55)]/40 bg-[oklch(0.75_0.15_55)]/10 text-[oklch(0.78_0.14_55)]",
  Moderate: "border-[oklch(0.8_0.16_85)]/40 bg-[oklch(0.8_0.16_85)]/10 text-[oklch(0.82_0.14_85)]",
  Low: "border-[oklch(0.75_0.12_220)]/40 bg-[oklch(0.75_0.12_220)]/10 text-[oklch(0.78_0.11_220)]",
  Clean: "border-primary/30 bg-primary/10 text-primary",
};

function CoverageRing({ percent }: { percent: number }) {
  const radius = 34;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (percent / 100) * circumference;
  return (
    <div className="relative flex size-[88px] items-center justify-center">
      <svg className="size-full -rotate-90" viewBox="0 0 88 88">
        <circle cx="44" cy="44" r={radius} fill="none" stroke="oklch(1 0 0 / 8%)" strokeWidth="7" />
        <motion.circle
          cx="44"
          cy="44"
          r={radius}
          fill="none"
          stroke="oklch(0.78 0.13 168)"
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1, ease: "easeOut", delay: 0.15 }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-xl font-semibold tracking-tight">{percent}%</span>
        <span className="text-[10px] uppercase tracking-widest text-muted-foreground">coverage</span>
      </div>
    </div>
  );
}

export function ComplianceView({ result }: { result: ScanResult }) {
  const report = buildCompliance(result);

  return (
    <div className="space-y-5">
      <Card className="border-border/60 bg-card/70">
        <CardContent className="flex flex-col gap-5 p-6 sm:flex-row sm:items-center">
          <CoverageRing percent={report.coveragePercent} />
          <div className="min-w-0 space-y-1.5">
            <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
              OWASP Top 10 (2021) & CWE mapping
            </p>
            <p className="font-medium">Standards coverage</p>
            <p className="text-sm text-muted-foreground">
              {report.testedChecks} of {report.totalChecks} checks automated in this scan tier ·{" "}
              {report.categories.filter((c) => c.findings.length > 0).length} of 10 categories with
              observations
            </p>
          </div>
        </CardContent>
      </Card>

      <Card className="border-border/60 bg-card/70">
        <CardContent className="p-6">
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Audit summary
          </p>
          <div className="mt-2 space-y-2.5">
            {report.summary.map((p, i) => (
              <p key={i} className="text-sm leading-6 text-muted-foreground">
                {p}
              </p>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-3 md:grid-cols-2">
        {report.categories.map((cov, i) => (
          <motion.div
            key={cov.category.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25, delay: Math.min(i * 0.03, 0.3) }}
          >
            <Card className="h-full border-border/60 bg-card/70">
              <CardContent className="flex h-full flex-col gap-3 p-5">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="font-mono text-xs text-muted-foreground">{cov.category.id}</p>
                    <p className="truncate text-sm font-medium">{cov.category.title}</p>
                  </div>
                  <Badge variant="outline" className={`shrink-0 rounded-full ${RISK_CHIP[cov.risk]}`}>
                    {cov.risk === "Clean" ? "clean" : cov.risk.toLowerCase()}
                  </Badge>
                </div>
                <p className="text-xs leading-5 text-muted-foreground">{cov.category.description}</p>
                <div className="space-y-1.5">
                  {cov.category.checks.map((check) => {
                    const active = check.status !== "planned";
                    return (
                      <div key={check.id} className="flex items-center gap-2 text-xs">
                        {active ? (
                          <CheckCircle2 className="size-3.5 shrink-0 text-primary" />
                        ) : (
                          <CircleDashed className="size-3.5 shrink-0 text-muted-foreground/60" />
                        )}
                        <span className={active ? "text-muted-foreground" : "text-muted-foreground/50"}>
                          {check.label}
                        </span>
                      </div>
                    );
                  })}
                </div>
                {cov.findings.length > 0 && (
                  <div className="mt-auto space-y-2 border-t border-border/50 pt-3">
                    <p className="flex items-center gap-1.5 text-xs font-medium">
                      <ListChecks className="size-3.5 text-muted-foreground" />
                      {cov.findings.length} finding{cov.findings.length === 1 ? "" : "s"}
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {cov.cweRefs.map((ref) => (
                        <Badge
                          key={ref.id}
                          variant="outline"
                          className="rounded-full font-mono text-[11px] text-muted-foreground"
                          title={ref.name}
                        >
                          {ref.id}
                        </Badge>
                      ))}
                      {cov.worst && (
                        <span
                          className={`rounded-full border px-2.5 py-0.5 text-[11px] font-medium capitalize ${SEVERITY_STYLE[cov.worst].chip}`}
                        >
                          worst: {cov.worst}
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
