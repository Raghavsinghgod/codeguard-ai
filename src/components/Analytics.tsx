// CrackScope Part 24 — risk analytics tab.
// Trend dashboard (score + severity over time), category × severity heatmap,
// language breakdown, and MTTR metrics — all derived client-side from the
// user's scan history via src/lib/analytics.ts.
import { useMemo } from "react";
import { motion } from "framer-motion";
import {
  Activity,
  BarChart3,
  Clock,
  Flame,
  Grid3x3,
  Loader2,
  TrendingDown,
  TrendingUp,
} from "lucide-react";
import {
  CartesianGrid,
  Line,
  LineChart,
  XAxis,
  YAxis,
} from "recharts";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import type { Finding, Severity } from "@/lib/scanner";
import {
  heatmap,
  languageBreakdown,
  mttrStats,
  postureSummary,
  trendSeries,
} from "@/lib/analytics";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const sevColor: Record<Severity, string> = {
  critical: "var(--color-critical)",
  high: "var(--color-high)",
  medium: "var(--color-medium)",
  low: "var(--color-low)",
  info: "var(--color-info)",
};

const trendConfig = {
  score: { label: "Score", color: "hsl(var(--primary))" },
  critical: { label: "Critical", color: "oklch(0.62 0.22 25)" },
  high: { label: "High", color: "oklch(0.68 0.19 40)" },
  medium: { label: "Medium", color: "oklch(0.8 0.16 85)" },
} satisfies ChartConfig;

const heatColor: Record<Severity, string> = {
  critical: "oklch(0.55 0.21 25)",
  high: "oklch(0.62 0.19 40)",
  medium: "oklch(0.8 0.15 85)",
  low: "oklch(0.75 0.08 180)",
  info: "oklch(0.7 0.02 260)",
};

function heatCellBg(sev: Severity, count: number, max: number): string {
  if (count === 0) return "transparent";
  const intensity = 0.15 + 0.75 * Math.sqrt(count / Math.max(max, 1));
  return `color-mix(in oklch, ${heatColor[sev]} ${Math.round(intensity * 100)}%, transparent)`;
}

export default function Analytics() {
  const scansQuery = useQuery(api.scans.listScans);

  // Triage coverage: count closed rows for the latest scan.
  const latestId = scansQuery?.[0]?._id;
  const triageRows = useQuery(
    api.scans.listTriage,
    latestId ? { scanId: latestId } : "skip",
  );

  const loading = scansQuery === undefined;

  const scans = useMemo(
    () =>
      (scansQuery ?? []).map((s) => ({
        _id: s._id as string,
        name: s.name,
        createdAt: s.createdAt,
        score: s.score,
        grade: s.grade,
        findings: s.findings as Finding[],
      })),
    [scansQuery],
  );

  const trend = useMemo(() => trendSeries(scans), [scans]);
  const mttr = useMemo(() => mttrStats(scans), [scans]);
  const latestFindings = scans.length > 0 ? scans[scans.length - 1].findings : [];
  const heat = useMemo(() => heatmap(latestFindings), [latestFindings]);
  const langs = useMemo(() => languageBreakdown(latestFindings), [latestFindings]);
  const triageClosed = useMemo(
    () => (triageRows ?? []).filter((t) => t.status !== "open").length,
    [triageRows],
  );
  const posture = useMemo(
    () => postureSummary(scans, triageClosed),
    [scans, triageClosed],
  );

  const chartData = trend.map((p) => ({
    ...p,
    date: new Date(p.createdAt).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
  }));

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-20 text-muted-foreground">
        <Loader2 className="size-4 animate-spin" /> Crunching scan history…
      </div>
    );
  }

  if (scans.length === 0) {
    return (
      <Card className="border-border/60 bg-card/60">
        <CardContent className="flex flex-col items-center gap-3 py-14 text-center">
          <BarChart3 className="size-8 text-muted-foreground" />
          <p className="font-medium">No analytics yet</p>
          <p className="max-w-sm text-sm text-muted-foreground">
            Risk analytics light up after your first scans — run one in the Scanner tab and this
            dashboard builds itself from history.
          </p>
        </CardContent>
      </Card>
    );
  }

  const trendUp = (posture.scoreTrend ?? 0) > 0;
  const maxLang = Math.max(...langs.map((l) => l.findings), 1);

  return (
    <div className="space-y-6">
      {/* Posture summary tiles */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          {
            icon: <Activity className="size-4" />,
            label: "Latest score",
            value: `${posture.latest?.score ?? "—"}/100`,
            sub: posture.latest ? `grade ${posture.latest.grade}` : "",
            tone: (posture.latest?.score ?? 0) >= 75 ? "text-primary" : (posture.latest?.score ?? 0) >= 50 ? "text-[oklch(0.75_0.14_85)]" : "text-destructive",
          },
          {
            icon: trendUp ? <TrendingUp className="size-4" /> : <TrendingDown className="size-4" />,
            label: "Score trend",
            value: posture.scoreTrend === null ? "—" : `${trendUp ? "+" : ""}${posture.scoreTrend}`,
            sub: `across ${posture.scans} scan${posture.scans === 1 ? "" : "s"}`,
            tone: trendUp ? "text-primary" : (posture.scoreTrend ?? 0) < 0 ? "text-destructive" : "text-muted-foreground",
          },
          {
            icon: <Flame className="size-4" />,
            label: "Open critical",
            value: String(posture.openCritical),
            sub: `${posture.openHigh} high open`,
            tone: posture.openCritical > 0 ? "text-destructive" : "text-primary",
          },
          {
            icon: <Clock className="size-4" />,
            label: "MTTR",
            value: mttr.meanDays === null ? "—" : `${mttr.meanDays}d`,
            sub: mttr.samples > 0 ? `${mttr.samples} fix${mttr.samples === 1 ? "" : "es"} observed` : "no fixes observed yet",
            tone: mttr.meanDays === null ? "text-muted-foreground" : mttr.meanDays <= 14 ? "text-primary" : "text-[oklch(0.75_0.14_85)]",
          },
        ].map((tile) => (
          <motion.div key={tile.label} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
            <Card className="border-border/60 bg-card/60">
              <CardContent className="p-5">
                <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-widest text-muted-foreground">
                  {tile.icon} {tile.label}
                </p>
                <p className={`mt-2 text-2xl font-semibold tracking-tight ${tile.tone}`}>{tile.value}</p>
                <p className="mt-0.5 text-xs text-muted-foreground">{tile.sub}</p>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Trend chart */}
      <Card className="border-border/60 bg-card/60">
        <CardContent className="p-6">
          <p className="font-medium tracking-tight">Risk trend</p>
          <p className="text-sm text-muted-foreground">
            Security score and open findings by severity, per scan (oldest → newest).
          </p>
          <ChartContainer config={trendConfig} className="mt-4 h-64 w-full">
            <LineChart data={chartData} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid vertical={false} strokeDasharray="3 3" />
              <XAxis dataKey="date" tickLine={false} axisLine={false} minTickGap={24} />
              <YAxis tickLine={false} axisLine={false} domain={[0, 100]} />
              <ChartTooltip content={<ChartTooltipContent />} />
              <Line
                type="monotone"
                dataKey="score"
                stroke="var(--color-score)"
                strokeWidth={2}
                dot={false}
              />
              <Line
                type="monotone"
                dataKey="critical"
                stroke="var(--color-critical)"
                strokeWidth={1.5}
                dot={false}
              />
              <Line
                type="monotone"
                dataKey="high"
                stroke="var(--color-high)"
                strokeWidth={1.5}
                dot={false}
              />
              <Line
                type="monotone"
                dataKey="medium"
                stroke="var(--color-medium)"
                strokeWidth={1.5}
                dot={false}
              />
            </LineChart>
          </ChartContainer>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Heatmap */}
        <Card className="border-border/60 bg-card/60">
          <CardContent className="p-6">
            <p className="flex items-center gap-2 font-medium tracking-tight">
              <Grid3x3 className="size-4 text-primary" /> Category × severity heatmap
            </p>
            <p className="mt-1 text-sm text-muted-foreground">
              Latest scan: where the risk concentrates. Darker = more findings.
            </p>
            <div className="mt-4 overflow-x-auto">
              <table className="w-full min-w-[420px] border-separate border-spacing-1">
                <thead>
                  <tr>
                    <th />
                    {SEVERITIES.map((s) => (
                      <th key={s} className="pb-1 font-mono text-[10px] font-medium uppercase text-muted-foreground">
                        {s}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {heat.categories.slice(0, 8).map((cat) => (
                    <tr key={cat}>
                      <td className="max-w-32 truncate pr-2 text-right font-mono text-[10px] text-muted-foreground">
                        {cat}
                      </td>
                      {SEVERITIES.map((sev) => {
                        const count = heat.cells.get(`${cat}|${sev}`) ?? 0;
                        return (
                          <td key={sev} className="p-0">
                            <div
                              className="flex h-9 items-center justify-center rounded-md border border-border/40 font-mono text-xs"
                              style={{ background: heatCellBg(sev, count, heat.maxCell) }}
                              title={`${cat} · ${sev}: ${count}`}
                            >
                              {count > 0 ? count : ""}
                            </div>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        {/* Language breakdown + MTTR by severity */}
        <div className="space-y-6">
          <Card className="border-border/60 bg-card/60">
            <CardContent className="p-6">
              <p className="font-medium tracking-tight">Language breakdown</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Findings per source language in the latest scan.
              </p>
              <div className="mt-4 space-y-2.5">
                {langs.length === 0 && (
                  <p className="text-sm text-muted-foreground">No findings — nothing to break down.</p>
                )}
                {langs.map((l) => (
                  <div key={l.language} className="flex items-center gap-3">
                    <span className="w-24 shrink-0 truncate text-xs text-muted-foreground">{l.language}</span>
                    <div className="h-2 flex-1 overflow-hidden rounded-full bg-secondary/60">
                      <div
                        className="h-full rounded-full bg-primary/70"
                        style={{ width: `${Math.round((l.findings / maxLang) * 100)}%` }}
                      />
                    </div>
                    <span className="w-8 text-right font-mono text-xs">{l.findings}</span>
                    {l.critical > 0 && (
                      <Badge variant="outline" className="rounded-full border-destructive/40 px-1.5 py-0 font-mono text-[10px] text-destructive">
                        {l.critical}C
                      </Badge>
                    )}
                    {l.high > 0 && (
                      <Badge variant="outline" className="rounded-full border-destructive/30 px-1.5 py-0 font-mono text-[10px] text-destructive">
                        {l.high}H
                      </Badge>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card className="border-border/60 bg-card/60">
            <CardContent className="p-6">
              <p className="font-medium tracking-tight">MTTR by severity</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Mean days from first detection to disappearance from a later scan.
              </p>
              <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3">
                {SEVERITIES.filter((s) => s !== "info").map((sev) => {
                  const days = mttr.bySeverity[sev];
                  return (
                    <div key={sev} className="rounded-lg border border-border/60 p-3">
                      <p className="font-mono text-[10px] uppercase text-muted-foreground">{sev}</p>
                      <p className={`mt-1 text-lg font-semibold ${days === null ? "text-muted-foreground" : ""}`}>
                        {days === null ? "—" : `${days}d`}
                      </p>
                    </div>
                  );
                })}
              </div>
              {mttr.slowest.length > 0 && (
                <div className="mt-4 space-y-1.5">
                  <p className="text-xs font-medium uppercase tracking-widest text-muted-foreground">
                    Slowest fixes
                  </p>
                  {mttr.slowest.slice(0, 3).map((f) => (
                    <div key={f.key} className="flex items-center gap-2 text-xs">
                      <Badge variant="outline" className={`rounded-full font-mono text-[10px] ${sevBadgeClass(f.severity)}`}>
                        {f.severity}
                      </Badge>
                      <span className="min-w-0 flex-1 truncate text-muted-foreground">{f.title}</span>
                      <span className="font-mono">{f.days}d</span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function sevBadgeClass(sev: Severity): string {
  switch (sev) {
    case "critical":
    case "high":
      return "border-destructive/40 bg-destructive/10 text-destructive";
    case "medium":
      return "border-[oklch(0.8_0.16_85)]/40 bg-[oklch(0.8_0.16_85)]/10 text-[oklch(0.75_0.14_85)]";
    default:
      return "border-border bg-muted text-muted-foreground";
  }
}
