// Mid-training Lab — Phase 3 (Parts 11–15) of the CrackScope-8B plan as
// runnable modules: curriculum mixer, 320B mid-train run sim, vulnerable→fixed
// pair factory, router distillation, and the mid-train eval gate.

import { useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  ResponsiveContainer,
  Tooltip as ChartTooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  AlertTriangle,
  CheckCircle2,
  FlaskConical,
  GitCompareArrows,
  GraduationCap,
  Layers,
  Play,
  Plus,
  RotateCcw,
  ShieldCheck,
  Trash2,
  XCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import {
  assessCurriculum,
  distillRouter,
  generateRepairPairs,
  runMidTrainGate,
  simulateMidTrain,
  LOCKED_CURRICULUM,
  MID_GATE_CRITERIA,
  MIDTRAIN_CONFIG,
  type CurriculumSliceState,
} from "@/lib/midtrain";
import { EXPERTS } from "@/lib/model";

function PartHeader({
  part, title, icon: Icon, action,
}: {
  part: number;
  title: string;
  icon: typeof Layers;
  action?: React.ReactNode;
}) {
  return (
    <div className="mb-3 flex flex-wrap items-center gap-2.5">
      <div className="flex size-8 items-center justify-center rounded-lg bg-primary/12 ring-1 ring-primary/30">
        <Icon className="size-4 text-primary" />
      </div>
      <h3 className="font-semibold tracking-tight">
        <span className="mr-2 font-mono text-xs text-muted-foreground">Part {part}</span>
        {title}
      </h3>
      <div className="ml-auto">{action}</div>
    </div>
  );
}

function Metric({ label, value, tone }: { label: string; value: string; tone?: "good" | "warn" }) {
  const toneClass = tone === "good" ? "text-[oklch(0.72_0.14_168)]" : tone === "warn" ? "text-[oklch(0.82_0.14_85)]" : "";
  return (
    <div className="rounded-lg border border-border/60 bg-secondary/40 px-3 py-2">
      <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</p>
      <p className={`mt-0.5 font-mono text-sm font-semibold ${toneClass}`}>{value}</p>
    </div>
  );
}

// ------------------------------- Part 11 -------------------------------------

function Part11Mixer({ quality, setQuality }: { quality: number; setQuality: (q: number) => void }) {
  const [slices, setSlices] = useState<CurriculumSliceState[]>(() => LOCKED_CURRICULUM.map((s) => ({ ...s })));
  const assessment = useMemo(() => assessCurriculum(slices), [slices]);

  function bump(id: string, delta: number) {
    setSlices((prev) => {
      const next = prev.map((s) => (s.id === id ? { ...s, tokens: Math.max(0, s.tokens + delta) } : s));
      setQuality(assessCurriculum(next).quality);
      return next;
    });
  }

  function reset() {
    setSlices(LOCKED_CURRICULUM.map((s) => ({ ...s })));
    setQuality(assessCurriculum(LOCKED_CURRICULUM).quality);
  }

  const total = slices.reduce((a, s) => a + s.tokens, 0) || 1;

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="p-5">
        <PartHeader
          part={11}
          title="Curriculum mixer — C1–C8 scheduler"
          icon={Layers}
          action={
            <Button variant="outline" size="sm" onClick={reset}>
              <RotateCcw className="mr-1.5 size-3.5" /> Reset
            </Button>
          }
        />

        <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Metric label="Total tokens" value={`${(assessment.totalTokens / 1e9).toFixed(0)}B`} />
          <Metric label="C8 anchor" value={`${(assessment.anchorShare * 100).toFixed(1)}%`} tone={assessment.anchorOk ? "good" : "warn"} />
          <Metric label="Budget imbalance" value={`${assessment.imbalanceRatio.toFixed(1)}×`} tone={assessment.imbalanceRatio <= 3 ? "good" : "warn"} />
          <Metric label="Schedule quality" value={`${assessment.quality.toFixed(0)}/100`} tone={assessment.quality >= 85 ? "good" : "warn"} />
        </div>

        <div className="space-y-1.5">
          {slices.map((s) => {
            const share = s.tokens / total;
            const drift = share - s.lockedTokens / (LOCKED_CURRICULUM.reduce((a, x) => a + x.tokens, 0) || 1);
            return (
              <div key={s.id} className="flex flex-wrap items-center gap-2 rounded-lg border border-border/50 bg-secondary/30 px-3 py-2">
                <span className="font-mono text-xs text-primary">{s.id}</span>
                <span className="min-w-0 flex-1 truncate text-sm">{s.name}</span>
                <span className="w-16 text-right font-mono text-xs">{(share * 100).toFixed(1)}%</span>
                <span className="w-20 text-right font-mono text-[11px] text-muted-foreground">{(s.tokens / 1e9).toFixed(0)}B</span>
                <span className={`w-16 text-right font-mono text-[11px] ${Math.abs(drift) > 0.02 ? "text-[oklch(0.82_0.14_85)]" : "text-muted-foreground"}`}>
                  {drift >= 0 ? "+" : ""}{(drift * 100).toFixed(1)}pp
                </span>
                <div className="flex gap-1">
                  <Button variant="outline" size="icon" className="size-6" onClick={() => bump(s.id, -5e9)} aria-label={`decrease ${s.id}`}>
                    <Trash2 className="size-3" />
                  </Button>
                  <Button variant="outline" size="icon" className="size-6" onClick={() => bump(s.id, +5e9)} aria-label={`increase ${s.id}`}>
                    <Plus className="size-3" />
                  </Button>
                </div>
                <div className="flex w-full flex-wrap gap-1">
                  {s.primaryExperts.map((e) => (
                    <span key={e} className="rounded-full border border-primary/30 bg-primary/5 px-2 py-0.5 font-mono text-[10px] text-primary">
                      {e}
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        <Separator className="my-4" />
        <p className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Per-expert token budgets</p>
        <div className="mb-3 space-y-1">
          {assessment.expertBudgets.map((b) => {
            const expert = EXPERTS.find((e) => e.id === b.expert);
            return (
              <div key={b.expert} className="flex items-center gap-2">
                <span className="w-32 shrink-0 truncate font-mono text-[11px] text-muted-foreground">
                  {b.expert} {expert?.name ?? ""}
                </span>
                <Progress value={Math.min(100, b.share * 400)} className="h-1.5 flex-1" />
                <span className="w-12 text-right font-mono text-[11px]">{(b.share * 100).toFixed(1)}%</span>
              </div>
            );
          })}
        </div>

        {assessment.warnings.length > 0 && (
          <div className="space-y-1.5">
            {assessment.warnings.map((w) => (
              <p key={w} className="flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0" /> {w}
              </p>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ------------------------------- Part 12 -------------------------------------

function Part12Run({ quality }: { quality: number }) {
  const run = useMemo(() => simulateMidTrain(MIDTRAIN_CONFIG, quality), [quality]);

  const chartData = run.log.map((e) => ({
    tokensB: +(e.tokens / 1e9).toFixed(0),
    loss: +e.loss.toFixed(3),
    secPpl: +e.secPplRatio.toFixed(3),
    purity: +e.purity.toFixed(3),
  }));

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="p-5">
        <PartHeader
          part={12}
          title="Run mid-train — 320B tokens, LR re-warm to 30%"
          icon={FlaskConical}
          action={<Badge variant="outline" className="rounded-full border-primary/40 bg-primary/10 font-mono text-[10px] text-primary">{run.spikes} re-warm spikes</Badge>}
        />

        <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Metric label="Final loss" value={run.finalLoss.toFixed(3)} />
          <Metric label="Sec-PPL vs base" value={`×${run.finalSecPplRatio.toFixed(3)}`} tone={run.finalSecPplRatio <= 0.59 ? "good" : "warn"} />
          <Metric label="MMLU" value={run.finalMmlu.toFixed(2)} tone={run.finalMmlu >= 64.8 ? "good" : "warn"} />
          <Metric label="Routing purity" value={run.finalPurity.toFixed(3)} tone={run.finalPurity >= 0.9 ? "good" : undefined} />
        </div>

        <p className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          Loss, security-probe PPL ratio, and routing purity vs tokens
        </p>
        <div className="h-52 rounded-lg border border-border/50 bg-secondary/30 p-2">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="secPplFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="oklch(0.72 0.14 168)" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="oklch(0.72 0.14 168)" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.5 0 0 / 0.2)" />
              <XAxis dataKey="tokensB" tick={{ fontSize: 10, fontFamily: "monospace" }} stroke="oklch(0.6 0 0)" unit="B" />
              <YAxis yAxisId="loss" domain={[1.2, 2.2]} tick={{ fontSize: 10, fontFamily: "monospace" }} stroke="oklch(0.6 0 0)" width={34} />
              <YAxis yAxisId="ratio" orientation="right" domain={[0.5, 1.05]} tick={{ fontSize: 10, fontFamily: "monospace" }} stroke="oklch(0.6 0 0)" width={34} />
              <ChartTooltip
                contentStyle={{ background: "oklch(0.2 0 0 / 0.95)", border: "1px solid oklch(0.4 0 0)", borderRadius: 8, fontSize: 12, fontFamily: "monospace" }}
                labelFormatter={(t) => `${t}B tokens`}
              />
              <Area yAxisId="ratio" type="monotone" dataKey="secPpl" stroke="oklch(0.72 0.14 168)" fill="url(#secPplFill)" strokeWidth={2} name="sec-PPL ratio" dot={false} />
              <Line yAxisId="loss" type="monotone" dataKey="loss" stroke="oklch(0.64 0.19 25)" strokeWidth={1.8} dot={false} name="loss" />
              <Line yAxisId="ratio" type="monotone" dataKey="purity" stroke="oklch(0.72 0.11 220)" strokeWidth={1.5} strokeDasharray="4 3" dot={false} name="purity" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <p className="mt-3 font-mono text-[11px] text-muted-foreground">
          curriculum quality carried from Part 11: <span className="text-foreground">{quality.toFixed(0)}/100</span> ·
          LR re-warmed to {(MIDTRAIN_CONFIG.pretrainPeakLr * MIDTRAIN_CONFIG.lrRewarmFraction * 1e5).toFixed(0)}e-5 for 2% of
          steps, then cosine to ~0 · checkpoints every 40B
        </p>
      </CardContent>
    </Card>
  );
}

// ------------------------------- Part 13 -------------------------------------

function Part13Pairs() {
  const [count, setCount] = useState("12");
  const [stats, setStats] = useState<ReturnType<typeof generateRepairPairs> | null>(null);
  const [selected, setSelected] = useState(0);

  function run() {
    const s = generateRepairPairs(Number(count) || 12, Math.floor(Math.random() * 1e6) + 1);
    setStats(s);
    setSelected(0);
  }

  const pair = stats?.pairs[Math.min(selected, stats.pairs.length - 1)];

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="p-5">
        <PartHeader
          part={13}
          title="Vulnerable→fixed pairs — compiler-verified generator"
          icon={GitCompareArrows}
          action={
            <div className="flex items-center gap-2">
              <select
                value={count}
                onChange={(e) => setCount(e.target.value)}
                className="h-8 rounded-md border border-border bg-background px-2 font-mono text-xs"
                aria-label="pairs to generate"
              >
                {["12", "50", "200"].map((v) => <option key={v} value={v}>{v} pairs</option>)}
              </select>
              <Button size="sm" onClick={run}>
                <Play className="mr-1.5 size-3.5" /> Generate
              </Button>
            </div>
          }
        />

        {!stats && (
          <p className="rounded-lg border border-dashed border-border/60 px-3 py-4 text-center text-xs text-muted-foreground">
            30M synthetic repair pairs injected for E1/E11 grounding in the real run — here, generate a live sample:
            six CWE templates (SQLi, command injection, path traversal, IDOR, hardcoded secrets, OOB read), instantiated
            with randomized contexts, filtered by the compile + minimal-diff gates.
          </p>
        )}

        {stats && (
          <>
            <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Metric label="Generated" value={String(stats.generated)} tone="good" />
              <Metric label="Compile-rejected" value={String(stats.rejectedCompile)} tone={stats.rejectedCompile ? "warn" : undefined} />
              <Metric label="Diff-rejected" value={String(stats.rejectedDiff)} tone={stats.rejectedDiff ? "warn" : undefined} />
              <Metric label="CWE coverage" value={String(Object.keys(stats.byCwe).length)} />
            </div>

            <div className="mb-3 flex flex-wrap gap-1">
              {Object.entries(stats.byCwe).map(([cwe, n]) => (
                <span key={cwe} className="rounded-full border border-border/60 bg-secondary/60 px-2 py-0.5 font-mono text-[10px] text-muted-foreground">
                  {cwe} ×{n}
                </span>
              ))}
            </div>

            {pair && (
              <div>
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-primary">{pair.pairId}</span>
                  <Badge variant="outline" className="rounded-full text-[10px]">{pair.cwe}</Badge>
                  <Badge variant="outline" className="rounded-full text-[10px]">{pair.language}</Badge>
                  <Badge variant="outline" className="rounded-full border-primary/40 bg-primary/10 text-[10px] text-primary">{pair.expert}</Badge>
                  <span className="ml-auto font-mono text-[11px] text-muted-foreground">diff: {pair.diffLines} lines</span>
                </div>
                <div className="grid gap-2 lg:grid-cols-2">
                  <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-3">
                    <p className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-destructive">vulnerable</p>
                    <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-[11px] leading-5 text-foreground/85">{pair.vulnerable}</pre>
                  </div>
                  <div className="rounded-lg border border-[oklch(0.72_0.14_168)]/30 bg-[oklch(0.72_0.14_168)]/5 p-3">
                    <p className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-[oklch(0.72_0.14_168)]">fixed</p>
                    <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-[11px] leading-5 text-foreground/85">{pair.fixed}</pre>
                  </div>
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <Button
                    variant="outline" size="sm"
                    onClick={() => setSelected((s) => Math.max(0, s - 1))}
                    disabled={selected === 0}
                  >
                    ← prev
                  </Button>
                  <span className="font-mono text-[11px] text-muted-foreground">
                    {Math.min(selected + 1, stats.pairs.length)} / {stats.pairs.length}
                  </span>
                  <Button
                    variant="outline" size="sm"
                    onClick={() => setSelected((s) => Math.min(stats.pairs.length - 1, s + 1))}
                    disabled={selected >= stats.pairs.length - 1}
                  >
                    next →
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

// ------------------------------- Part 14 -------------------------------------

function Part14Distill() {
  const distill = useMemo(() => distillRouter(), []);
  const gain = distill.purityAfter - distill.purityBefore;

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="p-5">
        <PartHeader
          part={14}
          title="Router distillation — 14B teacher → cs-8b router"
          icon={GraduationCap}
          action={<Badge variant="outline" className="rounded-full border-primary/40 bg-primary/10 font-mono text-[10px] text-primary">20B tokens</Badge>}
        />

        <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Metric label="Purity before" value={distill.purityBefore.toFixed(3)} />
          <Metric label="Purity after" value={distill.purityAfter.toFixed(3)} tone="good" />
          <Metric label="Gain" value={`+${(gain * 100).toFixed(1)}pp`} tone="good" />
          <Metric label="Teacher KL" value={distill.kl.toFixed(3)} />
        </div>

        <p className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Per-domain purity shift</p>
        <div className="space-y-1">
          {distill.domains.map((d) => (
            <div key={d.expert} className="flex items-center gap-2">
              <span className="w-40 shrink-0 truncate font-mono text-[11px] text-muted-foreground">
                {d.expert} {d.domain}
              </span>
              <div className="relative h-2 flex-1 overflow-hidden rounded-full bg-secondary">
                <div
                  className="absolute inset-y-0 left-0 rounded-full bg-primary/25"
                  style={{ width: `${d.before * 100}%` }}
                />
                <div
                  className="absolute inset-y-0 left-0 rounded-full bg-primary"
                  style={{ width: `${d.after * 100}%` }}
                />
              </div>
              <span className="w-24 text-right font-mono text-[11px]">
                {(d.before * 100).toFixed(0)}→{(d.after * 100).toFixed(0)}%
              </span>
            </div>
          ))}
        </div>

        <p className="mt-3 font-mono text-[11px] text-muted-foreground">
          orphan tokens {Math.round(distill.orphanRate * 1000) / 10}% · teacher soft labels (temperature 2.0) mixed 0.7 with
          hard ground-truth domain labels
        </p>
      </CardContent>
    </Card>
  );
}

// ------------------------------- Part 15 -------------------------------------

function Part15Gate({ quality }: { quality: number }) {
  const run = useMemo(() => simulateMidTrain(MIDTRAIN_CONFIG, quality), [quality]);
  const distill = useMemo(() => distillRouter(), []);
  const gate = useMemo(() => runMidTrainGate(run, distill), [run, distill]);

  return (
    <Card className={gate.pass ? "border-[oklch(0.72_0.14_168)]/40 bg-card/70" : "border-destructive/40 bg-card/70"}>
      <CardContent className="p-5">
        <PartHeader
          part={15}
          title="Mid-train eval gate"
          icon={ShieldCheck}
          action={
            <Badge variant="outline" className={`rounded-full text-[10px] ${gate.pass ? "border-[oklch(0.72_0.14_168)]/50 bg-[oklch(0.72_0.14_168)]/10 text-[oklch(0.72_0.14_168)]" : "border-destructive/50 bg-destructive/10 text-destructive"}`}>
              {gate.pass ? "PROCEED TO SFT" : gate.action === "extend-mid-train-40B" ? "EXTEND +40B" : "REBALANCE & RESTART"}
            </Badge>
          }
        />

        <div className="space-y-2">
          {gate.checks.map((c) => (
            <div key={c.metric} className={`flex flex-wrap items-center gap-3 rounded-lg border px-3.5 py-2.5 ${c.pass ? "border-border/50 bg-secondary/30" : "border-destructive/40 bg-destructive/5"}`}>
              {c.pass ? <CheckCircle2 className="size-4 shrink-0 text-[oklch(0.72_0.14_168)]" /> : <XCircle className="size-4 shrink-0 text-destructive" />}
              <p className="min-w-0 flex-1 text-sm font-medium">{c.metric}</p>
              <span className="font-mono text-xs text-muted-foreground">{c.detail}</span>
            </div>
          ))}
        </div>

        <p className="mt-3 text-xs leading-5 text-muted-foreground">
          {gate.pass ? (
            <>
              Security-topic PPL down {Math.round((1 - run.finalSecPplRatio) * 100)}% vs base with MMLU within budget —
              Phase 4 (SFT over the twelve expert domains) can start from this checkpoint.
            </>
          ) : (
            <>
              Gate failed. Per the plan:{" "}
              {gate.action === "extend-mid-train-40B"
                ? "extend mid-train by 40B tokens with the security slices re-weighted up, then re-gate."
                : "rebalance the Part 11 curriculum (check the C8 anchor and expert budgets), restart from the 240B checkpoint."}
            </>
          )}
        </p>
        <p className="mt-1 font-mono text-[11px] text-muted-foreground">
          thresholds: PPL −{(MID_GATE_CRITERIA.secPplImprovement * 100).toFixed(0)}% · MMLU ≥ −{MID_GATE_CRITERIA.mmluMaxRegress}pt ·
          purity ≥ {MID_GATE_CRITERIA.purityMin}
        </p>
      </CardContent>
    </Card>
  );
}

// ------------------------------- shell ---------------------------------------

export default function MidtrainingLab() {
  const [curriculumQuality, setCurriculumQuality] = useState(
    () => assessCurriculum(LOCKED_CURRICULUM).quality
  );

  return (
    <div className="space-y-6">
      <Card className="border-border/60 bg-card/70">
        <CardContent className="p-5">
          <div className="flex flex-wrap items-center gap-3">
            <GraduationCap className="size-5 text-primary" />
            <div className="min-w-0 flex-1">
              <h2 className="text-lg font-semibold tracking-tight">Security mid-training lab — Phase 3 (Parts 11–15)</h2>
              <p className="text-sm text-muted-foreground">
                The 320B-token security curriculum as a live simulation: the mixer enforces the C8 replay anchor and
                per-expert budgets, the run applies an LR re-warm to the 1.8T checkpoint, the pair factory shows the
                compiler-verified E1/E11 grounding data, and distillation sharpens the router toward the 14B teacher.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Part11Mixer quality={curriculumQuality} setQuality={setCurriculumQuality} />
      <Part12Run quality={curriculumQuality} />
      <Part13Pairs />
      <Part14Distill />
      <Part15Gate quality={curriculumQuality} />
    </div>
  );
}
