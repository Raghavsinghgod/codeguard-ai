// Pretraining Lab — Phase 2 (Parts 6–10) of the CrackScope-8B plan as
// runnable modules: data-mix planner, pretrain run simulator driven by the
// Phase 1 Chinchilla fit, the 0.9T mid-run eval gate, the YaRN long-context
// needle matrix, and the checkpoint manifest with a preemption/resume drill.

import { useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip as ChartTooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  Gauge,
  HardDriveDownload,
  LineChart,
  Minus,
  Play,
  Plus,
  RotateCcw,
  Ruler,
  XCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import {
  assessMix,
  buildCheckpointManifest,
  runEvalGate,
  runNeedleMatrix,
  runResumeDrill,
  simulatePretrain,
  GATE_CRITERIA,
  LOCKED_MIX,
  PRETRAIN_CONFIG,
  YARN_CONFIG,
  type MixSlice,
} from "@/lib/pretraining";

function PartHeader({
  part, title, icon: Icon, action,
}: {
  part: number;
  title: string;
  icon: typeof Database;
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

const KIND_COLOR: Record<MixSlice["kind"], string> = {
  general: "oklch(0.72 0.11 220)",
  code: "oklch(0.68 0.13 260)",
  security: "oklch(0.64 0.19 25)",
};

// ------------------------------- Part 6 --------------------------------------

function Part6Mix({ quality, setQuality }: { quality: number; setQuality: (q: number) => void }) {
  const [mix, setMix] = useState<MixSlice[]>(() => LOCKED_MIX.map((s) => ({ ...s })));
  const assessment = useMemo(() => assessMix(mix), [mix]);

  function nudge(id: string, delta: number) {
    setMix((prev) => {
      const next = prev.map((s) =>
        s.id === id ? { ...s, share: Math.max(0.001, Math.min(0.9, s.share + delta)) } : s
      );
      const a = assessMix(next);
      setQuality(a.quality);
      return next;
    });
  }

  function reset() {
    setMix(LOCKED_MIX.map((s) => ({ ...s })));
    setQuality(assessMix(LOCKED_MIX).quality);
  }

  const total = mix.reduce((a, s) => a + s.share, 0) || 1;

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="p-5">
        <PartHeader
          part={6}
          title="Data mix v1 — 1.4T general/code + 0.4T security"
          icon={Database}
          action={
            <Button variant="outline" size="sm" onClick={reset}>
              <RotateCcw className="mr-1.5 size-3.5" /> Reset to locked mix
            </Button>
          }
        />

        <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Metric label="Weighted probe PPL" value={assessment.weightedPpl.toFixed(3)} tone={assessment.weightedPpl <= 2.62 ? "good" : "warn"} />
          <Metric label="Security share" value={`${(assessment.securityShare * 100).toFixed(1)}%`} tone={assessment.securityShare >= 0.15 ? "good" : "warn"} />
          <Metric label="Mix quality" value={`${assessment.quality.toFixed(0)}/100`} tone={assessment.quality >= 85 ? "good" : "warn"} />
          <Metric label="Warnings" value={String(assessment.warnings.length)} tone={assessment.warnings.length ? "warn" : "good"} />
        </div>

        <div className="space-y-1.5">
          {mix.map((s) => {
            const normShare = s.share / total;
            const drift = normShare - s.lockedShare;
            return (
              <div key={s.id} className="flex flex-wrap items-center gap-2 rounded-lg border border-border/50 bg-secondary/30 px-3 py-2">
                <span className="font-mono text-xs text-muted-foreground">{s.id}</span>
                <span className="min-w-0 flex-1 truncate text-sm">{s.name}</span>
                <span
                  className="h-2.5 w-2.5 rounded-full"
                  style={{ background: KIND_COLOR[s.kind] }}
                  title={s.kind}
                />
                <span className="w-16 text-right font-mono text-xs">{(normShare * 100).toFixed(1)}%</span>
                <span className="w-20 text-right font-mono text-[11px] text-muted-foreground">
                  {assessment.tokens.find((t) => t.id === s.id)?.tokens.toLocaleString() ?? "0"} tok
                </span>
                <span className={`w-16 text-right font-mono text-[11px] ${Math.abs(drift) > 0.02 ? "text-[oklch(0.82_0.14_85)]" : "text-muted-foreground"}`}>
                  {drift >= 0 ? "+" : ""}{(drift * 100).toFixed(1)}pp
                </span>
                <div className="flex gap-1">
                  <Button variant="outline" size="icon" className="size-6" onClick={() => nudge(s.id, -0.01)} aria-label={`decrease ${s.name}`}>
                    <Minus className="size-3" />
                  </Button>
                  <Button variant="outline" size="icon" className="size-6" onClick={() => nudge(s.id, +0.01)} aria-label={`increase ${s.name}`}>
                    <Plus className="size-3" />
                  </Button>
                </div>
              </div>
            );
          })}
        </div>

        <div className="mt-3 flex h-5 w-full overflow-hidden rounded-lg border border-border/50">
          {mix.map((s) => (
            <div
              key={s.id}
              title={`${s.name}: ${((s.share / total) * 100).toFixed(1)}%`}
              style={{ width: `${(s.share / total) * 100}%`, background: KIND_COLOR[s.kind], opacity: 0.75 }}
              className="h-full border-r border-border/40 last:border-0"
            />
          ))}
        </div>
        <div className="mt-1.5 flex gap-4 font-mono text-[10px] text-muted-foreground">
          <span className="flex items-center gap-1"><span className="size-2 rounded-full" style={{ background: KIND_COLOR.general }} /> general</span>
          <span className="flex items-center gap-1"><span className="size-2 rounded-full" style={{ background: KIND_COLOR.code }} /> code</span>
          <span className="flex items-center gap-1"><span className="size-2 rounded-full" style={{ background: KIND_COLOR.security }} /> security</span>
        </div>

        {assessment.warnings.length > 0 && (
          <div className="mt-3 space-y-1.5">
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

// ------------------------------- Part 7 --------------------------------------

function Part7Run({ mixQuality }: { mixQuality: number }) {
  const run = useMemo(() => simulatePretrain(PRETRAIN_CONFIG), []);

  const chartData = run.log.map((e) => ({
    tokensT: +(e.tokens / 1e12).toFixed(2),
    loss: +e.loss.toFixed(3),
    mmlu: +e.mmlu.toFixed(1),
    humanEval: +e.humanEval.toFixed(1),
  }));

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="p-5">
        <PartHeader
          part={7}
          title="Launch 1.8T pretrain — 1,024×H100"
          icon={LineChart}
          action={<Badge variant="outline" className="rounded-full border-primary/40 bg-primary/10 font-mono text-[10px] text-primary">{run.totalSteps.toLocaleString()} steps</Badge>}
        />

        <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Metric label="Step time" value={`${run.stepSeconds.toFixed(1)} s`} />
          <Metric label="Total ETA" value={`${run.etaDaysTotal.toFixed(0)} days`} />
          <Metric label="Final loss" value={run.finalLoss.toFixed(2)} tone={run.finalLoss < 1.9 ? "good" : undefined} />
          <Metric label="Throughput" value={`${Math.round(run.clusterFlops / run.flopsPerToken / 1e6)}M tok/s`} />
        </div>

        <p className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          Loss & evals vs tokens — loss predicted by the Phase 1 Chinchilla fit
        </p>
        <div className="h-56 rounded-lg border border-border/50 bg-secondary/30 p-2">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="lossFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="oklch(0.64 0.19 25)" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="oklch(0.64 0.19 25)" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.5 0 0 / 0.2)" />
              <XAxis dataKey="tokensT" tick={{ fontSize: 10, fontFamily: "monospace" }} stroke="oklch(0.6 0 0)" unit="T" />
              <YAxis yAxisId="loss" domain={[1.4, 4.4]} tick={{ fontSize: 10, fontFamily: "monospace" }} stroke="oklch(0.6 0 0)" width={34} />
              <YAxis yAxisId="eval" orientation="right" domain={[0, 75]} tick={{ fontSize: 10, fontFamily: "monospace" }} stroke="oklch(0.6 0 0)" width={30} />
              <ChartTooltip
                contentStyle={{ background: "oklch(0.2 0 0 / 0.95)", border: "1px solid oklch(0.4 0 0)", borderRadius: 8, fontSize: 12, fontFamily: "monospace" }}
                labelFormatter={(t) => `${t}T tokens`}
                formatter={(value: number | string, name: string) => [value, name]}
              />
              <Area yAxisId="loss" type="monotone" dataKey="loss" stroke="oklch(0.64 0.19 25)" fill="url(#lossFill)" strokeWidth={2} name="loss" dot={false} />
              <Line yAxisId="eval" type="monotone" dataKey="mmlu" stroke="oklch(0.72 0.11 220)" strokeWidth={1.5} dot={false} name="MMLU" />
              <Line yAxisId="eval" type="monotone" dataKey="humanEval" stroke="oklch(0.72 0.14 168)" strokeWidth={1.5} dot={false} name="HumanEval" />
              <ReferenceLine yAxisId="loss" x={0.5} stroke="oklch(0.82 0.14 85)" strokeDasharray="4 4" label={{ value: "aux losses on @ step 2k", fontSize: 9, fontFamily: "monospace", fill: "oklch(0.82 0.14 85)", position: "insideTopRight" }} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <p className="mt-3 font-mono text-[11px] text-muted-foreground">
          6·N_active = {(run.flopsPerToken / 1e9).toFixed(1)} GFLOPs/token · cluster {((PRETRAIN_CONFIG.gpus * 989e12 * PRETRAIN_CONFIG.mfu) / 1e15).toFixed(1)} PFLOPs effective ·
          mix quality carried from Part 6: <span className="text-foreground">{mixQuality.toFixed(0)}/100</span>
        </p>
      </CardContent>
    </Card>
  );
}

// ------------------------------- Part 8 --------------------------------------

function Part8Gate({ mixQuality }: { mixQuality: number }) {
  const run = useMemo(() => simulatePretrain(PRETRAIN_CONFIG), []);
  const gate = useMemo(() => runEvalGate(run, mixQuality), [run, mixQuality]);

  return (
    <Card className={gate.pass ? "border-[oklch(0.72_0.14_168)]/40 bg-card/70" : "border-destructive/40 bg-card/70"}>
      <CardContent className="p-5">
        <PartHeader
          part={8}
          title="Mid-run eval gate — at 0.9T tokens"
          icon={Gauge}
          action={
            <Badge variant="outline" className={`rounded-full text-[10px] ${gate.pass ? "border-[oklch(0.72_0.14_168)]/50 bg-[oklch(0.72_0.14_168)]/10 text-[oklch(0.72_0.14_168)]" : "border-destructive/50 bg-destructive/10 text-destructive"}`}>
              {gate.pass ? "PROCEED" : "REMIX & BRANCH"}
            </Badge>
          }
        />

        <div className="space-y-2">
          {gate.checks.map((c) => (
            <div key={c.metric} className={`flex flex-wrap items-center gap-3 rounded-lg border px-3.5 py-2.5 ${c.pass ? "border-border/50 bg-secondary/30" : "border-destructive/40 bg-destructive/5"}`}>
              {c.pass ? <CheckCircle2 className="size-4 shrink-0 text-[oklch(0.72_0.14_168)]" /> : <XCircle className="size-4 shrink-0 text-destructive" />}
              <p className="min-w-0 flex-1 text-sm font-medium">{c.metric}</p>
              <span className="font-mono text-xs text-muted-foreground">{c.detail}</span>
              <Progress
                value={Math.min(100, c.metric === "Security-probe PPL ratio" ? (GATE_CRITERIA.secPplMax / Math.max(c.value, 0.01)) * 100 : (c.value / (c.threshold * 1.25)) * 100)}
                className="h-1.5 w-28"
              />
            </div>
          ))}
        </div>

        <p className="mt-3 text-xs leading-5 text-muted-foreground">
          {gate.pass ? (
            <>
              Gate passed with mix quality <span className="font-mono text-foreground">{mixQuality.toFixed(0)}/100</span> — the run
              continues to 1.8T with checkpoints every 0.15T (Part 10).
            </>
          ) : (
            <>
              Gate failed — the plan branches: re-mix per Part 6 warnings, restart from the 0.75T milestone checkpoint
              (Part 10), expected loss recovery ≈ <span className="font-mono text-foreground">−{gate.remixGain.toFixed(3)}</span>.
            </>
          )}
        </p>
      </CardContent>
    </Card>
  );
}

// ------------------------------- Part 9 --------------------------------------

function Part9Yarn() {
  const result = useMemo(() => runNeedleMatrix(), []);

  const cellColor = (a: number) =>
    a >= 0.995 ? "oklch(0.72 0.14 168 / 0.85)"
    : a >= 0.98 ? "oklch(0.78 0.13 168 / 0.6)"
    : a >= 0.96 ? "oklch(0.82 0.14 85 / 0.6)"
    : "oklch(0.6 0.2 25 / 0.7)";

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="p-5">
        <PartHeader
          part={9}
          title="Long-context extension — RoPE θ bump + 32k YaRN"
          icon={Ruler}
          action={
            <Badge variant="outline" className={`rounded-full text-[10px] ${result.gatePass ? "border-[oklch(0.72_0.14_168)]/50 bg-[oklch(0.72_0.14_168)]/10 text-[oklch(0.72_0.14_168)]" : "border-destructive/50 bg-destructive/10 text-destructive"}`}>
              {result.gatePass ? "≥ 98% @ 32k — PASS" : "BELOW GATE"}
            </Badge>
          }
        />

        <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Metric label="Accuracy @ 32k" value={`${(result.overallAt32k * 100).toFixed(1)}%`} tone={result.gatePass ? "good" : "warn"} />
          <Metric label="PPL @ 32k vs 8k" value={`×${result.perplexityAt32k.toFixed(3)}`} tone={result.perplexityAt32k < 1.06 ? "good" : "warn"} />
          <Metric label="Scale factor s" value={String(YARN_CONFIG.yarnFactor)} />
          <Metric label="Extension tokens" value="40B" />
        </div>

        <p className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          Needle-in-a-haystack matrix — depth × context
        </p>
        <div className="overflow-x-auto">
          <table className="w-full min-w-md border-separate border-spacing-1">
            <thead>
              <tr>
                <th className="w-16 font-mono text-[10px] font-normal text-muted-foreground" />
                {result.cols.map((d) => (
                  <th key={d} className="font-mono text-[10px] font-normal text-muted-foreground">{(d * 100).toFixed(0)}%</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {result.rows.map((ctx) => (
                <tr key={ctx}>
                  <td className="font-mono text-[10px] text-muted-foreground">{ctx / 1024}k</td>
                  {result.cols.map((d) => {
                    const cell = result.cells.find((c) => c.context === ctx && c.depth === d)!;
                    return (
                      <td key={d} className="p-0">
                        <div
                          title={`${ctx / 1024}k ctx @ depth ${(d * 100).toFixed(0)}% → ${(cell.accuracy * 100).toFixed(1)}%`}
                          className="flex h-8 items-center justify-center rounded font-mono text-[10px] text-foreground/80"
                          style={{ background: cellColor(cell.accuracy) }}
                        >
                          {(cell.accuracy * 100).toFixed(0)}
                        </div>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <p className="mt-3 font-mono text-[11px] text-muted-foreground">
          θ: {YARN_CONFIG.ropeThetaBase.toLocaleString()} → {YARN_CONFIG.ropeThetaScaled.toLocaleString()} · attn temperature
          correction {YARN_CONFIG.attentionTemperature} · trained on 40B long-doc tokens
        </p>
      </CardContent>
    </Card>
  );
}

// ------------------------------- Part 10 -------------------------------------

function Part10Checkpoints() {
  const manifest = useMemo(() => buildCheckpointManifest(PRETRAIN_CONFIG), []);
  const [drill, setDrill] = useState<ReturnType<typeof runResumeDrill> | null>(null);

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="p-5">
        <PartHeader
          part={10}
          title="Pretrain complete — checkpointed & resumable"
          icon={HardDriveDownload}
          action={
            <Button size="sm" onClick={() => setDrill(runResumeDrill(manifest, PRETRAIN_CONFIG, Math.floor(Math.random() * 1e6) + 1))}>
              <Play className="mr-1.5 size-3.5" /> Run preemption drill
            </Button>
          }
        />

        <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Metric label="Checkpoints" value={String(manifest.checkpoints.length)} />
          <Metric label="Per checkpoint" value={`${(manifest.bytesPerCheckpoint / 1e9).toFixed(1)} GB`} />
          <Metric label="Written (total)" value={`${(manifest.totalBytes / 1e12).toFixed(2)} TB`} />
          <Metric label="Retained" value={`${manifest.retainedCount} · ${(manifest.retainedBytes / 1e12).toFixed(2)} TB`} tone="good" />
        </div>

        <p className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Checkpoint timeline</p>
        <div className="flex h-9 w-full items-end gap-px overflow-hidden rounded-lg border border-border/50 bg-secondary/30 px-2 py-1.5">
          {manifest.checkpoints.map((c) => (
            <div
              key={c.id}
              title={`${c.id} @ ${(c.tokens / 1e12).toFixed(2)}T · loss ${c.loss.toFixed(3)} · ${c.kind}`}
              className={`min-w-[4px] flex-1 rounded-sm ${c.kind === "milestone" ? "bg-primary" : "bg-primary/35"}`}
              style={{ height: c.kind === "milestone" ? "100%" : "65%" }}
            />
          ))}
        </div>
        <p className="mt-1.5 font-mono text-[11px] text-muted-foreground">
          every 0.15T rolling (keep last 3) · milestones every 0.6T kept forever · 14 B/param (bf16 weights + fp32 master + 2× AdamW)
        </p>

        <Separator className="my-4" />

        {drill && (
          <div className="rounded-lg border border-primary/30 bg-primary/5 px-4 py-3">
            <p className="text-sm font-medium">Preemption drill</p>
            <p className="mt-1 text-sm text-muted-foreground">
              Spot loss at <span className="font-mono text-foreground">{(drill.preemptedAtTokens / 1e12).toFixed(2)}T</span> →
              resumed from <span className="font-mono text-foreground">{(drill.resumedFromTokens / 1e12).toFixed(2)}T</span> checkpoint.
              Re-did <span className="font-mono text-foreground">{drill.lostSteps}</span> steps
              ({(drill.lostTokens / 1e9).toFixed(1)}B tokens), 1-step throughput ramp-up,
              resumed loss <span className="font-mono text-foreground">{drill.resumedLoss.toFixed(3)}</span>.
            </p>
            <p className="mt-1.5 font-mono text-[11px] text-muted-foreground">{drill.verdict}</p>
          </div>
        )}
        {!drill && (
          <p className="rounded-lg border border-dashed border-border/60 px-3 py-4 text-center text-xs text-muted-foreground">
            Run the drill to simulate a spot-preemption and resume-from-checkpoint.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// ------------------------------- shell ---------------------------------------

export default function PretrainingLab() {
  const [mixQuality, setMixQuality] = useState(() => assessMix(LOCKED_MIX).quality);

  return (
    <div className="space-y-6">
      <Card className="border-border/60 bg-card/70">
        <CardContent className="p-5">
          <div className="flex flex-wrap items-center gap-3">
            <LineChart className="size-5 text-primary" />
            <div className="min-w-0 flex-1">
              <h2 className="text-lg font-semibold tracking-tight">Pretraining lab — Phase 2 (Parts 6–10)</h2>
              <p className="text-sm text-muted-foreground">
                The 1.8T-token run as a live simulation: the mix planner scores perturbations against the locked recipe,
                the loss curve comes from the Chinchilla fit fitted in Phase 1, and the eval gate, YaRN matrix, and
                checkpoint drill all consume the same numbers.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Part6Mix quality={mixQuality} setQuality={setMixQuality} />
      <Part7Run mixQuality={mixQuality} />
      <Part8Gate mixQuality={mixQuality} />
      <Part9Yarn />
      <Part10Checkpoints />
    </div>
  );
}
