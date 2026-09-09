// CrackScope-8B Model Lab — renders the MoE architecture, the twelve experts,
// the router, the training curriculum, and the 50-part build plan from
// lib/model.ts.

import { motion } from "framer-motion";
import {
  Bot,
  Boxes,
  Brain,
  CheckCircle2,
  Circle,
  CircleDot,
  Cpu,
  Gauge,
  Layers,
  Network,
  ShieldCheck,
  Split,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import FoundationLab from "@/components/FoundationLab";
import PretrainingLab from "@/components/PretrainingLab";
import {
  ALL_MODEL_PARTS,
  APP_INTEGRATION,
  CURRICULUM,
  EXPERTS,
  MODEL_CARD,
  MODEL_PHASES,
  PARAM_BUDGET,
  ROUTER,
  SAFETY_LAYER,
  SHIPPED_MODEL_PARTS,
  TOTAL_MODEL_PARTS,
  type Expert,
  type ModelPartStatus,
} from "@/lib/model";

const TIER_LABEL: Record<Expert["tier"], { label: string; chip: string }> = {
  foundational: { label: "foundational", chip: "border-border bg-muted text-muted-foreground" },
  offensive: { label: "offensive", chip: "border-destructive/40 bg-destructive/10 text-destructive" },
  defensive: { label: "defensive", chip: "border-[oklch(0.72_0.14_168)]/40 bg-[oklch(0.72_0.14_168)]/10 text-[oklch(0.72_0.14_168)]" },
  analysis: { label: "analysis", chip: "border-[oklch(0.78_0.11_220)]/40 bg-[oklch(0.78_0.11_220)]/10 text-[oklch(0.78_0.11_220)]" },
};

const STATUS_META: Record<ModelPartStatus, { icon: typeof CheckCircle2; label: string; className: string }> = {
  shipped: { icon: CheckCircle2, label: "Shipped", className: "text-primary border-primary/40 bg-primary/10" },
  "up-next": { icon: CircleDot, label: "Up next", className: "text-[oklch(0.82_0.14_85)] border-[oklch(0.8_0.16_85)]/40 bg-[oklch(0.8_0.16_85)]/10" },
  planned: { icon: Circle, label: "Planned", className: "text-muted-foreground border-border bg-muted" },
};

function StatBox({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-lg border border-border/60 bg-card/70 px-3.5 py-3">
      <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</p>
      <p className="mt-1 text-lg font-semibold tracking-tight">{value}</p>
      {sub && <p className="text-xs text-muted-foreground">{sub}</p>}
    </div>
  );
}

function ExpertCard({ expert, index }: { expert: Expert; index: number }) {
  const tier = TIER_LABEL[expert.tier];
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: index * 0.04 }}
    >
      <Card className="h-full border-border/60 bg-card/70">
        <CardContent className="p-4">
          <div className="mb-2 flex items-center gap-2">
            <div
              className="flex size-8 shrink-0 items-center justify-center rounded-lg border"
              style={{ borderColor: expert.color, color: expert.color, background: `${expert.color}14` }}
            >
              <Brain className="size-4" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium">
                <span className="font-mono text-xs text-muted-foreground">{expert.id}</span> {expert.name}
              </p>
              <Badge variant="outline" className={`mt-0.5 rounded-full text-[10px] ${tier.chip}`}>
                {tier.label} · {expert.params}
              </Badge>
            </div>
          </div>
          <div className="mb-2 flex flex-wrap gap-1">
            {expert.routes.slice(0, 4).map((r) => (
              <span key={r} className="rounded-full border border-border/60 bg-secondary/60 px-2 py-0.5 font-mono text-[10px] text-muted-foreground">
                {r}
              </span>
            ))}
          </div>
          <ul className="space-y-1">
            {expert.skills.map((s) => (
              <li key={s} className="flex items-start gap-1.5 text-xs leading-5 text-muted-foreground">
                <span className="mt-1.5 size-1 shrink-0 rounded-full" style={{ background: expert.color }} />
                {s}
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </motion.div>
  );
}

function ArchitectureTab() {
  return (
    <div className="space-y-6">
      {/* model card header */}
      <Card className="border-border/60 bg-card/70">
        <CardContent className="p-6">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex size-11 items-center justify-center rounded-xl bg-primary/12 ring-1 ring-primary/30">
              <Cpu className="size-5.5 text-primary" />
            </div>
            <div className="min-w-0 flex-1">
              <h2 className="text-xl font-semibold tracking-tight">
                {MODEL_CARD.name} <span className="font-mono text-sm text-muted-foreground">({MODEL_CARD.codename})</span>
              </h2>
              <p className="text-sm text-muted-foreground">
                Mixture-of-Experts LLM for penetration testing, bug bounty, cybersecurity, and code analysis.
              </p>
            </div>
            <Badge variant="outline" className="rounded-full border-primary/40 bg-primary/10 text-primary">
              Apache-2.0
            </Badge>
          </div>
          <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatBox label="Total params" value={MODEL_CARD.totalParams} sub={`${MODEL_CARD.activeParamsPerToken} active/token`} />
            <StatBox label="Experts" value={`${MODEL_CARD.expertsTotal}+1`} sub={`${MODEL_CARD.expertsActive} routed + 1 shared per token`} />
            <StatBox label="Context" value={`${(MODEL_CARD.contextLength / 1024).toFixed(0)}k`} sub="YaRN-scalable to 128k" />
            <StatBox label="Layers" value={`${MODEL_CARD.layers}`} sub={`GQA ${MODEL_CARD.attentionHeads}/${MODEL_CARD.kvHeads} heads`} />
          </div>
        </CardContent>
      </Card>

      {/* MoE diagram */}
      <Card className="border-border/60 bg-card/70">
        <CardContent className="p-6">
          <div className="mb-4 flex items-center gap-2">
            <Split className="size-4 text-primary" />
            <h3 className="font-semibold tracking-tight">Per-token flow</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center gap-3 rounded-lg border border-[oklch(0.78_0.11_220)]/40 bg-[oklch(0.78_0.11_220)]/5 px-4 py-3">
              <Network className="size-4 shrink-0 text-[oklch(0.78_0.11_220)]" />
              <div>
                <p className="text-sm font-medium">Router (top-2 softmax + z-loss)</p>
                <p className="text-xs text-muted-foreground">{ROUTER.kind}</p>
              </div>
            </div>
            <div className="ml-6 border-l border-dashed border-border pl-4">
              <div className="mb-2 flex items-center gap-2 rounded-lg border border-primary/40 bg-primary/5 px-4 py-2.5">
                <Layers className="size-4 shrink-0 text-primary" />
                <div>
                  <p className="text-sm font-medium">Shared expert — always on</p>
                  <p className="text-xs text-muted-foreground">{MODEL_CARD.sharedIntermediate} inter. · syntax + general reasoning · {PARAM_BUDGET[1].params}</p>
                </div>
              </div>
              <div className="grid gap-2 sm:grid-cols-3 lg:grid-cols-4">
                {EXPERTS.slice(0, 12).map((e) => (
                  <div key={e.id} className="rounded-lg border px-2.5 py-1.5" style={{ borderColor: `${e.color}55`, background: `${e.color}0d` }}>
                    <p className="font-mono text-[11px] font-medium" style={{ color: e.color }}>{e.id}</p>
                    <p className="truncate text-[11px] text-muted-foreground">{e.name}</p>
                  </div>
                ))}
              </div>
              <p className="mt-2 font-mono text-[11px] text-muted-foreground">
                capacity factor {ROUTER.capacityFactor} · overflow → shared expert · router distilled from 14B teacher ({ROUTER.calibration})
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* param budget */}
      <Card className="border-border/60 bg-card/70">
        <CardContent className="p-6">
          <div className="mb-4 flex items-center gap-2">
            <Boxes className="size-4 text-primary" />
            <h3 className="font-semibold tracking-tight">Parameter budget — adds to 8.0B</h3>
          </div>
          <div className="space-y-2">
            {PARAM_BUDGET.map((row) => (
              <div key={row.component} className="flex flex-wrap items-center gap-2 rounded-lg border border-border/50 bg-secondary/40 px-3.5 py-2.5">
                <p className="min-w-0 flex-1 text-sm">{row.component}</p>
                <span className="font-mono text-sm text-primary">{row.params}</span>
              </div>
            ))}
          </div>
          {PARAM_BUDGET.some((r) => r.note) && (
            <p className="mt-3 text-xs text-muted-foreground">{PARAM_BUDGET.find((r) => r.note)?.note}</p>
          )}
        </CardContent>
      </Card>

      {/* runtime */}
      <Card className="border-border/60 bg-card/70">
        <CardContent className="p-6">
          <div className="mb-4 flex items-center gap-2">
            <Gauge className="size-4 text-primary" />
            <h3 className="font-semibold tracking-tight">Inference & formats</h3>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg border border-border/50 bg-secondary/40 px-3.5 py-3">
              <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Serving</p>
              <p className="mt-1 text-sm">{MODEL_CARD.inference}</p>
            </div>
            <div className="rounded-lg border border-border/50 bg-secondary/40 px-3.5 py-3">
              <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Positions</p>
              <p className="mt-1 text-sm">{MODEL_CARD.position}</p>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {MODEL_CARD.quantized.map((q) => (
              <span key={q} className="rounded-full border border-border/60 bg-secondary/60 px-3 py-1 font-mono text-xs text-muted-foreground">
                {q}
              </span>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function ExpertsTab() {
  const tiers = ["offensive", "analysis", "defensive"] as const;
  return (
    <div className="space-y-6">
      <p className="max-w-3xl text-sm leading-6 text-muted-foreground">
        Twelve routed experts, one shared. The router picks the top-2 per token, so a
        request like <span className="font-mono text-foreground/80">"exploit this SSRF in an AWS Lambda"</span>
        {" "}fires <span className="font-mono text-foreground/80">E2 (Web Exploitation)</span> +{" "}
        <span className="font-mono text-foreground/80">E7 (Cloud & Infra)</span> while the shared
        expert carries language ability for every token.
      </p>
      {tiers.map((tier) => (
        <div key={tier}>
          <div className="mb-3 flex items-center gap-3">
            <Badge variant="outline" className={`rounded-full text-[11px] capitalize ${TIER_LABEL[tier].chip}`}>
              {TIER_LABEL[tier].label} experts
            </Badge>
            <Separator className="flex-1" />
            <span className="font-mono text-xs text-muted-foreground">
              {EXPERTS.filter((e) => e.tier === tier).length} expert(s)
            </span>
          </div>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {EXPERTS.filter((e) => e.tier === tier).map((e, i) => (
              <ExpertCard key={e.id} expert={e} index={i} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function TrainingTab() {
  return (
    <div className="space-y-6">
      <Card className="border-border/60 bg-card/70">
        <CardContent className="p-6">
          <div className="mb-4 flex items-center gap-2">
            <Layers className="size-4 text-primary" />
            <h3 className="font-semibold tracking-tight">Training pipeline</h3>
          </div>
          <ol className="space-y-2">
            {[
              { stage: "Pretrain", detail: MODEL_CARD.basePretrain },
              { stage: "Mid-train", detail: MODEL_CARD.midTrain },
              { stage: "Fine-tune", detail: MODEL_CARD.finetune },
            ].map((s, i) => (
              <li key={s.stage} className="flex gap-3 rounded-lg border border-border/50 bg-secondary/40 px-3.5 py-2.5">
                <span className="font-mono text-xs text-primary">{i + 1}</span>
                <div>
                  <p className="text-sm font-medium">{s.stage}</p>
                  <p className="text-xs text-muted-foreground">{s.detail}</p>
                </div>
              </li>
            ))}
          </ol>
        </CardContent>
      </Card>

      <div>
        <div className="mb-3 flex items-center gap-3">
          <h3 className="font-semibold tracking-tight">Security curriculum — 320B tokens</h3>
          <Separator className="flex-1" />
        </div>
        <div className="space-y-2">
          {CURRICULUM.map((slice) => (
            <div key={slice.id} className="rounded-lg border border-border/50 bg-card/70 px-4 py-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-primary">{slice.id}</span>
                <p className="min-w-0 flex-1 text-sm font-medium">{slice.name}</p>
                <span className="font-mono text-xs text-muted-foreground">{slice.tokens}</span>
              </div>
              <p className="mt-1 text-xs text-muted-foreground">{slice.sources.join(" · ")}</p>
              <div className="mt-2 flex flex-wrap gap-1">
                {slice.primaryExperts.map((e) => (
                  <span key={e} className="rounded-full border border-primary/30 bg-primary/5 px-2 py-0.5 font-mono text-[10px] text-primary">
                    {e}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      <Card className="border-destructive/25 bg-destructive/5">
        <CardContent className="p-5">
          <div className="mb-2 flex items-center gap-2">
            <ShieldCheck className="size-4 text-destructive" />
            <h3 className="font-semibold tracking-tight">{SAFETY_LAYER.name}</h3>
          </div>
          <ul className="space-y-1.5">
            {SAFETY_LAYER.mechanism.map((m) => (
              <li key={m} className="flex items-start gap-2 text-sm leading-6 text-foreground/85">
                <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-destructive/70" />
                {m}
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-muted-foreground">{SAFETY_LAYER.evalSuite}</p>
        </CardContent>
      </Card>
    </div>
  );
}

function RoadmapTab() {
  const pct = Math.round((SHIPPED_MODEL_PARTS / TOTAL_MODEL_PARTS) * 100);
  return (
    <div className="space-y-8">
      <Card className="border-border/60 bg-card/70">
        <CardContent className="p-6">
          <div className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <h2 className="text-xl font-semibold tracking-tight">CrackScope-8B build plan</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {TOTAL_MODEL_PARTS} parts across {MODEL_PHASES.length} phases — from data lake to open-source release.
              </p>
            </div>
            <span className="font-mono text-sm text-muted-foreground">
              {SHIPPED_MODEL_PARTS}/{TOTAL_MODEL_PARTS} · {pct}%
            </span>
          </div>
          <Progress value={pct} className="mt-5 h-2" />
        </CardContent>
      </Card>

      {MODEL_PHASES.map((phase, pi) => (
        <motion.div
          key={phase.phase}
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: pi * 0.05 }}
        >
          <div className="mb-3 flex flex-wrap items-baseline gap-2">
            <h3 className="font-semibold tracking-tight">
              Phase {phase.phase}: {phase.name}
            </h3>
            <span className="text-sm text-muted-foreground">— {phase.goal}</span>
          </div>
          <div className="space-y-2">
            {phase.parts.map((part) => {
              const meta = STATUS_META[part.status];
              const Icon = meta.icon;
              return (
                <Card key={part.part} className="border-border/60 bg-card/70">
                  <CardContent className="flex items-start gap-3 px-4 py-3.5">
                    <span className="w-8 shrink-0 text-center font-mono text-sm text-muted-foreground">
                      {part.part}
                    </span>
                    <Icon className={`mt-0.5 size-4 shrink-0 ${part.status === "shipped" ? "text-primary" : part.status === "up-next" ? "text-[oklch(0.82_0.14_85)]" : "text-muted-foreground/50"}`} />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium">{part.title}</p>
                      <p className="mt-0.5 text-xs leading-5 text-muted-foreground">{part.description}</p>
                    </div>
                    <Badge variant="outline" className={`shrink-0 rounded-full text-[10px] ${meta.className}`}>
                      {meta.label}
                    </Badge>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </motion.div>
      ))}
    </div>
  );
}

function IntegrationTab() {
  return (
    <div className="space-y-4">
      <p className="max-w-3xl text-sm leading-6 text-muted-foreground">
        How the model plugs into CrackScope once shipped — every existing surface
        keeps its contract and swaps the brain.
      </p>
      {APP_INTEGRATION.map((row) => (
        <Card key={row.surface} className="border-border/60 bg-card/70">
          <CardContent className="flex flex-col gap-1.5 p-5 sm:flex-row sm:items-start sm:gap-4">
            <div className="flex items-center gap-2 sm:w-56 sm:shrink-0">
              <Bot className="size-4 shrink-0 text-primary" />
              <p className="text-sm font-medium">{row.surface}</p>
            </div>
            <p className="text-sm leading-6 text-muted-foreground">{row.detail}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

export default function ModelLab() {
  return (
    <Tabs defaultValue="architecture" className="space-y-6">
      <TabsList className="flex-wrap">
        <TabsTrigger value="architecture">Architecture</TabsTrigger>
        <TabsTrigger value="experts">12 experts</TabsTrigger>
        <TabsTrigger value="training">Training & safety</TabsTrigger>
        <TabsTrigger value="roadmap">50-part plan</TabsTrigger>
        <TabsTrigger value="foundation">Foundation lab</TabsTrigger>
        <TabsTrigger value="pretraining">Pretraining lab</TabsTrigger>
        <TabsTrigger value="integration">App integration</TabsTrigger>
      </TabsList>
      <TabsContent value="architecture">
        <ArchitectureTab />
      </TabsContent>
      <TabsContent value="experts">
        <ExpertsTab />
      </TabsContent>
      <TabsContent value="training">
        <TrainingTab />
      </TabsContent>
      <TabsContent value="roadmap">
        <RoadmapTab />
      </TabsContent>
      <TabsContent value="foundation">
        <FoundationLab />
      </TabsContent>
      <TabsContent value="pretraining">
        <PretrainingLab />
      </TabsContent>
      <TabsContent value="integration">
        <IntegrationTab />
      </TabsContent>
    </Tabs>
  );
}
