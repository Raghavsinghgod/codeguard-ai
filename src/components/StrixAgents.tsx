// CrackScope × Strix — agent-team console.
// Visualizes the multi-agent red-team run from lib/strix.ts: the live action
// feed, the agent roster, discovered attack chains, the agentic toolkit, the
// nine agent skills, auto-fix patches, and the headless CI gate verdict.

import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  Bot,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  Code,
  Copy,
  Globe,
  Link2,
  Network,
  Play,
  Radar,
  ScanSearch,
  ShieldCheck,
  ShieldX,
  Terminal,
  Wrench,
  XCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import {
  SCAN_BUDGETS,
  type AgentAction,
  type AgentActionKind,
  type AgentRole,
  type ScanMode,
  type StrixRun,
} from "@/lib/strix";
import { SEVERITY_STYLE } from "@/components/ScanReport";

const ROLE_STYLE: Record<AgentRole, { chip: string; label: string }> = {
  orchestrator: { chip: "border-primary/40 bg-primary/10 text-primary", label: "orchestrator" },
  recon: { chip: "border-[oklch(0.78_0.11_220)]/40 bg-[oklch(0.78_0.11_220)]/10 text-[oklch(0.78_0.11_220)]", label: "recon" },
  exploitation: { chip: "border-destructive/40 bg-destructive/10 text-destructive", label: "exploitation" },
  validation: { chip: "border-[oklch(0.82_0.14_85)]/40 bg-[oklch(0.82_0.14_85)]/10 text-[oklch(0.82_0.14_85)]", label: "validation" },
  reporting: { chip: "border-[oklch(0.72_0.14_168)]/40 bg-[oklch(0.72_0.14_168)]/10 text-[oklch(0.72_0.14_168)]", label: "reporting" },
};

const KIND_STYLE: Record<AgentActionKind, string> = {
  recon: "text-[oklch(0.78_0.11_220)]",
  probe: "text-[oklch(0.78_0.11_220)]",
  exploit: "text-destructive",
  validate: "text-[oklch(0.82_0.14_85)]",
  chain: "text-primary",
  report: "text-[oklch(0.72_0.14_168)]",
};

const TOOL_ICON: Record<string, typeof Network> = {
  Network,
  Globe,
  Terminal,
  Code,
  Radar,
  ScanSearch,
  BookOpen,
};

const VERDICT_BADGE: Record<string, string> = {
  validated: "border-primary/40 bg-primary/10 text-primary",
  probable: "border-[oklch(0.82_0.14_85)]/40 bg-[oklch(0.82_0.14_85)]/10 text-[oklch(0.82_0.14_85)]",
  blocked: "border-border bg-muted text-muted-foreground",
  "needs-context": "border-border bg-muted text-muted-foreground",
};

function ActionFeed({ run }: { run: StrixRun }) {
  const [playing, setPlaying] = useState(false);
  const [visible, setVisible] = useState(run.actions.length);
  const [speed] = useState(1);

  const replay = () => {
    if (playing) return;
    setPlaying(true);
    setVisible(0);
    const total = run.actions.length;
    let i = 0;
    const step = () => {
      i += 1;
      setVisible(i);
      if (i < total) {
        const delay = Math.max(60, 420 - i * 12) / speed;
        window.setTimeout(step, delay);
      } else {
        setPlaying(false);
      }
    };
    window.setTimeout(step, 120);
  };

  const shown = run.actions.slice(0, visible);

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="p-0">
        <div className="flex flex-wrap items-center gap-2 border-b border-border/50 px-5 py-3">
          <Terminal className="size-4 text-primary" />
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            agent activity
          </p>
          <Separator className="mx-1 hidden flex-1 md:block" />
          <span className="font-mono text-xs text-muted-foreground">
            {run.actions.length} action{run.actions.length === 1 ? "" : "s"} · {(run.durationMs / 1000).toFixed(1)}s team time
          </span>
          <Button size="sm" variant="outline" className="h-7 gap-1.5 rounded-full text-xs" onClick={replay} disabled={playing}>
            <Play className="size-3" /> {playing ? "running…" : "Replay run"}
          </Button>
        </div>
        <div className="max-h-80 overflow-y-auto px-5 py-3">
          {shown.map((a: AgentAction) => {
            const agent = run.agents.find((ag) => ag.id === a.agentId);
            return (
              <div key={a.seq} className="flex gap-2 font-mono text-xs leading-6">
                <span className="shrink-0 text-muted-foreground/60">
                  {(a.atMs / 1000).toFixed(1)}s
                </span>
                <span className={`shrink-0 font-medium ${KIND_STYLE[a.kind]}`}>
                  [{agent?.name ?? a.agentId}]
                </span>
                <span className="min-w-0 break-all text-foreground/85">{a.line}</span>
              </div>
            );
          })}
          {visible < run.actions.length && (
            <p className="mt-1 font-mono text-xs text-muted-foreground/60">… {run.actions.length - visible} more</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function AgentRoster({ run }: { run: StrixRun }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {run.agents.map((agent, i) => {
        const style = ROLE_STYLE[agent.role];
        return (
          <motion.div
            key={agent.id}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: i * 0.06 }}
          >
            <Card className="h-full border-border/60 bg-card/70">
              <CardContent className="p-4">
                <div className="mb-2 flex items-center gap-2">
                  <div className={`flex size-8 items-center justify-center rounded-lg border ${style.chip}`}>
                    <Bot className="size-4" />
                  </div>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{agent.name}</p>
                    <Badge variant="outline" className={`rounded-full text-[10px] ${style.chip}`}>
                      {style.label}
                    </Badge>
                  </div>
                </div>
                <p className="text-xs leading-5 text-muted-foreground">{agent.specialty}</p>
                {agent.assigned.length > 0 && (
                  <p className="mt-2 font-mono text-[11px] text-muted-foreground">
                    {agent.assigned.length} target{agent.assigned.length === 1 ? "" : "s"} claimed
                  </p>
                )}
              </CardContent>
            </Card>
          </motion.div>
        );
      })}
    </div>
  );
}

function AttackChains({ run }: { run: StrixRun }) {
  const [open, setOpen] = useState<string | null>(run.chains[0]?.id ?? null);
  if (run.chains.length === 0) {
    return (
      <Card className="border-border/60 bg-card/60">
        <CardContent className="py-6 text-center">
          <p className="text-sm text-muted-foreground">
            No attack chains discovered — no pair of findings combined into a stronger exploit.
          </p>
        </CardContent>
      </Card>
    );
  }
  return (
    <div className="space-y-3">
      {run.chains.map((chain) => {
        const isOpen = open === chain.id;
        return (
          <Card key={chain.id} className="border-border/60 bg-card/70">
            <button
              type="button"
              onClick={() => setOpen(isOpen ? null : chain.id)}
              className="flex w-full items-center gap-3 px-5 py-4 text-left"
            >
              <Link2 className="size-4 shrink-0 text-primary" />
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{chain.name}</p>
                <p className="truncate font-mono text-xs text-muted-foreground">
                  {chain.steps.map((s) => s.split("|")[0]).join(" → ")}
                </p>
              </div>
              <ChevronDown className={`size-4 shrink-0 text-muted-foreground transition-transform ${isOpen ? "rotate-180" : ""}`} />
            </button>
            {isOpen && (
              <div className="space-y-3 border-t border-border/50 px-5 py-4">
                {/* kill-chain visualization */}
                <div className="flex flex-wrap items-center gap-2">
                  {chain.steps.map((step, i) => {
                    const v = run.validated.find((x) => x.key === step);
                    return (
                      <div key={step} className="flex items-center gap-2">
                        {i > 0 && <span className="text-muted-foreground">→</span>}
                        <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-3 py-2">
                          <p className="font-mono text-[11px] font-medium text-destructive">{step.split("|")[0]}</p>
                          <p className="max-w-56 truncate text-xs text-muted-foreground">
                            {v ? `${v.file}:${v.line}` : step}
                          </p>
                        </div>
                      </div>
                    );
                  })}
                </div>
                <p className="text-sm leading-6 text-foreground/85">{chain.narrative}</p>
                <div className="rounded-lg border border-primary/25 bg-primary/5 p-3">
                  <p className="font-mono text-[11px] uppercase tracking-widest text-primary">Impact</p>
                  <p className="mt-1 text-sm leading-6 text-foreground/90">{chain.impact}</p>
                </div>
              </div>
            )}
          </Card>
        );
      })}
    </div>
  );
}

function AutoFixPatches({ run }: { run: StrixRun }) {
  const [copied, setCopied] = useState<string | null>(null);
  if (run.fixes.length === 0) return null;
  const copy = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      window.setTimeout(() => setCopied(null), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <div>
      <div className="mb-3 flex items-center gap-3">
        <h3 className="text-lg font-semibold tracking-tight">Auto-fix patches</h3>
        <Separator className="flex-1" />
        <span className="font-mono text-xs text-muted-foreground">
          {run.fixes.length} ready-to-merge patch{run.fixes.length === 1 ? "" : "es"}
        </span>
      </div>
      <div className="space-y-3">
        {run.fixes.map((fix) => (
          <Card key={fix.key} className="border-border/60 bg-card/70">
            <CardContent className="p-4">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <Wrench className="size-3.5 text-primary" />
                <p className="min-w-0 flex-1 truncate text-sm font-medium">{fix.title}</p>
                <Badge
                  variant="outline"
                  className={`rounded-full text-[10px] capitalize ${
                    fix.confidence === "high"
                      ? VERDICT_BADGE.validated
                      : fix.confidence === "medium"
                        ? VERDICT_BADGE.probable
                        : VERDICT_BADGE["needs-context"]
                  }`}
                >
                  {fix.confidence} confidence
                </Badge>
              </div>
              <p className="mb-2 font-mono text-xs text-muted-foreground">
                {fix.file}:{fix.line} · {fix.ruleId}
              </p>
              <div className="group relative">
                <pre className="overflow-x-auto rounded-lg border border-primary/25 bg-secondary/60 p-3 pr-10 font-mono text-xs leading-5">
                  {fix.patch}
                </pre>
                <button
                  type="button"
                  onClick={() => copy(fix.patch, fix.key)}
                  className="absolute right-2 top-2 rounded p-1 text-muted-foreground opacity-0 transition-opacity hover:text-foreground group-hover:opacity-100"
                  aria-label="Copy patch"
                >
                  <Copy className="size-3.5" />
                </button>
                {copied === fix.key && (
                  <span className="absolute right-9 top-2 font-mono text-[10px] text-primary">copied</span>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

export function StrixModeSelector({
  mode,
  onMode,
}: {
  mode: ScanMode;
  onMode: (m: ScanMode) => void;
}) {
  return (
    <div className="flex flex-wrap gap-2">
      {(Object.keys(SCAN_BUDGETS) as ScanMode[]).map((m) => (
        <button
          key={m}
          type="button"
          onClick={() => onMode(m)}
          className={`rounded-full border px-3.5 py-1.5 text-xs font-medium capitalize transition-colors ${
            m === mode
              ? "border-primary/50 bg-primary/15 text-primary"
              : "border-border/60 bg-transparent text-muted-foreground hover:text-foreground"
          }`}
        >
          {m}
        </button>
      ))}
    </div>
  );
}

export function StrixAgents({ run, mode }: { run: StrixRun; mode: ScanMode }) {
  const toolkit = run.toolkit;
  const skills = run.skills;
  const gate = run.ciGate;
  const validated = useMemo(() => run.validated.filter((v) => v.verdict === "validated"), [run]);

  return (
    <div className="space-y-6">
      {/* header: team + gate */}
      <Card className="border-border/60 bg-card/70">
        <CardContent className="flex flex-col gap-4 p-6 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
              Strix agent team
            </p>
            <p className="mt-1 text-lg font-semibold tracking-tight">
              {run.agents.length} agents · {mode} mode
            </p>
            <p className="text-sm text-muted-foreground">{SCAN_BUDGETS[mode].label}</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-right">
              <p className="font-mono text-2xl font-semibold text-primary">{run.validationRate}%</p>
              <p className="text-xs text-muted-foreground">validation rate</p>
            </div>
            <div
              className={`flex items-center gap-2 rounded-full border px-4 py-2 ${
                gate.pass
                  ? "border-primary/40 bg-primary/10 text-primary"
                  : "border-destructive/40 bg-destructive/10 text-destructive"
              }`}
            >
              {gate.pass ? <ShieldCheck className="size-4" /> : <ShieldX className="size-4" />}
              <div className="text-left">
                <p className="text-sm font-semibold">CI gate {gate.pass ? "PASS" : "FAIL"}</p>
                <p className="font-mono text-[10px] opacity-80">exit {gate.exitCode}</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <ActionFeed run={run} />
      <AgentRoster run={run} />

      {/* attack chains */}
      <div>
        <div className="mb-4 flex items-center gap-3">
          <h3 className="text-lg font-semibold tracking-tight">Attack chains</h3>
          <Separator className="flex-1" />
          <span className="font-mono text-xs text-muted-foreground">
            {run.chains.length} chain{run.chains.length === 1 ? "" : "s"}
          </span>
        </div>
        <AttackChains run={run} />
      </div>

      {/* validated findings with PoCs */}
      <div>
        <div className="mb-4 flex items-center gap-3">
          <h3 className="text-lg font-semibold tracking-tight">Validated findings</h3>
          <Separator className="flex-1" />
          <span className="font-mono text-xs text-muted-foreground">
            {run.validated.length} worked · {validated.length} with confirmed PoCs
          </span>
        </div>
        <div className="space-y-3">
          {run.validated.map((v, i) => {
            const style = SEVERITY_STYLE[v.severity];
            return (
              <motion.div
                key={v.key}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: Math.min(i * 0.04, 0.3) }}
              >
                <Card className="border-border/60 bg-card/70">
                  <CardContent className="p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`size-2 shrink-0 rounded-full ${style.dot}`} />
                      <p className="min-w-0 flex-1 truncate text-sm font-medium">{v.title}</p>
                      <Badge variant="outline" className={`rounded-full text-[10px] ${VERDICT_BADGE[v.verdict]}`}>
                        {v.verdict}
                      </Badge>
                      <Badge variant="outline" className={`rounded-full text-[10px] capitalize ${style.chip}`}>
                        {v.severity}
                      </Badge>
                      <span className="font-mono text-xs text-muted-foreground">{v.confidence}%</span>
                    </div>
                    <p className="mt-1 font-mono text-xs text-muted-foreground">
                      {v.file}:{v.line} · {v.ruleId}
                      {v.chainId ? " · part of an attack chain" : ""}
                    </p>
                    <p className="mt-2 text-sm leading-6 text-foreground/85">{v.rationale}</p>
                    <div className="mt-2 rounded-lg border border-destructive/25 bg-destructive/5 p-3">
                      <p className="mb-1 font-mono text-[11px] uppercase tracking-widest text-destructive">
                        Proof-of-concept
                      </p>
                      <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-xs leading-5 text-foreground/90">
                        {v.poc}
                      </pre>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            );
          })}
        </div>
      </div>

      <AutoFixPatches run={run} />

      {/* toolkit + skills */}
      <div className="grid gap-6 lg:grid-cols-2">
        <div>
          <div className="mb-3 flex items-center gap-3">
            <h3 className="text-lg font-semibold tracking-tight">Agentic toolkit</h3>
            <Separator className="flex-1" />
          </div>
          <div className="space-y-2">
            {toolkit.map((tool) => {
              const Icon = TOOL_ICON[tool.icon] ?? Bot;
              return (
                <div
                  key={tool.id}
                  className={`flex items-center gap-3 rounded-lg border px-3.5 py-2.5 ${
                    tool.used ? "border-border/60 bg-card/70" : "border-border/30 bg-transparent opacity-55"
                  }`}
                >
                  <Icon className={`size-4 shrink-0 ${tool.used ? "text-primary" : "text-muted-foreground"}`} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium">{tool.name}</p>
                    <p className="truncate text-xs text-muted-foreground">{tool.description}</p>
                  </div>
                  <span className="shrink-0 font-mono text-[11px] text-muted-foreground">
                    {tool.used ? `${tool.calls} call${tool.calls === 1 ? "" : "s"}` : "idle"}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
        <div>
          <div className="mb-3 flex items-center gap-3">
            <h3 className="text-lg font-semibold tracking-tight">Agent skills</h3>
            <Separator className="flex-1" />
            <span className="font-mono text-xs text-muted-foreground">
              {skills.filter((s) => s.fired).length}/{skills.length} fired
            </span>
          </div>
          <div className="space-y-2">
            {skills.map((skill) => (
              <div
                key={skill.id}
                className={`flex items-start gap-3 rounded-lg border px-3.5 py-2.5 ${
                  skill.fired ? "border-border/60 bg-card/70" : "border-border/30 bg-transparent opacity-55"
                }`}
              >
                {skill.fired ? (
                  <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-primary" />
                ) : (
                  <XCircle className="mt-0.5 size-4 shrink-0 text-muted-foreground/50" />
                )}
                <div className="min-w-0">
                  <p className="text-sm font-medium">{skill.name}</p>
                  <p className="text-xs leading-5 text-muted-foreground">{skill.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* pentest summary */}
      <Card className="border-primary/25 bg-primary/5">
        <CardContent className="p-5">
          <p className="font-mono text-xs uppercase tracking-widest text-primary">Pentest summary</p>
          <div className="mt-2 space-y-2">
            {run.summary.map((line, i) => (
              <p key={i} className="text-sm leading-6 text-foreground/90">
                {line}
              </p>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
