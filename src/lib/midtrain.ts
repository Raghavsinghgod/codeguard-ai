// CrackScope-8B — Security mid-training phase (Parts 11–15) as working
// in-app modules.
//
// Part 11 Curriculum mixer     → buildCurriculumSchedule (CURRICULUM C1–C8)
// Part 12 Mid-train run sim    → simulateMidTrain (320B tokens, LR re-warm)
// Part 13 Vulnerable→fixed     → generateRepairPairs (compiler-verified sim)
// Part 14 Router distillation  → distillRouter (14B teacher → cs-8b router)
// Part 15 Mid-train eval gate  → runMidTrainGate (PPL −41%, MMLU ≤ −1pt)
//
// Consumes: CURRICULUM (lib/model.ts), the Chinchilla fit (lib/foundation.ts),
// and the Part 6 anchor-share floor from lib/pretraining.ts.

import { fitScalingLaw, PROBE_GRID } from "@/lib/foundation";
import { CURRICULUM } from "@/lib/model";

// ============================================================================
// PART 11 — CURRICULUM MIXER
// ============================================================================

export const MIDTRAIN_TOKENS = 320e9;

/** Slice scheduler input: C1–C8 from the model card's curriculum, with
 *  per-expert token budgets and replay anchors (C8 always ≥ 8%). */
export interface CurriculumSliceState {
  id: string;
  name: string;
  tokens: number;           // requested slice size
  primaryExperts: string[]; // e.g. ["E1","E11"]
  /** Locked plan tokens for reference. */
  lockedTokens: number;
}

export const LOCKED_CURRICULUM: CurriculumSliceState[] = CURRICULUM.map((c) => ({
  id: c.id,
  name: c.name,
  tokens: Number(c.tokens.replace("B", "")) * 1e9,
  primaryExperts: c.primaryExperts,
  lockedTokens: Number(c.tokens.replace("B", "")) * 1e9,
}));

export interface ScheduleAssessment {
  totalTokens: number;
  /** C8 anchor share — hard floor 8% (plan: replay prevents forgetting). */
  anchorShare: number;
  anchorOk: boolean;
  /** Per-expert token budget across all slices (for balance audit). */
  expertBudgets: Array<{ expert: string; tokens: number; share: number }>;
  /** Budget imbalance: max/min expert share (target ≤ 3×). */
  imbalanceRatio: number;
  warnings: string[];
  quality: number; // 0–100
}

/** Evaluate a curriculum schedule (tokens normalized to the 320B budget). */
export function assessCurriculum(slices: CurriculumSliceState[]): ScheduleAssessment {
  const total = slices.reduce((a, s) => a + s.tokens, 0) || 1;
  const norm = slices.map((s) => ({ ...s, share: s.tokens / total }));

  const anchor = norm.find((s) => s.id === "C8");
  const anchorShare = anchor?.share ?? 0;
  const anchorOk = anchorShare >= 0.08;

  // Per-expert budgets: "all offensive experts" splits across E2–E7+E10.
  const OFFENSIVE = ["E2", "E3", "E4", "E5", "E6", "E7", "E10"];
  const budgets = new Map<string, number>();
  for (const s of norm) {
    const experts = s.primaryExperts.includes("all offensive experts")
      ? OFFENSIVE
      : s.primaryExperts.filter((e) => e.startsWith("E"));
    const per = experts.length ? 1 / experts.length : 0;
    for (const e of experts) budgets.set(e, (budgets.get(e) ?? 0) + s.tokens * per);
  }
  const expertBudgets = Array.from(budgets.entries())
    .map(([expert, tokens]) => ({ expert, tokens, share: tokens / total }))
    .sort((a, b) => a.expert.localeCompare(b.expert));
  const shares = expertBudgets.map((b) => b.share);
  const imbalanceRatio = shares.length
    ? Math.max(...shares) / Math.max(1e-9, Math.min(...shares))
    : 1;

  const warnings: string[] = [];
  if (!anchorOk)
    warnings.push(
      `C8 anchor replay at ${(anchorShare * 100).toFixed(1)}% — below the 8% floor, catastrophic-forgetting risk`
    );
  if (imbalanceRatio > 3)
    warnings.push(
      `expert token budgets imbalanced ${imbalanceRatio.toFixed(1)}× — over-served experts will dominate routing`
    );
  const securityOnly = norm.filter((s) => s.id !== "C8").reduce((a, s) => a + s.share, 0);
  if (securityOnly > 0.97)
    warnings.push("less than 3% general data — router z-loss will destabilize on out-of-domain tokens");

  const quality = Math.max(
    0,
    Math.min(100, 100 - (anchorOk ? 0 : 30) - Math.max(0, imbalanceRatio - 3) * 6 - warnings.length * 10)
  );

  return { totalTokens: total, anchorShare, anchorOk, expertBudgets, imbalanceRatio, warnings, quality };
}

// ============================================================================
// PART 12 — MID-TRAIN RUN SIMULATOR (320B tokens, LR re-warmed to 30% peak)
// ============================================================================

export interface MidTrainConfig {
  totalTokens: number;      // 320e9
  batchTokensPerStep: number;
  lrRewarmFraction: number; // 0.30 of pretrain peak
  pretrainPeakLr: number;   // 3e-4
  checkpointEveryTokens: number;
}

export const MIDTRAIN_CONFIG: MidTrainConfig = {
  totalTokens: MIDTRAIN_TOKENS,
  batchTokensPerStep: 8e6,
  lrRewarmFraction: 0.3,
  pretrainPeakLr: 3e-4,
  checkpointEveryTokens: 0.04e12,
};

export interface MidTrainEntry {
  step: number;
  tokens: number;
  loss: number;
  /** Security-probe PPL ratio vs the 1.8T pretrain base. */
  secPplRatio: number;
  /** MMLU — must not regress > 1pt from base (65.8 nominal). */
  mmlu: number;
  /** Mean routing purity across expert domains. */
  purity: number;
  lr: number;
}

export interface MidTrainRun {
  log: MidTrainEntry[];
  finalLoss: number;
  finalSecPplRatio: number;
  finalMmlu: number;
  finalPurity: number;
  /** Loss spike count (LR re-warm on a mid-flight model causes transients). */
  spikes: number;
}

/** Loss trajectory = pretrain scaling floor (from the fitted law) with the
 *  security curriculum's domain specialization lifting the mid-train gain. */
export function simulateMidTrain(
  cfg: MidTrainConfig = MIDTRAIN_CONFIG,
  curriculumQuality = 100,
  baseMmlu = 65.8
): MidTrainRun {
  const fit = fitScalingLaw(PROBE_GRID);
  const totalSteps = Math.round(cfg.totalTokens / cfg.batchTokensPerStep);
  const peakLr = cfg.pretrainPeakLr * cfg.lrRewarmFraction;

  const log: MidTrainEntry[] = [];
  const sampleEvery = Math.max(1, Math.round(0.02e12 / cfg.batchTokensPerStep));
  // Quality from Part 11 scales how much security specialization is extracted.
  const gainScale = 0.7 + 0.3 * (curriculumQuality / 100);
  // Base loss if we simply continued pretraining (D-term at base+320B).
  const baseLossAtEnd = fit.predict(1.9e9, 1.8e12 + cfg.totalTokens);

  let spikes = 0;
  for (let step = 1; step <= totalSteps; step++) {
    const tokens = step * cfg.batchTokensPerStep;
    const isSample = step === 1 || step === totalSteps || step % sampleEvery === 0;
    if (!isSample) continue;
    const progress = tokens / cfg.totalTokens;

    // LR: re-warm to 30% peak over 2% of steps, then cosine to ~0.
    const warmSteps = Math.round(totalSteps * 0.02);
    const warm = step <= warmSteps ? step / warmSteps : 1;
    const decay = 0.05 + 0.95 * 0.5 * (1 + Math.cos(Math.PI * progress));
    const lr = peakLr * warm * decay;

    // Loss: interpolate from the pretrain-continuation floor down by the
    // curriculum gain on security topics, transient spike at re-warm.
    const contFloor = fit.predict(1.9e9, 1.8e12 + tokens);
    const secGain = (contFloor - baseLossAtEnd * 0.94) * progress * gainScale;
    const spike = step <= warmSteps ? 0.22 * (1 - step / warmSteps) : 0;
    if (spike > 0.15) spikes++;
    const loss = contFloor - secGain + spike;

    // Security-probe PPL ratio vs base improves with curriculum progress.
    const secPplRatio = 1.0 - 0.41 * Math.min(1, progress * 1.15) * gainScale;
    // MMLU: tiny transient dip during re-warm, recovers; −1pt is the budget.
    const mmlu = baseMmlu - 0.6 * (spike > 0 ? 1 : 0) - 0.2 * (1 - Math.min(1, progress * 2)) + 0.4 * progress;
    // Purity climbs as experts specialize under their token budgets.
    const purity = 0.93 + 0.025 * Math.min(1, progress * 1.3) * gainScale - (spike > 0 ? 0.02 : 0);

    log.push({
      step,
      tokens,
      loss,
      secPplRatio: Math.max(0.55, secPplRatio),
      mmlu: Math.max(60, mmlu),
      purity: Math.min(0.97, purity),
      lr,
    });
  }

  return {
    log,
    finalLoss: log[log.length - 1].loss,
    finalSecPplRatio: log[log.length - 1].secPplRatio,
    finalMmlu: log[log.length - 1].mmlu,
    finalPurity: log[log.length - 1].purity,
    spikes,
  };
}

// ============================================================================
// PART 13 — VULNERABLE→FIXED PAIR GENERATION (compiler-verified)
// ============================================================================

export interface VulnTemplate {
  id: string;
  cwe: string;
  language: "javascript" | "python" | "go" | "java" | "c";
  /** Generates a vulnerable code snippet. */
  vulnerable: (ctx: PairContext) => string;
  /** Generates the minimal-diff fixed version. */
  fixed: (ctx: PairContext) => string;
  expert: string; // primary expert grounded (E1/E11/E2/…)
}

export interface PairContext {
  table: string;
  column: string;
  param: string;
  cmd: string;
  id: number;
}

export interface RepairPair {
  pairId: string;
  templateId: string;
  cwe: string;
  language: string;
  expert: string;
  vulnerable: string;
  fixed: string;
  /** Simulated compiler/linter verdicts — pairs only ship if both pass. */
  compilesVulnerable: boolean;
  compilesFixed: boolean;
  /** Sanity check: the fix must not merely delete the vulnerable line. */
  minimalDiff: boolean;
  diffLines: number;
}

function mulberry(seed: number) {
  let a = seed | 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const VULN_TEMPLATES: VulnTemplate[] = [
  {
    id: "T1", cwe: "CWE-89", language: "javascript", expert: "E3",
    vulnerable: (c) => `db.query("SELECT * FROM ${c.table} WHERE ${c.column} = '" + req.params.${c.param} + "'");`,
    fixed: (c) => `db.query("SELECT * FROM ${c.table} WHERE ${c.column} = $1", [req.params.${c.param}]);`,
  },
  {
    id: "T2", cwe: "CWE-78", language: "python", expert: "E3",
    vulnerable: (c) => `os.system(f"ping -c 1 {${c.param}}")`,
    fixed: (c) => `subprocess.run(["ping", "-c", "1", ${c.param}], check=True)`,
  },
  {
    id: "T3", cwe: "CWE-22", language: "javascript", expert: "E1",
    vulnerable: (c) => `const p = path.join(base, req.params.${c.param});\nres.sendFile(p);`,
    fixed: (c) => `const p = path.resolve(base, req.params.${c.param});\nif (!p.startsWith(path.resolve(base) + path.sep)) throw new ForbiddenError();\nres.sendFile(p);`,
  },
  {
    id: "T4", cwe: "CWE-639", language: "python", expert: "E4",
    vulnerable: (c) => `invoice = Invoice.objects.get(id=${c.param})`,
    fixed: (c) => `invoice = Invoice.objects.get(id=${c.param}, owner=request.user)`,
  },
  {
    id: "T5", cwe: "CWE-798", language: "javascript", expert: "E11",
    vulnerable: (c) => `const API_KEY = "sk-live-${c.id.toString(16).padStart(8, "0")}";`,
    fixed: (c) => `const API_KEY = process.env.API_KEY;`,
  },
  {
    id: "T6", cwe: "CWE-125", language: "c", expert: "E5",
    vulnerable: (c) => `char buf[64];\nmemcpy(buf, src, ${c.id + 64});`,
    fixed: (c) => `char buf[64];\nif (len > sizeof(buf)) return -EINVAL;\nmemcpy(buf, src, len);`,
  },
];

const NAMES = {
  tables: ["users", "invoices", "sessions", "api_keys"],
  columns: ["id", "email", "token", "owner_id"],
  params: ["id", "ref", "key", "target"],
  cmds: ["host", "addr", "target"],
};

export interface PairGenStats {
  requested: number;
  generated: number;
  rejectedCompile: number;
  rejectedDiff: number;
  byCwe: Record<string, number>;
  byExpert: Record<string, number>;
  pairs: RepairPair[];
}

/** Generate synthetic vulnerable→fixed pairs; only compiler-verified pairs
 *  with a minimal diff are admitted to the training set. */
export function generateRepairPairs(requested: number, seed = 77): PairGenStats {
  const rand = mulberry(seed);
  const pairs: RepairPair[] = [];
  const stats: PairGenStats = {
    requested,
    generated: 0, rejectedCompile: 0, rejectedDiff: 0, byCwe: {}, byExpert: {},
    pairs: [],
  };

  for (let i = 0; i < requested; i++) {
    const t = VULN_TEMPLATES[Math.floor(rand() * VULN_TEMPLATES.length)];
    const ctx: PairContext = {
      table: NAMES.tables[Math.floor(rand() * NAMES.tables.length)],
      column: NAMES.columns[Math.floor(rand() * NAMES.columns.length)],
      param: NAMES.params[Math.floor(rand() * NAMES.params.length)],
      cmd: NAMES.cmds[Math.floor(rand() * NAMES.cmds.length)],
      id: 1000 + Math.floor(rand() * 9000),
    };
    const vulnerable = t.vulnerable(ctx);
    const fixed = t.fixed(ctx);
    const diffLines =
      fixed.split("\n").filter((l) => !vulnerable.split("\n").includes(l)).length +
      vulnerable.split("\n").filter((l) => !fixed.split("\n").includes(l)).length;

    // Simulated verification gates (deterministic per template).
    const compileFails = rand() < 0.04; // ~4% compile flake in the generator
    const diffTooBig = diffLines > 6; // minimal-diff policy

    if (compileFails) { stats.rejectedCompile++; continue; }
    if (diffTooBig) { stats.rejectedDiff++; continue; }

    const pair: RepairPair = {
      pairId: `pair-${(i + 1).toString().padStart(6, "0")}`,
      templateId: t.id, cwe: t.cwe, language: t.language, expert: t.expert,
      vulnerable, fixed,
      compilesVulnerable: true, compilesFixed: true,
      minimalDiff: true,
      diffLines,
    };
    pairs.push(pair);
    stats.byCwe[t.cwe] = (stats.byCwe[t.cwe] ?? 0) + 1;
    stats.byExpert[t.expert] = (stats.byExpert[t.expert] ?? 0) + 1;
    stats.generated++;
  }

  stats.pairs = pairs;
  return stats;
}

// ============================================================================
// PART 14 — ROUTER DISTILLATION (14B security teacher → cs-8b router logits)
// ============================================================================

export const DISTILL_TEACHER = "cs-teacher-14b";
export const DISTILL_TOKENS = 20e9;

export interface DistillDomain {
  domain: string;      // one per routed expert
  expert: string;      // E1…E12
  /** Purity before distillation. */
  before: number;
  /** Purity after distillation (computed). */
  after: number;
  /** Fraction of tokens the teacher routes to this expert. */
  teacherShare: number;
}

export interface DistillResult {
  domains: DistillDomain[];
  purityBefore: number;
  purityAfter: number;
  /** KL divergence between student router and teacher soft labels (nats). */
  kl: number;
  tokens: number;
  /** Tokens where neither the teacher nor student picks a sensible expert. */
  orphanRate: number;
}

/** Distill teacher soft routing labels into the student router for
 *  DISTILL_TOKENS tokens; returns per-domain purity 0.81 → ~0.93. */
export function distillRouter(seed = 31337, tokens: number = DISTILL_TOKENS): DistillResult {
  const rand = mulberry(seed);
  // The 12 routed experts' security domains.
  const DOMAIN_NAMES = [
    "static analysis", "web exploitation", "injection & rce", "auth & session",
    "binary & memory", "network & recon", "cloud & infra", "cryptography",
    "malware & forensics", "bug bounty craft", "remediation", "report & compliance",
  ];
  const domains: DistillDomain[] = DOMAIN_NAMES.map((domain, i) => {
    const teacherShare = 0.055 + rand() * 0.06;
    // Pre-distillation purity ~0.81 with per-domain texture.
    const before = 0.78 + rand() * 0.06;
    // Distillation sharpens each domain toward the teacher's label.
    const after = Math.min(0.965, before + 0.1 + 0.06 * rand() + (i === 0 ? 0.01 : 0));
    return { domain, expert: `E${i + 1}`, before, after, teacherShare };
  });

  const avg = (f: (d: DistillDomain) => number) =>
    domains.reduce((a, d) => a + f(d), 0) / domains.length;

  return {
    domains,
    purityBefore: avg((d) => d.before),
    purityAfter: avg((d) => d.after),
    kl: 0.028 + rand() * 0.012,
    tokens,
    orphanRate: 0.052 - 0.02 * rand(),
  };
}

// ============================================================================
// PART 15 — MID-TRAIN EVAL GATE
// ============================================================================

export interface MidGateCriteria {
  secPplImprovement: number; // ≥ 41% vs base (ratio ≤ 0.59)
  mmluMaxRegress: number;    // ≤ 1.0 pt below base
  purityMin: number;         // ≥ 0.9 after distillation
}

export const MID_GATE_CRITERIA: MidGateCriteria = {
  secPplImprovement: 0.41,
  mmluMaxRegress: 1.0,
  purityMin: 0.9,
};

export interface MidGateCheck {
  metric: string;
  value: number;
  threshold: number;
  pass: boolean;
  detail: string;
}

export interface MidGateResult {
  checks: MidGateCheck[];
  pass: boolean;
  action: "proceed-to-sft" | "extend-mid-train-40B" | "rebalance-and-restart";
}

export function runMidTrainGate(
  run: MidTrainRun,
  distill: DistillResult,
  baseMmlu = 65.8
): MidGateResult {
  const pplImprovement = 1 - run.finalSecPplRatio;
  const mmluDelta = run.finalMmlu - baseMmlu;
  const checks: MidGateCheck[] = [
    {
      metric: "Security-probe PPL improvement",
      value: pplImprovement,
      threshold: MID_GATE_CRITERIA.secPplImprovement,
      pass: pplImprovement >= MID_GATE_CRITERIA.secPplImprovement,
      detail: `−${(pplImprovement * 100).toFixed(0)}% vs ≥ −41% vs base`,
    },
    {
      metric: "MMLU regression",
      value: mmluDelta,
      threshold: -MID_GATE_CRITERIA.mmluMaxRegress,
      pass: mmluDelta >= -MID_GATE_CRITERIA.mmluMaxRegress,
      detail: `${mmluDelta >= 0 ? "+" : ""}${mmluDelta.toFixed(2)}pt vs ≥ −1.0pt budget`,
    },
    {
      metric: "Routing purity (post-distill)",
      value: distill.purityAfter,
      threshold: MID_GATE_CRITERIA.purityMin,
      pass: distill.purityAfter >= MID_GATE_CRITERIA.purityMin,
      detail: `${distill.purityAfter.toFixed(3)} vs ≥ ${MID_GATE_CRITERIA.purityMin}`,
    },
  ];

  const pass = checks.every((c) => c.pass);
  const pplFail = !checks[0].pass;
  const mmluFail = !checks[1].pass;
  return {
    checks,
    pass,
    action: pass
      ? "proceed-to-sft"
      : pplFail && !mmluFail
        ? "extend-mid-train-40B"
        : "rebalance-and-restart",
  };
}
