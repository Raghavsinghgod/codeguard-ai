// CrackScope-8B — Pretraining phase (Parts 6–10) as working in-app modules.
//
// Part 6  Data mix v1          → MixPlanner
// Part 7  Pretrain run sim     → simulatePretrain  (uses Phase 4's scaling fit!)
// Part 8  Mid-run eval gate    → runEvalGate
// Part 9  Long-context YaRN    → runNeedleMatrix
// Part 10 Checkpoint manifest  → buildCheckpointManifest + resume drill
//
// The Part 7 simulator calls the Chinchilla fit from lib/foundation.ts so the
// loss curve here is consistent with the probes fitted in Phase 1.

import { fitScalingLaw, PROBE_GRID } from "@/lib/foundation";

// ============================================================================
// PART 6 — DATA MIX v1 (1.4T general/code + 0.4T security slices)
// ============================================================================

export interface MixSlice {
  id: string;
  name: string;
  /** Share of the total 1.8T mix (0–1). */
  share: number;
  /** Probe perplexity on this slice from the Phase 4 pilot runs (lower = better). */
  pilotPpl: number;
  kind: "general" | "code" | "security";
  /** Locked reference share from the plan. */
  lockedShare: number;
}

/** The locked mix from the plan. Shares add to 1.0. */
export const LOCKED_MIX: MixSlice[] = [
  { id: "M1", name: "Filtered web (FineWeb-Edu class)", share: 0.42, pilotPpl: 2.71, kind: "general", lockedShare: 0.42 },
  { id: "M2", name: "The Stack v2 (permissive code)", share: 0.28, pilotPpl: 2.44, kind: "code", lockedShare: 0.28 },
  { id: "M3", name: "GitHub issues / PRs / docs", share: 0.08, pilotPpl: 2.52, kind: "code", lockedShare: 0.08 },
  { id: "M4", name: "Math & science (Dolma-class)", share: 0.05, pilotPpl: 2.83, kind: "general", lockedShare: 0.05 },
  { id: "M5", name: "SEC-Web security crawl", share: 0.09, pilotPpl: 2.31, kind: "security", lockedShare: 0.09 },
  { id: "M6", name: "CTF & advisory archives", share: 0.05, pilotPpl: 2.36, kind: "security", lockedShare: 0.05 },
  { id: "M7", name: "Bounty reports corpus", share: 0.02, pilotPpl: 2.4, kind: "security", lockedShare: 0.02 },
  { id: "M8", name: "General anchor replay", share: 0.01, pilotPpl: 2.66, kind: "general", lockedShare: 0.01 },
];

export const TOTAL_PRETRAIN_TOKENS = 1.8e12;

export interface MixAssessment {
  /** Weighted probe perplexity of the mix (lower is better). */
  weightedPpl: number;
  /** Security token share (plan target: ≥0.15). */
  securityShare: number;
  /** Anchor replay share (mid-train requires C8 ≥ 8% later; pretrain keeps ≥1%). */
  anchorShare: number;
  warnings: string[];
  /** 0–100 mix quality score used by the eval gate. */
  quality: number;
  tokens: Array<{ id: string; name: string; tokens: number }>;
}

/** Evaluate a perturbed mix (shares are normalized before scoring). */
export function assessMix(slices: MixSlice[]): MixAssessment {
  const total = slices.reduce((a, s) => a + s.share, 0) || 1;
  const norm = slices.map((s) => ({ ...s, share: s.share / total }));
  const weightedPpl = norm.reduce((a, s) => a + s.share * s.pilotPpl, 0);
  const securityShare = norm.filter((s) => s.kind === "security").reduce((a, s) => a + s.share, 0);
  const anchorShare = norm.filter((s) => s.id === "M8").reduce((a, s) => a + s.share, 0);
  const codeShare = norm.filter((s) => s.kind === "code").reduce((a, s) => a + s.share, 0);

  const warnings: string[] = [];
  if (securityShare < 0.15) warnings.push(`security share ${(securityShare * 100).toFixed(1)}% < 15% floor — security-probe PPL will regress`);
  if (anchorShare < 0.01) warnings.push("anchor replay below 1% — catastrophic-forgetting risk in mid-train");
  if (codeShare < 0.25) warnings.push(`code share ${(codeShare * 100).toFixed(1)}% < 25% — HumanEval gate at risk`);
  if (weightedPpl > 2.62) warnings.push(`weighted probe PPL ${weightedPpl.toFixed(3)} worse than locked mix (2.600)`);

  // Quality: 100 at locked mix; penalize PPL drift and floor violations.
  const pplPenalty = Math.max(0, (weightedPpl - 2.6) * 220);
  const floorPenalty = warnings.length * 9;
  const quality = Math.max(0, Math.min(100, 100 - pplPenalty - floorPenalty));

  return {
    weightedPpl,
    securityShare,
    anchorShare,
    warnings,
    quality,
    tokens: norm.map((s) => ({
      id: s.id,
      name: s.name,
      tokens: Math.round(s.share * TOTAL_PRETRAIN_TOKENS),
    })),
  };
}

// ============================================================================
// PART 7 — PRETRAIN RUN SIMULATOR (1,024×H100, loss from the fitted law)
// ============================================================================

export interface PretrainConfig {
  totalTokens: number;       // 1.8e12
  batchTokensPerStep: number;// 8M (from Phase 1 scaling probes)
  gpus: number;              // 1024 H100s
  mfu: number;               // model FLOPs utilization
  activeParams: number;      // 1.9e9 active per token
  auxStartStep: number;      // router aux losses active from step 2k
}

export const PRETRAIN_CONFIG: PretrainConfig = {
  totalTokens: TOTAL_PRETRAIN_TOKENS,
  batchTokensPerStep: 8e6,
  gpus: 1024,
  mfu: 0.47,
  activeParams: 1.9e9,
  auxStartStep: 2000,
};

export interface RunLogEntry {
  step: number;
  tokens: number;          // cumulative tokens
  loss: number;            // Chinchilla prediction from the fitted probes
  mmlu: number;            // interpolated eval estimate
  humanEval: number;
  secPplRatio: number;     // vs dense baseline
  tokPerSecPerGpu: number;
  etaDays: number;         // remaining
}

export interface PretrainRun {
  log: RunLogEntry[];
  totalSteps: number;
  stepSeconds: number;
  etaDaysTotal: number;
  finalLoss: number;
  flopsPerToken: number;
  clusterFlops: number;
  /** Router aux-loss activation step on the timeline. */
  auxStartStep: number;
}

/** Model-FLOPs per token ≈ 6·N_active (attention + MoE FFN, standard est.). */
export function simulatePretrain(cfg: PretrainConfig = PRETRAIN_CONFIG): PretrainRun {
  const flopsPerToken = 6 * cfg.activeParams;
  const clusterFlops = cfg.gpus * cfg.mfu * 989e12; // H100 SXM bf16 dense peak
  const tokPerSec = clusterFlops / flopsPerToken;
  const stepSeconds = (cfg.batchTokensPerStep * flopsPerToken) / clusterFlops;
  const totalSteps = Math.round(cfg.totalTokens / cfg.batchTokensPerStep);
  const etaDaysTotal = (cfg.totalTokens * flopsPerToken) / (clusterFlops * 86400);

  // Consistent scaling law: refit the Phase 1 probe grid (pure function).
  const fit = fitScalingLaw(PROBE_GRID);

  // Sample the run every ~0.1T tokens.
  const sampleEvery = 0.1e12 / cfg.batchTokensPerStep;
  const log: RunLogEntry[] = [];
  for (let step = 1; step <= totalSteps; step++) {
    const tokens = step * cfg.batchTokensPerStep;
    const isSample = step === 1 || step === totalSteps || step % Math.round(sampleEvery) === 0;
    if (!isSample) continue;
    const progress = tokens / cfg.totalTokens;
    // D-term scaling with a small mid-train-consistent correction:
    // add a mild schedule penalty early (warmup) and reward the locked mix.
    const base = fit.predict(cfg.activeParams, tokens);
    const warmupPenalty = progress < 0.02 ? 0.35 * (1 - progress / 0.02) : 0;
    const loss = base + warmupPenalty;
    // Eval estimates as smooth saturating curves of D.
    const dRel = Math.log10(tokens / 1e9) / Math.log10(cfg.totalTokens / 1e9);
    const mmlu = 38 + 30 * Math.pow(dRel, 0.55) - 2 * warmupPenalty;
    const humanEval = 8 + 34 * Math.pow(dRel, 0.7) - 3 * warmupPenalty;
    const secPplRatio = 1.3 - 0.16 * Math.pow(dRel, 0.6);
    log.push({
      step,
      tokens,
      loss,
      mmlu: Math.max(20, Math.min(70, mmlu)),
      humanEval: Math.max(0, Math.min(45, humanEval)),
      secPplRatio: Math.max(1.05, secPplRatio),
      tokPerSecPerGpu: tokPerSec / cfg.gpus,
      etaDays: (cfg.totalTokens - tokens) * flopsPerToken / (clusterFlops * 86400),
    });
  }

  return {
    log,
    totalSteps,
    stepSeconds,
    etaDaysTotal,
    finalLoss: log[log.length - 1].loss,
    flopsPerToken,
    clusterFlops,
    auxStartStep: cfg.auxStartStep,
  };
}

// ============================================================================
// PART 8 — MID-RUN EVAL GATE (at 0.9T tokens)
// ============================================================================

export interface GateCriteria {
  mmlu: number;        // ≥ 66
  humanEval: number;   // ≥ 38
  secPplMax: number;   // ≤ 1.15× dense baseline
}

export const GATE_CRITERIA: GateCriteria = { mmlu: 66, humanEval: 38, secPplMax: 1.15 };

export interface GateCheck {
  metric: "MMLU" | "HumanEval" | "Security-probe PPL ratio";
  value: number;
  threshold: number;
  pass: boolean;
  detail: string;
}

export interface GateResult {
  atTokens: number;
  checks: GateCheck[];
  pass: boolean;
  /** Branch action if failed. */
  action: "proceed" | "remix-and-branch";
  /** Loss delta expected after a remix-and-branch restart. */
  remixGain: number;
}

/** Evaluate the gate at `atTokens` given a mix quality from Part 6. */
export function runEvalGate(run: PretrainRun, mixQuality: number, atTokens = 0.9e12): GateResult {
  // Nearest logged sample at or before the gate point.
  const sample = [...run.log].reverse().find((e) => e.tokens <= atTokens) ?? run.log[0];
  // Mix quality shifts evals: quality 100 → nominal; each point below costs.
  const q = (mixQuality - 100) / 100; // ≤ 0
  const mmlu = sample.mmlu + q * 26;
  const humanEval = sample.humanEval + q * 22;
  const secPplRatio = sample.secPplRatio + Math.abs(q) * 0.22;

  const checks: GateCheck[] = [
    {
      metric: "MMLU",
      value: mmlu,
      threshold: GATE_CRITERIA.mmlu,
      pass: mmlu >= GATE_CRITERIA.mmlu,
      detail: `${mmlu.toFixed(1)} vs ≥ ${GATE_CRITERIA.mmlu}`,
    },
    {
      metric: "HumanEval",
      value: humanEval,
      threshold: GATE_CRITERIA.humanEval,
      pass: humanEval >= GATE_CRITERIA.humanEval,
      detail: `${humanEval.toFixed(1)} vs ≥ ${GATE_CRITERIA.humanEval}`,
    },
    {
      metric: "Security-probe PPL ratio",
      value: secPplRatio,
      threshold: GATE_CRITERIA.secPplMax,
      pass: secPplRatio <= GATE_CRITERIA.secPplMax,
      detail: `${secPplRatio.toFixed(3)}× vs ≤ ${GATE_CRITERIA.secPplMax}× dense`,
    },
  ];

  const pass = checks.every((c) => c.pass);
  return {
    atTokens,
    checks,
    pass,
    action: pass ? "proceed" : "remix-and-branch",
    remixGain: pass ? 0 : 0.04 + (1 - mixQuality / 100) * 0.1,
  };
}

// ============================================================================
// PART 9 — LONG-CONTEXT EXTENSION (RoPE θ bump + 32k YaRN stage, 40B tokens)
// ============================================================================

export interface YarnConfig {
  baseContext: number;      // 8192 pretrain context
  targetContext: number;    // 32768
  ropeThetaBase: number;    // 10000
  ropeThetaScaled: number;  // 160000 (θ bump)
  yarnFactor: number;       // scale factor s = 4
  extensionTokens: number;  // 40e9
  attentionTemperature: number; // 1/√(1+0.1·ln s) style correction
}

export const YARN_CONFIG: YarnConfig = {
  baseContext: 8192,
  targetContext: 32768,
  ropeThetaBase: 10000,
  ropeThetaScaled: 160000,
  yarnFactor: 4,
  extensionTokens: 40e9,
  attentionTemperature: 0.9, // ≈ 1/sqrt(1+0.1·ln 4)
};

export interface NeedleCell {
  /** Depth percentile of the needle in the context (0–1). */
  depth: number;
  /** Context length of this row. */
  context: number;
  /** Retrieval accuracy 0–1. */
  accuracy: number;
}

export interface YarnResult {
  cells: NeedleCell[];
  /** Aggregate accuracy at each context length. */
  byContext: Array<{ context: number; accuracy: number; pass: boolean }>;
  overallAt32k: number;
  gatePass: boolean; // ≥ 98% @ 32k
  perplexityAt32k: number;
  rows: number[];
  cols: number[];
}

/** Simulate needle-in-a-haystack retrieval across depth × context. */
export function runNeedleMatrix(cfg: YarnConfig = YARN_CONFIG, seed = 4242): YarnResult {
  // xorshift for reproducible texture on the matrix.
  let s = seed | 0 || 1;
  const rand = () => {
    s ^= s << 13; s ^= s >>> 17; s ^= s << 5;
    return ((s >>> 0) % 1000) / 1000;
  };

  const rows = [8192, 16384, 24576, 32768];
  const cols = [0.05, 0.2, 0.4, 0.6, 0.8, 0.95];
  const cells: NeedleCell[] = [];

  for (const context of rows) {
    for (const depth of cols) {
      // Difficulty grows with context length and at extreme depths.
      const ctxStress = (context - cfg.baseContext) / (cfg.targetContext - cfg.baseContext); // 0–1
      const edge = Math.min(depth, 1 - depth) * 2; // 0 at edges, 1 mid
      const baseAcc = 0.995 - 0.02 * ctxStress * (1 - 0.5 * edge) - 0.008 * (1 - edge);
      const accuracy = Math.max(0.9, Math.min(1, baseAcc + 0.006 * (rand() - 0.5)));
      cells.push({ depth, context, accuracy });
    }
  }

  const byContext = rows.map((context) => {
    const accs = cells.filter((c) => c.context === context).map((c) => c.accuracy);
    const accuracy = accs.reduce((a, b) => a + b, 0) / accs.length;
    return { context, accuracy, pass: accuracy >= 0.98 };
  });

  const at32k = byContext[byContext.length - 1].accuracy;
  // Post-extension PPL at 32k vs 8k baseline: YaRN keeps it under +6%.
  const perplexityAt32k = 1.035 + 0.01 * (rand() - 0.5);

  return {
    cells,
    byContext,
    overallAt32k: at32k,
    gatePass: at32k >= 0.98,
    perplexityAt32k,
    rows,
    cols,
  };
}

// ============================================================================
// PART 10 — CHECKPOINT MANIFEST & RESUME DRILL
// ============================================================================

export const CHECKPOINT_EVERY_TOKENS = 0.15e12;

export interface Checkpoint {
  id: string;
  step: number;
  tokens: number;
  loss: number;
  /** Bytes on storage (weights bf16 + AdamW moments fp32 + router states). */
  bytes: number;
  kind: "rolling" | "milestone";
}

export interface ManifestResult {
  checkpoints: Checkpoint[];
  bytesPerCheckpoint: number;
  totalBytes: number;
  /** Retention policy: keep last K rolling + all milestones (every 0.6T). */
  retainedBytes: number;
  retainedCount: number;
}

/** bf16 weights 2 B/param + fp32 master 4 + two AdamW moments 8 = 14 B/param,
 *  plus router/gate states and dataloader bookmarks (≈0.4 GB overhead). */
export function buildCheckpointManifest(run: PretrainConfig = PRETRAIN_CONFIG): ManifestResult {
  const bytesPerParam = 14;
  const bytesPerCheckpoint = Math.round(run.activeParams * bytesPerParam + 0.4e9);
  const fit = fitScalingLaw(PROBE_GRID);

  const checkpoints: Checkpoint[] = [];
  const totalSteps = Math.round(run.totalTokens / run.batchTokensPerStep);
  const ckptEverySteps = Math.round(CHECKPOINT_EVERY_TOKENS / run.batchTokensPerStep);
  for (let step = ckptEverySteps; step <= totalSteps; step += ckptEverySteps) {
    const tokens = step * run.batchTokensPerStep;
    const milestone = Math.round(tokens / (0.6e12)) * 0.6e12 === tokens;
    checkpoints.push({
      id: `ckpt-${checkpoints.length + 1}`,
      step,
      tokens,
      loss: fit.predict(run.activeParams, tokens),
      bytes: bytesPerCheckpoint,
      kind: milestone ? "milestone" : "rolling",
    });
  }

  const milestones = checkpoints.filter((c) => c.kind === "milestone");
  const rollingKeep = 3;
  const rolling = checkpoints.filter((c) => c.kind === "rolling").slice(-rollingKeep);
  const retained = [...milestones, ...rolling].sort((a, b) => a.tokens - b.tokens);

  return {
    checkpoints,
    bytesPerCheckpoint,
    totalBytes: bytesPerCheckpoint * checkpoints.length,
    retainedBytes: bytesPerCheckpoint * retained.length,
    retainedCount: retained.length,
  };
}

export interface ResumeDrill {
  preemptedAtTokens: number;
  resumedFromTokens: number;
  lostTokens: number;
  lostSteps: number;
  /** Effective throughput after restart (ramp-up loss of ~1 step). */
  rampUpSteps: number;
  resumedLoss: number;
  verdict: string;
}

/** Simulate a mid-run preemption (spot-node loss) and resume from the latest checkpoint. */
export function runResumeDrill(manifest: ManifestResult, cfg: PretrainConfig = PRETRAIN_CONFIG, seed = 909): ResumeDrill {
  let s = seed | 0 || 1;
  const rand = () => {
    s ^= s << 13; s ^= s >>> 17; s ^= s << 5;
    return ((s >>> 0) % 1000) / 1000;
  };
  const last = manifest.checkpoints[manifest.checkpoints.length - 1];
  const preemptedAtTokens = Math.min(cfg.totalTokens, last.tokens + rand() * CHECKPOINT_EVERY_TOKENS * 0.95);
  const resumedFromTokens = last.tokens;
  const lostTokens = preemptedAtTokens - resumedFromTokens;
  const lostSteps = Math.round(lostTokens / cfg.batchTokensPerStep);
  const fit = fitScalingLaw(PROBE_GRID);
  return {
    preemptedAtTokens,
    resumedFromTokens,
    lostTokens,
    lostSteps,
    rampUpSteps: 1,
    resumedLoss: fit.predict(cfg.activeParams, resumedFromTokens) + 0.012,
    verdict:
      lostSteps === 0
        ? "preemption landed on a checkpoint boundary — zero loss"
        : `resumed from ckpt at ${(resumedFromTokens / 1e12).toFixed(2)}T; re-did ${lostSteps} steps (${(lostTokens / 1e9).toFixed(1)}B tokens)`,
  };
}
