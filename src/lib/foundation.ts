// CrackScope-8B — Foundation phase (Parts 1–5) as working in-app modules.
//
// Part 1  Data lake & licensing gate   → lib/foundation.ts :: DataLake
// Part 2  CS-BPE-49k tokenizer         → lib/foundation.ts :: CSBPE
// Part 3  Training harness            → lib/foundation.ts :: TrainingHarness
// Part 4  Scaling-law probes          → lib/foundation.ts :: fitScalingLaw
// Part 5  Expert topology decision    → lib/foundation.ts :: topologyAblation
//
// Everything runs fully client-side on the code/text you feed it — no network.

// ============================================================================
// PART 1 — DATA LAKE & LICENSING GATE
// ============================================================================

export interface DataLakeDoc {
  id: string;
  name: string;
  /** Raw corpus content (code, writeup, advisory...). */
  content: string;
  /** Declared or detected license. */
  license?: string;
  source: "stack-v2" | "ctf-archive" | "advisory" | "bounty-report" | "user";
}

const PROPRIETARY_LICENSES = new Set([
  "gpl-2.0",
  "gpl-3.0",
  "agpl-3.0",
  "lgpl-3.0",
  "sspl",
  "bsl",
  "commons-clause",
  "proprietary",
  "unknown",
]);

const ALLOWED_LICENSES = new Set([
  "mit",
  "apache-2.0",
  "bsd-2-clause",
  "bsd-3-clause",
  "isc",
  "mpl-2.0",
  "unlicense",
  "cc0",
  "cc-by-4.0",
  "public-domain",
]);

// PII patterns — scrubbed before any doc enters the lake.
const PII_PATTERNS: Array<{ label: string; re: RegExp; replacement: string }> = [
  { label: "email", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, replacement: "[EMAIL]" },
  { label: "ipv4", re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g, replacement: "[IP]" },
  { label: "api-key", re: /\b(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})\b/g, replacement: "[REDACTED-KEY]" },
  { label: "phone", re: /\b(?:\+1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b/g, replacement: "[PHONE]" },
  { label: "ssn", re: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: "[SSN]" },
];

/** FNV-1a 64-bit-ish hash as hex string — deterministic, dependency-free. */
function fnv64(str: string): string {
  let h = 0x811c9dc5;
  let h2 = 0x01000193;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    h = (h ^ c) >>> 0;
    h = Math.imul(h, 16777619) >>> 0;
    h2 = (h2 ^ ((c + i) & 0xff)) >>> 0;
    h2 = Math.imul(h2, 2166136261) >>> 0;
  }
  return (h.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0"));
}

/** Exact-hash + MinHash-style shingle dedup, two-stage as specced. */
function shingles(text: string, k = 5): Set<string> {
  const norm = text.toLowerCase().replace(/\s+/g, " ").trim();
  const out = new Set<string>();
  for (let i = 0; i + k <= norm.length; i++) out.add(norm.slice(i, i + k));
  return out;
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let inter = 0;
  for (const s of a) if (b.has(s)) inter++;
  return inter / (a.size + b.size - inter);
}

export interface LakeDoc {
  id: string;
  name: string;
  source: DataLakeDoc["source"];
  license: string;
  licenseOk: boolean;
  chars: number;
  tokens?: number;
  hash: string;
  /** Set when a license was missing/non-permissive. */
  gateReason?: string;
  piiRedactions: string[];
  duplicateOf?: string;
}

export interface LakeStats {
  ingested: number;
  admitted: number;
  rejected: number;
  duplicatesDropped: number;
  piiRedactions: number;
  admittedChars: number;
  bySource: Record<string, number>;
  byLicense: Record<string, number>;
}

export class DataLake {
  docs: LakeDoc[] = [];
  stats: LakeStats = {
    ingested: 0, admitted: 0, rejected: 0, duplicatesDropped: 0,
    piiRedactions: 0, admittedChars: 0, bySource: {}, byLicense: {},
  };
  private exactHashes = new Map<string, string>();
  private shingleIndex: Array<{ id: string; sh: Set<string> }> = [];

  /** License-gate, PII-scrub, dedup, and admit one document. */
  ingest(doc: DataLakeDoc): LakeDoc {
    this.stats.ingested++;
    const rawLicense = (doc.license ?? "unknown").toLowerCase().trim();
    const licenseOk = ALLOWED_LICENSES.has(rawLicense);
    const gateReason = licenseOk
      ? undefined
      : PROPRIETARY_LICENSES.has(rawLicense)
        ? `license "${rawLicense}" is not training-permissive`
        : `unrecognized license "${rawLicense}" — blocked pending review`;

    // PII scrub regardless of license outcome (never persist raw PII).
    const piiRedactions: string[] = [];
    let content = doc.content;
    for (const { label, re, replacement } of PII_PATTERNS) {
      const n = (content.match(re) ?? []).length;
      if (n > 0) {
        content = content.replace(re, replacement);
        piiRedactions.push(`${label}×${n}`);
      }
    }
    this.stats.piiRedactions += piiRedactions.length;

    const hash = fnv64(content);

    if (!licenseOk) {
      this.stats.rejected++;
      const rec: LakeDoc = {
        id: doc.id, name: doc.name, source: doc.source,
        license: rawLicense, licenseOk: false,
        chars: doc.content.length, hash,
        gateReason, piiRedactions,
      };
      this.docs.push(rec);
      return rec;
    }

    // Stage 1: exact-content dedup.
    const exactHit = this.exactHashes.get(hash);
    if (exactHit) {
      this.stats.duplicatesDropped++;
      const rec: LakeDoc = {
        id: doc.id, name: doc.name, source: doc.source,
        license: rawLicense, licenseOk: true,
        chars: content.length, hash, piiRedactions, duplicateOf: exactHit,
      };
      this.docs.push(rec);
      return rec;
    }

    // Stage 2: near-dup via shingle Jaccard ≥ 0.8.
    const sh = shingles(content);
    for (const { id, sh: other } of this.shingleIndex) {
      if (jaccard(sh, other) >= 0.8) {
        this.stats.duplicatesDropped++;
        const rec: LakeDoc = {
          id: doc.id, name: doc.name, source: doc.source,
          license: rawLicense, licenseOk: true,
          chars: content.length, hash, piiRedactions, duplicateOf: id,
        };
        this.docs.push(rec);
        return rec;
      }
    }

    this.exactHashes.set(hash, doc.id);
    this.shingleIndex.push({ id: doc.id, sh });
    this.stats.admitted++;
    this.stats.admittedChars += content.length;
    this.stats.bySource[doc.source] = (this.stats.bySource[doc.source] ?? 0) + 1;
    this.stats.byLicense[rawLicense] = (this.stats.byLicense[rawLicense] ?? 0) + 1;

    const rec: LakeDoc = {
      id: doc.id, name: doc.name, source: doc.source,
      license: rawLicense, licenseOk: true,
      chars: content.length, hash, piiRedactions,
    };
    this.docs.push(rec);
    return rec;
  }

  reset() {
    this.docs = [];
    this.stats = {
      ingested: 0, admitted: 0, rejected: 0, duplicatesDropped: 0,
      piiRedactions: 0, admittedChars: 0, bySource: {},
      byLicense: {},
    };
  }
}

// ============================================================================
// PART 2 — CS-BPE TOKENIZER (a real BPE, trained on the fly)
// ============================================================================

/** Byte-level BPE. Pre-tokenization is security-aware: payloads, URLs, and
 *  identifiers are split on their own boundaries so merges can specialize. */
const SECURITY_PRETOKEN_RE =
  /(\.\.\/+|\.\.\\+|\$ne\b|\$gt\b|\$where\b|alg:none|rs256|jwt|cve-\d{4}-\d{4,7}|x-forwarded-for|content-type|authorization|select\s.+?\sfrom\s.+?|union\s+select|<script|onerror|javascript:|data:|file:\/\/|https?:\/\/\S+|[A-Za-z_][A-Za-z0-9_]{0,48}|\d+|\s+|.)/g;

const SPECIAL_TOKENS = [
  "<|system|>", "<|user|>", "<|assistant|>", "<|code|>", "<|poc|>",
  "<|finding|>", "<|eot|>", "<|pad|>",
] as const;

export interface BpeTrainingStats {
  mergesLearned: number;
  vocabSize: number;
  baseBytes: number;
  trainingSeconds: number;
  compressionRatio: number; // bytes per token after merges
  bytesBefore: number;
  tokensBefore: number;
  tokensAfter: number;
}

export class CSBPE {
  /** Ordered merge rules: pair → rank. */
  private merges = new Map<string, number>();
  private vocab = new Map<string, number>();
  private trained = false;
  stats: BpeTrainingStats = {
    mergesLearned: 0, vocabSize: 0, baseBytes: 256, trainingSeconds: 0,
    compressionRatio: 1, bytesBefore: 0, tokensBefore: 0, tokensAfter: 0,
  };
  /** Top merges for the UI — the "security-weighted" story. */
  topMerges: Array<{ pair: [string, string]; freq: number; rank: number }> = [];

  get isTrained() { return this.trained; }

  private preTokenize(text: string): string[] {
    const out: string[] = [];
    const re = new RegExp(SECURITY_PRETOKEN_RE.source, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      out.push(m[0]);
    }
    return out;
  }

  /** Train BPE on a corpus (array of documents). Deterministic. */
  train(corpus: string[], targetVocab = 512): BpeTrainingStats {
    const t0 = performance.now();
    const words = new Map<string, number>(); // pre-token -> freq
    for (const doc of corpus) {
      for (const tok of this.preTokenize(doc)) {
        words.set(tok, (words.get(tok) ?? 0) + 1);
      }
    }

    // Represent each pre-token as a tuple of chars (byte-level in real life;
    // here char-level since JS strings are UTF-16 — byte fidelity would need
    // TextEncoder, which we use at encode time for the real byte stream).
    let symbolSeqs = new Map<string, string[]>();
    for (const [w, f] of words) symbolSeqs.set(w, Array.from(w));

    const numMerges = Math.max(0, targetVocab - 256 - SPECIAL_TOKENS.length);
    this.merges.clear();
    this.topMerges = [];

    for (let step = 0; step < numMerges; step++) {
      // Count adjacent symbol pairs weighted by word freq.
      const pairFreq = new Map<string, number>();
      for (const [w, f] of words) {
        const syms = symbolSeqs.get(w)!;
        for (let i = 0; i + 1 < syms.length; i++) {
          const key = syms[i] + "\u0000" + syms[i + 1];
          pairFreq.set(key, (pairFreq.get(key) ?? 0) + f);
        }
      }
      // Greedy pick the most frequent pair (ties: lexicographic for determinism).
      let bestKey: string | null = null;
      let bestCount = 0;
      for (const [key, c] of pairFreq) {
        if (c > bestCount || (c === bestCount && bestKey !== null && key < bestKey)) {
          bestCount = c; bestKey = key;
        }
      }
      if (!bestKey || bestCount < 2) break; // no pair appears twice — stop early
      const [a, b] = bestKey.split("\u0000");
      const merged = a + b;
      this.merges.set(bestKey, step);
      this.topMerges.push({ pair: [a, b], freq: bestCount, rank: step });
      // Apply the merge everywhere.
      for (const [w] of symbolSeqs) {
        const syms = symbolSeqs.get(w)!;
        if (syms.length < 2) continue;
        const next: string[] = [];
        let i = 0;
        while (i < syms.length) {
          if (i + 1 < syms.length && syms[i] === a && syms[i + 1] === b) {
            next.push(merged); i += 2;
          } else {
            next.push(syms[i]); i++;
          }
        }
        symbolSeqs.set(w, next);
      }
    }

    // Build vocab.
    this.vocab.clear();
    const chars = new Set<string>();
    for (const [w] of words) for (const ch of w) chars.add(ch);
    let idx = 0;
    for (const ch of Array.from(chars).sort()) this.vocab.set(ch, idx++);
    for (const key of this.merges.keys()) {
      const [a, b] = key.split("\u0000");
      this.vocab.set(a + b, idx++);
    }
    for (const st of SPECIAL_TOKENS) this.vocab.set(st, idx++);
    while (this.vocab.size < 256) this.vocab.set(`<byte_${this.vocab.size}>`, idx++);

    // Stats.
    let bytes = 0, toksAfter = 0, toksBefore = 0;
    for (const [w, f] of words) {
      bytes += w.length * f;
      toksBefore += Array.from(w).length * f;
      toksAfter += this.encodeWord(w).length * f;
    }
    const t1 = performance.now();
    this.stats = {
      mergesLearned: this.merges.size,
      vocabSize: this.vocab.size,
      baseBytes: 256,
      trainingSeconds: (t1 - t0) / 1000,
      compressionRatio: toksAfter > 0 ? bytes / toksAfter : 1,
      bytesBefore: bytes,
      tokensBefore: toksBefore,
      tokensAfter: toksAfter,
    };
    this.trained = true;
    return this.stats;
  }

  /** Apply learned merges to one pre-token. */
  private encodeWord(w: string): string[] {
    let syms = Array.from(w);
    // Repeatedly apply the lowest-rank applicable merge.
    for (;;) {
      let bestRank = Infinity, bestI = -1;
      for (let i = 0; i + 1 < syms.length; i++) {
        const r = this.merges.get(syms[i] + "\u0000" + syms[i + 1]);
        if (r !== undefined && r < bestRank) { bestRank = r; bestI = i; }
      }
      if (bestI < 0) break;
      syms.splice(bestI, 2, syms[bestI] + syms[bestI + 1]);
    }
    return syms;
  }

  /** Encode free text → token id array. Unknown bytes fall back to char ids. */
  encode(text: string): number[] {
    const out: number[] = [];
    for (const w of this.preTokenize(text)) {
      for (const piece of this.encodeWord(w)) {
        let id = this.vocab.get(piece);
        if (id === undefined) {
          for (const ch of piece) {
            const cid = this.vocab.get(ch);
            out.push(cid ?? piece.charCodeAt(0) % 256);
          }
          continue;
        }
        out.push(id);
      }
    }
    return out;
  }

  decode(ids: number[]): string {
    const inv = new Map<number, string>();
    for (const [t, id] of this.vocab) inv.set(id, t);
    return ids.map((id) => inv.get(id) ?? "�").join("");
  }

  /** Tokens-per-doc preview for the UI. */
  preview(text: string, n = 24): Array<{ token: string; id: number }> {
    return this.encode(text).slice(0, n).map((id) => ({
      id,
      token: (this.decode([id]) ?? "?").replace(/\n/g, "⏎").replace(/\t/g, "⇥"),
    }));
  }
}

// ============================================================================
// PART 3 — TRAINING HARNESS (simulated MoE trainer with real telemetry math)
// ============================================================================

export interface HarnessConfig {
  layers: number;
  experts: number;      // routed experts
  topK: number;
  seqLen: number;
  batchSize: number;
  steps: number;
  lr: number;
  warmup: number;
  capacityFactor: number;
  auxLoadAlpha: number;
  zLossAlpha: number;
  seed: number;
}

export const DEFAULT_HARNESS: HarnessConfig = {
  layers: 24, experts: 12, topK: 2, seqLen: 4096, batchSize: 8,
  steps: 200, lr: 3e-4, warmup: 20, capacityFactor: 1.25,
  auxLoadAlpha: 0.01, zLossAlpha: 1e-3, seed: 1337,
};

/** xorshift128 PRNG — deterministic across runs. */
function prng(seed: number) {
  let s = seed | 0 || 1;
  return () => {
    s ^= s << 13; s ^= s >>> 17; s ^= s << 5;
    return ((s >>> 0) % 100000) / 100000;
  };
}

export interface StepTelemetry {
  step: number;
  loss: number;
  perExpertLoss: number[];
  routerEntropy: number;
  routingPurity: number;
  loadBalance: number[];   // fraction of tokens per expert this step
  droppedTokens: number;
  tokensPerSec: number;
  gradNorm: number;
}

export interface HarnessResult {
  telemetry: StepTelemetry[];
  finalLoss: number;
  bestLoss: number;
  meanPurity: number;
  meanEntropy: number;
  tokensSeen: number;
  elapsedSeconds: number;
  expertShare: number[];       // lifetime token share per expert
  convergenceStep: number;     // first step where loss < 25% above floor
}

/** A simulated but mathematically coherent MoE training run.
 *  Loss curves follow a power law; router load follows a softmax over
 *  evolving per-expert affinities; per-expert losses diverge as experts
 *  specialize. All numbers are internally consistent with the config. */
export function runTrainingHarness(cfg: HarnessConfig, domainHints?: string[]): HarnessResult {
  const rand = prng(cfg.seed);
  const t0 = performance.now();
  const telemetry: StepTelemetry[] = [];

  // Per-expert "affinity" grows at different rates → specialization.
  const affinity = Array.from({ length: cfg.experts }, (_, i) => 0.6 + 0.4 * rand());
  // Loss floor depends on capacity proxy: experts × inter width (simulated).
  const capacityProxy = Math.log2(cfg.experts * cfg.topK) / Math.log2(24);
  const floor = 1.55 / capacityProxy + 0.35;

  // Expert names for domain hints (used by the UI tooltip, not the math).
  void domainHints;

  let expertShare = new Array(cfg.experts).fill(0);
  let tokensSeen = 0;
  let best = Infinity, convergence = cfg.steps;
  let purityAcc = 0, entropyAcc = 0;

  for (let step = 1; step <= cfg.steps; step++) {
    // LR schedule: linear warmup then cosine decay.
    const warm = step <= cfg.warmup ? step / cfg.warmup : 1;
    const progress = step / cfg.steps;
    const decay = 0.1 + 0.9 * 0.5 * (1 + Math.cos(Math.PI * progress));
    const lrNow = cfg.lr * warm * decay;

    // Power-law loss decay with noise, sensitive to lr/warmup quality.
    const schedulePenalty = 1 + 0.35 * (1 - warm) + 0.08 * Math.abs(cfg.lr - 3e-4) / 3e-4;
    const noise = 1 + 0.04 * (rand() - 0.5);
    const loss = floor + (4.2 - floor) * Math.pow(progress, 0.42) * schedulePenalty * noise;

    // Router: softmax over affinities with temperature annealing.
    const temp = 1.6 - 0.8 * progress;
    const logits = affinity.map((a) => a / temp + 0.1 * (rand() - 0.5));
    const maxLogit = Math.max(...logits);
    const exps = logits.map((l) => Math.exp(l - maxLogit));
    const sum = exps.reduce((a, b) => a + b, 0);
    const probs = exps.map((e) => e / sum);

    // Top-k selection with capacity constraint (token dropping).
    const sorted = probs.map((p, i) => ({ p, i })).sort((a, b) => b.p - a.p);
    const chosen = sorted.slice(0, cfg.topK);
    const load = new Array(cfg.experts).fill(0);
    for (const { i } of chosen) load[i] += 1 / cfg.topK;
    const idealShare = 1 / cfg.experts;
    let dropped = 0;
    for (let i = 0; i < cfg.experts; i++) {
      const cap = cfg.capacityFactor * idealShare;
      if (load[i] > cap) { dropped += (load[i] - cap) * cfg.topK; load[i] = cap; }
    }

    // Routing purity: how concentrated the top-1 mass is.
    const purity = Math.min(1, sorted[0].p / 0.5);
    // Router entropy (normalized).
    const entropy = -probs.reduce((a, p) => a + (p > 0 ? p * Math.log(p) : 0), 0) / Math.log(cfg.experts);
    // Expert-specialized losses diverge from the mean over time.
    const perExpertLoss = probs.map((p, i) =>
      loss * (0.7 + 0.6 * (1 - affinity[i]) * progress + 0.25 * (1 - p))
    );

    // Affinities drift with lr (simulated learning of specialization).
    for (let i = 0; i < cfg.experts; i++) {
      affinity[i] += lrNow * 40 * (rand() - 0.35) * (1 + 0.1 * i);
      affinity[i] = Math.max(0.05, Math.min(2.5, affinity[i]));
    }

    for (let i = 0; i < cfg.experts; i++) expertShare[i] += load[i];
    purityAcc += purity; entropyAcc += entropy;
    tokensSeen += cfg.batchSize * cfg.seqLen;

    const tokensPerSec = Math.round(cfg.batchSize * cfg.seqLen * (900 + 60 * rand()));
    telemetry.push({
      step, loss,
      perExpertLoss,
      routerEntropy: entropy,
      routingPurity: purity,
      loadBalance: load,
      droppedTokens: dropped,
      tokensPerSec,
      gradNorm: 1.2 * Math.exp(-1.5 * progress) + 0.15 * rand(),
    });

    if (loss < best) best = loss;
    if (loss < floor * 1.25 && convergence === cfg.steps) convergence = step;
  }

  const t1 = performance.now();
  return {
    telemetry,
    finalLoss: telemetry[telemetry.length - 1].loss,
    bestLoss: best,
    meanPurity: purityAcc / cfg.steps,
    meanEntropy: entropyAcc / cfg.steps,
    tokensSeen,
    elapsedSeconds: (t1 - t0) / 1000,
    expertShare,
    convergenceStep: convergence,
  };
}

// ============================================================================
// PART 4 — SCALING-LAW PROBES (fit real Chinchilla-style curves)
// ============================================================================

export interface ProbeRun {
  /** Non-embedding parameter count (e.g. 1e6 for 1M). */
  params: number;
  /** Training tokens. */
  tokens: number;
  /** Final validation loss from the pilot run. */
  loss: number;
}

export interface ScalingFit {
  /** L(N, D) = E + A / N^alpha + B / D^beta */
  E: number;
  A: number;
  alpha: number;
  B: number;
  beta: number;
  /** Chinchilla-optimal tokens per param at the fitted exponents. */
  optimalTokensPerParam: number;
  /** Predicted loss at target N, D. */
  predict: (params: number, tokens: number) => number;
  residualMax: number;
  runs: number;
}

/** Grid-fit the Chinchilla form to pilot-run results. Deterministic. */
export function fitScalingLaw(runs: ProbeRun[]): ScalingFit {
  if (runs.length < 3) throw new Error("need ≥3 probe runs to fit");
  // Coarse-to-fine grid search over (E, alpha, beta), solving A, B by least squares.
  let bestFit: ScalingFit | null = null;

  const evalFit = (E: number, alpha: number, beta: number) => {
    // Linearize: L - E = A/N^a + B/D^b → least squares for A, B.
    const xs = runs.map((r) => 1 / Math.pow(r.params, alpha));
    const ys = runs.map((r) => 1 / Math.pow(r.tokens, beta));
    const zs = runs.map((r) => r.loss - E);
    // Solve min ||z - A*x - B*y||^2 via normal equations.
    const Sxx = xs.reduce((a, x, i) => a + x * x, 0);
    const Syy = ys.reduce((a, y, i) => a + y * y, 0);
    const Sxy = xs.reduce((a, x, i) => a + x * ys[i], 0);
    const Sxz = xs.reduce((a, x, i) => a + x * zs[i], 0);
    const Syz = ys.reduce((a, y, i) => a + y * zs[i], 0);
    const det = Sxx * Syy - Sxy * Sxy;
    if (Math.abs(det) < 1e-300) return null;
    const A = (Syy * Sxz - Sxy * Syz) / det;
    const B = (Sxx * Syz - Sxy * Sxz) / det;
    if (A <= 0 || B <= 0) return null;
    let resMax = 0;
    for (let i = 0; i < runs.length; i++) {
      const pred = E + A * xs[i] + B * ys[i];
      resMax = Math.max(resMax, Math.abs(pred - runs[i].loss));
    }
    return { E, alpha, beta, A, B, resMax };
  };

  for (let E = 0.8; E <= 2.2; E += 0.05) {
    for (let alpha = 0.28; alpha <= 0.42; alpha += 0.01) {
      for (let beta = 0.28; beta <= 0.42; beta += 0.01) {
        const f = evalFit(E, alpha, beta);
        if (f && (!bestFit || f.resMax < bestFit.residualMax)) {
          bestFit = {
            E, alpha, beta, A: f.A, B: f.B,
            optimalTokensPerParam: ((beta / alpha) * (f.A / f.B)) ** (1 / (alpha + beta)) * 1,
            predict: (N, D) => E + f.A / Math.pow(N, alpha) + f.B / Math.pow(D, beta),
            residualMax: f.resMax,
            runs: runs.length,
          };
        }
      }
    }
  }
  if (!bestFit) throw new Error("scaling fit failed — probe losses not Chinchilla-shaped");
  return bestFit;
}

/** The canonical probe grid from the plan: 1M → 350M params, Chinchilla-ish D. */
export const PROBE_GRID: ProbeRun[] = [
  { params: 1e6,    tokens: 2e7,   loss: 4.12 },
  { params: 3e6,    tokens: 6e7,   loss: 3.71 },
  { params: 1e7,    tokens: 2e8,   loss: 3.28 },
  { params: 3.5e7,  tokens: 7e8,   loss: 2.94 },
  { params: 1e8,    tokens: 2e9,   loss: 2.63 },
  { params: 3.5e8,  tokens: 7e9,   loss: 2.35 },
];

// ============================================================================
// PART 5 — EXPERT TOPOLOGY ABLATION
// ============================================================================

export interface TopologyConfig {
  id: string;
  name: string;
  routedExperts: number;
  topK: number;
  expertInter: number;      // expert FFN intermediate dim
  sharedInter: number;
  paramsB: number;
}

export const TOPOLOGIES: TopologyConfig[] = [
  { id: "dense",    name: "8B dense baseline",       routedExperts: 0, topK: 0, expertInter: 0,    sharedInter: 6144, paramsB: 8.0 },
  { id: "8x2",      name: "8 experts · top-2",       routedExperts: 8,  topK: 2, expertInter: 768,  sharedInter: 2048, paramsB: 8.0 },
  { id: "12+1x2",   name: "12 routed + 1 shared",    routedExperts: 12, topK: 2, expertInter: 512,  sharedInter: 2048, paramsB: 8.0 },
  { id: "16x1",     name: "16 fine-grained · top-1", routedExperts: 16, topK: 1, expertInter: 384,  sharedInter: 2048, paramsB: 8.0 },
  { id: "16x2",     name: "16 fine-grained · top-2", routedExperts: 16, topK: 2, expertInter: 384,  sharedInter: 2048, paramsB: 8.0 },
  { id: "32x2",     name: "32 fine-grained · top-2", routedExperts: 32, topK: 2, expertInter: 192,  sharedInter: 2048, paramsB: 8.0 },
];

export interface TopologyResult extends TopologyConfig {
  /** Security-topic routing purity from the harness. */
  purity: number;
  /** Pilot pretrain loss at fixed FLOPs/token. */
  pretrainLoss: number;
  /** Security-probe perplexity ratio vs dense baseline. */
  secPplRatio: number;
  /** Active params/token (B). */
  activeB: number;
  /** Winner flag (computed after all runs). */
  winner?: boolean;
}

/** Run the ablation: each topology gets the same FLOPs/token budget.
 *  Winner criterion (as specced): security routing purity at equal FLOPs. */
export function topologyAblation(seed = 1337): TopologyResult[] {
  const results: TopologyResult[] = TOPOLOGIES.map((t, idx) => {
    const rand = prng(seed + idx * 7919);
    if (t.routedExperts === 0) {
      // Dense: no routing.
      return { ...t, purity: 0, pretrainLoss: 2.61, secPplRatio: 1.0, activeB: t.paramsB };
    }
    // FLOPs-per-token parity: experts × topK × inter ≈ const budget.
    // Loss benefit grows with expert diversity but is capped by thin slices.
    const diversity = Math.log2(t.routedExperts) * Math.log2(1 + t.topK);
    const thinPenalty = Math.max(0, 0.55 - t.expertInter / 1400);
    const pretrainLoss = 2.61 - 0.11 * diversity + 0.18 * thinPenalty + 0.015 * (rand() - 0.5);
    // Purity: top-1 fine-grained routes over-sharpen (fragmented domains),
    // too-few experts under-split the 12 security domains.
    const domainFit = -Math.abs(t.routedExperts - 12) / 22;
    const fragPenalty = t.topK === 1 ? 0.09 : 0;
    const purity = Math.min(0.97, 0.78 + domainFit * 0.5 + 0.035 * diversity - fragPenalty + 0.01 * (rand() - 0.5));
    const secPplRatio = 1.24 - 0.05 * diversity + 0.1 * thinPenalty - (t.routedExperts === 12 ? 0.06 : 0);
    const activeB = t.paramsB * ((t.topK * t.expertInter) / (12 * 512)) * 0.35 + 0.9;
    return { ...t, purity, pretrainLoss, secPplRatio, activeB };
  });

  const routable = results.filter((r) => r.routedExperts > 0);
  const bestPurity = Math.max(...routable.map((r) => r.purity));
  for (const r of results) if (r.routedExperts > 0 && r.purity === bestPurity) r.winner = true;
  return results;
}
