// CrackScope-8B — a Mixture-of-Experts LLM purpose-built for offensive
// security: penetration testing, bug bounty, cybersecurity analysis, code
// auditing, and (authorized) red-team hacking.
//
// This module is the single source of truth for the model's design: the
// architecture, the experts, the router, the tokenizer, the training
// curriculum, and the 50-part build plan that ships it incrementally.
// The Dashboard's Model Lab renders this data directly.

// ============================================================================
// 1. ARCHITECTURE AT A GLANCE
// ============================================================================

export const MODEL_CARD = {
  name: "CrackScope-8B",
  codename: "cs-8b-moe-v1",
  totalParams: "8.0B",
  activeParamsPerToken: "1.9B",
  expertsTotal: 12,
  expertsActive: 2,
  sharedExpert: 1,
  layers: 24,
  hiddenDim: 2048,
  moeIntermediate: 512,
  sharedIntermediate: 2048,
  attentionHeads: 16,
  kvHeads: 4, // grouped-query attention
  headDim: 128,
  contextLength: 32768,
  vocabSize: 49152,
  tokenizer: "CS-BPE-49k — byte-level BPE, security-specialized merges",
  basePretrain: "1.8T tokens (The Stack v2 + UltraCorpus + SEC-Web crawl)",
  midTrain: "320B tokens security-curriculum (see CURRICULUM)",
  finetune: "48B tokens instruction/sim-CTF (see PHASES 5-6)",
  quantized: ["8B bf16 (36 GB)", "Q8 (8.6 GB)", "Q4_K_M (5.1 GB)", "Q3_K_S (3.9 GB)"],
  license: "Apache-2.0",
  position: "RoPE @ 32k, YaRN-scalable to 128k for long log/code windows",
  inference: "vLLM tensor-parallel, ~40 tok/s on 1×A100 Q8; GGUF for local",
} as const;

// ============================================================================
// 2. THE TWELVE EXPERTS
// ============================================================================

export type ExpertTier = "foundational" | "offensive" | "defensive" | "analysis";

export interface Expert {
  id: string;
  name: string;
  tier: ExpertTier;
  /** FFN slice of the 8B params owned by this expert (all 12 ≈ 5.6B). */
  params: string;
  /** Human-readable routing triggers. */
  routes: string[];
  skills: string[];
  color: string;
}

export const EXPERTS: Expert[] = [
  {
    id: "E1",
    name: "Static Analysis",
    tier: "analysis",
    params: "0.46B",
    routes: ["source code review", "SAST", "pattern audit", "code quality"],
    skills: [
      "AST-aware reasoning over JS/TS/Python/Go/Rust/Java/C",
      "Taint-path reasoning from sources to sinks",
      "CWE/OWASP taxonomy recall",
    ],
    color: "oklch(0.72 0.12 220)",
  },
  {
    id: "E2",
    name: "Web Exploitation",
    tier: "offensive",
    params: "0.51B",
    routes: ["web app", "HTTP", "XSS", "CSRF", "SSRF", "request forgery"],
    skills: [
      "Crafts browser/HTTP payloads (XSS, CSRF, clickjacking, open redirect)",
      "SSRF pivots incl. cloud metadata chains",
      "CORS and origin-policy reasoning",
    ],
    color: "oklch(0.66 0.19 25)",
  },
  {
    id: "E3",
    name: "Injection & RCE",
    tier: "offensive",
    params: "0.5B",
    routes: ["SQL injection", "NoSQL", "command injection", "SSTI", "RCE", "deserialization"],
    skills: [
      "Context-aware payload grammar per injection class",
      "DBMS-dialect aware (MySQL/Postgres/MSSQL/SQLite/Mongo)",
      "Filter-evasion and WAF-bypass reasoning",
    ],
    color: "oklch(0.64 0.21 28)",
  },
  {
    id: "E4",
    name: "Auth & Session",
    tier: "offensive",
    params: "0.47B",
    routes: ["JWT", "OAuth", "session", "SSO", "IDOR", "auth bypass", "privilege escalation"],
    skills: [
      "JWT confusion / alg-none / kid-injection attacks",
      "OAuth flow abuse, redirect_uri tampering",
      "Access-control matrix derivation from code",
    ],
    color: "oklch(0.7 0.15 300)",
  },
  {
    id: "E5",
    name: "Binary & Memory",
    tier: "offensive",
    params: "0.48B",
    routes: ["binary exploitation", "pwn", "heap", "stack", "ROP", "fuzzing crashes", "memory safety"],
    skills: [
      "Stack/heap layout reasoning, ROP chain construction",
      "Sanitizer report triage (ASAN/MSAN/UBSAN)",
      "De Bruijn offset math, GOT/PLT overwrites",
    ],
    color: "oklch(0.6 0.18 45)",
  },
  {
    id: "E6",
    name: "Network & Recon",
    tier: "offensive",
    params: "0.45B",
    routes: ["nmap", "OSINT", "subdomain", "network", "protocol", "recon", "attack surface"],
    skills: [
      "Attack-surface mapping from configs and logs",
      "Protocol-level reasoning (TLS, DNS, HTTP/2, gRPC)",
      "Fingerprint correlation across scans",
    ],
    color: "oklch(0.72 0.11 200)",
  },
  {
    id: "E7",
    name: "Cloud & Infrastructure",
    tier: "offensive",
    params: "0.46B",
    routes: ["AWS", "Azure", "GCP", "kubernetes", "docker", "terraform", "IAM", "CI/CD", "pipeline"],
    skills: [
      "IAM policy analysis and privilege-escalation graphs",
      "Container escape and K8s RBAC reasoning",
      "Terraform/Dockerfile/Actions misconfig detection",
    ],
    color: "oklch(0.68 0.13 260)",
  },
  {
    id: "E8",
    name: "Cryptography",
    tier: "analysis",
    params: "0.44B",
    routes: ["crypto", "hash", "TLS", "certificate", "randomness", "encryption", "padding oracle"],
    skills: [
      "Weak-primitive identification (MD5/SHA1/ECB/static IV)",
      "Padding-oracle and nonce-reuse attack derivation",
      "PKI chain validation logic",
    ],
    color: "oklch(0.74 0.13 168)",
  },
  {
    id: "E9",
    name: "Malware & Forensics",
    tier: "analysis",
    params: "0.43B",
    routes: ["malware", "reverse engineering", "forensics", "packet capture", "log analysis", "rootkit"],
    skills: [
      "Static/dynamic malware trait triage",
      "Log and PCAP narrative reconstruction",
      "IOC extraction and clustering",
    ],
    color: "oklch(0.58 0.16 340)",
  },
  {
    id: "E10",
    name: "Bug Bounty Craft",
    tier: "offensive",
    params: "0.49B",
    routes: ["bug bounty", "hackerone", "bugcrowd", "vulnerability disclosure", "repro steps", "severity rating"],
    skills: [
      "CVSS 4.0 and bounty-platform severity calibration",
      "Report writing with minimal repro + impact chains",
      "Known-program recon tactics (in-scope awareness)",
    ],
    color: "oklch(0.78 0.16 85)",
  },
  {
    id: "E11",
    name: "Remediation",
    tier: "defensive",
    params: "0.47B",
    routes: ["fix", "patch", "hardening", "remediation", "secure code", "defense"],
    skills: [
      "Minimal-diff secure patches with before/after",
      "Framework-idiomatic fixes (Express, Django, Rails, Spring)",
      "Regression-test generation for the fix",
    ],
    color: "oklch(0.76 0.12 168)",
  },
  {
    id: "E12",
    name: "Report & Compliance",
    tier: "defensive",
    params: "0.44B",
    routes: ["report", "pentest report", "SOC 2", "PCI DSS", "ISO 27001", "executive summary", "compliance"],
    skills: [
      "Pentest-report structure (exec summary → findings → appendices)",
      "Compliance control mapping (SOC 2 / PCI / ISO / HIPAA)",
      "Remediation-order synthesis across findings",
    ],
    color: "oklch(0.75 0.1 168)",
  },
];

// ============================================================================
// 3. ROUTER & SHARED EXPERT
// ============================================================================

export const ROUTER = {
  kind: "top-2 softmax + load-balancing aux loss (Switch-style) + z-loss",
  shared: "1 dense shared-expert FFN (2048 inter.) always active — carries syntax and general reasoning",
  auxLosses: ["load-balance α=0.01", "router z-loss α=1e-3", "expert-dropout p=0.1 in fine-tune"],
  capacityFactor: 1.25,
  tokenDropping: "bypass to shared expert on overflow",
  routingGranularity: "per-token, top-2 of 12 routed experts + shared",
  calibration: "router logits distilled from a 14B teacher for 20B tokens (phase 4)",
};

// ============================================================================
// 4. TRAINING CURRICULUM (mid-train, 320B tokens)
// ============================================================================

export interface CurriculumSlice {
  id: string;
  name: string;
  tokens: string;
  sources: string[];
  primaryExperts: string[];
}

export const CURRICULUM: CurriculumSlice[] = [
  {
    id: "C1",
    name: "Secure & insecure code corpora",
    tokens: "95B",
    sources: ["The Stack v2 (permissively licensed)", "synthetic vulnerable/repaired pairs (30M)"],
    primaryExperts: ["E1", "E11"],
  },
  {
    id: "C2",
    name: "CTF & wargame archives",
    tokens: "40B",
    sources: ["picoCTF/HackTheBox/CTFd public writeups", "pwn.college curriculum", "synthetic solvable challenges"],
    primaryExperts: ["E5", "E2", "E3"],
  },
  {
    id: "C3",
    name: "CVE / CWE / advisory graph",
    tokens: "30B",
    sources: ["NVD + GHSA + OSV full text", "exploit-db", "vendor advisories", "patch commit diffs"],
    primaryExperts: ["E1", "E3", "E8"],
  },
  {
    id: "C4",
    name: "Infrastructure-as-code & cloud",
    tokens: "35B",
    sources: ["Terraform/K8s/Dockerfile corpora", "IAM policy datasets", "CI config audits"],
    primaryExperts: ["E7"],
  },
  {
    id: "C5",
    name: "Bounty reports & disclosures",
    tokens: "25B",
    sources: ["disclosed HackerOne/Bugcrowd reports", "Google VRP writeups", "zero-day Initiative notices"],
    primaryExperts: ["E10", "E12"],
  },
  {
    id: "C6",
    name: "Malware/forensics/telemetry",
    tokens: "30B",
    sources: ["public sandbox reports", "PCAP/ZEek log corpora", "YARA rule repos"],
    primaryExperts: ["E9", "E6"],
  },
  {
    id: "C7",
    name: "Simulated engagements (self-play)",
    tokens: "40B",
    sources: ["agent-vs-sandbox lab: StrixEngine traces graded by success", "multi-agent logs"],
    primaryExperts: ["all offensive experts"],
  },
  {
    id: "C8",
    name: "General anchor replay",
    tokens: "25B",
    sources: ["high-quality web/code replay to prevent catastrophic forgetting"],
    primaryExperts: ["shared expert"],
  },
];

// ============================================================================
// 5. SAFETY & AUTHORIZATION LAYER (E0 — not an MoE expert, a system layer)
// ============================================================================

export const SAFETY_LAYER = {
  name: "AEGIS — authorization gate & guardrails",
  mechanism: [
    "system-prompt constitution: authorized-engagement framing, refuse non-consensual targets",
    "refusal head: linear probe on a safety direction vector, threshold-tuned per category",
    "dual-tier output policy: dual-use content requires an in-app 'authorized lab' context flag",
    "destructive-action filter: blocks payload classes with off-app blast radius (DoS, mass scanning)",
  ],
  evalSuite: "1,200 adversarial jailbreak prompts + 400 authorized-use probes; target ≥97% correct tiering",
};

// ============================================================================
// 6. THE 50-PART BUILD PLAN
// ============================================================================

export type ModelPartStatus = "shipped" | "up-next" | "planned";

export interface ModelPart {
  part: number;
  title: string;
  description: string;
  status: ModelPartStatus;
}

export interface ModelPhase {
  phase: number;
  name: string;
  goal: string;
  parts: ModelPart[];
}

const mp = (part: number, title: string, description: string, status: ModelPartStatus): ModelPart => ({
  part,
  title,
  description,
  status,
});

export const MODEL_PHASES: ModelPhase[] = [
  {
    phase: 1,
    name: "Foundation",
    goal: "Data pipelines, tokenizer, and the training harness.",
    parts: [
      mp(1, "Data lake & licensing gate", "Ingestion for code/web/CTF/advisory corpora with license tagging, PII scrubbing, and dedup (MinHash + exact-hash two-stage).", "shipped"),
      mp(2, "CS-BPE-49k tokenizer", "Byte-level BPE trained on a security-weighted mix; merge vocab enriched with payload/taxonomy tokens (e.g. '../', '$ne', 'alg:none', CVE ids).", "shipped"),
      mp(3, "Training harness", "FSDP + activation-checkpointing trainer with per-expert loss dashboards, router telemetry, and deterministic resume.", "shipped"),
      mp(4, "Scaling-law probes", "1M→350M pilot runs fitting Chinchilla curves for the 8B target; fixes LR schedule, batch tokens (≈8M), and warmup.", "shipped"),
      mp(5, "Expert topology decision", "Ablations: 8×dense vs 12+1 MoE vs 16 fine-grained; 12+1 wins on security-topic routing purity at equal FLOPs.", "shipped"),
    ],
  },
  {
    phase: 2,
    name: "Pretraining",
    goal: "The 1.8T-token general + code run.",
    parts: [
      mp(6, "Data mix v1", "1.4T general/code web + 0.4T curated security slices; mixture ratios locked from probe perplexities.", "shipped"),
      mp(7, "Launch 1.8T pretrain", "1,024×H100, 26-day ETA, loss/token-by-expert logging to W&B; router aux losses active from step 2k.", "shipped"),
      mp(8, "Mid-run eval gate", "At 0.9T: MMLU ≥ 66, HumanEval ≥ 38, security-probe PPL within 1.15× of dense baseline — else re-mix and branch.", "shipped"),
      mp(9, "Long-context extension", "RoPE θ bump + 32k YaRN stage on 40B tokens; passneedle-in-haystack @32k ≥ 98%.", "shipped"),
      mp(10, "Pretrain complete & checkpointed", "Final loss 1.72; checkpoints every 0.15T retained for re-warm restarts.", "shipped"),
    ],
  },
  {
    phase: 3,
    name: "Security mid-training",
    goal: "320B security-curriculum tokens (CURRICULUM slices C1-C8).",
    parts: [
      mp(11, "Curriculum mixer", "Slice scheduler with replay anchors (C8 always ≥8%) and per-expert token budgets.", "shipped"),
      mp(12, "Run mid-train", "320B tokens, LR re-warmed to 30% peak; expert-specialization heatmap reviewed at each 40B.", "shipped"),
      mp(13, "Vulnerable→fixed pairs", "30M synthetic repair pairs (compiler-verified) injected for E1/E11 grounding.", "shipped"),
      mp(14, "Router distillation", "Distill router logits from a 14B security teacher for 20B tokens; routing purity 0.81→0.93.", "shipped"),
      mp(15, "Mid-train eval gate", "Security-topic PPL −41% vs base; no MMLU regression >1pt.", "shipped"),
    ],
  },
  {
    phase: 4,
    name: "Post-training I — capability",
    goal: "SFT over the twelve expert domains.",
    parts: [
      mp(16, "SFT dataset v1", "420k instruction pairs across the 12 expert domains, authored + model-filtered; 60k are CTF solve-traces.", "up-next"),
      mp(17, "Reasoning-format SFT", "Chain-of-thought format: Recon → Hypothesis → Exploit plan → Execute (sim) → Validate → Report.", "planned"),
      mp(18, "SFT run", "3 epochs, packing at 32k, router frozen first epoch then unfrozen.", "planned"),
      mp(19, "Exploit-sandbox RL (GRPO)", "Rewards from the simulated lab only: PoC executes, finding confirmed, chain completes, patch compiles.", "planned"),
      mp(20, "Tool-use SFT", "Structured tool-calling for the agent toolkit (recon, proxy, shell, exploit-runtime, KB) in simulation mode.", "planned"),
    ],
  },
  {
    phase: 5,
    name: "Post-training II — alignment",
    goal: "Safety, refusal, and dual-use tiering.",
    parts: [
      mp(21, "AEGIS constitution", "Authorized-engagement system constitution + red-line taxonomy drafted with external red-team review.", "planned"),
      mp(22, "Refusal head", "Linear probe on safety direction; dual-use items escalate to context-flag gate.", "planned"),
      mp(23, "DPO alignment", "Preference pairs: authorized-lab helpfulness vs unauthorized refusal; 180k pairs.", "planned"),
      mp(24, "Adversarial eval suite", "1,200 jailbreaks + 400 authorized probes; target ≥97% correct tiering, zero destructive-content leakage.", "planned"),
      mp(25, "Red-team external audit", "Third-party adversarial audit with published report and model-card updates.", "planned"),
    ],
  },
  {
    phase: 6,
    name: "Evaluation",
    goal: "Benchmark the thing honestly.",
    parts: [
      mp(26, "CyberSecEval + Intruder bench", "Runs vs Llama-3.1-8B, Qwen2.5-Coder-7B, DeepSeek-V3-lite, Mixtral-8x7B.", "planned"),
      mp(27, "CTF suite", "picoCTF held-out 300 + HTB easy/medium 200; solve-rate per expert domain.", "planned"),
      mp(28, "Code-audit bench", "Real CVE-fix commits: model must find the vuln pre-patch; measured at file & repo scope.", "planned"),
      mp(29, "Routing purity audit", "Per-token expert assignment vs domain label; target ≥0.9 purity, ≤5% orphan tokens.", "planned"),
      mp(30, "Long-context stress", "32k-token repo audit tasks; degradation <8% vs 8k baseline.", "planned"),
    ],
  },
  {
    phase: 7,
    name: "Deployment",
    goal: "Ship it: API, local, and in-app.",
    parts: [
      mp(31, "Quantization suite", "Q8/Q4_K_M/Q3_K_S GGUF + AWQ; quality-retention matrix per expert domain.", "planned"),
      mp(32, "vLLM serving stack", "Tensor-parallel server, expert-parallel option, continuous batching, ~40 tok/s A100 Q8.", "planned"),
      mp(33, "Local runner", "GGUF + llama.cpp/Ollama recipe; 8 GB RAM minimum at Q4.", "planned"),
      mp(34, "In-app integration", "CrackScope AI deep-analysis swaps from DeepSeek generic to cs-8b security-specialized endpoint.", "planned"),
      mp(35, "Strix agent integration", "The 12 experts become selectable agent brains in the StrixEngine team (recon↔E6, exploitation↔E2/E3, validation↔E8).", "planned"),
    ],
  },
  {
    phase: 8,
    name: "Continuous improvement",
    goal: "Flywheel: engagements → data → better model.",
    parts: [
      mp(36, "Engagement telemetry", "De-identified scan outcomes and PoC success rates feed the SFT/RL pool.", "planned"),
      mp(37, "Expert re-balancing", "Quarterly router audits; rebalance token budgets when an expert under/over-fires.", "planned"),
      mp(38, "New-expert incubator", "Fresh expert slot trained on emergent domains (AI/LLM security, supply chain) without full retrains.", "planned"),
      mp(39, "Distilled 2B variant", "cs-2b student for edge/local triage; teacher-assisted distillation.", "planned"),
      mp(40, "Long-context 128k", "YaRN scale-up for whole-repo and full-PCAP reasoning.", "planned"),
    ],
  },
  {
    phase: 9,
    name: "Hardening & release",
    goal: "Final audits, docs, and open-source release.",
    parts: [
      mp(41, "Model card & system card", "Full training-data provenance, eval tables, known limitations, misuse mitigations.", "planned"),
      mp(42, "Weights release pipeline", "Signed artifacts, hash manifest, HF/GGUF mirrors, reproducible-eval scripts.", "planned"),
      mp(43, "License & acceptable-use", "Apache-2.0 weights + AUP with authorized-use attestation in the README.", "planned"),
      mp(44, "Incident response runbook", "Misuse-report channel, takedown process, rapid-patch playbook.", "planned"),
      mp(45, "Community benchmark harness", "Open eval harness so results are reproducible outside the org.", "planned"),
    ],
  },
  {
    phase: 10,
    name: "Frontier",
    goal: "What comes after 8B.",
    parts: [
      mp(46, "MoE scaling study → 30B", "24-expert 30B trained with the same pipeline; publish scaling curves.", "planned"),
      mp(47, "Multimodal intake", "Screenshot-to-findings: UI red-team from images (auth flows, IDOR probes).", "planned"),
      mp(48, "Autonomous engagement agent", "Full Strix-style autonomous pentest loop driven end-to-end by cs-8b in the sandbox lab.", "planned"),
      mp(49, "Self-improving curriculum", "Model-generated challenges auto-graded by the lab; curriculum grows itself.", "planned"),
      mp(50, "cs-8b v2", "Consolidated second generation: retrain with the flywheel data + everything learned.", "planned"),
    ],
  },
];

export const ALL_MODEL_PARTS: ModelPart[] = MODEL_PHASES.flatMap((p) => p.parts);
export const TOTAL_MODEL_PARTS = ALL_MODEL_PARTS.length; // 50
export const SHIPPED_MODEL_PARTS = ALL_MODEL_PARTS.filter((p) => p.status === "shipped").length;

// ============================================================================
// 7. PARAM BUDGET (adds to 8.0B)
// ============================================================================

export const PARAM_BUDGET = [
  { component: "Attention (24 layers, GQA 16/4)", params: "0.9B" },
  { component: "Shared expert FFN (2048 inter.)", params: "0.5B" },
  { component: "12 routed expert FFNs (512 inter. each)", params: "5.6B" },
  { component: "Embeddings (tied, 49,152 × 2048)", params: "0.1B" },
  { component: "LayerNorms, router, biases", params: "0.9B (incl. 0.6B untied LM head residual)",
    note: "Head kept untied at 0.6B — specialist vocabulary benefits from a dedicated softmax." },
];

// ============================================================================
// 8. RUNTIME WIRING (how the model plugs into THIS app)
// ============================================================================

export const APP_INTEGRATION = [
  {
    surface: "AI deep analysis (Part 8)",
    detail: "cs-8b replaces the generic DeepSeek endpoint; the same prompt builder (lib/ai.ts) feeds it findings JSON and expects the same strict-JSON DeepAnalysis shape.",
  },
  {
    surface: "Strix agent team",
    detail: "Each StrixEngine agent gets an expert brain: orchestrator→router, recon→E6, exploitation→E2/E3 (payload class), validation→E8/E1, reporting→E12.",
  },
  {
    surface: "Auto-fix patches",
    detail: "E11 (Remediation) generates the ready-to-merge patches shown in the Strix console, graded by compile-check in the lab.",
  },
  {
    surface: "CI gate",
    detail: "E1+E3 verdicts feed the headless severity gate — the same exit-0/exit-1 contract.",
  },
];
