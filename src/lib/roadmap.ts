// CrackScope 25-part build roadmap.
// Part 1 ships with this version; later parts are built incrementally.

export type RoadmapStatus = "shipped" | "up-next" | "planned";

export interface RoadmapPart {
  part: number;
  title: string;
  description: string;
  status: RoadmapStatus;
}

export interface RoadmapPhase {
  phase: number;
  name: string;
  parts: RoadmapPart[];
}

const p = (
  part: number,
  title: string,
  description: string,
  status: RoadmapStatus,
): RoadmapPart => ({ part, title, description, status });

export const ROADMAP_PHASES: RoadmapPhase[] = [
  {
    phase: 1,
    name: "Foundation",
    parts: [
      p(1, "Platform foundation", "Auth, database schema, projects, dashboard, and the first end-to-end attack simulation with a heuristic engine and pentest-style report.", "shipped"),
      p(2, "Code intake", "Multi-file paste, drag-and-drop upload, folder zips, and GitHub repo/URL ingestion with language auto-detection.", "shipped"),
      p(3, "Static analysis engine v1", "AST-aware detectors per language, taint tracking from sources to sinks, and dramatically fewer false positives.", "shipped"),
      p(4, "Attack simulation lab v1", "Per-finding exploit generation: live payload crafting, exploit chains, and a sandboxed 'try to crack' replay view.", "shipped"),
      p(5, "Pentest report generator", "Executive summary, CVSS-style scoring, methodology section, and export to Markdown/PDF.", "shipped"),
    ],
  },
  {
    phase: 2,
    name: "Detection core",
    parts: [
      p(6, "Secrets & credentials scanner", "Entropy analysis plus provider-specific patterns for API keys, tokens, and private keys, with git-history awareness.", "shipped"),
      p(7, "Dependency & supply-chain audit", "Vulnerable package versions, known CVE mapping, transitive risk, and lockfile analysis.", "shipped"),
      p(8, "AI deep analysis (open-source model)", "LLM review powered by DeepSeek via the Novita inference gateway: contextual reasoning over findings, business-logic flaws, and plain-English exploitation narrative.", "shipped"),
      p(9, "OWASP Top 10 & CWE mapping", "Compliance view with coverage scores, standards mapping, and audit-ready summaries.", "shipped"),
      p(10, "Hardening recommendations", "Auto-generated fixes with patch snippets, before/after code, and per-finding fix difficulty.", "shipped"),
    ],
  },
  {
    phase: 3,
    name: "Offensive modules",
    parts: [
      p(11, "Triage workflow", "Mark false positives, accept risk, add notes, re-open, and assign owners.", "shipped"),
      p(12, "Scan history & diffing", "Compare scans over time, detect regressions, and track remediation velocity.", "shipped"),
      p(13, "Fuzzing module", "Simulated input fuzzing of user-controlled flows with mutation strategies and crash-pattern heuristics.", "shipped"),
      p(14, "Auth & session attacks", "JWT flaws, session fixation, IDOR hunting, and privilege-escalation patterns.", "shipped"),
      p(15, "Crypto misuse detector", "Weak hashes, hardcoded IVs, ECB mode, insecure randomness, and certificate pitfalls.", "shipped"),
    ],
  },
  {
    phase: 4,
    name: "Product depth",
    parts: [
      p(16, "Injection deep-scan", "SQL/NoSQL/LDAP/template/ORM variants with database-engine-aware payload selection.", "shipped"),
      p(17, "Network surface mapper", "Endpoint discovery, CORS analysis, SSRF surface, and open-redirect graphing.", "shipped"),
      p(18, "CI/CD & pipeline guardrails", "GitHub Actions, Dockerfile, and Terraform/IaC scanning with pipeline-blocking severity gates.", "shipped"),
      p(19, "Team workspaces", "Multi-member projects, roles, shared reports, and activity feeds.", "shipped"),
      p(20, "Report center", "Branded pentest reports, client-ready exports, and scheduled email delivery.", "shipped"),
    ],
  },
  {
    phase: 5,
    name: "Scale",
    parts: [
      p(21, "Scheduled & recurring scans", "Background re-scans, drift alerts, and notification digests.", "shipped"),
      p(22, "Integrations", "GitHub App/webhooks, Slack and email alerts, and issue-tracker sync.", "shipped"),
      p(23, "Attack knowledge base", "Searchable technique library (MITRE/OWASP-inspired) mapped to live findings.", "shipped"),
      p(24, "Risk analytics", "Trend dashboards, heatmaps, language breakdown, and MTTR metrics.", "shipped"),
      p(25, "Public API & CLI", "Programmatic access, `crackscope` CLI, and CI webhooks for automation.", "shipped"),
    ],
  },
  {
    phase: 6,
    name: "Strix engine",
    parts: [
      p(26, "Strix multi-agent red team", "Graph-of-Agents orchestration modeled on usestrix/strix: recon, exploitation, validation, and reporting agents collaborate over scan findings like a real pentest team.", "shipped"),
      p(27, "Exploit validation & PoCs", "Working proof-of-concept exploits per finding with validation verdicts (validated / probable / needs-context) and confidence scoring — real exploitation evidence, not false positives.", "shipped"),
      p(28, "Attack-chain discovery", "Chains individual findings into multi-stage kill chains with narratives and end-to-end impact, prioritized above isolated findings.", "shipped"),
      p(29, "Agent toolkit & skills", "The Strix agentic toolkit (HTTP proxy, browser exploitation, shell, exploit runtime, recon/OSINT, SAST+DAST, knowledge base) plus the nine SKILL.md agent skills, with per-run usage tracking.", "shipped"),
      p(30, "Auto-fix & CI gate", "AI-generated ready-to-merge patches and the headless severity gate that blocks pipelines when validated critical/high findings remain.", "shipped"),
    ],
  },
];

export const ALL_PARTS: RoadmapPart[] = ROADMAP_PHASES.flatMap((phase) => phase.parts);

export const TOTAL_PARTS = ALL_PARTS.length;

export const SHIPPED_PARTS = ALL_PARTS.filter((part) => part.status === "shipped").length;
