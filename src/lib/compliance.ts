// CrackScope Part 9 — OWASP Top 10 & CWE mapping.
// Maps every rule (and the secrets/dependency passes) to CWE identifiers and
// the OWASP 2021 Top 10, computes per-category coverage (which checks we run
// vs. what fired), and generates audit-ready summaries. Pure TypeScript.
import type { Finding, ScanResult, Severity } from "./scanner";

export interface CweRef {
  id: string; // e.g. "CWE-89"
  name: string;
  owasp: string; // category id, e.g. "A03"
}

const RULE_CWE: Record<string, CweRef> = {
  "SQLI-001": { id: "CWE-89", name: "SQL Injection: Neutralization in SQL Query", owasp: "A03" },
  "SQLI-002": { id: "CWE-89", name: "SQL Injection: Neutralization in SQL Query", owasp: "A03" },
  "XSS-001": { id: "CWE-79", name: "Cross-site Scripting", owasp: "A03" },
  "XSS-002": { id: "CWE-79", name: "Cross-site Scripting", owasp: "A03" },
  "CMD-001": { id: "CWE-78", name: "OS Command Injection", owasp: "A03" },
  "CMD-002": { id: "CWE-95", name: "Eval Injection", owasp: "A03" },
  "SEC-001": { id: "CWE-798", name: "Use of Hard-coded Credentials", owasp: "A02" },
  "CRYPTO-001": { id: "CWE-327", name: "Use of a Broken Cryptographic Algorithm", owasp: "A02" },
  "CRYPTO-002": { id: "CWE-338", name: "Use of Cryptographically Weak PRNG", owasp: "A02" },
  "CRYPTO-003": { id: "CWE-295", name: "Improper Certificate Validation", owasp: "A02" },
  "AUTH-001": { id: "CWE-347", name: "Improper Verification of Cryptographic Signature", owasp: "A07" },
  "AUTH-002": { id: "CWE-639", name: "Authorization Bypass Through User-Controlled Key", owasp: "A01" },
  "PATH-001": { id: "CWE-22", name: "Path Traversal", owasp: "A01" },
  "NOSQL-001": { id: "CWE-943", name: "Improper Neutralization in Data Query Logic", owasp: "A03" },
  "SSRF-001": { id: "CWE-918", name: "Server-Side Request Forgery", owasp: "A10" },
  "DESER-001": { id: "CWE-502", name: "Deserialization of Untrusted Data", owasp: "A08" },
  "CONFIG-001": { id: "CWE-942", name: "Permissive Cross-domain Policy", owasp: "A05" },
  "CONFIG-002": { id: "CWE-489", name: "Active Debug Code", owasp: "A05" },
  "REDIR-001": { id: "CWE-601", name: "Open Redirect", owasp: "A01" },
  "PROTO-001": { id: "CWE-1321", name: "Prototype Pollution", owasp: "A03" },
  // Secrets pass (Part 6)
  "SECRET-ENTROPY": { id: "CWE-798", name: "Use of Hard-coded Credentials (entropy-detected)", owasp: "A02" },
  // Dependency & supply-chain pass (Part 7)
  "DEP-001": { id: "CWE-1395", name: "Dependency on Vulnerable Third-Party Component", owasp: "A06" },
  "DEP-002": { id: "CWE-1395", name: "Dependency on Vulnerable Third-Party Component (transitive)", owasp: "A06" },
  "DEP-003": { id: "CWE-1395", name: "Dependency on Vulnerable Third-Party Component", owasp: "A06" },
  "SUPPLY-001": { id: "CWE-494", name: "Download of Code Without Integrity Check", owasp: "A08" },
  "SUPPLY-002": { id: "CWE-1357", name: "Reliance on Uncontrolled Component", owasp: "A06" },
  "SUPPLY-003": { id: "CWE-1357", name: "Reliance on Uncontrolled Component (typosquat risk)", owasp: "A06" },
  // Fuzzing pass (Part 13)
  "FUZZ-001": { id: "CWE-1333", name: "Inefficient Regular Expression Complexity (ReDoS)", owasp: "A04" },
  "FUZZ-002": { id: "CWE-20", name: "Improper Input Validation (numeric parsing)", owasp: "A04" },
  "FUZZ-003": { id: "CWE-755", name: "Improper Handling of Exceptional Conditions", owasp: "A04" },
  "FUZZ-004": { id: "CWE-400", name: "Uncontrolled Resource Consumption", owasp: "A04" },
  "FUZZ-005": { id: "CWE-755", name: "Improper Handling of Exceptional Conditions (type confusion)", owasp: "A04" },
  "FUZZ-006": { id: "CWE-129", name: "Improper Validation of Array Index", owasp: "A04" },
  "FUZZ-007": { id: "CWE-117", name: "Improper Output Neutralization for Logs", owasp: "A04" },
  // Auth & session attack pass (Part 14)
  "JWT-002": { id: "CWE-347", name: "Improper Verification of Cryptographic Signature (algorithm confusion)", owasp: "A07" },
  "JWT-003": { id: "CWE-798", name: "Use of Hard-coded Credentials (JWT secret)", owasp: "A07" },
  "JWT-004": { id: "CWE-347", name: "Improper Verification of Cryptographic Signature (decode-only trust)", owasp: "A07" },
  "SESS-001": { id: "CWE-384", name: "Session Fixation", owasp: "A07" },
  "SESS-002": { id: "CWE-1004", name: "Sensitive Cookie Without 'HttpOnly' Flag", owasp: "A07" },
  "SESS-003": { id: "CWE-613", name: "Insufficient Session Expiration", owasp: "A07" },
  "PRIV-001": { id: "CWE-807", name: "Reliance on Untrusted Inputs in a Security Decision", owasp: "A01" },
  "PRIV-002": { id: "CWE-862", name: "Missing Authorization", owasp: "A01" },
  "BRUTE-001": { id: "CWE-307", name: "Improper Restriction of Excessive Authentication Attempts", owasp: "A07" },
  "BRUTE-002": { id: "CWE-208", name: "Observable Timing Discrepancy in Password Comparison", owasp: "A07" },
  // Crypto misuse pass (Part 15)
  "CIV-001": { id: "CWE-329", name: "Not Using an Unpredictable IV with CBC Mode", owasp: "A02" },
  "CIV-002": { id: "CWE-327", name: "Use of a Broken or Risky Cryptographic Algorithm (ECB)", owasp: "A02" },
  "CIV-003": { id: "CWE-323", name: "Reusing a Nonce, Key Pair in Encryption", owasp: "A02" },
  "CKEY-001": { id: "CWE-326", name: "Inadequate Encryption Strength", owasp: "A02" },
  "CKEY-002": { id: "CWE-321", name: "Use of Hard-coded Cryptographic Key (malleable ciphertext)", owasp: "A02" },
  "CPBK-001": { id: "CWE-916", name: "Use of Password Hash With Insufficient Computational Effort", owasp: "A02" },
  "CPBK-002": { id: "CWE-916", name: "Use of Password Hash With Insufficient Computational Effort (PBKDF2 iterations)", owasp: "A02" },
  "CCERT-001": { id: "CWE-295", name: "Improper Certificate Validation", owasp: "A02" },
  "CRAND-001": { id: "CWE-330", name: "Use of Insufficiently Random Values", owasp: "A02" },
  "CDES-001": { id: "CWE-327", name: "Use of a Broken or Risky Cryptographic Algorithm (legacy cipher)", owasp: "A02" },
  // Injection deep-scan pass (Part 16)
  "LDAP-001": { id: "CWE-90", name: "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')", owasp: "A03" },
  "LDAP-002": { id: "CWE-90", name: "Improper Neutralization of Special Elements used in an LDAP Query (DN injection)", owasp: "A03" },
  "SSTI-001": { id: "CWE-1336", name: "Improper Neutralization of Special Elements Used in a Template Engine", owasp: "A03" },
  "SSTI-002": { id: "CWE-1336", name: "Improper Neutralization of Special Elements Used in a Template Engine (compiled source)", owasp: "A03" },
  "ORM-001": { id: "CWE-89", name: "SQL Injection via ORM raw-query escape hatch", owasp: "A03" },
  "ORM-002": { id: "CWE-943", name: "Improper Neutralization in Data Query Logic (ORM operator injection)", owasp: "A03" },
  // Network surface pass (Part 17)
  "NET-001": { id: "CWE-306", name: "Missing Authentication for Critical Function", owasp: "A01" },
  "NET-002": { id: "CWE-942", name: "Permissive Cross-domain Policy with Untrusted Origins", owasp: "A05" },
  "NET-003": { id: "CWE-918", name: "Server-Side Request Forgery (internal surface)", owasp: "A10" },
  "NET-004": { id: "CWE-601", name: "Open Redirect (absolute target)", owasp: "A01" },
  // CI/CD & pipeline pass (Part 18)
  "CI-001": { id: "CWE-1357", name: "Reliance on Uncontrolled Component (mutable action tag)", owasp: "A08" },
  "CI-002": { id: "CWE-94", name: "Code Injection via workflow (pull_request_target)", owasp: "A08" },
  "CI-003": { id: "CWE-94", name: "Code Injection via GitHub context script injection", owasp: "A08" },
  "CI-004": { id: "CWE-250", name: "Execution with Unnecessary Privileges (GITHUB_TOKEN)", owasp: "A05" },
  "CI-005": { id: "CWE-532", name: "Insertion of Sensitive Information into Log File", owasp: "A09" },
  "CI-006": { id: "CWE-250", name: "Execution with Unnecessary Privileges (root container)", owasp: "A05" },
  "CI-007": { id: "CWE-1357", name: "Reliance on Uncontrolled Component (mutable base image)", owasp: "A08" },
  "CI-008": { id: "CWE-798", name: "Use of Hard-coded Credentials (image layers)", owasp: "A02" },
  "IAC-001": { id: "CWE-16", name: "Configuration (open security groups)", owasp: "A05" },
  "IAC-002": { id: "CWE-798", name: "Use of Hard-coded Credentials (IaC)", owasp: "A02" },
  "IAC-003": { id: "CWE-732", name: "Incorrect Permission Assignment for Critical Resource (public storage)", owasp: "A01" },
};

/** CWE reference for a rule id; SECRET-* provider rules all map to CWE-798 / A02. */
export function cweFor(ruleId: string): CweRef | null {
  if (RULE_CWE[ruleId]) return RULE_CWE[ruleId];
  if (ruleId.startsWith("SECRET-")) return RULE_CWE["SEC-001"];
  return null;
}

// ---------- OWASP Top 10 coverage model ----------

export type CheckStatus = "tested" | "partial" | "planned";

export interface OwaspCheck {
  /** Rule id (or rule-id prefix family) this check exercises. */
  id: string;
  label: string;
  status: CheckStatus;
}

export interface OwaspCategory {
  id: string;
  title: string;
  description: string;
  checks: OwaspCheck[];
}

export const OWASP_CATEGORIES: OwaspCategory[] = [
  {
    id: "A01",
    title: "Broken Access Control",
    description: "Users can act outside of their intended permissions.",
    checks: [
      { id: "AUTH-002", label: "IDOR hunting on parameter-resolved routes", status: "tested" },
      { id: "PATH-001", label: "Path traversal in file access", status: "tested" },
      { id: "REDIR-001", label: "Unvalidated redirect targets", status: "tested" },
      { id: "PRIV-", label: "Privilege escalation: client-trusted roles, unguarded admin routes", status: "tested" },
    ],
  },
  {
    id: "A02",
    title: "Cryptographic Failures",
    description: "Weak crypto, insecure randomness, and exposed secrets.",
    checks: [
      { id: "CRYPTO-001", label: "Weak hash algorithms (MD5/SHA1)", status: "tested" },
      { id: "CRYPTO-002", label: "Insecure randomness for security tokens", status: "tested" },
      { id: "CRYPTO-003", label: "Disabled TLS/certificate verification", status: "tested" },
      { id: "CIV-", label: "IV hygiene: hardcoded IVs, ECB mode, nonce reuse", status: "tested" },
      { id: "CKEY-", label: "Key strength & authenticated encryption (AEAD)", status: "tested" },
      { id: "CPBK-", label: "Password hashing strength (KDF choice & iterations)", status: "tested" },
      { id: "CCERT-", label: "Certificate validation bypasses in TLS clients", status: "tested" },
      { id: "CRAND-", label: "Predictable IV/salt/seed sources", status: "tested" },
      { id: "CDES-", label: "Legacy cipher usage (DES/3DES/RC4/Blowfish)", status: "tested" },
      { id: "SECRET-", label: "Hardcoded secrets & credentials (provider + entropy)", status: "tested" },
    ],
  },
  {
    id: "A03",
    title: "Injection",
    description: "Untrusted data interpreted as code or query syntax.",
    checks: [
      { id: "SQLI-", label: "SQL injection (concatenation & interpolation)", status: "tested" },
      { id: "NOSQL-001", label: "NoSQL operator injection", status: "tested" },
      { id: "CMD-", label: "OS command injection & dynamic evaluation", status: "tested" },
      { id: "XSS-", label: "Cross-site scripting sinks & reflection", status: "tested" },
      { id: "PROTO-001", label: "Prototype pollution via deep merge", status: "tested" },
      { id: "LDAP-", label: "LDAP filter & DN injection", status: "tested" },
      { id: "SSTI-", label: "Server-side template injection (SSTI)", status: "tested" },
      { id: "ORM-", label: "ORM raw-query & operator injection variants", status: "tested" },
    ],
  },
  {
    id: "A04",
    title: "Insecure Design",
    description: "Missing or ineffective control design (business-logic level).",
    checks: [
      { id: "AI-", label: "AI business-logic hypotheses (Part 8 deep analysis)", status: "partial" },
      { id: "FUZZ-", label: "Simulated fuzzing of user-controlled flows (mutation strategies + crash heuristics)", status: "tested" },
    ],
  },
  {
    id: "A05",
    title: "Security Misconfiguration",
    description: "Insecure default configurations and incomplete hardening.",
    checks: [
      { id: "CONFIG-001", label: "Permissive CORS policies", status: "tested" },
      { id: "CONFIG-002", label: "Debug mode / verbose errors exposed", status: "tested" },
      { id: "NET-002", label: "CORS origin reflection with credentials", status: "tested" },
      { id: "CI-004", label: "Excessive workflow/CI privileges", status: "tested" },
      { id: "CI-006", label: "Root container / image hardening", status: "tested" },
      { id: "IAC-001", label: "Open security-group ingress", status: "tested" },
      { id: "IAC-003", label: "Public storage/snapshot exposure", status: "tested" },
    ],
  },
  {
    id: "A06",
    title: "Vulnerable & Outdated Components",
    description: "Known-vulnerable or risky dependencies in the tree.",
    checks: [
      { id: "DEP-", label: "CVE matching on npm/pip manifests & lockfiles", status: "tested" },
      { id: "SUPPLY-002", label: "Unpinned dependency hygiene", status: "tested" },
      { id: "SUPPLY-003", label: "Typosquatting heuristics", status: "tested" },
    ],
  },
  {
    id: "A07",
    title: "Identification & Authentication Failures",
    description: "Weak session handling and authentication bypasses.",
    checks: [
      { id: "AUTH-001", label: "JWT algorithm confusion & weak secrets", status: "tested" },
      { id: "JWT-", label: "JWT deep checks: alg confusion, hardcoded secrets, decode-only trust", status: "tested" },
      { id: "SESS-", label: "Session fixation, cookie hygiene, session expiry", status: "tested" },
      { id: "BRUTE-", label: "Credential-stuffing surface & timing-safe comparison", status: "tested" },
    ],
  },
  {
    id: "A08",
    title: "Software & Data Integrity Failures",
    description: "Unsafe deserialization and supply-chain integrity.",
    checks: [
      { id: "DESER-001", label: "Unsafe deserialization of untrusted data", status: "tested" },
      { id: "SUPPLY-001", label: "Malicious install-script patterns", status: "tested" },
      { id: "CI-", label: "Pipeline integrity: action pinning, PR-target abuse, context injection", status: "tested" },
      { id: "CI-007", label: "Mutable base-image tags", status: "tested" },
    ],
  },
  {
    id: "A09",
    title: "Security Logging & Monitoring Failures",
    description: "Missing detection, alerting, and response capability.",
    checks: [
      { id: "LOG-", label: "Audit-logging & alerting detection (future part)", status: "planned" },
      { id: "CI-005", label: "Secret leakage through CI logs", status: "tested" },
    ],
  },
  {
    id: "A10",
    title: "Server-Side Request Forgery",
    description: "Server fetches an attacker-controlled destination.",
    checks: [
      { id: "SSRF-001", label: "User-controlled outbound request URLs", status: "tested" },
      { id: "NET-003", label: "Internal/loopback request surface mapping", status: "tested" },
    ],
  },
];

// ---------- coverage computation ----------

export type Risk = "Critical" | "High" | "Moderate" | "Low" | "Clean";

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface CategoryCoverage {
  category: OwaspCategory;
  findings: Finding[];
  cweRefs: CweRef[];
  worst: Severity | null;
  risk: Risk;
  testedChecks: number;
  totalChecks: number;
}

export interface ComplianceReport {
  categories: CategoryCoverage[];
  testedChecks: number;
  totalChecks: number;
  coveragePercent: number;
  summary: string[];
}

function riskFor(worst: Severity | null, count: number): Risk {
  if (count === 0 || !worst) return "Clean";
  if (worst === "critical") return "Critical";
  if (worst === "high") return "High";
  if (worst === "medium") return "Moderate";
  return "Low";
}

function ruleMatches(ruleId: string, checkId: string): boolean {
  return ruleId === checkId || ruleId.startsWith(checkId);
}

export function buildCompliance(result: ScanResult): ComplianceReport {
  const categories = OWASP_CATEGORIES.map((category) => {
    const checks = category.checks.filter((c) => c.status !== "planned");
    const findings: Finding[] = [];
    const cweRefs: CweRef[] = [];
    for (const f of result.findings) {
      const hit = checks.some((c) => ruleMatches(f.ruleId, c.id)) || cweFor(f.ruleId)?.owasp === category.id;
      if (!hit) continue;
      findings.push(f);
      const ref = cweFor(f.ruleId);
      if (ref && !cweRefs.some((r) => r.id === ref.id)) cweRefs.push(ref);
    }
    findings.sort(
      (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity),
    );
    const worst = findings.length > 0 ? findings[0].severity : null;
    const testedChecks = checks.length;
    return {
      category,
      findings,
      cweRefs,
      worst,
      risk: riskFor(worst, findings.length),
      testedChecks,
      totalChecks: category.checks.length,
    };
  });

  const totalChecks = categories.reduce((n, c) => n + c.totalChecks, 0);
  const testedChecks = categories.reduce((n, c) => n + c.testedChecks, 0);
  const coveragePercent = Math.round((testedChecks / totalChecks) * 100);

  const flagged = categories.filter((c) => c.findings.length > 0);
  const summary: string[] = [
    `This assessment maps all ${result.findings.length} finding${result.findings.length === 1 ? "" : "s"} to the OWASP Top 10 (2021) and CWE. Coverage: ${testedChecks} of ${totalChecks} checks (${coveragePercent}%) are automated in this scan tier, spanning ${categories.filter((c) => c.testedChecks > 0).length} of the 10 OWASP categories.`,
  ];

  if (flagged.length > 0) {
    const parts = flagged.map((c) => `${c.category.id} (${c.category.title}) — ${c.findings.length} finding${c.findings.length === 1 ? "" : "s"}, worst severity ${c.worst}`);
    summary.push(`Categories with observations: ${parts.join("; ")}. Each finding carries its CWE reference, a CVSS-style vector, and the simulated exploitation path for audit evidence.`);
  } else {
    summary.push("No observations mapped to the assessed OWASP categories — all automated checks came back clean for this submission.");
  }

  const gaps = categories.filter((c) => c.testedChecks < c.totalChecks);
  if (gaps.length > 0) {
    summary.push(
      `Scope notes for auditors: ${gaps.map((c) => c.category.id).join(", ")} include planned checks not yet automated in this tier (IaC scanning, logging/monitoring detection). Partial coverage there is provided by the AI deep-analysis pass where run.`,
    );
  }

  return { categories, testedChecks, totalChecks, coveragePercent, summary };
}
