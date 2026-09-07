// CrackScope Part 6 — secrets & credentials scanner.
// Two layers:
//   1. Provider-specific patterns (AWS, GCP, Stripe, Slack, GitHub, …)
//      with per-provider confidence and rotation guidance.
//   2. High-entropy string detection (Shannon) for generic secrets that
//      match no known provider format.
// Placeholder/env-var/looks-fake values are suppressed to keep precision
// high. Output uses the shared Finding shape so reports need no changes.

import type { Finding, ScanInput, Severity } from "./scanner";

const OWASP_A02 = "A02:2021 – Cryptographic Failures";
const CATEGORY = "Sensitive Data Exposure";

const GENERIC_PAYLOAD =
  `Attacker action: grep -rE "api_key|password\\s*=" repo/ (or an automated bot sweep of the public repo)\nEffect: valid production credential harvested; automated scanners index exposed keys within hours.`;
const GENERIC_REMEDIATION =
  "Revoke and rotate the credential immediately, purge it from git history (git filter-repo), and load it from environment variables or a secret manager at runtime.";

interface ProviderRule {
  id: string;
  kind: string;
  severity: Severity;
  confidence: "high" | "medium";
  pattern: RegExp;
  remediation?: string;
  payload?: string;
}

const PROVIDER_RULES: ProviderRule[] = [
  {
    id: "SECRET-AWS-AKID",
    kind: "AWS access key ID",
    severity: "critical",
    confidence: "high",
    pattern: /AKIA[0-9A-Z]{16}/,
    remediation:
      "Deactivate the access key in IAM immediately, rotate via a new key + secret, purge from history, and switch code to instance roles or short-lived STS credentials.",
    payload: `Bot action: regex sweep of public repos / paste sites (AKIA keys are indexed within minutes)\nEffect: EC2 instances, S3 buckets, and IAM roles provisioned on the victim's account.`,
  },
  {
    id: "SECRET-AWS-SECRET",
    kind: "AWS secret access key",
    severity: "critical",
    confidence: "high",
    pattern: /(?:(?:aws)?_?secret_?access_?key)\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']/i,
  },
  {
    id: "SECRET-GCP",
    kind: "Google API key",
    severity: "critical",
    confidence: "high",
    pattern: /AIza[0-9A-Za-z_-]{35}/,
  },
  {
    id: "SECRET-STRIPE",
    kind: "Stripe secret key",
    severity: "critical",
    confidence: "high",
    pattern: /(?:sk|rk)_live_[0-9a-zA-Z]{16,}/,
    remediation:
      "Roll the key in the Stripe dashboard now, update the deployment secret, and add live-key detection to CI. Test-mode keys (sk_test_) should still move to env vars.",
  },
  {
    id: "SECRET-SLACK",
    kind: "Slack token",
    severity: "critical",
    confidence: "high",
    pattern: /xox[baprs]-[0-9A-Za-z-]{10,}/,
  },
  {
    id: "SECRET-GITHUB",
    kind: "GitHub token",
    severity: "critical",
    confidence: "high",
    pattern: /gh[pousr]_[0-9A-Za-z]{36,}|github_pat_[0-9A-Za-z_]{22,}/,
  },
  {
    id: "SECRET-SENDGRID",
    kind: "SendGrid API key",
    severity: "critical",
    confidence: "high",
    pattern: /SG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}/,
  },
  {
    id: "SECRET-NPM",
    kind: "npm publish token",
    severity: "critical",
    confidence: "high",
    pattern: /npm_[0-9A-Za-z]{36}/,
    payload: `Attacker action: publish a tampered version of the affected package\nEffect: supply-chain compromise of every downstream consumer.`,
  },
  {
    id: "SECRET-PRIVATEKEY",
    kind: "Private key block",
    severity: "critical",
    confidence: "high",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----/,
    remediation:
      "Treat the key as compromised: generate a new keypair, update all trust stores, and never commit key files — keep them in a vault with restricted access.",
    payload: `Attacker action: use the private key to sign tokens / decrypt traffic / impersonate the service\nEffect: persistent impersonation that survives credential rotation elsewhere.`,
  },
  {
    id: "SECRET-DB-URL",
    kind: "Database URL with embedded password",
    severity: "critical",
    confidence: "high",
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|rediss):\/\/[^\s:@/]+:[^\s@/]{4,}@/,
    remediation:
      "Move the full connection string to an environment variable, rotate the database password, and restrict network access to the database (private networking / IP allowlist).",
    payload: `Attacker action: connect directly to the database with the embedded credentials\nEffect: full read/write access to production data, outside the app's defenses.`,
  },
  {
    id: "SECRET-TWILIO",
    kind: "Twilio API key / account SID",
    severity: "high",
    confidence: "medium",
    pattern: /\b(?:SK|AC)[0-9a-fA-F]{32}\b/,
  },
  {
    id: "SECRET-JWT",
    kind: "Hardcoded JWT (signed token in source)",
    severity: "medium",
    confidence: "medium",
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/,
    remediation:
      "Tokens in source are often replayable until expiry. Remove them, revoke via the auth provider if possible, and generate tokens at runtime only.",
    payload: `Attacker action: replay the hardcoded token against the live API\nEffect: authenticated as the token's subject until it expires.`,
  },
];

// ---------- Shannon entropy ----------

export function shannonEntropy(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

const ENTROPY_CANDIDATE = /[A-Za-z0-9_\-/+=]{20,}/g;

const SUPPRESS = [
  "placeholder", "example", "your-", "your_", "changeme", "change-me",
  "xxxx", "lorem", "ipsum", "dummy", "sample", "fake", "asdf", "qwer",
  "12345678", "abcdefgh", "test-key", "testkey", "redacted", "todo",
  "process.env", "os.environ", "import.meta.env", "env.", "${", "{{",
  "<", ">", "%s", "%d", "00000000", "aaaaaaaa", "secretmanager", "vault",
];

function isSuppressed(line: string, value: string): boolean {
  const lowerLine = line.toLowerCase();
  const lowerVal = value.toLowerCase();
  if (SUPPRESS.some((t) => lowerLine.includes(t) || lowerVal.includes(t))) return true;
  // Low character variety (e.g. "AAAA...") or pure repeats of one char.
  if (new Set(value).size < Math.max(4, value.length / 4)) return true;
  // Sequential runs (keyboard walks) are not random.
  if (/abcdef|123456|qwerty|012345/i.test(value)) return true;
  return false;
}

function looksLikeGenericSecret(value: string): boolean {
  const letters = /[a-z]/.test(value);
  const upper = /[A-Z]/.test(value);
  const digits = /\d/.test(value);
  const classes = [letters, upper, digits, /[_\-/+=]/.test(value)].filter(Boolean).length;
  return classes >= 3 && shannonEntropy(value) >= 3.2;
}

/** Run the secrets pass over one file. `excludeLines` skips lines already reported. */
export function detectSecrets(input: ScanInput, excludeLines: Set<number>): Finding[] {
  const lines = input.content.split("\n");
  const findings: Finding[] = [];
  const reportedLines = new Set<number>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("#")) continue;
    if (excludeLines.has(i + 1)) continue;

    let matched: Finding | null = null;

    for (const rule of PROVIDER_RULES) {
      const m = rule.pattern.exec(line);
      if (!m) continue;
      if (isSuppressed(line, m[0])) continue;
      matched = {
        ruleId: rule.id,
        title: `${rule.kind} committed to source (${rule.confidence} confidence)`,
        severity: rule.severity,
        category: CATEGORY,
        owasp: OWASP_A02,
        file: input.name,
        line: i + 1,
        snippet: trimmed.slice(0, 220),
        description: `A ${rule.kind.toLowerCase()} pattern matched with ${rule.confidence} confidence. Committed credentials are discoverable by anyone with repository access and by automated scanners within hours of exposure; rotation history is lost the moment the value lands in git.`,
        remediation: rule.remediation ?? GENERIC_REMEDIATION,
        payload: rule.payload ?? GENERIC_PAYLOAD,
      };
      break;
    }

    // Generic high-entropy fallback (no provider format matched).
    if (!matched) {
      for (const m of line.matchAll(ENTROPY_CANDIDATE)) {
        const value = m[0];
        if (value.length < 20) continue;
        // Skip URLs and import paths.
        if (/^[a-z]+:\/\//.test(value) || /^(?:import|from|require|package|com\.|org\.)/i.test(value)) continue;
        if (isSuppressed(line, value)) continue;
        if (!looksLikeGenericSecret(value)) continue;
        matched = {
          ruleId: "SECRET-ENTROPY",
          title: `High-entropy credential-like string (medium confidence)`,
          severity: "medium",
          category: CATEGORY,
          owasp: OWASP_A02,
          file: input.name,
          line: i + 1,
          snippet: trimmed.slice(0, 220),
          description: `A ${value.length}-character string with ${shannonEntropy(value).toFixed(1)} bits/char of Shannon entropy and mixed character classes resembles a generated secret (API key, token, or password). No provider format matched, so confidence is medium — verify against your secret inventory.`,
          remediation: GENERIC_REMEDIATION,
          payload: GENERIC_PAYLOAD,
        };
        break;
      }
    }

    if (matched) {
      findings.push(matched);
      reportedLines.add(i + 1);
    }
  }
  return findings;
}
