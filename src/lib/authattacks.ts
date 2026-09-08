// CrackScope Part 14 — auth & session attack module.
// Detection of authentication and session-management weaknesses beyond the
// Part 1 JWT rule: algorithm confusion, hardcoded JWT secrets, session
// fixation, missing session regeneration, cookie hygiene, privilege
// escalation via client-trusted roles, and credential-stuffing surface
// (login endpoints without rate limiting / lockout). Output uses the shared
// Finding shape; findings are taint-independent (auth structure is dangerous
// regardless of a specific input flow).
import type { Finding, ScanInput, Severity } from "./scanner";

const CATEGORY = "Auth & Session Attacks";
const OWASP_A07 = "A07:2021 – Identification and Authentication Failures";

interface AuthRule {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  remediation: string;
  payload: string;
  pattern: RegExp;
  maxMatchesPerFile: number;
  safeHints?: string[];
}

const RULES: AuthRule[] = [
  {
    id: "JWT-002",
    title: "JWT algorithm confusion surface (rs/rs256 mixed with hs256 secrets)",
    severity: "critical",
    description:
      "A JWT secret is used in a context that suggests symmetric verification while asymmetric keys are configured (or vice versa). Algorithm-confusion attacks (CVE-2015-9235 style) let attackers switch the header alg to HS256/none and forge tokens with a public key as the HMAC secret.",
    remediation:
      "Pin the algorithm at verification (jwt.verify with algorithms: ['RS256'] etc.), keep asymmetric and symmetric verification paths separate, and reject tokens whose header alg differs from the pinned value.",
    payload: `Attack: take a valid token, set header {"alg":"HS256","typ":"JWT"}, sign the payload with the server's PUBLIC key as the HMAC secret\nEffect: forged token accepted by the confused verifier — arbitrary identity/role claims.`,
    pattern: /jwt\.verify\s*\([^)]*(?:algorithms\s*:\s*\[\s*["'](?:HS256|RS256)["']\s*,\s*["'](?:RS256|HS256)["'])/i,
    maxMatchesPerFile: 4,
  },
  {
    id: "JWT-003",
    title: "JWT secret hardcoded or derived from weak constant",
    severity: "critical",
    description:
      "The JWT signing secret appears to be a literal string in source. Anyone with the repo (or a decompiled bundle) can mint valid tokens for any user, including admin identities.",
    remediation:
      "Load the secret from a secret manager / environment with a minimum 256-bit random value, rotate it, and support key rotation via kid headers.",
    payload: `Attack: extract the secret from source/config, then mint {"sub":"victim","role":"admin","exp":9999999999}\nEffect: permanent admin impersonation without any credential.`,
    pattern: /jwt\.(?:sign|verify)\s*\([^)]*(?:["'][^"']{6,}["']\s*,|secret\s*[:=]\s*["'][^"']{6,}["'])/i,
    maxMatchesPerFile: 4,
    safeHints: ["process.env", "os.environ", "import.meta.env", "config", "SECRET", "getenv"],
  },
  {
    id: "JWT-004",
    title: "JWT payload trusted without signature verification",
    severity: "critical",
    description:
      "Token claims are read via jwt.decode (or manual base64 parsing) and then used for authorization. decode performs no signature check — anyone can craft a token with arbitrary claims.",
    remediation:
      "Always use jwt.verify for authorization decisions; reserve decode for untrusted pre-inspection only, and never branch on decode output.",
    payload: `Attack: base64-encode {"role":"admin"} as the payload, keep any signature\nEffect: decode-only middleware grants admin access — full auth bypass.`,
    pattern: /jwt\.decode\s*\(/,
    maxMatchesPerFile: 4,
    safeHints: ["verify", "signature"],
  },
  {
    id: "SESS-001",
    title: "Session not regenerated after login (session fixation)",
    severity: "high",
    description:
      "A login handler appears to authenticate the user without regenerating the session identifier. An attacker who plants a known session id (via link, subdomain cookie, or XSS) keeps their pre-auth id after the victim logs in — a classic session fixation path.",
    remediation:
      "Regenerate the session on every privilege change (req.session.regenerate() in Express, session_regenerate_id(true) in PHP) and never accept session ids from URLs.",
    payload: `Attack: send victim a link with ?sid=ATTACKER_KNOWN_ID (or set the cookie via subdomain), victim logs in\nEffect: attacker's known session id is now authenticated as the victim — account takeover.`,
    pattern: /(?:app|router)\.(?:post)\s*\(\s*["'][^"']*login[^"']*["'][^)]*\)\s*,?\s*(?:async\s*)?\([^)]*\)\s*=>?\s*\{?(?![^}]*regenerate)(?![^}]*session_regenerate)/i,
    maxMatchesPerFile: 3,
    safeHints: ["regenerate", "regenerateId", "session_regenerate", "rotate"],
  },
  {
    id: "SESS-002",
    title: "Session cookie without security flags (secure/httpOnly/sameSite)",
    severity: "medium",
    description:
      "A session cookie is set without Secure (sent over plain HTTP), HttpOnly (readable by injected JavaScript), or SameSite (sent on cross-site requests, enabling CSRF). Missing flags compound XSS and network-interception attacks.",
    remediation:
      "Set cookie: { secure: true, httpOnly: true, sameSite: 'lax' } (or 'strict') for every session cookie, and force HTTPS with HSTS.",
    payload: `Attack: XSS on any subdomain reads document.cookie → session hijack; or intercept the cookie over HTTP on café Wi-Fi\nEffect: authenticated session replay as the victim.`,
    pattern: /(?:res\.cookie|cookies\.set|setCookie|Set-Cookie|session\s*[:=]\s*\{)[^;)]*(?:session|token|sid|auth)/i,
    maxMatchesPerFile: 4,
    safeHints: ["httponly", "secure", "samesite", "signed"],
  },
  {
    id: "SESS-003",
    title: "Persistent session with no expiry",
    severity: "medium",
    description:
      "A session or token is issued with no expiration (maxAge/expires/absent exp claim). Stolen sessions remain valid indefinitely, so revocation after compromise is impossible.",
    remediation:
      "Set a bounded session lifetime with rolling renewal, store a server-side session version for revocation, and require re-auth for sensitive operations.",
    payload: `Attack: harvest one session cookie (logs, shared machine, XSS) and replay it months later\nEffect: long-lived unauthorized access with no expiry to wait out.`,
    pattern: /(?:maxAge|expires)\s*:\s*(?:Infinity|false)\b|session\.(?:set|put)\s*\([^)]*\)(?![^;]*(?:expire|maxAge))/i,
    maxMatchesPerFile: 4,
    safeHints: ["maxAge", "expire", "ttl"],
  },
  {
    id: "PRIV-001",
    title: "Authorization decided by client-supplied role/claim",
    severity: "critical",
    description:
      "Authorization logic trusts a role, isAdmin, or scope value taken directly from the request (body/query/headers) instead of the server-side session or a verified token claim. Attackers simply send role=admin.",
    remediation:
      "Read roles exclusively from the verified session or a signed, verified token claim issued server-side; treat any request-supplied identity data as untrusted input.",
    payload: `Request: POST /api/admin/panel  body: {"role":"admin"}\nEffect: privilege escalation — the check reads the attacker-supplied role and grants admin actions.`,
    pattern: /(?:if|switch)\s*\(\s*(?:req\.(?:body|query|params|headers)|request\.(?:json|headers))\.?(?:role|isAdmin|admin|scope|permission|permissions|privilege)/i,
    maxMatchesPerFile: 4,
  },
  {
    id: "PRIV-002",
    title: "Role check missing on admin/destructive route",
    severity: "high",
    description:
      "A route named for administrative or destructive operations has no visible role/permission middleware. Anyone authenticated (or unauthenticated, if auth middleware is also absent) can invoke it.",
    remediation:
      "Attach role/permission middleware to every admin route (e.g. requireRole('admin')) and default-deny: routes are admin-only unless explicitly opened.",
    payload: `Request: DELETE /api/admin/users/42 as a regular authenticated user\nEffect: destructive admin action executed without privilege checks.`,
    pattern: /(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*["'][^"']*(?:\/admin|\/manage|\/users\/delete|\/delete-user|\/reset-password|\/role)[^"']*["']\s*(?:,\s*(?!.*(requireRole|requireAdmin|isAdmin|authorize|middleware|auth))[^)]*)?/i,
    maxMatchesPerFile: 4,
    safeHints: ["requireRole", "requireAdmin", "isAdmin", "authorize", "guard", "middleware", "checkRole"],
  },
  {
    id: "BRUTE-001",
    title: "Login endpoint without rate limiting or lockout",
    severity: "high",
    description:
      "An authentication route processes credential checks with no visible rate limiter, attempt counter, or account lockout. Automated credential stuffing and brute force can run unchecked — billions of leaked credentials make this the most common attack on internet-facing logins.",
    remediation:
      "Add per-IP and per-account rate limiting (e.g. express-rate-limit), exponential backoff or temporary lockout after repeated failures, CAPTCHA on suspicion, and breached-password screening (k-anonymity via HIBP).",
    payload: `Attack: spray 10k leaked email:password pairs from a botnet against /login\nEffect: valid credentials identified (0.1–1% hit rate typical); account takeover at scale.`,
    pattern: /(?:app|router)\.(?:post)\s*\(\s*["'][^"']*(?:\/login|\/signin|\/sign-in|\/auth|\/password)[^"']*["']\s*(?:,\s*(?!.*(rateLimit|limiter|slowDown|brute|lockout|captcha))[^)]*)?/i,
    maxMatchesPerFile: 3,
    safeHints: ["rateLimit", "rate-limit", "limiter", "slowDown", "lockout", "captcha", "attempts", "brute"],
  },
  {
    id: "BRUTE-002",
    title: "Password comparison not constant-time (timing side channel)",
    severity: "medium",
    description:
      "A password or token comparison uses === or == instead of a constant-time comparison (crypto.timingSafeEqual / bcrypt.compare). Response-time differences let attackers recover secrets byte-by-byte.",
    remediation:
      "Compare secrets with crypto.timingSafeEqual (after length check) or delegate to bcrypt/argon2 compare; never string-compare secrets.",
    payload: `Attack: measure response times across candidate bytes (e.g. 'a'…'z' at each position)\nEffect: secret reconstructed from timing deltas without brute-forcing the whole space.`,
    pattern: /(?:password|passwd|token|secret|hash|apiKey)\s*(?:===|==)\s*(?:req\.|body\.|query\.|provided|input|candidate)/i,
    maxMatchesPerFile: 4,
    safeHints: ["timingSafeEqual", "bcrypt", "argon2", "compare", "scrypt"],
  },
];

/** Run the auth & session attack pass over one file. `excludeLines` skips already-reported lines. */
export function detectAuthAttacks(input: ScanInput, excludeLines: Set<number>): Finding[] {
  const lines = input.content.split("\n");
  const findings: Finding[] = [];
  const reportedLines = new Set<number>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("#")) continue;
    if (excludeLines.has(i + 1) || reportedLines.has(i + 1)) continue;

    for (const rule of RULES) {
      const m = rule.pattern.exec(line);
      if (!m) continue;
      if (rule.safeHints?.some((h) => line.toLowerCase().includes(h.toLowerCase()))) continue;

      findings.push({
        ruleId: rule.id,
        title: rule.title,
        severity: rule.severity,
        category: CATEGORY,
        owasp: OWASP_A07,
        file: input.name,
        line: i + 1,
        snippet: trimmed.slice(0, 220),
        description: rule.description,
        remediation: rule.remediation,
        payload: rule.payload,
      });
      reportedLines.add(i + 1);
      break;
    }
  }
  return findings;
}
