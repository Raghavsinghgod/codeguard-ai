// CrackScope Part 10 — hardening recommendations.
// Per-rule fix recipes: difficulty, estimated effort, concrete steps,
// before/after code, and a verification step. Falls back to a
// category-level recipe for any rule without a dedicated guide.
import type { Finding, ScanResult, Severity } from "./scanner";

export type Difficulty = "trivial" | "easy" | "moderate" | "involved";

export interface HardeningGuide {
  difficulty: Difficulty;
  effort: string;
  steps: string[];
  before?: string;
  after?: string;
  verify: string;
}

export const DIFFICULTY_CHIP: Record<Difficulty, string> = {
  trivial: "border-primary/30 bg-primary/10 text-primary",
  easy: "border-[oklch(0.75_0.12_220)]/40 bg-[oklch(0.75_0.12_220)]/10 text-[oklch(0.78_0.11_220)]",
  moderate: "border-[oklch(0.8_0.16_85)]/40 bg-[oklch(0.8_0.16_85)]/10 text-[oklch(0.82_0.14_85)]",
  involved: "border-[oklch(0.75_0.15_55)]/40 bg-[oklch(0.75_0.15_55)]/10 text-[oklch(0.78_0.14_55)]",
};

const GUIDES: Record<string, HardeningGuide> = {
  "SQLI-001": {
    difficulty: "easy",
    effort: "~30 min per query",
    steps: [
      "Replace every string-built query with a parameterized call.",
      "Move the SQL text to a constant; pass values as bind parameters.",
      "Grep for `query(`, `execute(` with `+` to catch the stragglers.",
    ],
    before: "db.query(\"SELECT * FROM users WHERE name='\" + req.body.user + \"'\");",
    after: "db.query(\"SELECT * FROM users WHERE name = ?\", [req.body.user]);",
    verify: "Re-run the scan — SQLI-001 should be gone; try the tautology payload manually against a test DB.",
  },
  "SQLI-002": {
    difficulty: "easy",
    effort: "~30 min per query",
    steps: [
      "Stop formatting values into SQL text (f-strings, %s, ${}).",
      "Use the driver's parameter binding or an ORM filter expression.",
    ],
    before: "cursor.execute(f\"SELECT * FROM items WHERE id = {item_id}\")",
    after: "cursor.execute(\"SELECT * FROM items WHERE id = %s\", (item_id,))",
    verify: "Re-scan; confirm SQLI-002 findings dropped to zero.",
  },
  "XSS-001": {
    difficulty: "easy",
    effort: "~15 min per sink",
    steps: [
      "Prefer textContent / default React escaping over raw HTML.",
      "Where HTML is required, sanitize with DOMPurify before insertion.",
    ],
    before: "el.innerHTML = userSuppliedHtml;",
    after: "el.innerHTML = DOMPurify.sanitize(userSuppliedHtml);",
    verify: "Re-scan; paste an <img onerror> payload into the affected field in a test build.",
  },
  "XSS-002": {
    difficulty: "easy",
    effort: "~30 min",
    steps: [
      "HTML-encode every reflected value before it lands in markup.",
      "Add a strict Content-Security-Policy as defense in depth.",
    ],
    before: "res.send(`<h1>Results for ${req.query.q}</h1>`);",
    after: "res.send(`<h1>Results for ${escapeHtml(req.query.q)}</h1>`);",
    verify: "Re-scan; check the CSP header with curl -I.",
  },
  "CMD-001": {
    difficulty: "moderate",
    effort: "~1 h",
    steps: [
      "Replace exec() with execFile/spawn without shell:true.",
      "Pass arguments as an argv array — never interpolate into the command.",
      "If input must select a file, map allowlisted ids to paths instead.",
    ],
    before: "exec(`cat reports/${req.params.file}`, cb);",
    after: "execFile(\"cat\", [path.join(REPORTS_DIR, req.params.file)], cb);",
    verify: "Re-scan; attempt `file=../../etc/passwd` against a test instance.",
  },
  "CMD-002": {
    difficulty: "moderate",
    effort: "1–4 h",
    steps: [
      "Remove eval/new Function entirely.",
      "Parse structured data with JSON.parse; map strings to functions via a lookup table.",
      "If you truly need expressions, use a sandboxed evaluator (expr-eval, jexl) with no host access.",
    ],
    before: "const result = eval(userExpression);",
    after: "const result = LOOKUP[userExpression]?.() ?? parseExpression(userExpression);",
    verify: "Re-scan; grep for `eval(` and `new Function(` returning nothing.",
  },
  "SEC-001": {
    difficulty: "trivial",
    effort: "~10 min + rotation",
    steps: [
      "Move the value to an environment variable / secret manager.",
      "Rotate the exposed credential immediately — code history is forever.",
      "Add the file pattern to .gitignore and a pre-commit secret scan.",
    ],
    before: 'const API_KEY = "sk_live_9f8a7b6c...";',
    after: "const API_KEY = process.env.API_KEY;",
    verify: "Re-scan; confirm the secret was revoked with the provider.",
  },
  "CRYPTO-001": {
    difficulty: "easy",
    effort: "~30 min–2 h (data migration)",
    steps: [
      "For integrity: switch to SHA-256 or better.",
      "For passwords: migrate to bcrypt/argon2 with per-user salts.",
      "Re-hash lazily on next login to avoid a big-bang migration.",
    ],
    before: "const hash = createHash(\"md5\").update(pw).digest(\"hex\");",
    after: "const hash = await argon2.hash(pw);",
    verify: "Re-scan; log in with a pre-migration account to confirm the lazy re-hash path.",
  },
  "CRYPTO-002": {
    difficulty: "trivial",
    effort: "~5 min",
    steps: [
      "Replace Math.random() with a CSPRNG for tokens, ids, and nonces.",
    ],
    before: "const token = Math.random().toString(36).substring(2);",
    after: "const token = crypto.randomBytes(32).toString(\"hex\");",
    verify: "Re-scan; confirm session tokens are 256-bit CSPRNG output.",
  },
  "CRYPTO-003": {
    difficulty: "trivial",
    effort: "~5 min",
    steps: [
      "Delete the verification-disabling flag.",
      "For self-signed dev servers, pin the specific CA certificate instead.",
    ],
    before: "https.get(url, { rejectUnauthorized: false }, cb);",
    after: "https.get(url, { ca: INTERNAL_CA_PEM }, cb);",
    verify: "Re-scan; run the app against a valid endpoint to confirm TLS succeeds.",
  },
  "AUTH-001": {
    difficulty: "easy",
    effort: "~30 min",
    steps: [
      "Pin the accepted algorithms at verification (no alg from the token).",
      "Load the secret from the environment with a strong random value.",
      "Validate exp/iss/aud claims explicitly.",
    ],
    before: 'jwt.verify(token, "secret", { ignoreExpiration: true });',
    after: 'jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"], issuer: "myapp" });',
    verify: "Re-scan; attempt an alg:none forged token against a test deployment — it must be rejected.",
  },
  "AUTH-002": {
    difficulty: "moderate",
    effort: "1–4 h",
    steps: [
      "Scope every query by the authenticated principal, not just the id.",
      "Centralize the ownership check in one helper/middleware.",
      "Add authorization tests for cross-tenant access.",
    ],
    before: "const inv = await db.invoice.findUnique({ where: { id: req.params.id } });",
    after: "const inv = await db.invoice.findFirst({ where: { id: req.params.id, userId: session.userId } });",
    verify: "Re-scan; request another user's record id — expect 404/403.",
  },
  "PATH-001": {
    difficulty: "easy",
    effort: "~30 min",
    steps: [
      "Resolve the requested path against a fixed base directory.",
      "Reject resolved paths that escape the base (prefix check).",
      "Prefer allowlisted ids mapped to filenames over raw input paths.",
    ],
    before: 'fs.readFile("uploads/" + req.params.path, cb);',
    after: "const p = path.resolve(UPLOADS_DIR, req.params.path);\nif (!p.startsWith(UPLOADS_DIR + path.sep)) return res.status(400).end();\nfs.readFile(p, cb);",
    verify: "Re-scan; request `..%2f..%2fetc%2fpasswd` — expect rejection.",
  },
  "NOSQL-001": {
    difficulty: "easy",
    effort: "~30 min",
    steps: [
      "Never pass raw request objects into queries — pick typed fields.",
      "Validate payloads with a schema (zod/joi) and strip $-prefixed keys.",
    ],
    before: "db.users.findOne({ email: req.body.email, password: req.body.password });",
    after: "const { email, password } = loginSchema.parse(req.body);\ndb.users.findOne({ email: String(email) }); // password verified with bcrypt.compare",
    verify: "Re-scan; POST {\"email\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}} — login must fail.",
  },
  "SSRF-001": {
    difficulty: "moderate",
    effort: "1–2 h",
    steps: [
      "Allowlist target hosts and schemes; never fetch raw user URLs.",
      "Resolve DNS first and block private/link-local/loopback ranges.",
      "Disable redirect following for outbound fetches.",
    ],
    before: "const data = await fetch(req.query.targetUrl).then(r => r.json());",
    after: "const url = new URL(req.query.targetUrl);\nif (!ALLOWED_HOSTS.has(url.hostname) || isPrivateIp(await lookup(url.hostname))) return res.status(400).end();\nconst data = await fetch(url, { redirect: \"error\" }).then(r => r.json());",
    verify: "Re-scan; try http://169.254.169.254/ and http://127.0.0.1:8080/ — both must be blocked.",
  },
  "DESER-001": {
    difficulty: "moderate",
    effort: "1–4 h",
    steps: [
      "Switch to data-only formats: JSON, or yaml.safe_load.",
      "Delete unpickle/unserialize/yaml.load paths entirely.",
      "Validate the parsed shape against a schema before use.",
    ],
    before: "data = pickle.loads(request.body)",
    after: "data = PayloadSchema(**json.loads(request.body))",
    verify: "Re-scan; send a __reduce__ payload — it must be treated as plain invalid JSON.",
  },
  "CONFIG-001": {
    difficulty: "trivial",
    effort: "~10 min",
    steps: [
      "Restrict CORS to an explicit origin allowlist.",
      "Enable credentials only for those specific origins.",
    ],
    before: 'app.use(cors({ origin: "*" }));',
    after: 'app.use(cors({ origin: ["https://app.example.com"], credentials: true }));',
    verify: "Re-scan; curl -H \"Origin: https://evil.tld\" -I — no ACAO header must come back.",
  },
  "CONFIG-002": {
    difficulty: "trivial",
    effort: "~10 min",
    steps: [
      "Gate debug flags on the environment (NODE_ENV !== \"production\").",
      "Return generic error pages; log details server-side only.",
    ],
    before: 'app.run(debug=True)',
    after: 'if os.environ.get("FLASK_ENV") == "development":\n    app.run(debug=True)\nelse:\n    serve(app)',
    verify: "Re-scan; trigger a 500 in production config — the response must not contain a stack trace.",
  },
  "REDIR-001": {
    difficulty: "easy",
    effort: "~20 min",
    steps: [
      "Validate redirect targets against an allowlist of relative paths or hosts.",
      "Fall back to a known-safe default when validation fails.",
    ],
    before: "res.redirect(req.query.next);",
    after: "const next = req.query.next;\nres.redirect(next && next.startsWith(\"/\") && !next.startsWith(\"//\") ? next : \"/dashboard\");",
    verify: "Re-scan; try ?next=https://evil.tld — must land on the default.",
  },
  "PROTO-001": {
    difficulty: "easy",
    effort: "~20 min",
    steps: [
      "Block __proto__/constructor/prototype keys in recursive merges.",
      "Or switch to structuredClone / Object.create(null) based merging.",
    ],
    before: "merge(defaults, req.body);",
    after: "merge(defaults, JSON.parse(sanitize(JSON.stringify(req.body)))); // sanitize strips __proto__/constructor",
    verify: "Re-scan; POST {\"__proto__\":{\"isAdmin\":true}} — ({}).isAdmin must stay undefined.",
  },
  // Secrets pass (Part 6) — shared recipe; rotation guidance is per-provider in remediation.
  "SECRET-": {
    difficulty: "trivial",
    effort: "~10 min + rotation",
    steps: [
      "Revoke the exposed credential at the provider immediately.",
      "Issue a new one into the secret manager / environment.",
      "Purge the value from git history (git filter-repo / BFG).",
    ],
    before: 'stripe_key = "sk_live_..."',
    after: "stripe_key = os.environ[\"STRIPE_SECRET_KEY\"]",
    verify: "Re-scan; confirm the old key returns 401 from the provider.",
  },
  // Dependency & supply-chain pass (Part 7)
  "DEP-001": {
    difficulty: "easy",
    effort: "~15 min per package",
    steps: [
      "Bump the package to the fixed version (see the finding).",
      "Run the test suite — check the changelog for breaking changes.",
      "Commit the updated lockfile.",
    ],
    before: '"lodash": "4.17.15"',
    after: '"lodash": "4.17.21"',
    verify: "Re-scan; the CVE finding for this package is gone.",
  },
  "DEP-002": {
    difficulty: "easy",
    effort: "~15 min",
    steps: [
      'Add an npm "overrides" (or yarn "resolutions") entry pinning the transitive package to the fixed version.',
      "Reinstall to regenerate the lockfile; run the test suite.",
    ],
    before: '// transitive semver@6.3.0 stays vulnerable\nnpm install',
    after: '// package.json\n"overrides": { "semver": "^6.3.1" }\nnpm install',
    verify: "Re-scan; the transitive finding no longer appears in the lockfile audit.",
  },
  "DEP-003": {
    difficulty: "easy",
    effort: "~15 min per package",
    steps: [
      "Update the pinned requirement to the fixed version.",
      "Regenerate the environment and run tests.",
    ],
    before: "pyyaml==5.3.1",
    after: "pyyaml>=5.4",
    verify: "Re-scan; the pip finding is gone.",
  },
  "SUPPLY-001": {
    difficulty: "easy",
    effort: "~20 min",
    steps: [
      "Remove network/exec calls from install & lifecycle scripts.",
      "Move the step into a reviewed build script committed to the repo.",
      "Run CI installs with --ignore-scripts where feasible.",
    ],
    before: '"setup": "curl -s https://example.com/install.sh | bash"',
    after: '"setup": "node scripts/setup.js" // reviewed in-repo, no network at install time',
    verify: "Re-scan; the install-script finding is gone.",
  },
  "SUPPLY-002": {
    difficulty: "trivial",
    effort: "~5 min per dep",
    steps: [
      'Pin the exact version (replace *, latest, or loose ranges).',
      'Use "npm ci" in CI so installs match the lockfile exactly.',
    ],
    before: '"json-utils": "*"',
    after: '"json-utils": "1.2.3"',
    verify: "Re-scan; no unpinned-dependency findings remain.",
  },
  "SUPPLY-003": {
    difficulty: "trivial",
    effort: "~5 min",
    steps: [
      "Verify the package name is intentional — check downloads, repo, maintainers.",
      "If it was a typo for a popular package, fix the name and reinstall.",
    ],
    before: '"reacts": "^18.0.0"',
    after: '"react": "^18.2.0"',
    verify: "Re-scan; the typosquat finding is gone.",
  },
};

// Category fallback for anything without a dedicated guide.
const CATEGORY_GUIDE: Record<string, HardeningGuide> = {
  Injection: {
    difficulty: "moderate",
    effort: "1–2 h",
    steps: [
      "Neutralize the injection sink with the platform's parameterized/safe API.",
      "Add input validation on the affected field.",
      "Re-scan and re-test the documented payload.",
    ],
    verify: "Re-scan — the finding must not reappear.",
  },
};

export function hardeningFor(finding: Finding): HardeningGuide {
  const exact = GUIDES[finding.ruleId];
  if (exact) return exact;
  if (finding.ruleId.startsWith("SECRET-")) return GUIDES["SECRET-"];
  if (finding.ruleId.startsWith("DEP-")) return GUIDES["DEP-001"];
  if (finding.ruleId.startsWith("SUPPLY-")) return GUIDES["SUPPLY-002"];
  return CATEGORY_GUIDE[finding.category] ?? {
    difficulty: "moderate",
    effort: "~1 h",
    steps: [
      "Apply the remediation described on the finding.",
      "Re-scan to confirm the finding disappears.",
    ],
    verify: "Re-scan — the finding must not reappear.",
  };
}

// ---------- repo-wide hardening plan ----------

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface PlanItem {
  ruleId: string;
  title: string;
  severity: Severity;
  difficulty: Difficulty;
  effort: string;
  occurrences: number;
  files: string[];
}

export interface HardeningPlan {
  items: PlanItem[];
  counts: Record<Difficulty, number>;
}

export function hardeningPlan(result: ScanResult): HardeningPlan {
  const byRule = new Map<string, PlanItem>();
  for (const f of result.findings) {
    const guide = hardeningFor(f);
    const existing = byRule.get(f.ruleId);
    if (existing) {
      existing.occurrences += 1;
      if (!existing.files.includes(f.file)) existing.files.push(f.file);
    } else {
      byRule.set(f.ruleId, {
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity,
        difficulty: guide.difficulty,
        effort: guide.effort,
        occurrences: 1,
        files: [f.file],
      });
    }
  }
  const items = [...byRule.values()].sort(
    (a, b) =>
      SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) ||
      b.occurrences - a.occurrences,
  );
  const counts: Record<Difficulty, number> = { trivial: 0, easy: 0, moderate: 0, involved: 0 };
  for (const item of items) counts[item.difficulty]++;
  return { items, counts };
}
