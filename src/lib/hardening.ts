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
  // Fuzzing pass (Part 13)
  "FUZZ-001": {
    difficulty: "easy",
    effort: "~30 min per pattern",
    steps: [
      "Cap input length before any regex runs on untrusted data.",
      "Replace risky patterns with linear-time alternatives (RE2, or rewrite nested quantifiers).",
      "Validate the pattern with safe-regex / recheck in CI.",
    ],
    before: 'const ok = /^(a+)+$/.test(req.body.name);',
    after: 'const ok = req.body.name.length <= 64 && safePattern.test(req.body.name);',
    verify: "Re-scan; FUZZ-001 findings gone, and a 100k-char input completes in <10ms.",
  },
  "FUZZ-002": {
    difficulty: "trivial",
    effort: "~10 min per site",
    steps: [
      "Validate with a schema (zod) at the boundary instead of raw parsing.",
      "Check Number.isFinite and clamp to the expected range immediately.",
    ],
    before: "const page = parseInt(req.query.page);",
    after: "const page = pageSchema.parse(req.query.page); // zod: int().min(1).max(1000)",
    verify: "Re-scan; send 'abc' and '1e999' to the endpoint — expect a clean 400.",
  },
  "FUZZ-003": {
    difficulty: "trivial",
    effort: "~10 min per site",
    steps: [
      "Wrap JSON.parse in try/catch, or use a body parser with strict mode.",
      "Return 400 (not 500) on malformed input.",
    ],
    before: "const data = JSON.parse(req.body.raw);",
    after: "let data;\ntry { data = JSON.parse(req.body.raw); } catch { return res.status(400).json({ error: \"invalid JSON\" }); }",
    verify: "Re-scan; POST '{' to the endpoint — expect 400, no stack trace.",
  },
  "FUZZ-004": {
    difficulty: "easy",
    effort: "~20 min per site",
    steps: [
      "Clamp every user-supplied size/count to a hard maximum before allocating.",
      "Enforce body-size and page-size limits at the edge (proxy or framework).",
    ],
    before: "const buf = Buffer.alloc(Number(req.query.size));",
    after: "const size = Math.min(Number(req.query.size) || 0, 1_048_576);\nconst buf = Buffer.alloc(size);",
    verify: "Re-scan; request size=2000000000 — expect a clean 413/400, not an OOM kill.",
  },
  "FUZZ-005": {
    difficulty: "easy",
    effort: "~30 min per handler",
    steps: [
      "Validate request bodies against a schema at the boundary (zod/valibot).",
      "Use optional chaining for defensive nested reads.",
    ],
    before: "const city = req.body.user.address.city;",
    after: "const city = userSchema.parse(req.body).address?.city;",
    verify: "Re-scan; POST '[1,2]' and 'null' — expect 400, not 500.",
  },
  "FUZZ-006": {
    difficulty: "easy",
    effort: "~15 min per site",
    steps: [
      "Reject non-integer and out-of-range values before use.",
      "Clamp indices to [0, length-1]; bound loops by a constant max.",
    ],
    before: "const item = items[Number(req.query.idx)];\nfor (let i = 0; i < count; i++) process(items[i]);",
    after: "const idx = clampInt(req.query.idx, 0, items.length - 1);\nconst item = items[idx];\nfor (let i = 0; i < Math.min(count, MAX_ITEMS); i++) process(items[i]);",
    verify: "Re-scan; send idx=-1 and idx=999999999 — expect bounded behavior.",
  },
  "FUZZ-007": {
    difficulty: "easy",
    effort: "~30 min",
    steps: [
      "Strip control/format characters (\\u202A-\\u202E, \\u200B-\\u200F, \\uFEFF) from input.",
      "Use structured logging (JSON fields) instead of string interpolation.",
    ],
    before: 'logger.info(`User ${req.body.name} logged in`);',
    after: "logger.info({ event: \"login\", user: sanitize(req.body.name) });",
    verify: "Re-scan; a name containing \\u202E no longer corrupts the log line.",
  },
  // Auth & session attack pass (Part 14)
  "JWT-002": {
    difficulty: "easy",
    effort: "~20 min",
    steps: [
      "Pin exactly one algorithm per verification path (algorithms: ['RS256']).",
      "Keep asymmetric and symmetric verification in separate code paths.",
      "Reject tokens whose header alg differs from the pinned value.",
    ],
    before: "jwt.verify(token, key, { algorithms: ['HS256', 'RS256'] });",
    after: "jwt.verify(token, publicKey, { algorithms: ['RS256'] });",
    verify: "Re-scan; craft an HS256-signed token with the public key — expect rejection.",
  },
  "JWT-003": {
    difficulty: "easy",
    effort: "~20 min + rotation",
    steps: [
      "Move the signing secret to a secret manager / environment (≥256-bit random).",
      "Rotate the exposed secret; support kid-based key rotation.",
      "Purge the old value from git history.",
    ],
    before: 'jwt.sign(payload, "s3cr3t-key", { expiresIn: "1h" });',
    after: "jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: \"1h\" });",
    verify: "Re-scan; tokens signed with the old secret must be rejected.",
  },
  "JWT-004": {
    difficulty: "easy",
    effort: "~15 min",
    steps: [
      "Replace jwt.decode with jwt.verify wherever claims drive authorization.",
      "Reserve decode for pre-inspection/logging only.",
    ],
    before: "const claims = jwt.decode(token); if (claims.role === 'admin') allow();",
    after: "const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] });\nif (claims.role === 'admin') allow();",
    verify: "Re-scan; a token with a garbage signature must now be rejected with 401.",
  },
  "SESS-001": {
    difficulty: "easy",
    effort: "~20 min",
    steps: [
      "Regenerate the session id immediately after successful login.",
      "Never accept session ids from URLs or query parameters.",
    ],
    before: "req.session.user = user; // same pre-auth session id kept",
    after: "req.session.regenerate((err) => {\n  req.session.user = user;\n  res.redirect('/dashboard');\n});",
    verify: "Re-scan; log in and confirm the session cookie value changed.",
  },
  "SESS-002": {
    difficulty: "trivial",
    effort: "~10 min",
    steps: [
      "Set secure: true, httpOnly: true, sameSite: 'lax' on every session cookie.",
      "Force HTTPS with HSTS so secure cookies are never downgraded.",
    ],
    before: "res.cookie('sid', id, { maxAge: 86400000 });",
    after: "res.cookie('sid', id, { maxAge: 86400000, secure: true, httpOnly: true, sameSite: 'lax' });",
    verify: "Re-scan; check Set-Cookie headers with curl -I — all three flags present.",
  },
  "SESS-003": {
    difficulty: "easy",
    effort: "~30 min",
    steps: [
      "Set a bounded session lifetime with rolling renewal on activity.",
      "Store a server-side session version to enable instant revocation.",
    ],
    before: "req.session.cookie.maxAge = Infinity;",
    after: "req.session.cookie.maxAge = 24 * 60 * 60 * 1000; // 24h, rolling",
    verify: "Re-scan; a session idle for >24h must require re-authentication.",
  },
  "PRIV-001": {
    difficulty: "moderate",
    effort: "~1–2 h",
    steps: [
      "Read roles exclusively from the verified session or signed token claims.",
      "Treat every request-supplied identity field as untrusted data.",
      "Add a regression test that posts role=admin as a normal user.",
    ],
    before: "if (req.body.role === 'admin') { grantAdmin(); }",
    after: "const session = await getSession(req); // server-side only\nif (session?.role === 'admin') { grantAdmin(); }",
    verify: "Re-scan; POST role=admin as a normal user must have no effect.",
  },
  "PRIV-002": {
    difficulty: "moderate",
    effort: "~1 h per route group",
    steps: [
      "Attach role middleware to every admin/destructive route.",
      "Default-deny: routes are admin-only unless explicitly opened.",
      "Enumerate routes in CI to catch future unguarded admin endpoints.",
    ],
    before: 'router.delete("/admin/users/:id", handler);',
    after: 'router.delete("/admin/users/:id", requireRole("admin"), handler);',
    verify: "Re-scan; call the route as a regular user — expect 403.",
  },
  "BRUTE-001": {
    difficulty: "easy",
    effort: "~30 min",
    steps: [
      "Add per-IP and per-account rate limiting (express-rate-limit or equivalent).",
      "Add temporary lockout or exponential backoff after repeated failures.",
      "Screen passwords against breached-password corpora (HIBP k-anonymity).",
    ],
    before: 'app.post("/login", loginHandler);',
    after: 'app.post("/login", loginLimiter, loginHandler);\n// loginLimiter: 5 attempts / 15 min per IP+account, then 429',
    verify: "Re-scan; 20 rapid failed logins must trigger 429/lockout.",
  },
  "BRUTE-002": {
    difficulty: "trivial",
    effort: "~10 min",
    steps: [
      "Replace === secret comparisons with a constant-time comparison.",
      "Prefer bcrypt.compare / argon2.verify for passwords.",
    ],
    before: "if (user.password === req.body.password) { login(); }",
    after: "const ok = await bcrypt.compare(req.body.password, user.passwordHash);\nif (ok) { login(); }",
    verify: "Re-scan; timing across candidate bytes no longer correlates with correctness.",
  },
  // Crypto misuse pass (Part 15)
  "CIV-001": {
    difficulty: "easy",
    effort: "~20 min",
    steps: [
      "Generate a fresh random IV per encryption call.",
      "Prepend the IV to the ciphertext (IVs are public but must never repeat).",
    ],
    before: 'const IV = Buffer.from("0123456789abcdef");\ncipher = crypto.createCipheriv("aes-256-cbc", key, IV);',
    after: "const iv = crypto.randomBytes(16);\nconst out = Buffer.concat([iv, encrypted]); // store iv with ciphertext",
    verify: "Re-scan; encrypt the same plaintext twice — ciphertexts must differ.",
  },
  "CIV-002": {
    difficulty: "moderate",
    effort: "~1–2 h (data migration)",
    steps: [
      "Switch the mode string to aes-256-gcm.",
      "Store and verify the authTag on every ciphertext.",
      "Re-encrypt existing data during a migration window.",
    ],
    before: 'crypto.createCipheriv("aes-256-ecb", key, null);',
    after: 'const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);\nconst tag = cipher.getAuthTag(); // store with ciphertext',
    verify: "Re-scan; ECB mode no longer appears anywhere in the codebase.",
  },
  "CIV-003": {
    difficulty: "easy",
    effort: "~30 min",
    steps: [
      "Replace the fixed nonce with crypto.randomBytes(12) per message (GCM).",
      "If using counters, persist and increment them per key; never reset.",
    ],
    before: 'const nonce = Buffer.from("00112233445566778899aabb");',
    after: "const nonce = crypto.randomBytes(12); // unique per message, stored with ciphertext",
    verify: "Re-scan; no literal nonce bytes remain in cipher construction.",
  },
  "CKEY-001": {
    difficulty: "involved",
    effort: "~1 day (key rotation)",
    steps: [
      "Raise RSA modulus to 3072+ or move to ECC P-256/Ed25519.",
      "Use AES-256 keys for symmetric encryption.",
      "Rotate undersized keys and re-encrypt stored data.",
    ],
    before: "generateKeyPairSync('rsa', { modulusLength: 1024 })",
    after: "generateKeyPairSync('rsa', { modulusLength: 3072 })",
    verify: "Re-scan; no sub-2048-bit RSA or sub-128-bit AES keys remain.",
  },
  "CKEY-002": {
    difficulty: "moderate",
    effort: "~2–4 h",
    steps: [
      "Migrate to AES-GCM (authenticated encryption).",
      "If CBC must stay, add encrypt-then-MAC with HMAC-SHA256 and verify before decrypting.",
    ],
    before: 'const enc = crypto.createCipheriv("aes-256-cbc", key, iv).update(data);',
    after: 'const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);\nconst enc = Buffer.concat([cipher.update(data), cipher.final()]);\nconst tag = cipher.getAuthTag(); // verify on decrypt',
    verify: "Re-scan; tampered ciphertext must fail decryption with an auth error.",
  },
  "CPBK-001": {
    difficulty: "moderate",
    effort: "~2–4 h (hash migration)",
    steps: [
      "Switch password hashing to bcrypt (cost ≥ 12) or Argon2id.",
      "Re-hash transparently on next successful login (legacy hash → new KDF).",
      "Never log or transmit the plaintext password.",
    ],
    before: "crypto.createHash('sha256').update(password).digest('hex');",
    after: "const hash = await bcrypt.hash(password, 12);",
    verify: "Re-scan; stored hashes now carry the bcrypt/argon2 prefix ($2b$ / $argon2id$).",
  },
  "CPBK-002": {
    difficulty: "trivial",
    effort: "~10 min",
    steps: [
      "Raise PBKDF2 iterations to ≥ 600,000 (SHA-256) or 210,000 (SHA-512).",
      "Consider migrating to Argon2id for better GPU resistance.",
    ],
    before: "crypto.pbkdf2Sync(password, salt, 10000, 32, 'sha256');",
    after: "crypto.pbkdf2Sync(password, salt, 600000, 32, 'sha256');",
    verify: "Re-scan; login latency stays under ~250ms with the new count.",
  },
  "CCERT-001": {
    difficulty: "easy",
    effort: "~30 min",
    steps: [
      "Remove the verification bypass entirely.",
      "For internal self-signed services, provide the private CA via NODE_EXTRA_CA_CERTS or pin the SPKI hash.",
    ],
    before: "https.get(url, { rejectUnauthorized: false }, cb);",
    after: "https.get(url, { ca: fs.readFileSync('internal-ca.pem') }, cb);",
    verify: "Re-scan; MITM with a self-signed cert must fail the connection.",
  },
  "CRAND-001": {
    difficulty: "trivial",
    effort: "~10 min",
    steps: [
      "Replace timestamp/counter-derived randomness with crypto.randomBytes.",
    ],
    before: "const iv = Date.now().toString(16);",
    after: "const iv = crypto.randomBytes(16);",
    verify: "Re-scan; generated IVs are unpredictable across runs.",
  },
  "CDES-001": {
    difficulty: "involved",
    effort: "~1 day (data migration)",
    steps: [
      "Inventory all data encrypted with the legacy cipher.",
      "Decrypt once and re-encrypt with AES-256-GCM in a migration window.",
      "Remove the legacy cipher code path.",
    ],
    before: 'crypto.createCipheriv("des-ede3-cbc", key, iv);',
    after: 'crypto.createCipheriv("aes-256-gcm", key, iv); // + authTag handling',
    verify: "Re-scan; no DES/3DES/RC4/Blowfish references remain.",
  },
  // Injection deep-scan pass (Part 16)
  "LDAP-001": {
    difficulty: "easy",
    effort: "~30 min",
    steps: [
      "Escape filter metacharacters per RFC 4515 with a dedicated encoder.",
      "Prefer library APIs that parameterize filter values.",
      "Validate input shape before it reaches any filter.",
    ],
    before: 'const filter = `(&(uid=${req.body.user})(pw=${req.body.pw}))`;',
    after: "const filter = `(&(uid=${ldapEscape.filter(req.body.user)})(pw=${ldapEscape.filter(req.body.pw)}))`;",
    verify: "Re-scan; a username of '*)' must no longer alter the filter.",
  },
  "LDAP-002": {
    difficulty: "easy",
    effort: "~30 min",
    steps: [
      "Escape DN metacharacters per RFC 4514.",
      "Build DNs from validated, allowlisted components only.",
    ],
    before: 'const dn = `uid=${req.body.user},ou=people,dc=corp,dc=com`;',
    after: "const dn = `uid=${ldapEscape.dn(req.body.user)},ou=people,dc=corp,dc=com`;",
    verify: "Re-scan; a username containing ',' must not re-root the DN.",
  },
  "SSTI-001": {
    difficulty: "moderate",
    effort: "~1–2 h",
    steps: [
      "Render user input as template data (context), never as template source.",
      "Replace render_template_string with static templates + context vars.",
      "If dynamic templates are unavoidable, sandbox and allowlist functions.",
    ],
    before: "render_template_string(req.args.get('tpl'))",
    after: "render_template('greeting.html', name=req.args.get('name'))",
    verify: "Re-scan; {{7*7}} in any input must render literally, not evaluate.",
  },
  "SSTI-002": {
    difficulty: "moderate",
    effort: "~1–2 h",
    steps: [
      "Keep templates as static files in the repository.",
      "Pass user input strictly as render context variables.",
    ],
    before: 'ejs.render(`<h1>${req.query.tpl}</h1>`, {});',
    after: 'ejs.renderFile("views/hello.ejs", { name: req.query.name });',
    verify: "Re-scan; no compile/render call receives a string containing request data.",
  },
  "ORM-001": {
    difficulty: "easy",
    effort: "~30 min per query",
    steps: [
      "Use the ORM's parameterized raw form (Prisma $queryRaw`…` tagged template, knex.raw with ? bindings).",
      "Replace *Unsafe variants ($queryRawUnsafe, $executeRawUnsafe) with the safe forms.",
    ],
    before: 'prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${req.params.id}`);',
    after: "prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`; // tagged template = parameterized",
    verify: "Re-scan; an id of '1; DROP TABLE users' must be treated as a literal string.",
  },
  "ORM-002": {
    difficulty: "easy",
    effort: "~30 min",
    steps: [
      "Pick typed fields explicitly instead of spreading the request body.",
      "Validate with a schema and strip operator-like keys ($gt, Op.or, __gt).",
    ],
    before: "db.user.findMany({ where: req.body });",
    after: "const { email } = userSchema.parse(req.body);\ndb.user.findMany({ where: { email } });",
    verify: "Re-scan; a body of {\"$ne\":null} must not alter the filter.",
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
