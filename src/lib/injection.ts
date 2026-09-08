// CrackScope Part 16 — injection deep-scan.
// Extends the Part 1/3 injection rules with variant classes the base engine
// does not cover: LDAP filter injection, server-side template injection
// (SSTI), ORM raw-query injection, and LDAP DN injection. Where relevant the
// payload is selected per database/engine context (MySQL/Postgres/MSSQL/
// SQLite/Mongo) so the simulated attack matches the detected stack.
import type { Finding, ScanInput, Severity } from "./scanner";
import { computeTaint, isLineTainted } from "./taint";

const CATEGORY = "Injection";
const OWASP_A03 = "A03:2021 – Injection";

interface DeepRule {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  remediation: string;
  /** payload template; ${engine} replaced with the detected engine context when available. */
  payload: string;
  pattern: RegExp;
  maxMatchesPerFile: number;
  taintRequired?: boolean;
  safeHints?: string[];
}

export const RULES: DeepRule[] = [
  {
    id: "LDAP-001",
    title: "LDAP filter injection (search filter built from input)",
    severity: "high",
    description:
      "An LDAP search filter is assembled from user input without escaping. Metacharacters like * ( ) \\ NUL alter filter logic — attackers bypass authentication filters, enumerate directory entries, or dump the entire tree.",
    remediation:
      "Escape filter metacharacters per RFC 4515 (\\28 \\29 \\5c \\2a and non-printables) with a dedicated encoder, or use a library API that parameterizes filter values. Also validate input shape before it reaches the filter.",
    payload: `Input: username = *)(objectClass=*  (or cn=*)(&(password=*))\nResulting filter: (&(uid=*)(objectClass=*)(&(password=*)))\nEffect: authentication filter always matches — login bypass; iterate attributes for full directory enumeration.`,
    pattern: /(?:search|find|ldap_search|searchEntries)\s*\(\s*[`'"][^`'"]*(?:\(&|objectClass|\|%s|\$\{|'\s*\+)|filter\s*=\s*[`'"][^`'"]*\(&/i,
    maxMatchesPerFile: 4,
    taintRequired: true,
    safeHints: ["escape", "sanitize", "encode", "ldap.escape"],
  },
  {
    id: "LDAP-002",
    title: "LDAP DN injection (distinguished name built from input)",
    severity: "high",
    description:
      "A distinguished name (bind DN, base DN, or entry DN) is built from user input. Injected commas/equals signs re-root the DN — attackers bind as arbitrary entries or write objects into unintended OUs.",
    remediation:
      "Escape DN metacharacters (leading space/#, trailing space, , + \" \\ < > ;) per RFC 4514, or construct DNs from validated, allowlisted components only.",
    payload: `Input: username = x,ou=Attackers,dc=corp\nResulting DN: uid=x,ou=Attackers,dc=corp,dc=com\nEffect: bind/write operations re-rooted into an attacker-chosen OU.`,
    pattern: /(?:bind|add|modify)\s*\(\s*[`'"][^`'"]*(?:\$\{|%s|\+\s*\w+|\w+\s*\+)|dn\s*=\s*[`'"][^`'"]*\$\{/i,
    maxMatchesPerFile: 4,
    taintRequired: true,
    safeHints: ["escape", "sanitize", "encode"],
  },
  {
    id: "SSTI-001",
    title: "Server-side template injection (user input into template engine)",
    severity: "critical",
    description:
      "User input is rendered through a template engine (Jinja2, EJS, Handlebars, Pug, Thymeleaf, Velocity) as template source rather than as data. Crafted expressions evaluate server-side: {{7*7}}, <%= %>, #{…} — escalating to full RCE via template sandboxes' escape hatches.",
    remediation:
      "Render user input as template *data* (context variables), never as template source. If dynamic templates are unavoidable, sandbox the engine (no eval-based loaders), allowlist functions, and validate input against template syntax before rendering.",
    payload: `Probe: {{7*7}} → 49 (Jinja2) · <%= 7*7 %> → 49 (EJS) · #{7*7} → 49 (Thymeleaf)\nEscalation: {{ ''.__class__.__mro__[1].__subclasses__() }} → Python RCE\nEffect: server-side code execution with the app's privileges.`,
    pattern: /(?:render|render_template_string|renderTemplate|ejs\.render|handlebars\.compile|pug\.render|template\s*\()?\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:query|json|args))\s*\)|render_template_string\s*\(/,
    maxMatchesPerFile: 4,
    taintRequired: true,
    safeHints: ["render_template(", "renderTemplate(", "context", "locals"],
  },
  {
    id: "SSTI-002",
    title: "Template engine used with user-controlled template source",
    severity: "critical",
    description:
      "A template engine compiles a string that includes user input (ejs.render with concatenated template, Handlebars.compile of request data). Even 'safe' engines become RCE when the template source itself is attacker-controlled.",
    remediation:
      "Keep templates as static files; pass user input strictly as render context. Never compile strings that embed request data.",
    payload: `Input: template = "<%= process.env.FLAG %>" (attacker-controlled)\nEffect: arbitrary JS expression evaluation inside the Node process — secrets and env vars exfiltrated.`,
    pattern: /(?:ejs\.render|handlebars\.compile|pug\.compile|hbs\.compile|nunjucks\.renderString|template\.render)\s*\(\s*(?:req\.|request\.|`[^`]*\$\{|['"][^'"]*['"]\s*\+)/,
    maxMatchesPerFile: 4,
    taintRequired: true,
  },
  {
    id: "ORM-001",
    title: "Raw query escape hatch with interpolated input (ORM bypass)",
    severity: "high",
    description:
      "An ORM's raw-query escape hatch (sequelize.literal, knex.raw, Prisma $queryRaw with template interpolation, Django extra/raw, TypeORM query) receives interpolated user input. Parameter binding is skipped — classic SQL injection through the ORM.",
    remediation:
      "Use the ORM's parameterized raw form: Prisma $queryRaw`…${value}` tagged templates (safe) vs $queryRawUnsafe (unsafe), knex.raw('… ?', [v]), Django raw params list. Never interpolate values into raw SQL strings.",
    payload: `Input: id = 1; DROP TABLE users;--\nRaw query: SELECT * FROM users WHERE id = 1; DROP TABLE users;--\nEffect: full SQL injection despite the ORM — stacked statements or boolean-based exfiltration depending on driver.`,
    pattern: /(?:\$queryRawUnsafe|\$executeRawUnsafe|knex\.raw|sequelize\.literal|\.query\s*\(\s*`[^`]*\$\{|extra\s*\(|rawQuery\s*\()/,
    maxMatchesPerFile: 4,
    taintRequired: true,
    safeHints: ["$queryRaw`", "$executeRaw`", "sql`", "bind", "parameters"],
  },
  {
    id: "ORM-002",
    title: "ORM filter built from raw request object",
    severity: "high",
    description:
      "An ORM filter/where clause is constructed directly from request data without field allowlisting. Beyond mass-assignment, attackers craft operator objects ($gt, $ne, Op.or, __gt suffixes) to alter query logic or read unintended columns.",
    remediation:
      "Pick typed fields explicitly (const { email, name } = req.body), validate with a schema, and strip operator-like keys before they reach the filter.",
    payload: `Request body: {"email":{"$ne":null},"password":{"$ne":null}} (or Django: ?age__gt=0)\nEffect: filter matches every row — login bypass / bulk data read via operator injection.`,
    pattern: /(?:where|filter|findAll|findOne|findMany)\s*\(\s*\{\s*(?:\.\.\.(?:req|request|body|query)|where\s*:\s*req\.(?:body|query)|filter\s*:\s*req\.(?:body|query))|req\.(?:body|query)\s*\)|request\.(?:json|args)\s*\)/,
    maxMatchesPerFile: 4,
    taintRequired: true,
    safeHints: ["pick", "omit", "zod", "schema", "validate"],
  },
];

/** Database-engine-aware payload variants for SQL-family findings. */
export function enginePayloads(engine: string, base: string): string {
  const variants: Record<string, string> = {
    mysql: `Engine variant (MySQL): ' OR 1=1-- - · UNION SELECT user,password FROM mysql.user · sleep(5) for time-based blind\nStacked queries: disabled by default (mysqli) — boolean/error-based preferred.`,
    postgres: `Engine variant (PostgreSQL): ' OR 1=1-- · UNION SELECT usename,passwd FROM pg_shadow · pg_sleep(5)\nExtras: COPY TO PROGRAM for RCE with superuser; error-based via cast errors.`,
    mssql: `Engine variant (MSSQL): ' OR 1=1-- · WAITFOR DELAY '0:0:5' time-based blind\nExtras: xp_cmdshell for RCE if enabled; stacked queries allowed by default.`,
    sqlite: `Engine variant (SQLite): ' OR 1=1-- · UNION SELECT sql FROM sqlite_master (schema dump)\nNo stacked queries; attach-database and readfile() variants for file access.`,
    mongo: `Engine variant (MongoDB): operator injection {"$gt":""}, {"$where":"sleep(5000)"} for blind extraction.`,
  };
  const key = engine.toLowerCase();
  const variant = variants[key];
  return variant ? `${base}\n${variant}` : base;
}

/** Guess the database engine from manifest content (package.json / requirements.txt). */
export function detectEngine(input: ScanInput): string | null {
  const c = input.content;
  if (nameMatches(input.name, ["package.json", "package-lock.json"])) {
    if (/"mongoose"/.test(c) || /mongodb/.test(c)) return "mongo";
    if (/"pg"|postgres/.test(c)) return "postgres";
    if (/"mysql"/.test(c)) return "mysql";
    if (/"sqlite"|better-sqlite3/.test(c)) return "sqlite";
    if (/"mssql"|tedious/.test(c)) return "mssql";
    return null;
  }
  if (nameMatches(input.name, ["requirements.txt", "Pipfile", "pyproject.toml"])) {
    if (/psycopg|postgres/.test(c)) return "postgres";
    if (/pymysql|mysqlclient/.test(c)) return "mysql";
    if (/pymongo/.test(c)) return "mongo";
    if (/sqlite/.test(c)) return "sqlite";
    if (/pymssql/.test(c)) return "mssql";
    return null;
  }
  return null;
}

function nameMatches(name: string, candidates: string[]): boolean {
  return candidates.some((c) => name === c || name.endsWith("/" + c));
}

/** Run the injection deep-scan pass over one file. `excludeLines` skips already-reported lines. */
export function runInjectionDeepScan(
  input: ScanInput,
  excludeLines: Set<number>,
  engine: string | null,
): Finding[] {
  const lines = input.content.split("\n");
  const taint = computeTaint(lines);
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
      if (rule.taintRequired && !isLineTainted(line, taint)) continue;
      if (rule.safeHints?.some((h) => line.toLowerCase().includes(h.toLowerCase()))) continue;

      findings.push({
        ruleId: rule.id,
        title: rule.title,
        severity: rule.severity,
        category: CATEGORY,
        owasp: OWASP_A03,
        file: input.name,
        line: i + 1,
        snippet: trimmed.slice(0, 220),
        description: rule.description,
        remediation: rule.remediation,
        payload: enginePayloads(engine ?? "", rule.payload),
      });
      reportedLines.add(i + 1);
      break;
    }
  }
  return findings;
}
