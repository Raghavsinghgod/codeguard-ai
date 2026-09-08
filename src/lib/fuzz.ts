// CrackScope Part 13 — fuzzing module.
// Simulates input fuzzing against user-controlled flows found in the code:
// mutation strategies (boundary, overflow, type confusion, unicode, format
// strings) are applied to detected input sources, and crash-pattern
// heuristics predict which mutations would break the target — ReDoS,
// unhandled parse crashes, memory exhaustion, type errors, out-of-bounds
// access. Everything is simulated client-side; no requests are ever sent.
import type { Finding, ScanInput, Severity } from "./scanner";
import { computeTaint, isLineTainted } from "./taint";

const CATEGORY = "Fuzzing / Robustness";
const OWASP_A04 = "A04:2021 – Insecure Design";

interface FuzzRule {
  id: string;
  title: string;
  severity: Severity;
  /** What the fuzzer does to the input. */
  strategy: string;
  /** The mutated input that breaks it. */
  sample: string;
  /** Simulated outcome of the fuzz iteration. */
  outcome: string;
  description: string;
  remediation: string;
  pattern: RegExp;
  maxMatchesPerFile: number;
  taintRequired?: boolean;
  safeHints?: string[];
}

const FUZZ_RULES: FuzzRule[] = [
  {
    id: "FUZZ-001",
    title: "Regex evaluated on user input (ReDoS surface)",
    severity: "high",
    strategy: "pathological backtracking strings (a.a.a.a…b, ((a+)+)b)",
    sample: `input = "a".repeat(28) + "!"  // nested-quantifier killer`,
    outcome: "request thread pegged at 100% CPU for >30s — single request starves the event loop (simulated)",
    description:
      "A regular expression is evaluated against user-controlled data. Patterns with nested quantifiers or overlapping alternations fall into catastrophic backtracking on crafted input, freezing the request thread (ReDoS).",
    remediation:
      "Avoid regex over untrusted input where possible; use RE2 / safe-regex-validated patterns, cap input length before matching, and add request timeouts.",
    pattern: /(?:new RegExp\s*\(|\.(?:test|match|matchAll|exec|replace|replaceAll|split)\s*\()/,
    maxMatchesPerFile: 4,
    taintRequired: true,
  },
  {
    id: "FUZZ-002",
    title: "Numeric parse of user input without NaN guard",
    severity: "medium",
    strategy: "non-numeric and boundary mutations ('abc', '1e999', '-0', ' 12', '0x1f')",
    sample: `input = "1e999"  // parses to Infinity`,
    outcome: "NaN/Infinity propagated into pricing and pagination logic — downstream comparison always false; record set returned empty or unbounded (simulated 500s on 34% of mutations)",
    description:
      "User input is parsed as a number (parseInt/parseFloat/Number/+) with no NaN or range check. Fuzzed mutations produce NaN or Infinity that silently corrupt queries, pagination, and arithmetic.",
    remediation:
      "Validate with a schema (zod) before use, check Number.isFinite and clamp to expected ranges immediately after parsing.",
    pattern: /\b(?:parseInt|parseFloat|Number)\s*\(|(?<!=)\+\s*req\.(?:query|params|body)/,
    maxMatchesPerFile: 4,
    taintRequired: true,
    safeHints: ["isNaN", "Number.isFinite", "isFinite", "zod", "schema", "validate"],
  },
  {
    id: "FUZZ-003",
    title: "JSON.parse on user input without error handling",
    severity: "medium",
    strategy: "malformed JSON mutations ('{', '[1,', '\"\\ud800\", trailing garbage)",
    sample: `input = '{"a":'  // truncated JSON`,
    outcome: "uncaught SyntaxError — simulated HTTP 500 on 41% of mutations; attacker can fail an endpoint at will (availability)",
    description:
      "JSON.parse is called on request data without a surrounding try/catch or schema validation. Any malformed body crashes the request handler with an unhandled exception.",
    remediation:
      "Parse inside try/catch or use a body parser with strict mode plus schema validation; return 400 on malformed input instead of crashing.",
    pattern: /JSON\.parse\s*\(\s*(?:req\.|request\.|body|payload|data)/,
    maxMatchesPerFile: 4,
    safeHints: ["try", "catch", "safeParse", "zod"],
  },
  {
    id: "FUZZ-004",
    title: "Unbounded memory allocation from user input",
    severity: "high",
    strategy: "huge-count mutations ('9'.repeat(1e9), length = 2**31)",
    sample: `input = { "size": 2000000000 }`,
    outcome: "simulated OOM: allocation of ~2 GB from a 24-byte request — process killed, all in-flight requests dropped",
    description:
      "A length/count/size value derived from user input drives an allocation (Buffer.alloc, Array, repeat, string padding). Crafted sizes exhaust process memory — a one-request denial of service.",
    remediation:
      "Clamp every user-supplied size to a hard maximum before allocating; reject requests exceeding limits at the edge (body size, page size, count).",
    pattern: /(?:Buffer\.alloc(?:Unsafe)?|new Array|\.repeat\(|padStart\(|padEnd\(|slice\()\s*[^;)]*(?:req\.(?:query|body|params)|request\.)/,
    maxMatchesPerFile: 4,
    taintRequired: true,
  },
  {
    id: "FUZZ-005",
    title: "Deep property access on unvalidated request body",
    severity: "medium",
    strategy: "type-confusion mutations (arrays, null, strings where objects expected)",
    sample: `input = '["not","an","object"]'  // body is an array, not the expected shape`,
    outcome: "TypeError: Cannot read properties of undefined — simulated 500 on 28% of mutations; 500s leak stack traces when debug responses are enabled",
    description:
      "Nested properties are read straight off request data (req.body.a.b.c) without validating the shape. Fuzzed type mutations (null, arrays, scalars) throw TypeErrors that turn into 500 responses.",
    remediation:
      "Validate request bodies against a schema at the boundary (zod/valibot) and use optional chaining for defensive reads of nested data.",
    pattern: /req\.(?:body|query|params)\.[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*/,
    maxMatchesPerFile: 4,
    safeHints: ["?.", "zod", "schema", "typeof"],
  },
  {
    id: "FUZZ-006",
    title: "User input used as array index or loop bound",
    severity: "medium",
    strategy: "out-of-range mutations (-1, 1e9, 0.5, MAX_SAFE_INTEGER+1)",
    sample: `input = "-1"  // negative index reads from array end; 1e9 hangs the loop`,
    outcome: "simulated out-of-bounds read returning undefined data, plus a 12-second hot loop on the count mutation — request queue backlog",
    description:
      "A user-controlled value indexes an array or bounds a loop without range validation. Negative or huge indices read unintended elements or stall the event loop.",
    remediation:
      "Clamp indices to [0, length-1], reject non-integer values, and bound every loop whose limit derives from input.",
    pattern: /\[[^\]]*(?:req\.(?:query|body|params)|request\.|idx|index|offset)\b[^\]]*\]|\bfor\s*\([^;]*;\s*\w+\s*<\s*(?:req\.|parseInt|Number)/,
    maxMatchesPerFile: 4,
    taintRequired: true,
  },
  {
    id: "FUZZ-007",
    title: "String formatting/template built from user input",
    severity: "low",
    strategy: "format-string and unicode mutations (%s%n%p, RTL overrides, zero-width chars)",
    sample: `input = "%s%s%s%s%n" + "\\u202Egol\\u202D"  // format specifiers + bidi spoof`,
    outcome: "simulated log forgery: attacker-controlled lines injected into audit logs with spoofed directionality, breaking log-based forensics",
    description:
      "User input flows into string formatting, templates, or log lines without normalization. Format-specifier and bidi/zero-width mutations enable log injection and display spoofing.",
    remediation:
      "Strip control/format characters (\\u202A-\\u202E, \\u200B-\\u200F, \\uFEFF) from input, use structured/parameterized logging, and never interpolate raw input into format strings.",
    pattern: /(?:console\.log|logger\.\w+|log\.\w+|util\.format|String\.format|sprintf)\s*\([^)]*(?:req\.(?:query|body|params)|request\.)/,
    maxMatchesPerFile: 4,
    taintRequired: true,
  },
];

interface FuzzSession {
  strategy: string;
  iterations: number;
  triggered: number;
}

/** Build the simulated fuzz-session narrative appended to the payload. */
function sessionSummary(sessions: FuzzSession[]): string {
  const total = sessions.reduce((n, s) => n + s.iterations, 0);
  const triggered = sessions.reduce((n, s) => n + s.triggered, 0);
  return `\nFuzz session (simulated): ${total} mutations across ${sessions.length} strategies → ${triggered} crash-inducing inputs. Top strategy: ${sessions.sort((a, b) => b.triggered - a.triggered)[0]?.strategy ?? "n/a"}.`;
}

/** Run the fuzzing pass over one file. `excludeLines` skips already-reported lines. */
export function runFuzzing(input: ScanInput, excludeLines: Set<number>): Finding[] {
  const lines = input.content.split("\n");
  const taint = computeTaint(lines);
  const findings: Finding[] = [];
  const reportedLines = new Set<number>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("#")) continue;
    if (excludeLines.has(i + 1) || reportedLines.has(i + 1)) continue;

    for (const rule of FUZZ_RULES) {
      if (!rule.pattern.test(line)) continue;
      if (rule.taintRequired && !isLineTainted(line, taint)) continue;
      if (rule.safeHints?.some((h) => line.toLowerCase().includes(h.toLowerCase()))) continue;

      // Deterministic pseudo-random session stats derived from rule + line,
      // so the same code always produces the same simulated session.
      const seed = [...rule.id].reduce((n, c) => n + c.charCodeAt(0), 0) + (i + 1) * 7;
      const sessions: FuzzSession[] = [
        { strategy: rule.strategy, iterations: 180 + (seed % 120), triggered: 2 + (seed % 9) },
        { strategy: "boundary values (0, -1, MAX_INT, empty)", iterations: 96, triggered: seed % 5 },
        { strategy: "type confusion (null, arrays, nested)", iterations: 96, triggered: (seed >> 2) % 6 },
        { strategy: "unicode & format-string mutations", iterations: 72, triggered: (seed >> 3) % 4 },
      ];

      findings.push({
        ruleId: rule.id,
        title: rule.title,
        severity: rule.severity,
        category: CATEGORY,
        owasp: OWASP_A04,
        file: input.name,
        line: i + 1,
        snippet: trimmed.slice(0, 220),
        description: rule.description,
        remediation: rule.remediation,
        payload: `Fuzz iteration:\n  strategy: ${rule.strategy}\n  input: ${rule.sample}\n  observed: ${rule.outcome}${sessionSummary(sessions)}`,
      });
      reportedLines.add(i + 1);
      break;
    }
  }
  return findings;
}
