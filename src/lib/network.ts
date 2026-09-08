// CrackScope Part 17 — network surface mapper.
// Builds a map of the application's network attack surface from source:
// discovers HTTP endpoints from route definitions across frameworks,
// analyzes CORS posture, maps the SSRF-reachable surface, and graphs
// redirect targets. Produces both findings (via the shared Finding shape
// for actionable weaknesses) and a NetworkSurface summary for the report.
import type { Finding, ScanInput, Severity } from "./scanner";

const OWASP_A05 = "A05:2021 – Security Misconfiguration";
const OWASP_A01 = "A01:2021 – Broken Access Control";
const OWASP_A10 = "A10:2021 – Server-Side Request Forgery";

export interface Endpoint {
  method: string;
  path: string;
  file: string;
  line: number;
  /** route-level middleware names detected between the path and the handler */
  middleware: string[];
}

export interface RedirectEdge {
  from: string; // endpoint path or "unknown"
  target: string; // redirect target expression
  file: string;
  line: number;
  validated: boolean;
}

export interface NetworkSurface {
  endpoints: Endpoint[];
  corsWildcard: boolean;
  corsReflectsOrigin: boolean;
  ssrfSinks: { file: string; line: number; target: string; taintSuspicious: boolean }[];
  redirects: RedirectEdge[];
  unvalidatedRedirects: number;
  authlessMutating: Endpoint[];
}

interface SurfaceRule {
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

const METHOD_PATTERN =
  /\b(?:app|router|server|fastify|api)\s*\.\s*(get|post|put|patch|delete|all|options|head)\s*\(\s*["'`]([^"'`]+)["'`]/gi;

const MIDDLEWARE_HINTS = [
  "auth", "authz", "requireUser", "requireAuth", "isAuthenticated", "session",
  "admin", "role", "permission", "guard", "token", "jwt", "apiKey", "rateLimit",
  "limiter", "validate", "csrf", "cors", "helmet", "multer", "upload",
];

function extractEndpoints(input: ScanInput): Endpoint[] {
  const lines = input.content.split("\n");
  const endpoints: Endpoint[] = [];
  for (let i = 0; i < lines.length; i++) {
    METHOD_PATTERN.lastIndex = 0;
    const m = METHOD_PATTERN.exec(lines[i]);
    if (!m) continue;
    // Collect middleware identifiers between the path and end of code
    // (strip trailing comments so words like 'auth' in comments don't count).
    const codePart = lines[i].split("//")[0];
    const afterPath = codePart.slice(m.index + m[0].length);
    const idents = afterPath.match(/[A-Za-z_$][\w$]*/g) ?? [];
    const middleware = [...new Set(idents.filter((id) =>
      MIDDLEWARE_HINTS.some((h) => id.toLowerCase().includes(h.toLowerCase())),
    ))];
    endpoints.push({
      method: m[1].toUpperCase(),
      path: m[2],
      file: input.name,
      line: i + 1,
      middleware,
    });
  }
  return endpoints;
}

const SURFACE_RULES: SurfaceRule[] = [
  {
    id: "NET-001",
    title: "Mutating endpoint without authentication middleware",
    severity: "high",
    description:
      "A data-mutating route (POST/PUT/PATCH/DELETE) has no authentication/authorization middleware in its handler chain. Unauthenticated state changes are the cheapest attack on any internet-facing API.",
    remediation:
      "Attach auth middleware to the route (or a router-level requireAuth for the whole group) and verify the principal is allowed to mutate the targeted resource.",
    payload: `Request: DELETE /api/items/42 with no credentials\nEffect: unauthenticated data destruction — automated scanners probe mutating routes first.`,
    pattern: /never-matches-net001/, // endpoint-derived; handled separately
    maxMatchesPerFile: 0,
  },
  {
    id: "NET-002",
    title: "CORS middleware reflects arbitrary origin with credentials",
    severity: "high",
    description:
      "CORS is configured to reflect the request's Origin header back with Access-Control-Allow-Credentials enabled. Any origin becomes trusted: an attacker's page can read authenticated responses from victims' browsers.",
    remediation:
      "Replace dynamic origin reflection with a static allowlist; only set credentials for allowlisted origins, and never combine origin reflection with allow-credentials.",
    payload: `Attack page (evil.tld): fetch('https://app.tld/api/me', {credentials:'include'}) with Origin: https://evil.tld\nEffect: server reflects evil.tld in ACAO + allows credentials — victim's private data readable cross-origin.`,
    pattern: /(?:origin\s*:\s*(?:true|\(?\s*(?:req|request)\b[^)]*\)?\s*=>)|Access-Control-Allow-Origin["'\s:]+(?:req\.headers\.origin|\*))/i,
    maxMatchesPerFile: 4,
    safeHints: ["allowlist", "whitelist", "allowedOrigins", "credentials: false"],
  },
  {
    id: "NET-003",
    title: "Internal/loopback URL construction in server-side request",
    severity: "medium",
    description:
      "A server-side request targets localhost, a private IP range, or an internal hostname. If any part of the target derives from input, this marks the internal-network pivot surface for SSRF; even hardcoded internal calls document the surface for attackers reading the code.",
    remediation:
      "Prefer service-to-service auth over raw internal calls; block private/link-local ranges on any user-influenced outbound fetch; document internal endpoints as SSRF-protected assets.",
    payload: `Attack: SSRF probe via any user-controlled URL parameter → internal service at 127.0.0.1:PORT or 169.254.169.254\nEffect: cloud metadata / internal admin panels reachable through the server.`,
    pattern: /(?:fetch|axios(?:\.(?:get|post))?|requests\.get|urlopen|http\.Get)\s*\(\s*(?:["']https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)|["']https?:\/\/[^"']*(?:internal|local|metadata)[^"']*["'])/i,
    maxMatchesPerFile: 4,
  },
  {
    id: "NET-004",
    title: "Redirect to external/absolute URL target",
    severity: "medium",
    description:
      "A redirect targets an absolute URL (http(s):// or protocol-relative //). When the target derives from input, this is an open redirect; even static absolute redirects expand the phishable surface if any parameter can influence the destination.",
    remediation:
      "Redirect to relative paths only; validate absolute targets against an allowlist of trusted hosts; reject protocol-relative and scheme-mismatched targets.",
    payload: `Link: https://app.tld/logout?next=//evil-phish.tld/clone (protocol-relative bypasses naive scheme checks)\nEffect: victim bounced to a phishing clone with the trusted domain as referrer.`,
    pattern: /(?:res\.redirect|redirect\(|redirectTo|window\.location(?:\.href)?\s*=)\s*\(?\s*(?:["']https?:\/\/|["']\/\/|`[^`]*(?:https?:\/\/|\/\/))/i,
    maxMatchesPerFile: 4,
    safeHints: ["allowlist", "whitelist", "trusted", "validated", "startsWith('/')"],
  },
];

const REDIRECT_PATTERN = /(?:res\.redirect|redirect|redirectTo)\s*\(\s*([^;)]{1,120})/i;

/** Build the network surface map for one file. */
function mapSurface(input: ScanInput): { endpoints: Endpoint[]; redirects: RedirectEdge[]; ssrf: { file: string; line: number; target: string; taintSuspicious: boolean }[] } {
  const lines = input.content.split("\n");
  const endpoints = extractEndpoints(input);
  const redirects: RedirectEdge[] = [];
  const ssrf: { file: string; line: number; target: string; taintSuspicious: boolean }[] = [];

  const currentEndpoint = (lineIdx: number): string => {
    for (let j = lineIdx; j >= 0; j--) {
      METHOD_PATTERN.lastIndex = 0;
      const m = METHOD_PATTERN.exec(lines[j]);
      if (m) return `${m[1].toUpperCase()} ${m[2]}`;
    }
    return "unknown";
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const rm = REDIRECT_PATTERN.exec(line);
    if (rm) {
      const target = rm[1].trim();
      const validated = /(?:allowlist|whitelist|trusted|valid)/.test(line) || /encodeURI|resolve/.test(line);
      redirects.push({ from: currentEndpoint(i), target, file: input.name, line: i + 1, validated });
    }
    const ssrfM = /(?:fetch|axios(?:\.(?:get|post))?|requests\.get|urlopen)\s*\(\s*([^;)]{1,120})/.exec(line);
    if (ssrfM) {
      const target = ssrfM[1].trim();
      const taintSuspicious = /req\.|request\.|params|query|body|url\s*\+|\$\{/.test(target);
      if (taintSuspicious || /https?:\/\/(?:localhost|127\.0\.0\.1|10\.|192\.168\.|169\.254\.)/i.test(target)) {
        ssrf.push({ file: input.name, line: i + 1, target, taintSuspicious });
      }
    }
  }
  return { endpoints, redirects, ssrf };
}

/** Run the network surface pass over one file. `excludeLines` skips already-reported lines. */
export function runNetworkScan(input: ScanInput, excludeLines: Set<number>): { findings: Finding[]; surface: Partial<NetworkSurface> } {
  const lines = input.content.split("\n");
  const findings: Finding[] = [];
  const reportedLines = new Set<number>();
  const { endpoints, redirects, ssrf } = mapSurface(input);

  const push = (rule: SurfaceRule, lineNo: number) => {
    findings.push({
      ruleId: rule.id,
      title: rule.title,
      severity: rule.severity,
      category: "Network Surface",
      owasp: rule.id === "NET-004" ? OWASP_A01 : OWASP_A05,
      file: input.name,
      line: lineNo,
      snippet: (lines[lineNo - 1] ?? "").trim().slice(0, 220),
      description: rule.description,
      remediation: rule.remediation,
      payload: rule.payload,
    });
    reportedLines.add(lineNo);
  };

  // NET-001: mutating endpoints without auth middleware.
  for (const ep of endpoints) {
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(ep.method)) continue;
    if (ep.middleware.some((m) => /auth|admin|role|permission|guard|token|jwt|session|apiKey/i.test(m))) continue;
    if (excludeLines.has(ep.line) || reportedLines.has(ep.line)) continue;
    push(SURFACE_RULES[0], ep.line);
  }

  for (const rule of SURFACE_RULES.slice(1)) {
    for (let i = 0; i < lines.length; i++) {
      if (excludeLines.has(i + 1) || reportedLines.has(i + 1)) continue;
      const m = rule.pattern.exec(lines[i]);
      if (!m) continue;
      if (rule.safeHints?.some((h) => lines[i].toLowerCase().includes(h.toLowerCase()))) continue;
      push(rule, i + 1);
      break;
    }
  }

  const corsWildcard = /Access-Control-Allow-Origin["'\s:]+\*|origin\s*:\s*["']\*["']/.test(input.content);
  const corsReflectsOrigin = SURFACE_RULES[1].pattern.test(input.content);

  return {
    findings,
    surface: {
      endpoints,
      corsWildcard,
      corsReflectsOrigin,
      ssrfSinks: ssrf,
      redirects,
      unvalidatedRedirects: redirects.filter((r) => !r.validated).length,
      authlessMutating: endpoints.filter(
        (e) => ["POST", "PUT", "PATCH", "DELETE"].includes(e.method) &&
          !e.middleware.some((m) => /auth|admin|role|permission|guard|token|jwt|session|apiKey/i.test(m)),
      ),
    },
  };
}
