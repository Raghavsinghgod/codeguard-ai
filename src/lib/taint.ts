// CrackScope Part 3 — lightweight taint tracking.
// A pragmatic dataflow layer (no full AST parser needed): identifies
// user-input "sources" across language families, propagates taint through
// local assignments, and lets sink rules demand a source→sink flow before
// firing. This cuts false positives dramatically versus pattern-only
// matching while staying instant and dependency-free.

export interface TaintState {
  /** Variables known to carry user-controlled data at some point in the file. */
  taintedVars: Set<string>;
}

/**
 * Expressions that read attacker-controlled input.
 * Covers the common web-framework source shapes across JS/TS, Python,
 * PHP, Go, and Ruby. Intentionally broad — a false "source" here only
 * affects whether a sink finding fires.
 */
const SOURCE_RE =
  /req(?:uest)?\.(?:query|body|params|headers|cookies|args|form|json|data|values|GET|POST|files|files)\b|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b|\binput\s*\(|sys\.argv|process\.argv\b|r\.URL\.Query|r\.FormValue\(|r\.Body\b|c\.(?:Query|Param|PostForm|Bind)\b|\bparams\[/;

const ASSIGN_RE =
  /^\s*(?:const|let|var|final)?\s*([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*(?!=)(.+)$/;

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function referencesTainted(line: string, taintedVars: Set<string>): boolean {
  for (const v of taintedVars) {
    if (new RegExp(`\\b${escapeRegExp(v)}\\b`).test(line)) return true;
  }
  return false;
}

/**
 * Single-flow pass over a file's lines: a variable becomes tainted when it
 * is assigned from a source expression, a template/concat containing one,
 * or another tainted variable. Chained assignments propagate in order.
 */
export function computeTaint(lines: string[]): TaintState {
  const taintedVars = new Set<string>();
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith("//") || line.startsWith("#")) continue;
    const m = ASSIGN_RE.exec(line);
    if (!m) continue;
    const [, name, rhs] = m;
    if (SOURCE_RE.test(rhs) || referencesTainted(rhs, taintedVars)) {
      taintedVars.add(name);
    }
  }
  return { taintedVars };
}

/**
 * True when a sink line demonstrably carries user-controlled data:
 * either a source appears directly on the line, or it references a
 * variable the taint pass marked as attacker-controlled.
 */
export function isLineTainted(line: string, state: TaintState): boolean {
  return SOURCE_RE.test(line) || referencesTainted(line, state.taintedVars);
}
