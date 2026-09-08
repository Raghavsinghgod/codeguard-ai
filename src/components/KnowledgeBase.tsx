// CrackScope Part 23 — attack knowledge base tab.
// Searchable technique library (MITRE/OWASP-inspired) mapped to live scan
// findings: coverage panel shows which techniques actually hit your code.
import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  BookOpen,
  ChevronDown,
  Crosshair,
  Loader2,
  Search,
  ShieldCheck,
  Target,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import type { Finding, Severity } from "@/lib/scanner";
import {
  TACTICS,
  TECHNIQUES,
  severityRank,
  searchTechniques,
  techniqueCoverage,
  techniqueForFinding,
  type Technique,
} from "@/lib/techniques";

const severityClass: Record<Severity, string> = {
  critical: "border-destructive/40 bg-destructive/10 text-destructive",
  high: "border-destructive/30 bg-destructive/5 text-destructive",
  medium: "border-[oklch(0.8_0.16_85)]/40 bg-[oklch(0.8_0.16_85)]/10 text-[oklch(0.75_0.14_85)]",
  low: "border-border bg-muted text-muted-foreground",
  info: "border-border bg-muted text-muted-foreground",
};

// Live findings from the most recent scan (falls back to empty → pure library).
function useLiveFindings(): {
  findings: Finding[];
  loading: boolean;
  latestName: string | null;
} {
  const scans = useQuery(api.scans.listScans);
  if (scans === undefined) return { findings: [], loading: true, latestName: null };
  const latest = scans[0];
  if (!latest) return { findings: [], loading: false, latestName: null };
  return { findings: latest.findings as Finding[], loading: false, latestName: latest.name };
}

function severityBadge(sev: Severity, count?: number) {
  return (
    <Badge variant="outline" className={`rounded-full font-mono text-[10px] ${severityClass[sev]}`}>
      {sev}
      {count !== undefined ? ` ×${count}` : ""}
    </Badge>
  );
}

function TechniqueCard({ technique, liveCount }: { technique: Technique; liveCount?: number }) {
  const [open, setOpen] = useState(false);
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
    >
      <Card className="border-border/60 bg-card/60">
        <CardContent className="p-5">
          <button
            className="flex w-full cursor-pointer items-start gap-3 text-left"
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
          >
            <span className="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 font-mono text-[10px] font-semibold text-primary">
              {technique.id}
            </span>
            <span className="min-w-0 flex-1">
              <span className="flex flex-wrap items-center gap-2">
                <span className="font-medium tracking-tight">{technique.name}</span>
                {liveCount !== undefined && (
                  <Badge className="rounded-full bg-primary text-[10px] text-primary-foreground">
                    <Target className="mr-1 size-3" /> {liveCount} live
                  </Badge>
                )}
              </span>
              <span className="mt-1 flex flex-wrap items-center gap-1.5">
                <Badge variant="outline" className="rounded-full font-mono text-[10px] text-muted-foreground">
                  {technique.tactic}
                </Badge>
                {severityBadge(technique.severity)}
                <Badge variant="outline" className="rounded-full font-mono text-[10px] text-muted-foreground">
                  {technique.owasp}
                </Badge>
              </span>
              <span className="mt-2 block text-sm text-muted-foreground">{technique.summary}</span>
            </span>
            <ChevronDown
              className={`mt-1 size-4 shrink-0 text-muted-foreground transition-transform ${open ? "rotate-180" : ""}`}
            />
          </button>

          {open && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              className="mt-4 space-y-4 overflow-hidden border-t border-border/60 pt-4"
            >
              <section>
                <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">Attack flow</p>
                <ol className="mt-2 space-y-1.5">
                  {technique.attackFlow.map((step, i) => (
                    <li key={i} className="flex gap-2 text-sm">
                      <span className="font-mono text-xs text-primary">{i + 1}.</span>
                      <span className="text-muted-foreground">{step}</span>
                    </li>
                  ))}
                </ol>
              </section>

              <section>
                <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">Payloads</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {technique.payloads.map((p) => (
                    <code
                      key={p}
                      className="rounded-md border border-border/60 bg-secondary/50 px-2 py-1 font-mono text-xs break-all"
                    >
                      {p}
                    </code>
                  ))}
                </div>
              </section>

              <section>
                <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">Detection</p>
                <p className="mt-1.5 text-sm text-muted-foreground">{technique.detection}</p>
                <p className="mt-1 font-mono text-xs text-muted-foreground/80">
                  rules: {technique.ruleIds.join(", ")}
                </p>
              </section>

              <section>
                <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">Mitigations</p>
                <ul className="mt-2 space-y-1.5">
                  {technique.mitigations.map((m, i) => (
                    <li key={i} className="flex gap-2 text-sm">
                      <ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-primary" />
                      <span className="text-muted-foreground">{m}</span>
                    </li>
                  ))}
                </ul>
              </section>
            </motion.div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}

export default function KnowledgeBase() {
  const { findings, loading, latestName } = useLiveFindings();
  const [query, setQuery] = useState("");
  const [tactic, setTactic] = useState<string | null>(null);
  const [liveOnly, setLiveOnly] = useState(false);

  const coverage = useMemo(() => techniqueCoverage(findings), [findings]);
  const matchedRules = useMemo(
    () => new Set(findings.filter((f) => techniqueForFinding(f)).map((f) => f.ruleId)),
    [findings],
  );

  const results = useMemo(() => {
    const base = searchTechniques(query, tactic);
    if (!liveOnly) return base;
    return base.filter((t) => coverage.has(t.id));
  }, [query, tactic, liveOnly, coverage]);

  const liveFindings = useMemo(
    () => findings.filter((f) => techniqueForFinding(f)),
    [findings],
  );

  return (
    <div className="space-y-6">
      {/* Header + live coverage summary */}
      <Card className="border-border/60 bg-card/60">
        <CardContent className="flex flex-wrap items-center gap-6 p-6">
          <span className="flex size-11 items-center justify-center rounded-xl bg-primary/10 text-primary">
            <BookOpen className="size-5" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="font-semibold tracking-tight">Attack knowledge base</p>
            <p className="text-sm text-muted-foreground">
              {TECHNIQUES.length} offensive techniques across {TACTICS.length} tactics, mapped to{" "}
              {matchedRules.size} detection rule{matchedRules.size === 1 ? "" : "s"} in the CrackScope engine.
            </p>
          </div>
          {loading ? (
            <Loader2 className="size-4 animate-spin text-muted-foreground" />
          ) : findings.length > 0 ? (
            <div className="flex flex-col items-end gap-1">
              <Badge
                variant="outline"
                className={`rounded-full ${
                  liveFindings.length > 0
                    ? "border-destructive/40 bg-destructive/10 text-destructive"
                    : "border-primary/40 bg-primary/10 text-primary"
                }`}
              >
                <Target className="mr-1 size-3" />
                {liveFindings.length} live finding{liveFindings.length === 1 ? "" : "s"} mapped
              </Badge>
              <span className="font-mono text-xs text-muted-foreground">
                from "{latestName}" · {coverage.size} techniques hit
              </span>
            </div>
          ) : (
            <Badge variant="outline" className="rounded-full text-muted-foreground">
              Run a scan to see live coverage
            </Badge>
          )}
        </CardContent>
      </Card>

      {/* Search + filters */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search techniques, payloads, rules, OWASP… (e.g. jwt, pickle, A03)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <Button
            variant={tactic === null ? "default" : "outline"}
            size="sm"
            className="rounded-full"
            onClick={() => setTactic(null)}
          >
            All tactics
          </Button>
          {TACTICS.map((t) => (
            <Button
              key={t}
              variant={tactic === t ? "default" : "outline"}
              size="sm"
              className="rounded-full"
              onClick={() => setTactic(tactic === t ? null : t)}
            >
              {t}
            </Button>
          ))}
        </div>
      </div>

      {findings.length > 0 && (
        <Button
          variant={liveOnly ? "default" : "outline"}
          size="sm"
          className="self-start gap-2 rounded-full"
          onClick={() => setLiveOnly((v) => !v)}
        >
          <Crosshair className="size-3.5" />
          {liveOnly ? "Showing live-hit techniques only" : "Show only techniques hitting my code"}
        </Button>
      )}

      {/* Live mapping panel */}
      {findings.length > 0 && liveFindings.length > 0 && (
        <Card className="border-primary/30 bg-primary/5">
          <CardContent className="space-y-3 p-6">
            <p className="text-xs font-semibold uppercase tracking-widest text-primary">
              Techniques detected in your latest scan
            </p>
            <div className="flex flex-wrap gap-2">
              {[...coverage.values()]
                .sort((a, b) => severityRank(b.technique.severity) - severityRank(a.technique.severity) || b.count - a.count)
                .map(({ technique, count }) => (
                  <div
                    key={technique.id}
                    className="flex items-center gap-2 rounded-full border border-border/60 bg-background/60 px-3 py-1.5"
                  >
                    <span className="font-mono text-[10px] font-semibold text-primary">{technique.id}</span>
                    <span className="text-xs">{technique.name}</span>
                    {severityBadge(technique.severity, count)}
                  </div>
                ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Technique list */}
      <div className="space-y-3">
        {results.length === 0 ? (
          <Card className="border-border/60 bg-card/60">
            <CardContent className="flex flex-col items-center gap-2 py-12 text-center">
              <BookOpen className="size-8 text-muted-foreground" />
              <p className="font-medium">No techniques match</p>
              <p className="text-sm text-muted-foreground">
                {liveOnly && !coverage.size
                  ? "None of your scans hit a cataloged technique yet — run a scan or clear the filter."
                  : "Try a different search term or clear the tactic filter."}
              </p>
            </CardContent>
          </Card>
        ) : (
          results.map((t) => (
            <TechniqueCard key={t.id} technique={t} liveCount={coverage.get(t.id)?.count} />
          ))
        )}
      </div>
    </div>
  );
}
