// CrackScope Part 8 — AI deep analysis panel.
// Sends the finished scan report to the Convex AI action (Novita LLM) and
// renders the structured result: exploitation narrative, per-finding verdicts,
// business-logic hypotheses, and prioritized fixes. Persisted to the scan row
// so history views reload it instantly.
import { useState } from "react";
import { motion } from "framer-motion";
import { useAction, useMutation } from "convex/react";
import { BrainCircuit, KeyRound, Loader2, Sparkles, TriangleAlert } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";
import type { ScanResult } from "@/lib/scanner";
import {
  findingByKey,
  parseDeepAnalysis,
  type AiVerdict,
  type DeepAnalysis,
} from "@/lib/ai";

const VERDICT_STYLE: Record<AiVerdict, { chip: string; label: string }> = {
  confirmed: {
    chip: "border-destructive/40 bg-destructive/10 text-destructive",
    label: "AI: confirmed exploitable",
  },
  likely: {
    chip: "border-[oklch(0.75_0.15_55)]/40 bg-[oklch(0.75_0.15_55)]/10 text-[oklch(0.78_0.14_55)]",
    label: "AI: likely exploitable",
  },
  suspicious: {
    chip: "border-[oklch(0.75_0.12_220)]/40 bg-[oklch(0.75_0.12_220)]/10 text-[oklch(0.78_0.11_220)]",
    label: "AI: suspicious — needs manual review",
  },
};

function tryParse(json: string | null): DeepAnalysis | null {
  if (!json) return null;
  try {
    return parseDeepAnalysis(json);
  } catch {
    return null;
  }
}

export function AiAnalysis({
  name,
  result,
  scanId,
  initialJson,
}: {
  name: string;
  result: ScanResult;
  scanId: Id<"scans"> | null;
  initialJson: string | null;
}) {
  const runAnalysis = useAction(api.ai.deepAnalysis);
  const saveAi = useMutation(api.scans.saveAiAnalysis);
  const [analysis, setAnalysis] = useState<DeepAnalysis | null>(() => tryParse(initialJson));
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleRun = async () => {
    setRunning(true);
    setError(null);
    try {
      const res = await runAnalysis({
        name,
        score: result.score,
        grade: result.grade,
        filesScanned: result.filesScanned,
        linesScanned: result.linesScanned,
        findings: result.findings,
      });
      setAnalysis(res);
      if (scanId) {
        saveAi({ id: scanId, aiAnalysis: JSON.stringify(res) }).catch(() => {
          // Non-fatal: the analysis is still shown for this session.
        });
      }
      toast.success("AI deep analysis complete");
    } catch (err) {
      setError(err instanceof Error ? err.message : "AI analysis failed");
    } finally {
      setRunning(false);
    }
  };

  const needsKey = error?.includes("NOVITA_API_KEY");

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="space-y-5 p-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <span className="flex size-9 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <BrainCircuit className="size-4" />
            </span>
            <div>
              <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                Part 8 · AI deep analysis
              </p>
              <p className="text-sm text-muted-foreground">
                LLM reasoning over the report: exploitation narrative, verdicts, business-logic hypotheses
              </p>
            </div>
          </div>
          <Button
            onClick={handleRun}
            disabled={running || result.findings.length === 0}
            className="gap-2 rounded-full"
          >
            {running ? <Loader2 className="size-4 animate-spin" /> : <Sparkles className="size-4" />}
            {running ? "Reasoning…" : analysis ? "Re-run AI analysis" : "Run AI deep analysis"}
          </Button>
        </div>

        {running && (
          <p className="rounded-lg border border-primary/20 bg-primary/5 px-4 py-3 text-sm text-muted-foreground">
            Sending the report to the model and reasoning over {result.findings.length} finding
            {result.findings.length === 1 ? "" : "s"} — this usually takes 10–30 seconds…
          </p>
        )}

        {error && (
          <div
            className={`flex items-start gap-3 rounded-lg border px-4 py-3 text-sm ${
              needsKey
                ? "border-primary/30 bg-primary/5 text-foreground"
                : "border-destructive/40 bg-destructive/10 text-destructive"
            }`}
          >
            {needsKey ? (
              <KeyRound className="mt-0.5 size-4 shrink-0 text-primary" />
            ) : (
              <TriangleAlert className="mt-0.5 size-4 shrink-0" />
            )}
            <span>{error}</span>
          </div>
        )}

        {!analysis && !running && !error && (
          <p className="text-sm text-muted-foreground">
            The heuristic engine found the weaknesses — the AI pass adds what rules can't: how the
            findings chain together, which are genuinely exploitable, and where the business logic
            breaks. Run it on this report to see the full picture.
          </p>
        )}

        {analysis && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25 }}
            className="space-y-6"
          >
            {analysis.narrative.length > 0 && (
              <div className="space-y-2.5">
                <p className="font-medium">Exploitation narrative</p>
                {analysis.narrative.map((p, i) => (
                  <p key={i} className="text-sm leading-6 text-muted-foreground">
                    {p}
                  </p>
                ))}
              </div>
            )}

            {analysis.verdicts.length > 0 && (
              <div className="space-y-2.5">
                <p className="font-medium">Finding verdicts</p>
                <div className="space-y-2">
                  {analysis.verdicts.map((v, i) => {
                    const f = findingByKey(result, v.key);
                    const style = VERDICT_STYLE[v.verdict];
                    return (
                      <div
                        key={`${v.key}-${i}`}
                        className="rounded-lg border border-border/70 bg-secondary/40 px-4 py-3"
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant="outline" className={`rounded-full font-mono text-xs ${style.chip}`}>
                            {style.label}
                          </Badge>
                          <span className="font-mono text-xs text-muted-foreground">
                            {f ? `${f.ruleId} · ${f.file}:${f.line}` : v.key} · exploitability:{" "}
                            {v.exploitability}
                          </span>
                        </div>
                        {f && <p className="mt-1.5 text-sm font-medium">{f.title}</p>}
                        {v.note && (
                          <p className="mt-1 text-sm leading-5 text-muted-foreground">{v.note}</p>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {analysis.businessLogicFlaws.length > 0 && (
              <div className="space-y-2.5">
                <p className="font-medium">Business-logic hypotheses</p>
                <div className="space-y-2">
                  {analysis.businessLogicFlaws.map((flaw, i) => (
                    <div
                      key={i}
                      className="rounded-lg border border-[oklch(0.8_0.16_85)]/30 bg-[oklch(0.8_0.16_85)]/5 px-4 py-3"
                    >
                      <p className="text-sm font-medium">{flaw.title}</p>
                      {flaw.detail && (
                        <p className="mt-1 text-sm leading-5 text-muted-foreground">{flaw.detail}</p>
                      )}
                      {flaw.affected && (
                        <p className="mt-1 font-mono text-xs text-muted-foreground">
                          affected: {flaw.affected}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {analysis.fixPriorities.length > 0 && (
              <div className="space-y-2.5">
                <p className="font-medium">Prioritized fixes</p>
                <ol className="space-y-2">
                  {analysis.fixPriorities.map((step, i) => (
                    <li key={i} className="flex items-start gap-3 text-sm leading-6">
                      <span className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full bg-primary/10 font-mono text-xs font-semibold text-primary">
                        {i + 1}
                      </span>
                      <span className="text-muted-foreground">{step}</span>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </motion.div>
        )}
      </CardContent>
    </Card>
  );
}
