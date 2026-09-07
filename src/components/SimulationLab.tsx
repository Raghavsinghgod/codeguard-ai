import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { ChevronRight, Copy, FlaskConical, Play, RotateCcw, Swords } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { SEVERITY_STYLE } from "@/components/ScanReport";
import type { Finding } from "@/lib/scanner";
import { exploitChain, payloadsFor, simulatedResponse } from "@/lib/payloads";

function copyText(text: string) {
  void navigator.clipboard?.writeText(text);
}

export function SimulationLab({ finding }: { finding: Finding }) {
  const chain = exploitChain(finding);
  const payloads = payloadsFor(finding);

  const [payloadIdx, setPayloadIdx] = useState(0);
  const [craft, setCraft] = useState(payloads[0]?.body ?? "");
  const [step, setStep] = useState(-1);
  const [running, setRunning] = useState(false);
  const [response, setResponse] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  const selectPayload = (i: number) => {
    setPayloadIdx(i);
    setCraft(payloads[i].body);
  };

  const runReplay = () => {
    if (timerRef.current) clearInterval(timerRef.current);
    setResponse(null);
    setStep(0);
    setRunning(true);
    let i = 0;
    timerRef.current = setInterval(() => {
      i += 1;
      if (i < chain.length) {
        setStep(i);
      } else {
        if (timerRef.current) clearInterval(timerRef.current);
        setRunning(false);
        setResponse(
          simulatedResponse(finding, {
            name: payloads[payloadIdx]?.name ?? "Custom",
            body: craft,
            note: "",
          }),
        );
      }
    }, 750);
  };

  const reset = () => {
    if (timerRef.current) clearInterval(timerRef.current);
    setRunning(false);
    setStep(-1);
    setResponse(null);
  };

  const style = SEVERITY_STYLE[finding.severity];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <Badge variant="outline" className={`rounded-full capitalize ${style.chip}`}>
          {finding.severity}
        </Badge>
        <p className="text-sm font-medium">{finding.title}</p>
        <span className="font-mono text-xs text-muted-foreground">
          {finding.file}:{finding.line}
        </span>
        <Badge variant="outline" className="gap-1.5 rounded-full border-primary/40 bg-primary/10 text-[11px] text-primary">
          <FlaskConical className="size-3" /> Sandbox — no real requests leave your browser
        </Badge>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        {/* Left: vulnerable code + payload crafting */}
        <div className="space-y-4">
          <div>
            <p className="mb-1.5 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
              Vulnerable code
            </p>
            <pre className="overflow-x-auto rounded-lg border border-destructive/25 bg-destructive/5 p-3 font-mono text-xs leading-5">
              {finding.snippet}
            </pre>
          </div>

          <div>
            <p className="mb-1.5 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
              Payload library
            </p>
            <div className="space-y-1.5">
              {payloads.map((p, i) => (
                <button
                  key={p.name}
                  type="button"
                  onClick={() => selectPayload(i)}
                  className={`flex w-full items-center gap-2.5 rounded-lg border px-3 py-2 text-left text-sm transition-colors ${
                    payloadIdx === i
                      ? "border-primary/50 bg-primary/10"
                      : "border-border/60 bg-card/50 hover:border-primary/30"
                  }`}
                >
                  <span className="font-medium">{p.name}</span>
                  <span className="ml-auto truncate font-mono text-[11px] text-muted-foreground">
                    {p.body.slice(0, 34)}
                  </span>
                </button>
              ))}
            </div>
          </div>

          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <p className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
                Craft payload
              </p>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 gap-1 rounded-full px-2 text-[11px] text-muted-foreground"
                onClick={() => {
                  copyText(craft);
                  setCopied(true);
                  window.setTimeout(() => setCopied(false), 1200);
                }}
              >
                <Copy className="size-3" /> {copied ? "Copied" : "Copy"}
              </Button>
            </div>
            <Textarea
              value={craft}
              onChange={(e) => setCraft(e.target.value)}
              className="min-h-[72px] resize-y rounded-lg font-mono text-xs leading-5"
            />
            {payloads[payloadIdx] && (
              <p className="mt-1.5 text-xs text-muted-foreground">{payloads[payloadIdx].note}</p>
            )}
          </div>
        </div>

        {/* Right: exploit chain replay */}
        <div className="space-y-4">
          <div>
            <p className="mb-1.5 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
              Exploit chain
            </p>
            <ol className="space-y-1">
              {chain.map((s, i) => {
                const isActive = running && i === step;
                const isDone = step > i || (!running && step >= chain.length - 1 && i <= step);
                return (
                  <li
                    key={s.label}
                    className={`flex items-start gap-3 rounded-lg px-3 py-2 transition-colors ${
                      isActive ? "bg-primary/10" : ""
                    }`}
                  >
                    <ChevronRight
                      className={`mt-0.5 size-3.5 shrink-0 ${
                        isDone ? "text-primary" : isActive ? "animate-pulse text-primary" : "text-muted-foreground/40"
                      }`}
                    />
                    <div className="min-w-0">
                      <p
                        className={`font-mono text-sm ${
                          isActive ? "font-medium text-primary" : isDone ? "text-foreground" : "text-muted-foreground"
                        }`}
                      >
                        {s.label}
                      </p>
                      {(isActive || isDone) && (
                        <p className="mt-0.5 text-xs leading-5 text-muted-foreground">{s.detail}</p>
                      )}
                    </div>
                  </li>
                );
              })}
            </ol>
          </div>

          <div className="flex gap-2">
            <Button onClick={runReplay} disabled={running} className="gap-2 rounded-full scan-glow">
              <Play className="size-4" /> {running ? "Replaying…" : "Run replay"}
            </Button>
            {(running || response) && (
              <Button variant="outline" onClick={reset} className="gap-2 rounded-full">
                <RotateCcw className="size-4" /> Reset
              </Button>
            )}
          </div>

          {response && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="rounded-lg border border-destructive/25 bg-destructive/5 p-3.5"
            >
              <p className="mb-1.5 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-widest text-destructive">
                <Swords className="size-3.5" /> Simulated result — sandbox only
              </p>
              <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-xs leading-5 text-foreground/90">
                {response}
              </pre>
            </motion.div>
          )}
        </div>
      </div>
    </div>
  );
}
