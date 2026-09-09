// Foundation Lab — Parts 1–5 of the CrackScope-8B plan as runnable modules.
// Licensing/PII/dedup gate, live CS-BPE tokenizer, MoE harness telemetry,
// Chinchilla scaling fit, and the expert-topology ablation.

import { useMemo, useState } from "react";
import {
  Braces,
  CheckCircle2,
  Database,
  FlaskConical,
  LineChart,
  Play,
  RotateCcw,
  ShieldAlert,
  Split,
  Trophy,
  XCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import {
  CSBPE,
  DataLake,
  PROBE_GRID,
  fitScalingLaw,
  runTrainingHarness,
  topologyAblation,
  type DataLakeDoc,
  type LakeDoc,
} from "@/lib/foundation";

function PartHeader({
  part, title, icon: Icon, action,
}: {
  part: number;
  title: string;
  icon: typeof Database;
  action?: React.ReactNode;
}) {
  return (
    <div className="mb-3 flex flex-wrap items-center gap-2.5">
      <div className="flex size-8 items-center justify-center rounded-lg bg-primary/12 ring-1 ring-primary/30">
        <Icon className="size-4 text-primary" />
      </div>
      <h3 className="font-semibold tracking-tight">
        <span className="mr-2 font-mono text-xs text-muted-foreground">Part {part}</span>
        {title}
      </h3>
      <div className="ml-auto">{action}</div>
    </div>
  );
}

function Metric({ label, value, tone }: { label: string; value: string; tone?: "good" | "warn" }) {
  const toneClass = tone === "good" ? "text-[oklch(0.72_0.14_168)]" : tone === "warn" ? "text-[oklch(0.82_0.14_85)]" : "";
  return (
    <div className="rounded-lg border border-border/60 bg-secondary/40 px-3 py-2">
      <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</p>
      <p className={`mt-0.5 font-mono text-sm font-semibold ${toneClass}`}>{value}</p>
    </div>
  );
}

// ------------------------------- Part 1 --------------------------------------

const SAMPLE_DOCS: DataLakeDoc[] = [
  {
    id: "doc-1", name: "auth_bypass.py", source: "stack-v2", license: "mit",
    content: "import requests\n\n# contact: research@example-corp.com\n\ndef fetch(url, token):\n    headers = {'Authorization': f'Bearer {token}'}\n    r = requests.get(url, headers=headers)\n    return r.json()\n\nprobe = 'https://169.254.169.254/latest/meta-data/'\nprint(fetch(probe, 'ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'))\n",
  },
  {
    id: "doc-2", name: "sqli_payloads.md", source: "ctf-archive", license: "cc-by-4.0",
    content: "Payloads:\n' OR 1=1 --\nUNION SELECT username, password FROM users\nNoSQL: {'$ne': None} and {'$gt': ''}\nSSRF chain: file:///etc/passwd -> ../\n",
  },
  {
    id: "doc-3", name: "leaked_advisory.txt", source: "advisory", license: "proprietary",
    content: "Internal advisory — not licensed for training. Vendor NDA content, blocked by the gate.",
  },
  {
    id: "doc-4", name: "bounty_writeup.md", source: "bounty-report",
    content: "Found IDOR on /api/v1/invoices/{id}. JWT used alg:none in staging.\nCall 555-123-4567 to confirm repro. SSN field exposed: 123-45-6789.\n",
  },
  {
    id: "doc-5", name: "auth_bypass_copy.py", source: "stack-v2", license: "apache-2.0",
    content: "import requests\n\n# contact: research@example-corp.com\n\ndef fetch(url, token):\n    headers = {'Authorization': f'Bearer {token}'}\n    r = requests.get(url, headers=headers)\n    return r.json()\n\nprobe = 'https://169.254.169.254/latest/meta-data/'\nprint(fetch(probe, 'ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'))\n",
  },
];

function DocRow({ doc }: { doc: LakeDoc }) {
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border/50 bg-secondary/30 px-3 py-2">
      <span className="font-mono text-xs text-muted-foreground">{doc.name}</span>
      {doc.licenseOk ? (
        <Badge variant="outline" className="rounded-full border-[oklch(0.72_0.14_168)]/40 bg-[oklch(0.72_0.14_168)]/10 text-[10px] text-[oklch(0.72_0.14_168)]">
          <CheckCircle2 className="mr-1 size-3" /> {doc.license}
        </Badge>
      ) : (
        <Badge variant="outline" className="rounded-full border-destructive/40 bg-destructive/10 text-[10px] text-destructive">
          <XCircle className="mr-1 size-3" /> {doc.license}
        </Badge>
      )}
      {doc.piiRedactions.length > 0 && (
        <Badge variant="outline" className="rounded-full border-[oklch(0.8_0.16_85)]/40 bg-[oklch(0.8_0.16_85)]/10 text-[10px] text-[oklch(0.82_0.14_85)]">
          <ShieldAlert className="mr-1 size-3" /> PII: {doc.piiRedactions.join(", ")}
        </Badge>
      )}
      {doc.duplicateOf && (
        <Badge variant="outline" className="rounded-full text-[10px]">
          dup of {doc.duplicateOf}
        </Badge>
      )}
      <span className="ml-auto font-mono text-[11px] text-muted-foreground">
        {doc.chars.toLocaleString()} chars · #{doc.hash.slice(0, 10)}
      </span>
      {doc.gateReason && <p className="w-full text-[11px] text-destructive/80">gate: {doc.gateReason}</p>}
    </div>
  );
}

function Part1DataLake({ onAdmitted }: { onAdmitted: (docs: string[]) => void }) {
  const [lake, setLake] = useState<DataLake>(() => new DataLake());
  const [ingested, setIngested] = useState(false);
  const [name, setName] = useState("my_findings.md");
  const [license, setLicense] = useState("mit");
  const [text, setText] = useState("");

  function runIngest() {
    const next = new DataLake();
    for (const d of SAMPLE_DOCS) next.ingest(d);
    if (text.trim().length > 0) {
      next.ingest({
        id: "user-" + Date.now().toString(36),
        name: name || "untitled.txt",
        source: "user",
        license,
        content: text,
      });
    }
    setLake(next);
    setIngested(true);
    onAdmitted(
      next.docs
        .filter((d) => d.licenseOk && !d.duplicateOf)
        .map((d) => {
          const src = SAMPLE_DOCS.find((s) => s.id === d.id);
          return src ? src.content : (text ?? "");
        })
    );
  }

  function reset() {
    setLake(new DataLake());
    setIngested(false);
    onAdmitted([]);
  }

  const s = lake.stats;

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="p-5">
        <PartHeader
          part={1}
          title="Data lake & licensing gate"
          icon={Database}
          action={
            <div className="flex gap-2">
              {ingested && (
                <Button variant="outline" size="sm" onClick={reset}>
                  <RotateCcw className="mr-1.5 size-3.5" /> Reset
                </Button>
              )}
              <Button size="sm" onClick={runIngest}>
                <Play className="mr-1.5 size-3.5" /> Run ingestion
              </Button>
            </div>
          }
        />

        <div className="mb-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Metric label="Ingested" value={String(s.ingested)} />
          <Metric label="Admitted" value={String(s.admitted)} tone={s.admitted > 0 ? "good" : undefined} />
          <Metric label="Blocked" value={String(s.rejected)} tone={s.rejected > 0 ? "warn" : undefined} />
          <Metric label="Dups dropped" value={String(s.duplicatesDropped)} tone={s.duplicatesDropped > 0 ? "warn" : undefined} />
        </div>
        <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-3">
          <Metric label="PII redactions" value={String(s.piiRedactions)} />
          <Metric label="Corpus chars" value={s.admittedChars.toLocaleString()} />
          <Metric
            label="Sources"
            value={
              Object.keys(s.bySource).length
                ? Object.entries(s.bySource).map(([k, v]) => `${k}:${v}`).join(" ")
                : "—"
            }
          />
        </div>

        <div className="space-y-1.5">
          <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Pipeline decisions</p>
          {ingested ? (
            lake.docs.map((d) => <DocRow key={d.id} doc={d} />)
          ) : (
            <p className="rounded-lg border border-dashed border-border/60 px-3 py-4 text-center text-xs text-muted-foreground">
              Nothing ingested yet — run ingestion to see license gating, PII scrubbing, and two-stage dedup in action.
            </p>
          )}
        </div>

        <Separator className="my-4" />

        <div className="grid gap-3 sm:grid-cols-[1fr_200px]">
          <div>
            <Label htmlFor="lake-doc-name" className="text-xs text-muted-foreground">Your own document (optional)</Label>
            <Input
              id="lake-doc-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="mt-1.5 h-8 font-mono text-xs"
              placeholder="filename"
            />
            <Textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              className="mt-2 min-h-20 font-mono text-xs"
              placeholder="Paste code/writeup text. Emails, API keys, IPs, phones and SSNs get redacted; the license decides admission."
            />
          </div>
          <div>
            <Label htmlFor="lake-doc-license" className="text-xs text-muted-foreground">License</Label>
            <Select value={license} onValueChange={setLicense}>
              <SelectTrigger id="lake-doc-license" className="mt-1.5 h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {["mit", "apache-2.0", "bsd-3-clause", "mpl-2.0", "cc-by-4.0", "cc0", "public-domain", "gpl-3.0", "agpl-3.0", "proprietary", "unknown"].map((l) => (
                  <SelectItem key={l} value={l}>{l}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="mt-2 text-[11px] leading-4 text-muted-foreground">
              GPL/AGPL/proprietary/unknown are blocked; permissive licenses pass.
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ------------------------------- Part 2 --------------------------------------

const DEFAULT_PROBE = "../../etc/passwd UNION SELECT * FROM users CVE-2024-1234 $ne alg:none <script>alert(1)</script>";

function Part2Tokenizer({ corpus }: { corpus: string[] }) {
  const [targetVocab, setTargetVocab] = useState("512");
  const [probe, setProbe] = useState(DEFAULT_PROBE);
  const [tok, setTok] = useState<CSBPE | null>(null);

  function train() {
    const t = new CSBPE();
    const docs = corpus.length > 0 ? corpus : [DEFAULT_PROBE.repeat(3)];
    t.train(docs, Number(targetVocab) || 512);
    setTok(t);
  }

  const preview = tok ? tok.preview(probe, 28) : [];

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="p-5">
        <PartHeader
          part={2}
          title="CS-BPE tokenizer — trained live"
          icon={Braces}
          action={
            <Button size="sm" onClick={train}>
              <Play className="mr-1.5 size-3.5" /> Train tokenizer
            </Button>
          }
        />

        <div className="mb-4 flex flex-wrap items-end gap-3">
          <div className="w-40">
            <Label htmlFor="bpe-vocab" className="text-xs text-muted-foreground">Target vocab</Label>
            <Select value={targetVocab} onValueChange={setTargetVocab}>
              <SelectTrigger id="bpe-vocab" className="mt-1.5 h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {["384", "512", "768", "1024"].map((v) => (
                  <SelectItem key={v} value={v}>{v}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="min-w-0 flex-1">
            <Label htmlFor="bpe-probe" className="text-xs text-muted-foreground">Encode probe</Label>
            <Input
              id="bpe-probe"
              value={probe}
              onChange={(e) => setProbe(e.target.value)}
              className="mt-1.5 h-8 font-mono text-xs"
            />
          </div>
        </div>

        {tok && (
          <>
            <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Metric label="Merges" value={String(tok.stats.mergesLearned)} />
              <Metric label="Vocab size" value={String(tok.stats.vocabSize)} />
              <Metric label="Bytes / token" value={tok.stats.compressionRatio.toFixed(2)} tone={tok.stats.compressionRatio > 1.4 ? "good" : undefined} />
              <Metric label="Train time" value={`${(tok.stats.trainingSeconds * 1000).toFixed(0)} ms`} />
            </div>

            <p className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Encoded probe</p>
            <div className="mb-4 flex flex-wrap gap-1">
              {preview.map((p, i) => (
                <span
                  key={`${p.id}-${i}`}
                  title={`id ${p.id}`}
                  className="rounded border border-primary/30 bg-primary/5 px-1.5 py-0.5 font-mono text-[11px] text-primary"
                >
                  {p.token}
                </span>
              ))}
              {preview.length === 0 && <span className="text-xs text-muted-foreground">—</span>}
            </div>

            <p className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Top merges learned</p>
            <div className="flex flex-wrap gap-1">
              {tok.topMerges.slice(0, 16).map((m) => (
                <span key={m.rank} className="rounded border border-border/60 bg-secondary/50 px-1.5 py-0.5 font-mono text-[11px]">
                  {m.pair[0]}
                  <span className="text-muted-foreground">+</span>
                  {m.pair[1]}
                  <span className="ml-1 text-[10px] text-muted-foreground">×{m.freq}</span>
                </span>
              ))}
            </div>
          </>
        )}
        {!tok && (
          <p className="rounded-lg border border-dashed border-border/60 px-3 py-4 text-center text-xs text-muted-foreground">
            A real byte-level BPE trainer — greedy most-frequent-pair merges over security-aware pre-tokens.
            Training uses the Part 1 admitted corpus (or a built-in security sample if none).
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// ------------------------------- Part 3 --------------------------------------

function Part3Harness() {
  const [result, setResult] = useState<ReturnType<typeof runTrainingHarness> | null>(null);
  const [steps, setSteps] = useState("200");
  const [experts, setExperts] = useState("12");

  function run() {
    setResult(
      runTrainingHarness({
        ...{ layers: 24, topK: 2, seqLen: 4096, batchSize: 8, lr: 3e-4, warmup: 20, capacityFactor: 1.25, auxLoadAlpha: 0.01, zLossAlpha: 1e-3, seed: 1337 },
        steps: Number(steps) || 200,
        experts: Number(experts) || 12,
      })
    );
  }

  // Downsample telemetry for the sparkline-ish bar chart.
  const bars = result
    ? result.telemetry.filter((_, i) => i % Math.max(1, Math.ceil(result.telemetry.length / 60)) === 0)
    : [];

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="p-5">
        <PartHeader
          part={3}
          title="Training harness — simulated MoE run"
          icon={FlaskConical}
          action={
            <Button size="sm" onClick={run}>
              <Play className="mr-1.5 size-3.5" /> Run training
            </Button>
          }
        />

        <div className="mb-4 flex flex-wrap items-end gap-3">
          <div className="w-32">
            <Label htmlFor="h-steps" className="text-xs text-muted-foreground">Steps</Label>
            <Select value={steps} onValueChange={setSteps}>
              <SelectTrigger id="h-steps" className="mt-1.5 h-8 text-xs"><SelectValue /></SelectTrigger>
              <SelectContent>
                {["100", "200", "400"].map((v) => <SelectItem key={v} value={v}>{v}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div className="w-32">
            <Label htmlFor="h-experts" className="text-xs text-muted-foreground">Routed experts</Label>
            <Select value={experts} onValueChange={setExperts}>
              <SelectTrigger id="h-experts" className="mt-1.5 h-8 text-xs"><SelectValue /></SelectTrigger>
              <SelectContent>
                {["8", "12", "16"].map((v) => <SelectItem key={v} value={v}>{v}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
        </div>

        {result && (
          <>
            <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Metric label="Final loss" value={result.finalLoss.toFixed(3)} tone={result.finalLoss < 2 ? "good" : undefined} />
              <Metric label="Routing purity" value={`${(result.meanPurity * 100).toFixed(0)}%`} />
              <Metric label="Router entropy" value={result.meanEntropy.toFixed(2)} />
              <Metric label="Tokens seen" value={`${(result.tokensSeen / 1e6).toFixed(1)}M`} />
            </div>

            <p className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Loss curve</p>
            <div className="mb-4 flex h-24 items-end gap-px rounded-lg border border-border/50 bg-secondary/30 p-2">
              {bars.map((t) => {
                const h = Math.max(4, (t.loss / 4.4) * 100);
                return (
                  <div
                    key={t.step}
                    title={`step ${t.step} · loss ${t.loss.toFixed(3)} · purity ${(t.routingPurity * 100).toFixed(0)}%`}
                    className="min-w-[3px] flex-1 rounded-sm bg-primary/60"
                    style={{ height: `${h}%` }}
                  />
                );
              })}
            </div>

            <p className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              Expert load share (lifetime)
            </p>
            <div className="flex h-6 w-full overflow-hidden rounded-lg border border-border/50">
              {result.expertShare.map((share, i) => {
                const total = result.expertShare.reduce((a, b) => a + b, 0) || 1;
                return (
                  <div
                    key={i}
                    title={`expert ${i + 1}: ${((share / total) * 100).toFixed(1)}%`}
                    style={{ width: `${(share / total) * 100}%` }}
                    className="h-full border-r border-border/40 last:border-0 bg-primary/30"
                  />
                );
              })}
            </div>
            <p className="mt-2 font-mono text-[11px] text-muted-foreground">
              convergence at step {result.convergenceStep} · grad-norm decay tracked · dropped tokens on capacity overflow
            </p>
          </>
        )}
        {!result && (
          <p className="rounded-lg border border-dashed border-border/60 px-3 py-4 text-center text-xs text-muted-foreground">
            Simulated but mathematically coherent: power-law loss decay, softmax router with temperature annealing,
            per-expert losses diverging with specialization, capacity-factor token dropping.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// ------------------------------- Part 4 --------------------------------------

function Part4Scaling() {
  const fit = useMemo(() => {
    try {
      return fitScalingLaw(PROBE_GRID);
    } catch {
      return null;
    }
  }, []);

  const targetLoss = fit ? fit.predict(8e9, 1.8e12) : 0;

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="p-5">
        <PartHeader part={4} title="Scaling-law probes — Chinchilla fit" icon={LineChart} />

        <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Metric label="E (irreducible)" value={fit ? fit.E.toFixed(2) : "—"} />
          <Metric label="α (params)" value={fit ? fit.alpha.toFixed(2) : "—"} />
          <Metric label="β (tokens)" value={fit ? fit.beta.toFixed(2) : "—"} />
          <Metric label="Max residual" value={fit ? fit.residualMax.toFixed(4) : "—"} />
        </div>

        <div className="mb-4 space-y-1.5">
          {PROBE_GRID.map((r) => (
            <div key={r.params} className="flex items-center gap-3 rounded-lg border border-border/50 bg-secondary/30 px-3 py-2">
              <span className="w-20 font-mono text-xs text-muted-foreground">
                {r.params >= 1e6 ? `${(r.params / 1e6).toFixed(0)}M` : r.params}
              </span>
              <span className="w-20 font-mono text-xs text-muted-foreground">{(r.tokens / 1e9).toFixed(1)}B tok</span>
              <div className="min-w-0 flex-1">
                <Progress value={(1 - r.loss / 4.5) * 100} className="h-1.5" />
              </div>
              <span className="w-14 text-right font-mono text-xs">L={r.loss.toFixed(2)}</span>
            </div>
          ))}
        </div>

        {fit && (
          <div className="rounded-lg border border-primary/30 bg-primary/5 px-4 py-3">
            <p className="text-sm">
              Fitted <span className="font-mono text-primary">L(N,D) = {fit.E.toFixed(2)} + {fit.A.toExponential(2)}/N^{fit.alpha.toFixed(2)} + {fit.B.toExponential(2)}/D^{fit.beta.toFixed(2)}</span>
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              Chinchilla-optimal ratio ≈ <span className="font-mono">{fit.optimalTokensPerParam.toFixed(0)} tokens/param</span> ·
              predicted cs-8b pretrain loss at (8B, 1.8T): <span className="font-mono text-primary">{targetLoss.toFixed(2)}</span>
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ------------------------------- Part 5 --------------------------------------

function Part5Topology() {
  const results = useMemo(() => topologyAblation(), []);
  const maxPurity = Math.max(...results.map((r) => r.purity));

  return (
    <Card className="border-border/60 bg-card/70">
      <CardContent className="p-5">
        <PartHeader part={5} title="Expert topology decision — ablation" icon={Split} />

        <div className="space-y-2">
          {results.map((r) => (
            <div
              key={r.id}
              className={`flex flex-wrap items-center gap-3 rounded-lg border px-3.5 py-2.5 ${
                r.winner ? "border-[oklch(0.72_0.14_168)]/50 bg-[oklch(0.72_0.14_168)]/8" : "border-border/50 bg-secondary/30"
              }`}
            >
              {r.winner && <Trophy className="size-4 shrink-0 text-[oklch(0.72_0.14_168)]" />}
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">{r.name}</p>
                <p className="font-mono text-[11px] text-muted-foreground">
                  {r.routedExperts === 0
                    ? "no routing · dense FFN"
                    : `${r.routedExperts} routed · top-${r.topK} · ${r.expertInter} inter. · ~${r.activeB.toFixed(1)}B active/token`}
                </p>
              </div>
              <div className="w-28">
                <Progress value={maxPurity > 0 ? (r.purity / maxPurity) * 100 : 0} className="h-1.5" />
              </div>
              <span className="w-24 text-right font-mono text-xs">
                purity {r.purity > 0 ? `${(r.purity * 100).toFixed(0)}%` : "—"}
              </span>
              <span className="w-20 text-right font-mono text-xs">L={r.pretrainLoss.toFixed(2)}</span>
              <span className="w-24 text-right font-mono text-xs">
                sec-ppl ×{r.secPplRatio.toFixed(2)}
              </span>
            </div>
          ))}
        </div>

        <p className="mt-3 text-xs leading-5 text-muted-foreground">
          All topologies are matched at ~8B total parameters and the same FLOPs/token. Winner criterion per the plan:
          <span className="text-foreground"> security-topic routing purity at equal FLOPs</span> — which is why the
          12+1 topology (one expert per security domain, plus a shared FFN) was locked into the architecture.
        </p>
      </CardContent>
    </Card>
  );
}

// ------------------------------- shell ---------------------------------------

export default function FoundationLab() {
  const [admitted, setAdmitted] = useState<string[]>([]);

  return (
    <div className="space-y-6">
      <Card className="border-border/60 bg-card/70">
        <CardContent className="p-5">
          <div className="flex flex-wrap items-center gap-3">
            <FlaskConical className="size-5 text-primary" />
            <div className="min-w-0 flex-1">
              <h2 className="text-lg font-semibold tracking-tight">Foundation lab — Phase 1 (Parts 1–5)</h2>
              <p className="text-sm text-muted-foreground">
                The five foundation subsystems running live in your browser: the licensing/PII/dedup gate, a real
                security-weighted BPE tokenizer, MoE training telemetry, the Chinchilla scaling fit, and the
                expert-topology ablation that picked the 12+1 design.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Part1DataLake onAdmitted={setAdmitted} />
      <Part2Tokenizer corpus={admitted} />
      <Part3Harness />
      <Part4Scaling />
      <Part5Topology />
    </div>
  );
}
