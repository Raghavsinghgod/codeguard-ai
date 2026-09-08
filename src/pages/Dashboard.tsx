// CrackScope dashboard — the authenticated attack-simulation workspace.
// Scanner (intake + live simulation + report), History (saved scans, diffing,
// sharing), Roadmap, and Team workspaces (Part 19).
import { useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import { useMutation, useQuery } from "convex/react";
import { toast } from "sonner";
import {
  Crosshair,
  FileOutput,
  FlaskConical,
  FolderOpen,
  GitCompareArrows,
  Github,
  History,
  ListChecks,
  Loader2,
  LogOut,
  Minus,
  Play,
  Radar,
  Trash2,
  TrendingDown,
  TrendingUp,
  Upload,
  Users,
  X,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScanReport } from "@/components/ScanReport";
import { DiffView } from "@/components/DiffView";
import { AiAnalysis } from "@/components/AiAnalysis";
import { RoadmapView } from "@/components/RoadmapView";
import { TeamTab } from "@/components/TeamTab";
import { ReportCenter } from "@/components/ReportCenter";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";
import { useAuth } from "@/hooks/use-auth";
import { scan, type ScanInput, type ScanResult } from "@/lib/scanner";
import { diffScanResults, velocityStats } from "@/lib/diff";
import {
  fetchGithubRepo,
  intakeFiles,
  parseGithubTarget,
  summarizeInputs,
} from "@/lib/intake";

// The intentionally vulnerable demo app (Part 1) — plus a vulnerable
// package.json (Part 7) so dependency findings show out of the box.
const DEMO_FILES: ScanInput[] = [
  {
    name: "server.js",
    content: `const express = require("express");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());

const db = mysql.createConnection({ host: "localhost", user: "root", password: "hunter2" });

app.get("/user", (req, res) => {
  const name = req.query.name;
  db.query("SELECT * FROM users WHERE name = '" + name + "'", (err, rows) => {
    if (err) return res.status(500).send(err.stack);
    res.send(rows);
  });
});

app.post("/login", (req, res) => {
  db.query("SELECT * FROM users WHERE email = '" + req.body.email + "' AND pw = '" + req.body.password + "'", (err, rows) => {
    if (rows.length) {
      const token = jwt.sign({ id: rows[0].id }, "s3cr3t-key", { algorithm: "HS256" });
      res.cookie("session", token);
      res.send({ token });
    } else {
      res.send("No user " + req.body.email);
    }
  });
});

app.get("/file", (req, res) => {
  const fs = require("fs");
  fs.readFile("uploads/" + req.query.path, (err, data) => res.send(data));
});

app.get("/fetch", async (req, res) => {
  const out = await fetch(req.query.url);
  res.send(await out.text());
});

app.get("/greet", (req, res) => {
  const name = req.query.name;
  res.send("<h1>Hello " + name + "</h1>");
});

app.post("/merge", (req, res) => {
  const defaults = { role: "user" };
  deepMerge(defaults, req.body);
  res.send(defaults);
});

app.delete("/api/invoices/:id", (req, res) => {
  db.query("DELETE FROM invoices WHERE id = " + req.params.id, () => res.send("ok"));
});

app.listen(3000);
`,
  },
  {
    name: "utils.py",
    content: `import hashlib
import pickle
import os
import subprocess

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def load_session(data):
    return pickle.loads(data)

def run_report(name):
    os.system("run_report " + name)
    return subprocess.call("cat reports/" + name, shell=True)

AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
STRIPE_KEY = "sk_live_9f8a7b6c5d4e3f2a1b0c"
`,
  },
  {
    name: "package.json",
    content: `{
  "name": "vulnerable-demo",
  "version": "1.0.0",
  "scripts": {
    "setup": "curl -s https://example.com/install.sh | bash"
  },
  "dependencies": {
    "express": "*",
    "lodash": "4.17.15",
    "axios": "0.20.0",
    "ejs": "3.1.6",
    "json-utils": "latest"
  }
}
`,
  },
];

type ViewingState = {
  name: string;
  result: ScanResult;
  id: Id<"scans"> | null;
  aiAnalysis: string | null;
};

export default function Dashboard() {
  const { user, signOut } = useAuth();

  const [tab, setTab] = useState("scanner");
  const [scanName, setScanName] = useState("");
  const [pasteText, setPasteText] = useState("");
  const [pasteName, setPasteName] = useState("pasted.js");
  const [queue, setQueue] = useState<ScanInput[]>([]);
  const [githubUrl, setGithubUrl] = useState("");
  const [githubLoading, setGithubLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [stage, setStage] = useState(0);
  const [result, setResult] = useState<ViewingState | null>(null);
  const [viewing, setViewing] = useState<ViewingState | null>(null);
  const [dragActive, setDragActive] = useState(false);

  // History state
  const [compareBaseId, setCompareBaseId] = useState<string | null>(null);
  const [diffPair, setDiffPair] = useState<{
    baseName: string;
    base: ScanResult;
    currName: string;
    curr: ScanResult;
  } | null>(null);

  const saveScan = useMutation(api.scans.saveScan);
  const deleteScan = useMutation(api.scans.deleteScan);
  const shareScan = useMutation(api.workspaces.shareScan);
  const workspaces = useQuery(api.workspaces.listMyWorkspaces) ?? [];
  const scans = useQuery(api.scans.listScans) ?? [];

  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  const addFiles = async (files: File[]) => {
    const inputs = await intakeFiles(files);
    if (inputs.length === 0) {
      toast.error("No scannable source files found in that selection.");
      return;
    }
    setQueue((q) => {
      const merged = [...q];
      for (const input of inputs) {
        if (!merged.some((m) => m.name === input.name)) merged.push(input);
      }
      return merged.slice(0, 40);
    });
    toast.success(`Added ${inputs.length} file${inputs.length === 1 ? "" : "s"} to the queue`);
  };

  const fetchRepo = async () => {
    const target = parseGithubTarget(githubUrl);
    if (!target) {
      toast.error("Enter a GitHub URL, or owner/repo, or owner/repo/tree/branch.");
      return;
    }
    setGithubLoading(true);
    try {
      const inputs = await fetchGithubRepo(target);
      setQueue((q) => {
        const merged = [...q];
        for (const input of inputs) {
          if (!merged.some((m) => m.name === input.name)) merged.push(input);
        }
        return merged.slice(0, 40);
      });
      toast.success(`Fetched ${inputs.length} files from ${target.owner}/${target.repo}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "GitHub fetch failed");
    } finally {
      setGithubLoading(false);
    }
  };

  const runScan = async () => {
    const inputs: ScanInput[] = [...queue];
    if (pasteText.trim()) {
      inputs.push({ name: pasteName.trim() || "pasted.js", content: pasteText });
    }
    if (inputs.length === 0) {
      toast.error("Add code to scan first — paste, upload, or fetch a repo.");
      return;
    }
    setRunning(true);
    setResult(null);
    setViewing(null);
    // Staged attack-simulation console animation (Part 1 signature UX).
    const stages = 5;
    for (let i = 1; i <= stages; i++) {
      setStage(i);
      await new Promise((r) => setTimeout(r, 420));
    }
    try {
      const res = scan(inputs);
      setStage(0);
      setRunning(false);
      setResult({ name: scanName.trim() || "Untitled scan", result: res, id: null, aiAnalysis: null });
      // Persist in the background so triage/compare activate quickly.
      saveScan({
        name: scanName.trim() || "Untitled scan",
        score: res.score,
        grade: res.grade,
        filesScanned: res.filesScanned,
        linesScanned: res.linesScanned,
        critical: res.counts.critical,
        high: res.counts.high,
        medium: res.counts.medium,
        low: res.counts.low,
        info: res.counts.info,
        findings: res.findings,
      })
        .then((id) => {
          setResult((r) => (r ? { ...r, id } : r));
        })
        .catch(() => toast.error("Could not save the scan to history"));
    } catch (e) {
      setStage(0);
      setRunning(false);
      toast.error("Scan failed — check the submitted files");
      throw e;
    }
  };

  const toScanResult = (row: {
    name: string;
    score: number;
    grade: string;
    filesScanned: number;
    linesScanned: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    findings: ScanResult["findings"];
  }): { name: string; result: ScanResult } => ({
    name: row.name,
    result: {
      score: row.score,
      grade: row.grade as ScanResult["grade"],
      filesScanned: row.filesScanned,
      linesScanned: row.linesScanned,
      languages: [],
      counts: {
        critical: row.critical,
        high: row.high,
        medium: row.medium,
        low: row.low,
        info: row.info,
      },
      findings: row.findings,
      durationMs: 0,
    },
  });

  const handleDelete = async (id: Id<"scans">) => {
    await deleteScan({ id });
    toast.success("Scan deleted");
  };

  const velocity = useMemo(
    // eslint-disable-next-line react-hooks/exhaustive-deps
    () => (scans.length >= 2 ? velocityStats(scans as any) : null),
    [scans],
  );

  const summary = summarizeInputs(queue);

  return (
    <div className="min-h-screen bg-background">
      {/* Top bar */}
      <header className="sticky top-0 z-40 border-b border-border/60 bg-background/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center gap-4 px-6 py-3.5">
          <div className="flex items-center gap-2.5">
            <span className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <Crosshair className="size-4" />
            </span>
            <span className="font-semibold tracking-tight">CrackScope</span>
            <Badge variant="outline" className="rounded-full font-mono text-[10px] text-muted-foreground">
              {20}/25 shipped
            </Badge>
          </div>
          <div className="ml-auto flex items-center gap-3">
            <span className="hidden text-sm text-muted-foreground sm:inline">
              {user?.name ?? user?.email ?? "operator"}
            </span>
            <Button variant="ghost" size="sm" className="gap-2 rounded-full text-muted-foreground" onClick={() => void signOut()}>
              <LogOut className="size-4" /> Sign out
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-8">
        <Tabs value={tab} onValueChange={setTab} className="gap-8">
          <div className="flex flex-col gap-6 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">
                Attack simulation workspace
              </h1>
              <p className="mt-1.5 text-sm text-muted-foreground">
                Submit code you own. CrackScope simulates the attacks, you read the report.
              </p>
            </div>
            <TabsList className="rounded-full">
              <TabsTrigger value="scanner" className="gap-2 rounded-full">
                <Radar className="size-4" /> Scanner
              </TabsTrigger>
              <TabsTrigger value="history" className="gap-2 rounded-full">
                <History className="size-4" /> History
              </TabsTrigger>
              <TabsTrigger value="roadmap" className="gap-2 rounded-full">
                <ListChecks className="size-4" /> Roadmap
              </TabsTrigger>
              <TabsTrigger value="reports" className="gap-2 rounded-full">
                <FileOutput className="size-4" /> Reports
              </TabsTrigger>
              <TabsTrigger value="team" className="gap-2 rounded-full">
                <Users className="size-4" /> Team
              </TabsTrigger>
            </TabsList>
          </div>

          {/* Scanner */}
          <TabsContent value="scanner" className="space-y-8">
            <div className="grid gap-6 lg:grid-cols-5">
              <Card className="border-border/60 bg-card/60 lg:col-span-3">
                <CardContent className="space-y-4 p-6">
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">Scan name</label>
                      <Input
                        placeholder="e.g. payments-service main"
                        value={scanName}
                        onChange={(e) => setScanName(e.target.value)}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">Filename for pasted code</label>
                      <Input
                        placeholder="pasted.js"
                        value={pasteName}
                        onChange={(e) => setPasteName(e.target.value)}
                      />
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-muted-foreground">Paste code</label>
                    <textarea
                      className="min-h-40 w-full resize-y rounded-lg border border-border/60 bg-secondary/40 p-3 font-mono text-xs leading-5 outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
                      placeholder="Paste source code here…"
                      value={pasteText}
                      onChange={(e) => setPasteText(e.target.value)}
                    />
                  </div>

                  {/* Drag & drop intake (Part 2) */}
                  <div
                    onDragOver={(e) => {
                      e.preventDefault();
                      setDragActive(true);
                    }}
                    onDragLeave={() => setDragActive(false)}
                    onDrop={(e) => {
                      e.preventDefault();
                      setDragActive(false);
                      void addFiles(Array.from(e.dataTransfer.files));
                    }}
                    className={`flex flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed p-6 text-center transition-colors ${
                      dragActive ? "border-primary/60 bg-primary/5" : "border-border/70"
                    }`}
                  >
                    <Upload className="size-5 text-muted-foreground" />
                    <p className="text-sm text-muted-foreground">
                      Drag & drop files, a folder, or a .zip — or use the pickers
                    </p>
                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" className="rounded-full" onClick={() => fileInputRef.current?.click()}>
                        <FolderOpen className="size-3.5" /> Files
                      </Button>
                      <Button variant="outline" size="sm" className="rounded-full" onClick={() => folderInputRef.current?.click()}>
                        Folder
                      </Button>
                    </div>
                    <input
                      ref={fileInputRef}
                      type="file"
                      multiple
                      className="hidden"
                      onChange={(e) => {
                        void addFiles(Array.from(e.target.files ?? []));
                        e.target.value = "";
                      }}
                    />
                    <input
                      ref={folderInputRef}
                      type="file"
                      multiple
                      // @ts-expect-error non-standard but widely supported
                      webkitdirectory=""
                      className="hidden"
                      onChange={(e) => {
                        void addFiles(Array.from(e.target.files ?? []));
                        e.target.value = "";
                      }}
                    />
                  </div>

                  {/* GitHub intake */}
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <Github className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                      <Input
                        placeholder="github.com/owner/repo (public repos)"
                        value={githubUrl}
                        onChange={(e) => setGithubUrl(e.target.value)}
                        className="pl-9"
                        onKeyDown={(e) => {
                          if (e.key === "Enter") void fetchRepo();
                        }}
                      />
                    </div>
                    <Button variant="outline" className="rounded-full" disabled={githubLoading} onClick={() => void fetchRepo()}>
                      {githubLoading ? <Loader2 className="size-4 animate-spin" /> : "Fetch"}
                    </Button>
                  </div>
                </CardContent>
              </Card>

              <Card className="border-border/60 bg-card/60 lg:col-span-2">
                <CardContent className="flex h-full flex-col gap-4 p-6">
                  <div className="flex items-center justify-between">
                    <p className="font-medium">Scan queue</p>
                    {queue.length > 0 && (
                      <Button variant="ghost" size="sm" className="h-7 rounded-full text-xs text-muted-foreground" onClick={() => setQueue([])}>
                        <X className="size-3.5" /> Clear
                      </Button>
                    )}
                  </div>
                  {queue.length === 0 ? (
                    <div className="flex flex-1 flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border/70 p-6 text-center">
                      <FlaskConical className="size-5 text-muted-foreground" />
                      <p className="text-sm text-muted-foreground">
                        Empty. Paste code, drop files, or fetch a repo.
                      </p>
                      <Button
                        variant="outline"
                        size="sm"
                        className="rounded-full"
                        onClick={() => {
                          setQueue(DEMO_FILES);
                          toast.success("Vulnerable demo loaded — 20+ findings expected");
                        }}
                      >
                        Load vulnerable demo
                      </Button>
                    </div>
                  ) : (
                    <>
                      <div className="max-h-56 space-y-1.5 overflow-y-auto pr-1">
                        {queue.map((f) => (
                          <div key={f.name} className="flex items-center gap-2 rounded-lg border border-border/60 px-3 py-1.5">
                            <span className="min-w-0 flex-1 truncate font-mono text-xs">{f.name}</span>
                            <button
                              className="text-muted-foreground hover:text-destructive"
                              onClick={() => setQueue((q) => q.filter((x) => x.name !== f.name))}
                              aria-label={`Remove ${f.name}`}
                            >
                              <X className="size-3.5" />
                            </button>
                          </div>
                        ))}
                      </div>
                      <p className="font-mono text-xs text-muted-foreground">{summary}</p>
                      <Button variant="outline" size="sm" className="rounded-full" onClick={() => { setQueue(DEMO_FILES); toast.success("Vulnerable demo loaded"); }}>
                        Replace with vulnerable demo
                      </Button>
                    </>
                  )}
                  <Button
                    size="lg"
                    className="mt-auto w-full gap-2 rounded-full scan-glow"
                    disabled={running || (queue.length === 0 && !pasteText.trim())}
                    onClick={() => void runScan()}
                  >
                    {running ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4" />}
                    {running ? "Attacking…" : "Run attack simulation"}
                  </Button>
                </CardContent>
              </Card>
            </div>

            {/* Attack simulation console */}
            {(running || stage > 0) && (
              <Card className="border-primary/30 bg-primary/5">
                <CardContent className="space-y-2 p-6 font-mono text-xs">
                  {[
                    [1, "recon", "Enumerating entry points and input sources…"],
                    [2, "probes", "Fuzzing user-controlled flows with mutation strategies…"],
                    [3, "auth", "Probing auth, session, and privilege boundaries…"],
                    [4, "crypto", "Auditing cryptographic primitives and secrets…"],
                    [5, "report", "Scoring and assembling the pentest report…"],
                  ].map(([n, tag, msg]) => (
                    <p
                      key={tag as string}
                      className={stage >= (n as number) ? "text-foreground" : "text-muted-foreground/40"}
                    >
                      [{stage >= (n as number) ? "✓" : " "}] {String(tag).padEnd(7)} {msg}
                    </p>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* Report */}
            {result && (
              <div className="space-y-6">
                <ScanReport data={result} />
                <AiAnalysis
                  name={result.name}
                  result={result.result}
                  scanId={result.id}
                  initialJson={result.aiAnalysis}
                />
              </div>
            )}
          </TabsContent>

          {/* History */}
          <TabsContent value="history" className="space-y-6">
            {scans.length === 0 ? (
              <Card className="border-border/60 bg-card/60">
                <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
                  <History className="size-8 text-muted-foreground" />
                  <p className="font-medium">No saved scans yet</p>
                  <p className="text-sm text-muted-foreground">Run your first attack simulation — it will appear here.</p>
                  <Button variant="outline" className="mt-2 rounded-full" onClick={() => setTab("scanner")}>
                    Open scanner
                  </Button>
                </CardContent>
              </Card>
            ) : (
              <>
                {diffPair && (
                  <DiffView
                    baselineName={diffPair.baseName}
                    baseline={diffPair.base}
                    currentName={diffPair.currName}
                    current={diffPair.curr}
                    diff={diffScanResults(diffPair.base, diffPair.curr)}
                    onClose={() => setDiffPair(null)}
                  />
                )}

                {velocity && (
                  <Card className="border-border/60 bg-card/60">
                    <CardContent className="p-6">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div>
                          <p className="font-medium">Remediation velocity</p>
                          <p className="text-sm text-muted-foreground">
                            {velocity.totalFixed} fixed · {velocity.totalAdded} introduced · {velocity.netPerScan > 0 ? "+" : ""}
                            {velocity.netPerScan} findings/scan
                          </p>
                        </div>
                        <Badge
                          variant="outline"
                          className={`rounded-full ${
                            velocity.verdict === "improving"
                              ? "border-primary/40 bg-primary/10 text-primary"
                              : velocity.verdict === "degrading"
                                ? "border-destructive/40 bg-destructive/10 text-destructive"
                                : "border-border bg-muted text-muted-foreground"
                          }`}
                        >
                          {velocity.verdict === "improving" ? (
                            <TrendingDown className="mr-1 size-3" />
                          ) : velocity.verdict === "degrading" ? (
                            <TrendingUp className="mr-1 size-3" />
                          ) : (
                            <Minus className="mr-1 size-3" />
                          )}
                          {velocity.verdict}
                        </Badge>
                      </div>
                      {/* score sparkline */}
                      <svg viewBox="0 0 600 60" className="mt-4 h-14 w-full">
                        <polyline
                          fill="none"
                          stroke="currentColor"
                          className="text-primary"
                          strokeWidth="2"
                          points={velocity.points
                            .map((p, i) => {
                              const x = (i / Math.max(velocity.points.length - 1, 1)) * 590 + 5;
                              const y = 55 - (p.score / 100) * 50;
                              return `${x},${y}`;
                            })
                            .join(" ")}
                        />
                      </svg>
                    </CardContent>
                  </Card>
                )}

                <div className="space-y-3">
                  {scans.map((s) => (
                    <Card key={s._id} className="border-border/60 bg-card/60">
                      <CardContent className="flex flex-wrap items-center gap-4 p-5">
                        <span
                          className={`flex size-12 shrink-0 items-center justify-center rounded-xl font-semibold ${
                            s.score >= 75
                              ? "bg-primary/10 text-primary"
                              : s.score >= 50
                                ? "bg-[oklch(0.8_0.16_85)]/10 text-[oklch(0.82_0.14_85)]"
                                : "bg-destructive/10 text-destructive"
                          }`}
                        >
                          {s.grade}
                        </span>
                        <div className="min-w-0 flex-1">
                          <p className="truncate font-medium">{s.name}</p>
                          <p className="text-sm text-muted-foreground">
                            score {s.score}/100 · {s.critical} critical · {s.high} high ·{" "}
                            {s.medium} medium · {new Date(s.createdAt).toLocaleString()}
                          </p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            className="rounded-full"
                            onClick={() => {
                              setDiffPair(null);
                              if (!compareBaseId) {
                                setCompareBaseId(s._id);
                                return;
                              }
                              const base = scans.find((x) => x._id === compareBaseId);
                              setCompareBaseId(null);
                              if (base && base._id !== s._id) {
                                setDiffPair({
                                  baseName: base.name,
                                  base: toScanResult(base).result,
                                  currName: s.name,
                                  curr: toScanResult(s).result,
                                });
                              }
                            }}
                          >
                            <GitCompareArrows className="size-3.5" />
                            {compareBaseId && compareBaseId !== s._id && !diffPair
                              ? "vs baseline"
                              : "Compare"}
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            className="rounded-full"
                            onClick={() => {
                              setViewing({ ...toScanResult(s), id: s._id, aiAnalysis: s.aiAnalysis ?? null });
                              setTab("scanner");
                            }}
                          >
                            View report
                          </Button>
                          {workspaces.length > 0 && (
                            <Button
                              variant="outline"
                              size="sm"
                              className="rounded-full"
                              onClick={async () => {
                                const ws = workspaces[0];
                                try {
                                  await shareScan({ workspaceId: ws._id, scanId: s._id });
                                  toast.success(`Shared to "${ws.name}"`);
                                } catch (e: any) {
                                  toast.error(e.message ?? "Could not share scan");
                                }
                              }}
                            >
                              <Users className="size-3.5" />
                              Share
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            size="icon"
                            className="rounded-full text-muted-foreground hover:text-destructive"
                            onClick={() => void handleDelete(s._id)}
                            aria-label="Delete scan"
                          >
                            <Trash2 className="size-4" />
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </>
            )}
          </TabsContent>

          {/* Roadmap */}
          <TabsContent value="roadmap">
            <RoadmapView />
          </TabsContent>

          {/* Report center (Part 20) */}
          <TabsContent value="reports">
            <ReportCenter />
          </TabsContent>

          {/* Team workspaces (Part 19) */}
          <TabsContent value="team">
            <TeamTab />
          </TabsContent>
        </Tabs>
      </main>

      {/* Viewing a historical report overlays the scanner tab content */}
      {viewing && tab === "scanner" && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-background/95 p-6 backdrop-blur">
          <div className="mx-auto max-w-5xl space-y-6">
            <div className="flex items-center justify-between">
              <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                Historical report
              </p>
              <Button variant="outline" className="rounded-full" onClick={() => setViewing(null)}>
                Close
              </Button>
            </div>
            <ScanReport data={viewing} />
            <AiAnalysis
              name={viewing.name}
              result={viewing.result}
              scanId={viewing.id}
              initialJson={viewing.aiAnalysis}
            />
          </div>
        </div>
      )}
    </div>
  );
}
