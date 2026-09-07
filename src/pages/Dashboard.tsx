import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router";
import { useMutation, useQuery } from "convex/react";
import { toast } from "sonner";
import { Crosshair, FlaskConical, FolderOpen, GitCompareArrows, Github, History, ListChecks, Loader2, LogOut, Minus, Play, Radar, Trash2, TrendingDown, TrendingUp, Upload } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { ScanReport } from "@/components/ScanReport";
import { AiAnalysis } from "@/components/AiAnalysis";
import { DiffView } from "@/components/DiffView";
import { diffScanResults, velocityStats } from "@/lib/diff";
import { RoadmapView } from "@/components/RoadmapView";
import { useAuth } from "@/hooks/use-auth";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";
import { scan, type ScanInput, type ScanResult } from "@/lib/scanner";
import {
  fetchGithubRepo,
  intakeFiles,
  parseGithubTarget,
  summarizeInputs,
} from "@/lib/intake";

const STAGES = [
  { id: "recon", label: "Recon & fingerprint", detail: "Detecting languages, entry points, and data flows…" },
  { id: "probes", label: "Injection probes", detail: "Simulating SQL, command, and code injection payloads…" },
  { id: "auth", label: "Auth & session attacks", detail: "Testing token forgery, IDOR, and access-control gaps…" },
  { id: "crypto", label: "Crypto & secrets sweep", detail: "Sweeping for weak hashing, hardcoded keys, and TLS bypasses…" },
  { id: "report", label: "Report generation", detail: "Scoring findings and assembling the pentest report…" },
];

const SAMPLE_NAME = "vulnerable-demo.js";
const SAMPLE_CODE = `// Demo API service — intentionally vulnerable (for testing CrackScope)
const express = require("express");
const { exec } = require("child_process");
const jwt = require("jsonwebtoken");
const db = require("./db");

const API_KEY = "sk_live_9f8a7b6c5d4e3f2a1b";
const awsKey = "AKIAIOSFODNN7EXAMPLE";

app.use(cors({ origin: "*" }));

app.get("/login", (req, res) => {
  db.query("SELECT * FROM users WHERE name='" + req.body.user + "'");
  const sessionToken = Math.random().toString(36).substring(2);
  res.cookie("session", sessionToken);
});

app.get("/report", (req, res) => {
  exec("cat reports/" + req.params.file, (err, out) => res.send(out));
  res.redirect(req.query.next);
  fs.readFile("uploads/" + req.params.path, (e, d) => {});
  const data = axios.get(req.query.targetUrl);
});

app.get("/verify", (req, res) => {
  jwt.verify(req.headers.token, "secret", { ignoreExpiration: true });
});

document.getElementById("out").innerHTML = req.query.q;
`;

// Intentionally vulnerable manifest — exercises the Part 7 dependency audit
// (known CVEs, unpinned dep, install-script pattern).
const SAMPLE_MANIFEST = `{
  "name": "vulnerable-demo",
  "version": "1.0.0",
  "scripts": {
    "setup": "curl -s https://downloads.example.com/install.sh | bash",
    "start": "node server.js"
  },
  "dependencies": {
    "express": "4.16.0",
    "lodash": "4.17.15",
    "jsonwebtoken": "^8.5.0",
    "axios": "0.20.0",
    "json-utils": "*"
  }
}`;

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

export default function Dashboard() {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();

  const [tab, setTab] = useState("scanner");
  const [scanName, setScanName] = useState("");
  const [fileName, setFileName] = useState("pasted.js");
  const [codeText, setCodeText] = useState("");
  const [uploaded, setUploaded] = useState<ScanInput[]>([]);
  const [repoUrl, setRepoUrl] = useState("");
  const [repoLoading, setRepoLoading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [running, setRunning] = useState(false);
  const [stageIdx, setStageIdx] = useState(-1);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [savedName, setSavedName] = useState<string | null>(null);
  const [viewing, setViewing] = useState<{ name: string; result: ScanResult; id: Id<"scans"> | null; aiAnalysis: string | null } | null>(null);
  const [savedScanId, setSavedScanId] = useState<Id<"scans"> | null>(null);
  const [compareBaseId, setCompareBaseId] = useState<Id<"scans"> | null>(null);
  const [diffPair, setDiffPair] = useState<
    { baseName: string; base: ScanResult; currName: string; curr: ScanResult } | null
  >(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const scans = useQuery(api.scans.listScans, {});
  const velocity = useMemo(
    () => (scans && scans.length >= 2 ? velocityStats(scans) : null),
    [scans],
  );
  const saveScan = useMutation(api.scans.saveScan);
  const deleteScan = useMutation(api.scans.deleteScan);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  const handleSignOut = async () => {
    await signOut();
    navigate("/");
  };

  const handleFiles = async (fileList: File[]) => {
    if (fileList.length === 0) return;
    try {
      const inputs = await intakeFiles(fileList);
      if (inputs.length === 0) {
        toast.error(
          "No scannable source files found. Supported: code files, folders, .zip archives (max 40 files).",
        );
        return;
      }
      setUploaded((prev) => [...prev, ...inputs].slice(0, 40));
      toast.success(`${inputs.length} file${inputs.length === 1 ? "" : "s"} queued for attack simulation`);
    } catch {
      toast.error("Could not read those files. Try again or paste the code directly.");
    }
  };

  const handleFetchRepo = async () => {
    const target = parseGithubTarget(repoUrl);
    if (!target) {
      toast.error("Enter a GitHub URL or owner/repo (public repos only)." );
      return;
    }
    setRepoLoading(true);
    try {
      const inputs = await fetchGithubRepo(target);
      setUploaded((prev) => [...prev, ...inputs].slice(0, 40));
      toast.success(
        `Fetched ${target.owner}/${target.repo} — ${inputs.length} files queued`,
      );
      setRepoUrl("");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Repo fetch failed");
    } finally {
      setRepoLoading(false);
    }
  };

  const queuedCount = uploaded.length + (codeText.trim() ? 1 : 0);
  const canRun = queuedCount > 0 && !running;

  const handleRun = () => {
    const inputs: ScanInput[] = [];
    if (codeText.trim()) inputs.push({ name: fileName || "pasted.js", content: codeText });
    inputs.push(...uploaded);
    if (inputs.length === 0) {
      toast.error("Add code first — paste a file or upload one to attack.");
      return;
    }
    if (timerRef.current) clearInterval(timerRef.current);
    setResult(null);
    setViewing(null);
    setSavedName(null);
    setSavedScanId(null);
    setStageIdx(0);
    setRunning(true);
    let i = 0;
    timerRef.current = setInterval(() => {
      i += 1;
      if (i < STAGES.length) {
        setStageIdx(i);
      } else {
        if (timerRef.current) clearInterval(timerRef.current);
        setStageIdx(STAGES.length - 1);
        setRunning(false);
        const res = scan(inputs);
        setResult(res);
      }
    }, 620);
  };

  // Auto-save every finished scan to the workspace history.
  useEffect(() => {
    if (!result || savedName) return;
    saveScan({
      name: scanName.trim() || `Scan ${new Date().toLocaleString()}`,
      score: result.score,
      grade: result.grade,
      filesScanned: result.filesScanned,
      linesScanned: result.linesScanned,
      critical: result.counts.critical,
      high: result.counts.high,
      medium: result.counts.medium,
      low: result.counts.low,
      info: result.counts.info,
      findings: result.findings,
    })
      .then((id) => {
        setSavedName(scanName.trim() || `Scan ${new Date().toLocaleString()}`);
        setSavedScanId(id);
        toast.success("Report saved to workspace history");
      })
      .catch(() => toast.error("Could not save the report"));
  }, [result, savedName, scanName, saveScan]);

  const handleDelete = async (id: Id<"scans">) => {
    await deleteScan({ id });
    toast.success("Scan deleted");
  };

  const activeReport =
    viewing ?? (result ? { name: scanName || "Untitled scan", result, id: savedScanId, aiAnalysis: null } : null);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-40 border-b border-border/60 bg-background/85 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
          <Link to="/" className="flex items-center gap-2.5">
            <div className="flex size-8 items-center justify-center rounded-lg bg-primary/12 ring-1 ring-primary/30">
              <Crosshair className="size-4.5 text-primary" />
            </div>
            <span className="text-[15px] font-semibold tracking-tight">CrackScope</span>
            <Badge variant="outline" className="ml-1 rounded-full border-primary/30 text-[11px] text-primary">
              beta
            </Badge>
          </Link>
          <div className="flex items-center gap-3">
            <span className="hidden text-sm text-muted-foreground sm:block">
              {user?.email ?? user?.name ?? "Guest"}
            </span>
            <Button variant="outline" size="sm" className="gap-2 rounded-full" onClick={handleSignOut}>
              <LogOut className="size-3.5" /> Sign out
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-6xl px-6 py-10">
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
            </TabsList>
          </div>

          {/* Scanner */}
          <TabsContent value="scanner" className="space-y-8">
            <div className="grid gap-6 lg:grid-cols-5">
              <Card className="border-border/60 bg-card/60 lg:col-span-3">
                <CardContent className="space-y-4 p-6">
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <label className="text-sm font-medium">Scan name</label>
                      <Input
                        value={scanName}
                        onChange={(e) => setScanName(e.target.value)}
                        placeholder="e.g. payments-service"
                        className="rounded-lg"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-sm font-medium">Pasted file name</label>
                      <Input
                        value={fileName}
                        onChange={(e) => setFileName(e.target.value)}
                        placeholder="pasted.js"
                        className="rounded-lg font-mono text-sm"
                      />
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <label className="text-sm font-medium">Code to attack</label>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 gap-1.5 rounded-full text-xs text-muted-foreground"
                        onClick={() => {
                          setScanName((n) => n || "vulnerable-demo");
                          setFileName(SAMPLE_NAME);
                          setCodeText(SAMPLE_CODE);
                          setUploaded((prev) =>
                            prev.some((f) => f.name === "package.json")
                              ? prev
                              : [...prev, { name: "package.json", content: SAMPLE_MANIFEST }].slice(0, 40),
                          );
                        }}
                      >
                        <FlaskConical className="size-3.5" /> Load vulnerable demo
                      </Button>
                    </div>
                    <Textarea
                      value={codeText}
                      onChange={(e) => setCodeText(e.target.value)}
                      placeholder={"// Paste source code here — JS/TS, Python, Go, Ruby, PHP, Java…\n// Nothing is uploaded until you save a report."}
                      className="min-h-[220px] resize-y rounded-lg font-mono text-[13px] leading-5"
                    />
                  </div>
                  <div
                    onDragOver={(e) => {
                      e.preventDefault();
                      setDragging(true);
                    }}
                    onDragLeave={() => setDragging(false)}
                    onDrop={(e) => {
                      e.preventDefault();
                      setDragging(false);
                      void handleFiles(Array.from(e.dataTransfer.files));
                    }}
                    className={`rounded-xl border border-dashed p-4 transition-colors ${
                      dragging ? "border-primary bg-primary/10" : "border-border bg-secondary/30"
                    }`}
                  >
                    <div className="flex flex-wrap items-center gap-3">
                      <Upload className="size-5 shrink-0 text-primary" />
                      <p className="min-w-0 flex-1 text-sm text-muted-foreground">
                        Drag & drop files, a folder, or a <span className="font-medium text-foreground">.zip</span> here
                      </p>
                      <label>
                        <input
                          type="file"
                          multiple
                          className="hidden"
                          onChange={(e) => {
                            void handleFiles(Array.from(e.target.files ?? []));
                            e.target.value = "";
                          }}
                        />
                        <span className="inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-full border border-input bg-background px-3 text-xs font-medium shadow-xs hover:bg-secondary">
                          <Upload className="size-3.5" /> Files
                        </span>
                      </label>
                      <label>
                        <input
                          type="file"
                          multiple
                          className="hidden"
                          {...({ webkitdirectory: "", directory: "" } as Record<string, string>)}
                          onChange={(e) => {
                            void handleFiles(Array.from(e.target.files ?? []));
                            e.target.value = "";
                          }}
                        />
                        <span className="inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-full border border-input bg-background px-3 text-xs font-medium shadow-xs hover:bg-secondary">
                          <FolderOpen className="size-3.5" /> Folder
                        </span>
                      </label>
                    </div>
                    <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-border/50 pt-3">
                      <Github className="size-4 shrink-0 text-muted-foreground" />
                      <Input
                        value={repoUrl}
                        onChange={(e) => setRepoUrl(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && !repoLoading) void handleFetchRepo();
                        }}
                        placeholder="github.com/owner/repo — or owner/repo (public)"
                        className="h-8 min-w-0 flex-1 rounded-full bg-background px-3 text-xs"
                        disabled={repoLoading}
                      />
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-8 rounded-full px-3 text-xs"
                        disabled={repoLoading}
                        onClick={() => void handleFetchRepo()}
                      >
                        {repoLoading ? (
                          <Loader2 className="size-3.5 animate-spin" />
                        ) : (
                          "Fetch repo"
                        )}
                      </Button>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-3">
                    <Button onClick={handleRun} disabled={!canRun} className="gap-2 rounded-full scan-glow">
                      <Play className="size-4" />
                      {running ? "Attacking…" : `Run attack simulation${queuedCount > 0 ? ` (${queuedCount})` : ""}`}
                    </Button>
                    {uploaded.length > 0 && (
                      <span className="font-mono text-xs text-muted-foreground">
                        {summarizeInputs(uploaded)}
                      </span>
                    )}
                  </div>
                  {uploaded.length > 0 && (
                    <div className="flex max-h-40 flex-wrap gap-2 overflow-y-auto pt-1">
                      {uploaded.map((f, i) => (
                        <span
                          key={`${f.name}-${i}`}
                          className="inline-flex items-center gap-1.5 rounded-full border border-border bg-secondary px-3 py-1 font-mono text-xs"
                        >
                          {f.name.split("/").pop()}
                          <span className="text-muted-foreground/70">{f.name.split("/").slice(0, -1).join("/")}</span>
                          <button
                            className="ml-0.5 text-muted-foreground hover:text-foreground"
                            onClick={() => setUploaded((prev) => prev.filter((_, j) => j !== i))}
                            aria-label={`Remove ${f.name}`}
                          >
                            ×
                          </button>
                        </span>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Live stage console */}
              <Card className="border-border/60 bg-card/60 lg:col-span-2">
                <CardContent className="p-6">
                  <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                    Attack console
                  </p>
                  <div className="mt-5 space-y-1">
                    {STAGES.map((stage, i) => {
                      const isActive = running && i === stageIdx;
                      const isDone = stageIdx > i || (!running && result !== null);
                      return (
                        <div
                          key={stage.id}
                          className={`flex items-start gap-3 rounded-lg px-3 py-2.5 transition-colors ${
                            isActive ? "bg-primary/10" : ""
                          }`}
                        >
                          <span
                            className={`mt-1 size-2 shrink-0 rounded-full ${
                              isDone
                                ? "bg-primary"
                                : isActive
                                  ? "animate-pulse bg-primary"
                                  : "bg-muted-foreground/30"
                            }`}
                          />
                          <div className="min-w-0">
                            <p
                              className={`font-mono text-sm ${
                                isActive ? "font-medium text-primary" : isDone ? "text-foreground" : "text-muted-foreground"
                              }`}
                            >
                              [{stage.id}] {stage.label}
                            </p>
                            {isActive && (
                              <p className="mt-0.5 text-xs text-muted-foreground">{stage.detail}</p>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            </div>

            {activeReport && (
              <>
                <ScanReport data={activeReport} />
                <div className="mt-6">
                  <AiAnalysis
                    name={activeReport.name}
                    result={activeReport.result}
                    scanId={activeReport.id}
                    initialJson={activeReport.aiAnalysis}
                  />
                </div>
              </>
            )}
          </TabsContent>

          {/* History */}
          <TabsContent value="history" className="space-y-6">
            {scans === undefined ? (
              <p className="py-12 text-center text-sm text-muted-foreground">Loading history…</p>
            ) : scans.length === 0 ? (
              <Card className="border-border/60 bg-card/60">
                <CardContent className="py-14 text-center">
                  <History className="mx-auto size-8 text-muted-foreground/60" />
                  <p className="mt-4 font-medium">No scans yet</p>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Run your first attack simulation and it will be saved here.
                  </p>
                  <Button variant="outline" className="mt-6 rounded-full" onClick={() => setTab("scanner")}>
                    Go to scanner
                  </Button>
                </CardContent>
              </Card>
            ) : (
              <>
                {velocity && (
                  <Card className="border-border/60 bg-card/60">
                    <CardContent className="flex flex-col gap-4 p-5 sm:flex-row sm:items-center">
                      <div className="min-w-0 flex-1">
                        <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                          Remediation velocity
                        </p>
                        <p className="mt-1 text-sm text-muted-foreground">
                          {velocity.totalFixed} finding{velocity.totalFixed === 1 ? "" : "s"} fixed ·{" "}
                          {velocity.totalAdded} introduced across {velocity.points.length - 1} scan
                          transition{velocity.points.length === 2 ? "" : "s"} · net{" "}
                          {velocity.netPerScan > 0 ? "+" : ""}
                          {velocity.netPerScan} per scan
                        </p>
                      </div>
                      <Badge
                        variant="outline"
                        className={`shrink-0 gap-1.5 rounded-full capitalize ${
                          velocity.verdict === "improving"
                            ? "border-primary/30 bg-primary/10 text-primary"
                            : velocity.verdict === "degrading"
                              ? "border-destructive/40 bg-destructive/10 text-destructive"
                              : "border-border bg-muted text-muted-foreground"
                        }`}
                      >
                        {velocity.verdict === "improving" ? (
                          <TrendingUp className="size-3.5" />
                        ) : velocity.verdict === "degrading" ? (
                          <TrendingDown className="size-3.5" />
                        ) : (
                          <Minus className="size-3.5" />
                        )}
                        {velocity.verdict}
                      </Badge>
                      <svg viewBox="0 0 240 40" className="h-10 w-full shrink-0 text-primary sm:w-64">
                        <polyline
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          points={velocity.points
                            .map(
                              (p, i) =>
                                `${(i / Math.max(velocity.points.length - 1, 1)) * 236 + 2},${38 - (p.score / 100) * 34}`,
                            )
                            .join(" ")}
                        />
                      </svg>
                    </CardContent>
                  </Card>
                )}

                {diffPair && (
                  <DiffView
                    baselineName={diffPair.baseName}
                    baseline={diffPair.base}
                    currentName={diffPair.currName}
                    current={diffPair.curr}
                    diff={diffScanResults(diffPair.base, diffPair.curr)}
                    onClose={() => {
                      setDiffPair(null);
                      setCompareBaseId(null);
                    }}
                  />
                )}

                {!diffPair &&
                  compareBaseId &&
                  (() => {
                    const base = scans.find((x) => x._id === compareBaseId);
                    return base ? (
                      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-primary/30 bg-primary/5 px-4 py-3 text-sm">
                        <span>
                          Baseline selected: <span className="font-medium">{base.name}</span> — pick
                          another scan to compare.
                        </span>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 rounded-full text-xs"
                          onClick={() => setCompareBaseId(null)}
                        >
                          Cancel
                        </Button>
                      </div>
                    ) : null;
                  })()}

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
                        <div className="flex gap-2">
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
        </Tabs>
      </main>
    </div>
  );
}
