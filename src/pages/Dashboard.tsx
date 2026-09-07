import { useCallback, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useMutation, useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScanReportView } from "@/components/ScanReportView";
import { useAuth } from "@/hooks/use-auth";
import {
  runScan,
  ATTACK_PHASES,
  EMPTY_COUNTS,
  type ScanFile,
  type ScanReport,
} from "@/lib/scanner";
import { ROADMAP_PHASES, TOTAL_PARTS, SHIPPED_PARTS } from "@/lib/roadmap";
import {
  Crosshair,
  LogOut,
  Play,
  Trash2,
  History,
  Loader2,
  FileCode2,
  Radar,
  Map,
  FileWarning,
} from "lucide-react";
import { cn } from "@/lib/utils";
import logo from "@/assets/logo.svg";
import { toast } from "sonner";

const SAMPLE_CODE = `// checkout-service/billing.ts
import express from "express";
import db from "./db";

const app = express();

app.get("/invoice", (req, res) => {
  const userQuery = "SELECT * FROM invoices WHERE owner = '" + req.query.user + "'";
  db.query(userQuery, (err, rows) => {
    res.send("<h1>Invoices for " + req.query.user + "</h1>" + rows.map(r => r.html).join(""));
  });
});

app.get("/download", (req, res) => {
  const path = "./uploads/" + req.query.file;
  res.sendFile(path);
});

const apiKey = "sk_live_51H9xKdQz8fTj2mNp3vLwXyZa";
const resetToken = Math.random().toString(36).slice(2);
const md5 = require("crypto").createHash("md5").update(req.body.password).digest("hex");

eval("console.log('processing ' + req.body.action)");
`;

type Phase = "idle" | "running" | "done";

export default function Dashboard() {
  const { user, signOut } = useAuth();
  const saveScan = useMutation(api.scans.saveScan);
  const deleteScan = useMutation(api.scans.deleteScan);
  const scans = useQuery(api.scans.listScans, {});

  const [tab, setTab] = useState("scan");
  const [phase, setPhase] = useState<Phase>("idle");
  const [phaseIdx, setPhaseIdx] = useState(0);
  const [name, setName] = useState("Untitled target");
  const [code, setCode] = useState("");
  const [files, setFiles] = useState<ScanFile[]>([]);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [viewingId, setViewingId] = useState<Id<"scans"> | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSignOut = async () => {
    await signOut();
  };

  const addFiles = useCallback((list: FileList | null) => {
    if (!list) return;
    const incoming = Array.from(list).slice(0, 10);
    Promise.all(
      incoming.map(
        (f) =>
          new Promise<ScanFile>((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve({ name: f.name, content: String(reader.result ?? "") });
            reader.onerror = reject;
            reader.readAsText(f);
          }),
      ),
    )
      .then((added) => {
        setFiles((prev) => [...prev, ...added].slice(0, 20));
        toast.success(`Added ${added.length} file${added.length === 1 ? "" : "s"}`);
      })
      .catch(() => toast.error("Failed to read a file"));
  }, []);

  const runSimulation = async () => {
    const allFiles: ScanFile[] = [
      ...files,
      ...(code.trim()
        ? [{ name: files.length === 0 && code.includes("\n") === false ? "pasted-snippet" : "pasted-code", content: code }]
        : []),
    ];
    if (allFiles.length === 0) {
      toast.error("Paste some code or add files first");
      return;
    }
    setReport(null);
    setViewingId(null);
    setPhase("running");
    setPhaseIdx(0);
    // Staged attack-simulation animation
    for (let i = 0; i < ATTACK_PHASES.length; i++) {
      setPhaseIdx(i);
      await new Promise((r) => setTimeout(r, 420));
    }
    const result = runScan(allFiles, name.trim() || "Untitled target");
    setReport(result);
    setPhase("done");
    try {
      await saveScan({
        name: result.name,
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
      });
      toast.success("Scan saved to history");
    } catch {
      toast.error("Scan completed but could not be saved");
    }
  };

  const handleDelete = async (id: Id<"scans">) => {
    await deleteScan({ id });
    if (viewingId === id) {
      setViewingId(null);
      setTab("history");
    }
  };

  const viewedScan = useMemo(
    () => (viewingId ? scans?.find((s) => s._id === viewingId) ?? null : null),
    [viewingId, scans],
  );

  const viewedReport: ScanReport | null = useMemo(() => {
    if (!viewedScan) return null;
    return {
      name: viewedScan.name,
      createdAt: viewedScan.createdAt,
      score: viewedScan.score,
      grade: viewedScan.grade,
      filesScanned: viewedScan.filesScanned,
      linesScanned: viewedScan.linesScanned,
      counts: {
        critical: viewedScan.critical,
        high: viewedScan.high,
        medium: viewedScan.medium,
        low: viewedScan.low,
        info: viewedScan.info,
      },
      findings: viewedScan.findings,
      phases: ATTACK_PHASES,
    };
  }, [viewedScan]);

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <header className="sticky top-0 z-40 border-b border-border/60 bg-background/80 backdrop-blur-md">
        <div className="mx-auto flex h-16 w-full max-w-6xl items-center justify-between px-6">
          <div className="flex items-center gap-2.5">
            <img src={logo} alt="CrackScope" className="size-8 rounded-lg" />
            <span className="text-[15px] font-semibold tracking-tight">CrackScope</span>
            <Badge variant="secondary" className="ml-1 hidden sm:inline-flex">
              Part 1 / {TOTAL_PARTS}
            </Badge>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden text-sm text-muted-foreground sm:block">
              {user?.name ?? user?.email ?? "Operator"}
            </span>
            <Button variant="outline" size="sm" className="cursor-pointer gap-1.5" onClick={handleSignOut}>
              <LogOut className="size-3.5" /> Sign out
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-6xl px-6 py-8">
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList className="grid w-full max-w-md grid-cols-3">
            <TabsTrigger value="scan" className="cursor-pointer gap-1.5">
              <Crosshair className="size-4" /> Scanner
            </TabsTrigger>
            <TabsTrigger value="history" className="cursor-pointer gap-1.5">
              <History className="size-4" /> History
            </TabsTrigger>
            <TabsTrigger value="roadmap" className="cursor-pointer gap-1.5">
              <Map className="size-4" /> Roadmap
            </TabsTrigger>
          </TabsList>

          {/* Scanner tab */}
          <TabsContent value="scan" className="mt-6">
            <AnimatePresence mode="wait">
              {phase !== "running" && (
                <motion.div
                  key="workspace"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex flex-col gap-4"
                >
                  <Card className="border-border/70 shadow-sm">
                    <CardHeader className="pb-4">
                      <CardTitle className="flex items-center gap-2 text-base">
                        <Radar className="size-4 text-primary" /> New attack simulation
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="flex flex-col gap-4">
                      <div className="flex flex-col gap-3 sm:flex-row">
                        <Input
                          value={name}
                          onChange={(e) => setName(e.target.value)}
                          placeholder="Target name (e.g. checkout-service)"
                          className="flex-1"
                        />
                        <input
                          ref={fileInputRef}
                          type="file"
                          multiple
                          className="hidden"
                          onChange={(e) => {
                            addFiles(e.target.files);
                            e.target.value = "";
                          }}
                        />
                        <Button
                          variant="outline"
                          className="cursor-pointer gap-1.5"
                          onClick={() => fileInputRef.current?.click()}
                        >
                          <FileCode2 className="size-4" /> Add files
                        </Button>
                        <Button
                          variant="ghost"
                          className="cursor-pointer gap-1.5"
                          onClick={() => setCode(SAMPLE_CODE)}
                        >
                          <FileWarning className="size-4" /> Load sample
                        </Button>
                      </div>

                      {files.length > 0 && (
                        <div className="flex flex-wrap gap-2">
                          {files.map((f, i) => (
                            <Badge
                              key={`${f.name}-${i}`}
                              variant="secondary"
                              className="cursor-pointer gap-1.5 pr-1.5"
                            >
                              {f.name}
                              <button
                                className="rounded-full p-0.5 hover:bg-foreground/10"
                                onClick={() => setFiles((prev) => prev.filter((_, j) => j !== i))}
                                aria-label={`Remove ${f.name}`}
                              >
                                ×
                              </button>
                            </Badge>
                          ))}
                        </div>
                      )}

                      <Textarea
                        value={code}
                        onChange={(e) => setCode(e.target.value)}
                        placeholder="Paste source code here — any language. The engine fires injection probes, secrets sweeps, crypto audits and config checks against it."
                        className="min-h-[220px] resize-y font-mono text-[13px] leading-5"
                      />

                      <div className="flex items-center justify-between gap-3">
                        <p className="text-xs text-muted-foreground">
                          Only scan code you own or are authorized to test. Analysis runs locally in your browser.
                        </p>
                        <Button
                          className="cursor-pointer gap-2 shadow-lg shadow-primary/20"
                          onClick={runSimulation}
                        >
                          <Play className="size-4" /> Run attack simulation
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              )}

              {phase === "running" && (
                <motion.div
                  key="running"
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                >
                  <Card className="border-border/70 shadow-sm">
                    <CardContent className="p-8">
                      <div className="flex items-center gap-3">
                        <Loader2 className="size-5 animate-spin text-primary" />
                        <p className="font-mono text-sm">Firing attack battery against {name || "target"}…</p>
                      </div>
                      <div className="mt-6 space-y-2.5 font-mono text-[13px]">
                        {ATTACK_PHASES.map((p, i) => (
                          <div
                            key={p}
                            className={cn(
                              "flex items-center gap-2.5 transition-colors",
                              i < phaseIdx ? "text-muted-foreground" : i === phaseIdx ? "text-primary" : "text-muted-foreground/40",
                            )}
                          >
                            {i < phaseIdx ? (
                              <span className="text-primary">✓</span>
                            ) : i === phaseIdx ? (
                              <span className="relative flex size-2">
                                <span className="absolute inline-flex size-full animate-ping rounded-full bg-primary opacity-60" />
                                <span className="relative inline-flex size-2 rounded-full bg-primary" />
                              </span>
                            ) : (
                              <span className="size-2 rounded-full border border-current" />
                            )}
                            {p}
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              )}
            </AnimatePresence>

            {phase === "done" && report && (
              <motion.div
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4 }}
                className="mt-4"
              >
                <ScanReportView report={report} />
              </motion.div>
            )}
          </TabsContent>

          {/* History tab */}
          <TabsContent value="history" className="mt-6">
            {scans === undefined ? (
              <div className="flex items-center justify-center py-16 text-muted-foreground">
                <Loader2 className="size-5 animate-spin" />
              </div>
            ) : viewedReport ? (
              <div className="flex flex-col gap-4">
                <Button
                  variant="ghost"
                  className="w-fit cursor-pointer gap-1.5"
                  onClick={() => setViewingId(null)}
                >
                  ← Back to history
                </Button>
                <ScanReportView report={viewedReport} />
              </div>
            ) : scans.length === 0 ? (
              <Card className="border-dashed border-border/70 shadow-none">
                <CardContent className="flex flex-col items-center gap-2 py-14 text-center">
                  <History className="size-8 text-muted-foreground/50" />
                  <p className="text-sm font-medium">No scans yet</p>
                  <p className="max-w-sm text-sm text-muted-foreground">
                    Run your first attack simulation and every report will be archived here.
                  </p>
                  <Button variant="outline" className="mt-2 cursor-pointer" onClick={() => setTab("scan")}>
                    Go to scanner
                  </Button>
                </CardContent>
              </Card>
            ) : (
              <div className="flex flex-col gap-3">
                {scans.map((s) => (
                  <Card
                    key={s._id}
                    className="cursor-pointer border-border/70 shadow-sm transition-colors hover:border-primary/30"
                    onClick={() => setViewingId(s._id)}
                  >
                    <CardContent className="flex items-center gap-4 p-4">
                      <span
                        className={cn(
                          "flex size-12 shrink-0 items-center justify-center rounded-xl text-lg font-semibold",
                          s.score >= 75
                            ? "bg-primary/10 text-primary"
                            : s.score >= 50
                              ? "bg-amber-500/10 text-amber-400"
                              : "bg-red-500/10 text-red-400",
                        )}
                      >
                        {s.grade}
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-semibold">{s.name}</p>
                        <p className="mt-0.5 text-xs text-muted-foreground">
                          {new Date(s.createdAt).toLocaleString()} · {s.filesScanned} files ·{" "}
                          {s.critical + s.high + s.medium + s.low + s.info} findings
                        </p>
                      </div>
                      <div className="hidden gap-1.5 sm:flex">
                        {s.critical > 0 && (
                          <Badge variant="outline" className="bg-red-500/15 text-red-400 border-red-500/30">
                            {s.critical} crit
                          </Badge>
                        )}
                        {s.high > 0 && (
                          <Badge variant="outline" className="bg-orange-500/15 text-orange-400 border-orange-500/30">
                            {s.high} high
                          </Badge>
                        )}
                      </div>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="shrink-0 cursor-pointer text-muted-foreground hover:text-red-400"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDelete(s._id);
                        }}
                        aria-label="Delete scan"
                      >
                        <Trash2 className="size-4" />
                      </Button>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </TabsContent>

          {/* Roadmap tab */}
          <TabsContent value="roadmap" className="mt-6">
            <div className="flex flex-col gap-8">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-xl font-semibold tracking-tight">The 25-part build plan</h2>
                  <p className="mt-1 text-sm text-muted-foreground">
                    {SHIPPED_PARTS} of {TOTAL_PARTS} parts shipped. Each part lands as an increment you can use.
                  </p>
                </div>
                <Badge variant="outline" className="gap-1.5 border-primary/30 text-primary">
                  {SHIPPED_PARTS}/{TOTAL_PARTS} complete
                </Badge>
              </div>
              {ROADMAP_PHASES.map((phase) => (
                <div key={phase.phase}>
                  <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                    Phase {phase.phase} — {phase.name}
                  </p>
                  <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                    {phase.parts.map((part) => (
                      <div
                        key={part.part}
                        className={cn(
                          "rounded-xl border p-4",
                          part.status === "shipped"
                            ? "border-primary/40 bg-primary/5"
                            : "border-border/70 bg-card",
                        )}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-xs text-muted-foreground">
                            #{String(part.part).padStart(2, "0")}
                          </span>
                          <span
                            className={cn(
                              "text-[10px] font-semibold uppercase tracking-wider",
                              part.status === "shipped"
                                ? "text-primary"
                                : part.status === "up-next"
                                  ? "text-amber-400"
                                  : "text-muted-foreground/60",
                            )}
                          >
                            {part.status === "shipped" ? "Shipped" : part.status === "up-next" ? "Up next" : "Planned"}
                          </span>
                        </div>
                        <p className="mt-2 text-sm font-medium">{part.title}</p>
                        <p className="mt-1 text-xs leading-5 text-muted-foreground">{part.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}
