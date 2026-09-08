// CrackScope Part 21 — scheduled & recurring scans UI.
// Create daily/weekly re-scans of public GitHub repos, run due schedules on
// demand, and review drift alerts (regressions / fixes / new criticals)
// recorded by the scheduleRuns.runDue action.
import { useEffect, useState } from "react";
import { useAction, useMutation, useQuery } from "convex/react";
import { toast } from "sonner";
import {
  AlarmClock,
  BellRing,
  CheckCheck,
  CircleSlash,
  GitCompareArrows,
  Github,
  Loader2,
  Pause,
  Play,
  Plus,
  Radar,
  Trash2,
  TrendingDown,
  TrendingUp,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { api } from "@/convex/_generated/api";

const VERDICT_META = {
  regressed: {
    label: "Regressed",
    className: "border-destructive/40 bg-destructive/10 text-destructive",
    icon: TrendingUp,
  },
  improved: {
    label: "Improved",
    className: "border-primary/40 bg-primary/10 text-primary",
    icon: TrendingDown,
  },
  unchanged: {
    label: "No drift",
    className: "border-border bg-muted text-muted-foreground",
    icon: CircleSlash,
  },
  mixed: {
    label: "Mixed",
    className: "border-[oklch(0.8_0.16_85)]/40 bg-[oklch(0.8_0.16_85)]/10 text-[oklch(0.82_0.14_85)]",
    icon: GitCompareArrows,
  },
  first_run: {
    label: "First run",
    className: "border-border bg-muted text-muted-foreground",
    icon: Radar,
  },
} as const;

function timeUntil(ts: number): string {
  const s = Math.floor((ts - Date.now()) / 1000);
  if (s <= 0) return "due now";
  if (s < 3600) return `in ${Math.floor(s / 60)}m`;
  if (s < 86400) return `in ${Math.floor(s / 3600)}h`;
  return `in ${Math.floor(s / 86400)}d`;
}

function timeAgo(ts: number): string {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function ScheduledScans() {
  const schedules = useQuery(api.schedules.listSchedules) ?? [];
  const alerts = useQuery(api.schedules.listAlerts, { limit: 20 }) ?? [];
  const unread = useQuery(api.schedules.unreadCount) ?? 0;
  const dueCount = useQuery(api.schedules.dueCount) ?? 0;

  const runDue = useAction(api.scheduleRuns.runDue);
  const createSchedule = useMutation(api.schedules.createSchedule);
  const toggleSchedule = useMutation(api.schedules.toggleSchedule);
  const deleteSchedule = useMutation(api.schedules.deleteSchedule);
  const markAlertsSeen = useMutation(api.schedules.markAlertsSeen);

  const [repoUrl, setRepoUrl] = useState("");
  const [frequency, setFrequency] = useState<"daily" | "weekly">("weekly");
  const [notify, setNotify] = useState(true);
  const [running, setRunning] = useState(false);
  // Auto-run due schedules shortly after the tab mounts (same pattern as the
  // Part 20 report center). Skip while a run is already in flight.
  useEffect(() => {
    if (dueCount === 0 || running) return;
    setRunning(true);
    runDue({ notify })
      .then((results) => {
        const ok = results.filter((r) => r.ok).length;
        if (ok > 0) toast.success(`Ran ${ok} scheduled scan${ok === 1 ? "" : "s"}`);
        for (const r of results.filter((x) => !x.ok)) toast.error(r.message);
      })
      .catch((e: Error) => toast.error(e.message))
      .finally(() => setRunning(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dueCount]);

  const handleRunDue = async () => {
    setRunning(true);
    try {
      const results = await runDue({ notify });
      const ok = results.filter((r) => r.ok).length;
      if (ok > 0) toast.success(`Ran ${ok} scheduled scan${ok === 1 ? "" : "s"}`);
      else toast.info("No schedules are due yet");
      for (const r of results.filter((x) => !x.ok)) toast.error(r.message);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Scheduled run failed");
    } finally {
      setRunning(false);
    }
  };

  const handleCreate = async () => {
    try {
      await createSchedule({ repoUrl, frequency });
      setRepoUrl("");
      toast.success(
        `Schedule created — first run ${frequency === "daily" ? "tomorrow" : "next week"}`,
      );
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not create schedule");
    }
  };

  return (
    <div className="space-y-6">
      {/* Run due */}
      <Card className="border-primary/30 bg-primary/5">
        <CardContent className="flex flex-wrap items-center gap-4 p-5">
          <Radar className="size-5 shrink-0 text-primary" />
          <div className="min-w-0 flex-1">
            <p className="font-medium">Scheduled re-scans</p>
            <p className="text-sm text-muted-foreground">
              {dueCount > 0
                ? `${dueCount} schedule${dueCount === 1 ? " is" : "s are"} due right now.`
                : "Schedules fire automatically when due. Diffing records drift alerts between runs."}
            </p>
          </div>
          <Button className="gap-2 rounded-full" disabled={running} onClick={() => void handleRunDue()}>
            {running ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4" />}
            {running ? "Running…" : "Run due now"}
          </Button>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Schedules */}
        <Card className="border-border/60 bg-card/60">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <AlarmClock className="size-4 text-primary" /> Your schedules
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {schedules.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No schedules yet — add a public GitHub repo below to re-scan it automatically.
              </p>
            ) : (
              <div className="space-y-2">
                {schedules.map((s) => (
                  <div key={s._id} className="rounded-lg border border-border/60 px-3 py-2.5">
                    <div className="flex items-center gap-2">
                      <Github className="size-3.5 shrink-0 text-muted-foreground" />
                      <p className="min-w-0 flex-1 truncate font-mono text-sm font-medium">{s.repoUrl}</p>
                      <Badge
                        variant="outline"
                        className={`rounded-full text-[11px] ${
                          !s.enabled
                            ? "border-border bg-muted text-muted-foreground"
                            : s.nextRunAt <= Date.now()
                              ? "border-primary/40 bg-primary/10 text-primary"
                              : "border-border bg-muted text-muted-foreground"
                        }`}
                      >
                        {s.enabled ? timeUntil(s.nextRunAt) : "paused"}
                      </Badge>
                    </div>
                    <p className="mt-1 font-mono text-xs text-muted-foreground">
                      {s.frequency} · {s.lastStatus ?? "not run yet"}
                      {s.lastRunAt ? ` · ${timeAgo(s.lastRunAt)}` : ""}
                      {s.lastScore !== null ? ` · score ${s.lastScore}/100 (${s.lastGrade})` : ""}
                    </p>
                    <div className="mt-2 flex gap-2">
                      <Button size="sm" variant="outline" className="h-7 rounded-full text-xs" onClick={() => void toggleSchedule({ id: s._id })}>
                        {s.enabled ? <Pause className="size-3" /> : <Play className="size-3" />}
                        {s.enabled ? "Pause" : "Resume"}
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-7 rounded-full text-xs text-muted-foreground hover:text-destructive"
                        onClick={() => void deleteSchedule({ id: s._id })}
                      >
                        <Trash2 className="size-3" /> Delete
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
            <Separator />
            <div className="grid gap-3 sm:grid-cols-2">
              <Input
                placeholder="github.com/owner/repo"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && repoUrl.trim()) void handleCreate();
                }}
              />
              <Select value={frequency} onValueChange={(v) => setFrequency(v as "daily" | "weekly")}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="daily">Daily</SelectItem>
                  <SelectItem value="weekly">Weekly</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button className="w-full rounded-full" disabled={!repoUrl.trim()} onClick={() => void handleCreate()}>
              <Plus className="size-4" /> Create schedule
            </Button>
          </CardContent>
        </Card>

        {/* Drift alerts */}
        <Card className="border-border/60 bg-card/60">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <BellRing className="size-4 text-primary" /> Drift alerts
              {unread > 0 && (
                <Badge className="rounded-full bg-primary text-primary-foreground">{unread} new</Badge>
              )}
              {alerts.length > 0 && unread > 0 && (
                <Button
                  size="sm"
                  variant="ghost"
                  className="ml-auto h-7 gap-1.5 rounded-full text-xs text-muted-foreground"
                  onClick={() => void markAlertsSeen()}
                >
                  <CheckCheck className="size-3.5" /> Mark all seen
                </Button>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {alerts.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                Alerts appear after a scheduled run — regressions, fixes, and new criticals vs the
                previous run.
              </p>
            ) : (
              alerts.map((a) => {
                const meta = VERDICT_META[a.verdict as keyof typeof VERDICT_META];
                const Icon = meta.icon;
                return (
                  <div
                    key={a._id}
                    className={`rounded-lg border px-3 py-2.5 ${a.seen ? "border-border/60" : "border-primary/40 bg-primary/5"}`}
                  >
                    <div className="flex items-center gap-2">
                      <Icon className="size-3.5 shrink-0" />
                      <p className="min-w-0 flex-1 truncate font-mono text-sm font-medium">{a.scanName}</p>
                      <span
                        className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${meta.className}`}
                      >
                        {meta.label}
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground">{a.detail}</p>
                    <p className="mt-0.5 font-mono text-[11px] text-muted-foreground/70">{timeAgo(a.at)}</p>
                  </div>
                );
              })
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
