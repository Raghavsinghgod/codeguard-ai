// CrackScope Part 20 — Report center UI.
// Branded report profiles (client-facing company, accent color, footer) and
// scheduled email delivery of saved scan reports. Delivery runs through the
// Resend-backed `deliverDue` action; scheduling state lives in Convex.
import { useEffect, useState } from "react";
import { useAction, useMutation, useQuery } from "convex/react";
import { toast } from "sonner";
import {
  CalendarClock,
  Mail,
  Palette,
  Plus,
  Send,
  Trash2,
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
import type { Id } from "@/convex/_generated/dataModel";

const ACCENTS = [
  { value: "#22c55e", label: "Green" },
  { value: "#38bdf8", label: "Blue" },
  { value: "#a78bfa", label: "Violet" },
  { value: "#f59e0b", label: "Amber" },
  { value: "#f43f5e", label: "Rose" },
];

function timeAgo(ts: number): string {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function timeUntil(ts: number): string {
  const s = Math.floor((ts - Date.now()) / 1000);
  if (s <= 0) return "due now";
  if (s < 3600) return `in ${Math.floor(s / 60)}m`;
  if (s < 86400) return `in ${Math.floor(s / 3600)}h`;
  return `in ${Math.floor(s / 86400)}d`;
}

export function ReportCenter() {
  const profiles = useQuery(api.reports.listProfiles) ?? [];
  const schedules = useQuery(api.reports.listSchedules) ?? [];
  const scans = useQuery(api.scans.listScans) ?? [];
  const deliverDue = useAction(api.reports.deliverDue);
  const saveProfile = useMutation(api.reports.saveProfile);
  const deleteProfile = useMutation(api.reports.deleteProfile);
  const createSchedule = useMutation(api.reports.createSchedule);
  const toggleSchedule = useMutation(api.reports.toggleSchedule);
  const deleteSchedule = useMutation(api.reports.deleteSchedule);

  // Profile form
  const [profileName, setProfileName] = useState("");
  const [company, setCompany] = useState("");
  const [accent, setAccent] = useState(ACCENTS[0].value);
  const [footer, setFooter] = useState("");

  // Schedule form
  const [scanId, setScanId] = useState<string>("");
  const [recipients, setRecipients] = useState("");
  const [frequency, setFrequency] = useState<"weekly" | "monthly">("weekly");

  const [sending, setSending] = useState(false);

  // Auto-fire due schedules shortly after the tab mounts.
  const dueCount = schedules.filter((s) => s.enabled && s.nextSendAt <= Date.now()).length;
  useEffect(() => {
    if (dueCount === 0 || sending) return;
    setSending(true);
    deliverDue()
      .then((results) => {
        const ok = results.filter((r) => r.ok).length;
        if (ok > 0) toast.success(`Delivered ${ok} scheduled report${ok === 1 ? "" : "s"}`);
        for (const r of results.filter((x) => !x.ok)) toast.error(r.message);
      })
      .catch((e: Error) => toast.error(e.message))
      .finally(() => setSending(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dueCount]);

  const handleSendNow = async () => {
    setSending(true);
    try {
      const results = await deliverDue();
      const ok = results.filter((r) => r.ok).length;
      if (ok > 0) toast.success(`Delivered ${ok} report${ok === 1 ? "" : "s"}`);
      else toast.info("No schedules are due yet");
      for (const r of results.filter((x) => !x.ok)) toast.error(r.message);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Delivery failed");
    } finally {
      setSending(false);
    }
  };

  const handleCreateProfile = async () => {
    try {
      await saveProfile({ name: profileName, company, accent, footer });
      setProfileName("");
      setCompany("");
      setFooter("");
      toast.success("Report profile saved");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not save profile");
    }
  };

  const handleCreateSchedule = async () => {
    if (!scanId) {
      toast.error("Pick a saved scan to schedule");
      return;
    }
    try {
      await createSchedule({
        scanId: scanId as Id<"scans">,
        recipients: recipients.split(/[,\s]+/),
        frequency,
      });
      setRecipients("");
      toast.success(`Schedule created — first delivery ${frequency === "weekly" ? "in 7 days" : "in 30 days"}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not create schedule");
    }
  };

  return (
    <div className="space-y-6">
      {/* Deliver due */}
      <Card className="border-primary/30 bg-primary/5">
        <CardContent className="flex flex-wrap items-center gap-4 p-5">
          <Send className="size-5 shrink-0 text-primary" />
          <div className="min-w-0 flex-1">
            <p className="font-medium">Scheduled delivery</p>
            <p className="text-sm text-muted-foreground">
              {dueCount > 0
                ? `${dueCount} schedule${dueCount === 1 ? " is" : "s are"} due right now.`
                : "Schedules fire automatically when due. Requires a RESEND_API_KEY in the Keys tab."}
            </p>
          </div>
          <Button className="gap-2 rounded-full" disabled={sending} onClick={() => void handleSendNow()}>
            <Send className="size-4" /> {sending ? "Delivering…" : "Deliver due now"}
          </Button>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Profiles */}
        <Card className="border-border/60 bg-card/60">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Palette className="size-4 text-primary" /> Report branding profiles
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Brand client-ready reports: company name, accent color, and a footer line applied to
              scheduled emails.
            </p>
            {profiles.length > 0 && (
              <div className="space-y-2">
                {profiles.map((p) => (
                  <div key={p._id} className="flex items-center gap-3 rounded-lg border border-border/60 px-3 py-2">
                    <span className="size-3 shrink-0 rounded-full" style={{ backgroundColor: p.accent }} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium">{p.name}</p>
                      <p className="truncate font-mono text-xs text-muted-foreground">{p.company}</p>
                    </div>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="size-7 text-muted-foreground hover:text-destructive"
                      aria-label={`Delete ${p.name}`}
                      onClick={async () => {
                        await deleteProfile({ id: p._id });
                        toast.success("Profile deleted");
                      }}
                    >
                      <Trash2 className="size-3.5" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
            <Separator />
            <div className="grid gap-3 sm:grid-cols-2">
              <Input placeholder="Profile name (e.g. Acme brand)" value={profileName} onChange={(e) => setProfileName(e.target.value)} />
              <Input placeholder="Client-facing company" value={company} onChange={(e) => setCompany(e.target.value)} />
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {ACCENTS.map((a) => (
                <button
                  key={a.value}
                  type="button"
                  title={a.label}
                  aria-label={`Accent ${a.label}`}
                  onClick={() => setAccent(a.value)}
                  className={`size-6 rounded-full border-2 transition-transform ${accent === a.value ? "scale-110 border-foreground" : "border-transparent"}`}
                  style={{ backgroundColor: a.value }}
                />
              ))}
            </div>
            <Input placeholder="Footer (e.g. Confidential — Acme Security)" value={footer} onChange={(e) => setFooter(e.target.value)} />
            <Button className="w-full rounded-full" disabled={!profileName.trim() || !company.trim()} onClick={() => void handleCreateProfile()}>
              <Plus className="size-4" /> Save profile
            </Button>
          </CardContent>
        </Card>

        {/* Schedules */}
        <Card className="border-border/60 bg-card/60">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <CalendarClock className="size-4 text-primary" /> Delivery schedules
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {schedules.length > 0 && (
              <div className="space-y-2">
                {schedules.map((s) => (
                  <div key={s._id} className="rounded-lg border border-border/60 px-3 py-2.5">
                    <div className="flex items-center gap-2">
                      <Mail className="size-3.5 shrink-0 text-muted-foreground" />
                      <p className="min-w-0 flex-1 truncate text-sm font-medium">{s.scanName}</p>
                      <Badge variant="outline" className={`rounded-full text-[11px] ${s.enabled ? "border-primary/40 bg-primary/10 text-primary" : "border-border bg-muted text-muted-foreground"}`}>
                        {s.enabled ? timeUntil(s.nextSendAt) : "paused"}
                      </Badge>
                    </div>
                    <p className="mt-1 truncate font-mono text-xs text-muted-foreground">
                      {s.frequency} → {s.recipients.join(", ")}
                      {s.lastStatus ? ` · last: ${s.lastStatus}${s.lastSentAt ? ` ${timeAgo(s.lastSentAt)}` : ""}` : ""}
                    </p>
                    <div className="mt-2 flex gap-2">
                      <Button size="sm" variant="outline" className="h-7 rounded-full text-xs" onClick={() => void toggleSchedule({ id: s._id })}>
                        {s.enabled ? "Pause" : "Resume"}
                      </Button>
                      <Button size="sm" variant="ghost" className="h-7 rounded-full text-xs text-muted-foreground hover:text-destructive" onClick={() => void deleteSchedule({ id: s._id })}>
                        <Trash2 className="size-3" /> Delete
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
            <Separator />
            {scans.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                Run and save a scan first — schedules deliver saved reports.
              </p>
            ) : (
              <>
                <div className="grid gap-3 sm:grid-cols-2">
                  <Select value={scanId} onValueChange={setScanId}>
                    <SelectTrigger className="w-full">
                      <SelectValue placeholder="Saved scan" />
                    </SelectTrigger>
                    <SelectContent>
                      {scans.map((s) => (
                        <SelectItem key={s._id} value={s._id}>
                          {s.name} ({s.score}/100)
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Select value={frequency} onValueChange={(v) => setFrequency(v as "weekly" | "monthly")}>
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="weekly">Weekly</SelectItem>
                      <SelectItem value="monthly">Monthly</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Input
                  placeholder="Recipients — comma-separated emails"
                  value={recipients}
                  onChange={(e) => setRecipients(e.target.value)}
                />
                <Button className="w-full rounded-full" disabled={!scanId || !recipients.trim()} onClick={() => void handleCreateSchedule()}>
                  <Plus className="size-4" /> Create schedule
                </Button>
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
