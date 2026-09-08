// CrackScope Part 22 — Integrations UI.
// Outgoing webhooks (Slack-style receivers) with event filters, HMAC
// secrets, test delivery, and a delivery log — plus per-schedule GitHub
// webhook setup with a copyable receiver URL.
import { useState } from "react";
import { useAction, useMutation, useQuery } from "convex/react";
import { toast } from "sonner";
import {
  Bell,
  Check,
  Copy,
  Github,
  Plus,
  Send,
  Trash2,
  Webhook,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";

const EVENT_OPTIONS = [
  { value: "drift", label: "All drift alerts", hint: "every scheduled-run drift" },
  { value: "critical", label: "Critical only", hint: "regressions or new criticals" },
] as const;

type EventValue = (typeof EVENT_OPTIONS)[number]["value"];

function timeAgo(ts: number): string {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      size="sm"
      variant="outline"
      className="h-7 gap-1.5 rounded-full text-xs"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          toast.error("Could not copy — select the text manually");
        }
      }}
    >
      {copied ? <Check className="size-3" /> : <Copy className="size-3" />} {label}
    </Button>
  );
}

export function IntegrationsTab() {
  const endpoints = useQuery(api.integrations.listEndpoints) ?? [];
  const deliveries = useQuery(api.integrations.listDeliveries, { limit: 15 }) ?? [];
  const schedules = useQuery(api.schedules.listSchedules) ?? [];

  const createEndpoint = useMutation(api.integrations.createEndpoint);
  const toggleEndpoint = useMutation(api.integrations.toggleEndpoint);
  const deleteEndpoint = useMutation(api.integrations.deleteEndpoint);
  const sendTest = useAction(api.integrationDelivery.sendTest);
  const setGithubSecret = useMutation(api.schedules.setGithubSecret);

  // Endpoint form
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [events, setEvents] = useState<EventValue[]>(["drift"]);
  const [testingId, setTestingId] = useState<string | null>(null);

  // GitHub webhook form
  const [ghSecrets, setGhSecrets] = useState<Record<string, string>>({});
  const siteUrl = typeof window !== "undefined" ? window.location.origin : "";

  const handleCreate = async () => {
    try {
      await createEndpoint({
        name,
        url,
        secret: secret.trim() || undefined,
        events,
      });
      setName("");
      setUrl("");
      setSecret("");
      setEvents(["drift"]);
      toast.success("Endpoint registered — send a test to verify wiring");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not create endpoint");
    }
  };

  const handleTest = async (id: Id<"webhookEndpoints">) => {
    setTestingId(id);
    try {
      await sendTest({ id });
      toast.success("Test delivered — check your receiver");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Test delivery failed");
    } finally {
      setTestingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Outgoing webhooks */}
        <Card className="border-border/60 bg-card/60">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Webhook className="size-4 text-primary" /> Outgoing webhooks
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              POST a JSON digest to any HTTPS receiver (Slack incoming webhook, Discord, custom).
              An optional secret signs each payload with{" "}
              <code className="font-mono text-xs text-foreground/80">x-crackscope-signature</code>.
            </p>

            {endpoints.length > 0 && (
              <div className="space-y-2">
                {endpoints.map((e) => (
                  <div key={e._id} className="rounded-lg border border-border/60 px-3 py-2.5">
                    <div className="flex items-center gap-2">
                      <span className={`size-2 shrink-0 rounded-full ${e.enabled ? "bg-primary" : "bg-muted-foreground/40"}`} />
                      <p className="min-w-0 flex-1 truncate text-sm font-medium">{e.name}</p>
                      {e.lastStatus && (
                        <Badge
                          variant="outline"
                          className={`max-w-44 truncate rounded-full font-mono text-[10px] ${
                            e.lastStatus.startsWith("delivered")
                              ? "border-primary/40 bg-primary/10 text-primary"
                              : "border-destructive/40 bg-destructive/10 text-destructive"
                          }`}
                        >
                          {e.lastStatus}
                          {e.lastDeliveryAt ? ` · ${timeAgo(e.lastDeliveryAt)}` : ""}
                        </Badge>
                      )}
                    </div>
                    <p className="mt-1 truncate font-mono text-xs text-muted-foreground">{e.url}</p>
                    <p className="mt-0.5 font-mono text-[11px] text-muted-foreground/70">
                      {e.events.join(" · ")} {e.hasSecret ? "· signed" : ""}
                    </p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 gap-1.5 rounded-full text-xs"
                        disabled={testingId === e._id}
                        onClick={() => void handleTest(e._id)}
                      >
                        <Zap className="size-3" /> {testingId === e._id ? "Sending…" : "Send test"}
                      </Button>
                      <Button size="sm" variant="outline" className="h-7 rounded-full text-xs" onClick={() => void toggleEndpoint({ id: e._id })}>
                        {e.enabled ? "Pause" : "Resume"}
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-7 rounded-full text-xs text-muted-foreground hover:text-destructive"
                        onClick={() => void deleteEndpoint({ id: e._id })}
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
              <Input placeholder="Name (e.g. #security-alerts)" value={name} onChange={(e) => setName(e.target.value)} />
              <Input placeholder="https://hooks.slack.com/…" value={url} onChange={(e) => setUrl(e.target.value)} />
            </div>
            <Input
              placeholder="Signing secret (optional, min 8 chars)"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
            <div className="flex flex-wrap gap-x-5 gap-y-2">
              {EVENT_OPTIONS.map((opt) => (
                <label key={opt.value} className="flex cursor-pointer items-center gap-2 text-sm">
                  <Checkbox
                    checked={events.includes(opt.value)}
                    onCheckedChange={(v) =>
                      setEvents((prev) =>
                        v ? [...prev, opt.value] : prev.filter((x) => x !== opt.value),
                      )
                    }
                  />
                  <span>
                    {opt.label} <span className="text-xs text-muted-foreground">— {opt.hint}</span>
                  </span>
                </label>
              ))}
            </div>
            <Button className="w-full rounded-full" disabled={!name.trim() || !/^https:\/\/.+/.test(url.trim()) || events.length === 0} onClick={() => void handleCreate()}>
              <Plus className="size-4" /> Add endpoint
            </Button>
          </CardContent>
        </Card>

        {/* GitHub incoming webhooks */}
        <Card className="border-border/60 bg-card/60">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Github className="size-4 text-primary" /> GitHub push webhooks
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Point a repo webhook at your receiver URL — pushes pull the next scheduled re-scan to
              now. Set the same secret in GitHub so signatures verify.
            </p>

            {schedules.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                Create a scheduled scan first (Scheduled tab) — webhooks attach to schedules.
              </p>
            ) : (
              <div className="space-y-3">
                {schedules.map((s) => {
                  const receiverUrl = `${siteUrl}/api/webhooks/github/${s._id}`;
                  return (
                    <div key={s._id} className="rounded-lg border border-border/60 px-3 py-2.5">
                      <p className="font-mono text-sm font-medium">{s.repoUrl}</p>
                      <p className="mt-1 break-all rounded bg-secondary/50 px-2 py-1 font-mono text-[11px] text-muted-foreground">
                        {receiverUrl}
                      </p>
                      <div className="mt-2 flex flex-wrap items-center gap-2">
                        <CopyButton text={receiverUrl} label="Copy URL" />
                        <Input
                          placeholder="Webhook secret"
                          className="h-7 max-w-44 text-xs"
                          value={ghSecrets[s._id] ?? ""}
                          onChange={(e) => setGhSecrets((m) => ({ ...m, [s._id]: e.target.value }))}
                        />
                        <Button
                          size="sm"
                          className="h-7 gap-1.5 rounded-full text-xs"
                          disabled={!(ghSecrets[s._id] ?? "").trim()}
                          onClick={async () => {
                            try {
                              await setGithubSecret({ id: s._id, secret: ghSecrets[s._id] });
                              toast.success("Secret saved — use the same value in the GitHub webhook");
                            } catch (e) {
                              toast.error(e instanceof Error ? e.message : "Could not save secret");
                            }
                          }}
                        >
                          <Bell className="size-3" /> Save secret
                        </Button>
                      </div>
                      <p className="mt-1.5 font-mono text-[11px] text-muted-foreground/70">
                        Events: ping + push · Content type: application/json
                        {s.lastStatus ? ` · last: ${s.lastStatus}` : ""}
                      </p>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Delivery log */}
      <Card className="border-border/60 bg-card/60">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Send className="size-4 text-primary" /> Recent deliveries
          </CardTitle>
        </CardHeader>
        <CardContent>
          {deliveries.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No deliveries yet — send a test or wait for the next scheduled drift digest.
            </p>
          ) : (
            <div className="space-y-1.5">
              {deliveries.map((d) => (
                <div key={d._id} className="flex flex-wrap items-center gap-2 rounded-lg border border-border/60 px-3 py-2">
                  <span className={`size-2 shrink-0 rounded-full ${d.ok ? "bg-primary" : "bg-destructive"}`} />
                  <p className="min-w-0 flex-1 truncate text-sm">
                    <span className="font-medium">{d.endpointName}</span>
                    <span className="text-muted-foreground"> · {d.event} · {d.detail}</span>
                  </p>
                  <span className="font-mono text-[11px] text-muted-foreground">
                    {d.status > 0 ? `HTTP ${d.status} · ` : ""}{timeAgo(d.at)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
