// CrackScope Part 25 — public API & CLI tab.
// Manage API keys (generate/revoke/copy), see the endpoint reference with a
// copyable site URL, and grab a ready-to-paste `crackscope` CLI snippet and a
// GitHub Actions step wired to the CI webhook.
import { useState } from "react";
import { motion } from "framer-motion";
import {
  Check,
  Copy,
  KeyRound,
  Loader2,
  Plus,
  Terminal,
  Trash2,
  Webhook,
} from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useMutation, useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";

function CodeBlock({ children }: { children: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(children);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      toast.error("Could not copy to clipboard");
    }
  };
  return (
    <div className="group relative">
      <pre className="overflow-x-auto rounded-lg border border-border/60 bg-secondary/40 p-3 font-mono text-xs leading-5">
        {children}
      </pre>
      <Button
        variant="outline"
        size="icon"
        className="absolute top-2 right-2 size-7 rounded-full opacity-0 transition-opacity group-hover:opacity-100"
        onClick={() => void copy()}
        aria-label="Copy code"
      >
        {copied ? <Check className="size-3.5 text-primary" /> : <Copy className="size-3.5" />}
      </Button>
    </div>
  );
}

const ENDPOINTS = [
  { method: "POST", path: "/api/v1/scan", desc: "Scan a public repo → score + findings JSON" },
  { method: "GET", path: "/api/v1/scans", desc: "List your latest 25 scans" },
  { method: "GET", path: "/api/v1/scans/:id", desc: "Fetch one scan's full report" },
  { method: "POST", path: "/api/v1/ci/webhook", desc: "CI trigger — queue a re-scan of a watched repo" },
];

export default function ApiTab() {
  const keys = useQuery(api.apiKeys.listKeys);
  const createKey = useMutation(api.apiKeys.createKey);
  const revokeKey = useMutation(api.apiKeys.revokeKey);
  const deleteKey = useMutation(api.apiKeys.deleteKey);

  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [freshKey, setFreshKey] = useState<string | null>(null);

  // HTTP routes are served on the deployment's *.convex.site host — derive it
  // from the configured Convex URL instead of hardcoding a deployment name.
  const apiBase =
    (import.meta.env.VITE_CONVEX_URL as string | undefined)?.replace(/\.cloud\b/, ".site") ??
    "https://your-deployment.convex.site";

  const handleCreate = async () => {
    setCreating(true);
    try {
      const key = await createKey({ name });
      setFreshKey(key);
      setName("");
      toast.success("API key created — copy it now, it won't be shown again");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not create key");
    } finally {
      setCreating(false);
    }
  };

  const cliSnippet = `# Install (one file, no dependencies)
npm install -g crackscope-cli   # or: npx crackscope-cli

# Scan a repo and pretty-print the report
crackscope scan ${"owner/repo"} --json | jq '.score, .counts'

# Fail a CI job on any critical finding
crackscope scan ${"owner/repo"} --fail-on critical

# CLI environment
export CRACKSCOPE_URL=${apiBase}
export CRACKSCOPE_KEY=cs_...   # your key`;

  const ciSnippet = `# .github/workflows/crackscope.yml
name: crackscope
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Trigger CrackScope attack simulation
        run: |
          curl -sf -X POST ${apiBase}/api/v1/ci/webhook \\
            -H "Authorization: Bearer \${{ secrets.CRACKSCOPE_KEY }}" \\
            -H "Content-Type: application/json" \\
            -d '{"repository":{"full_name":"${"${{ github.repository }}"}"},"ref":"refs/heads/\${{ github.ref_name }}"}'`;

  const curlSnippet = `curl -X POST ${apiBase}/api/v1/scan \\
  -H "Authorization: Bearer cs_..." \\
  -H "Content-Type: application/json" \\
  -d '{"repo":"owner/repo"}'`;

  return (
    <div className="space-y-6">
      {/* API keys */}
      <Card className="border-border/60 bg-card/60">
        <CardContent className="space-y-4 p-6">
          <div className="flex flex-wrap items-center gap-4">
            <span className="flex size-11 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <KeyRound className="size-5" />
            </span>
            <div className="min-w-0 flex-1">
              <p className="font-semibold tracking-tight">API keys</p>
              <p className="text-sm text-muted-foreground">
                Programmatic access to the CrackScope HTTP API and CI triggers. Keys are stored
                hashed — the full key is shown once at creation.
              </p>
            </div>
          </div>

          <div className="flex gap-2">
            <Input
              placeholder="Key label, e.g. ci-pipeline"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void handleCreate()}
            />
            <Button className="gap-2 rounded-full" disabled={creating} onClick={() => void handleCreate()}>
              {creating ? <Loader2 className="size-4 animate-spin" /> : <Plus className="size-4" />}
              Generate key
            </Button>
          </div>

          {freshKey && (
            <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}>
              <div className="rounded-lg border border-primary/40 bg-primary/5 p-3">
                <p className="text-xs font-medium text-primary">
                  Copy this key now — it is never shown again
                </p>
                <div className="mt-2 flex items-center gap-2">
                  <code className="min-w-0 flex-1 truncate rounded bg-background/60 px-2 py-1.5 font-mono text-xs">
                    {freshKey}
                  </code>
                  <Button variant="outline" size="sm" className="rounded-full" onClick={() => void navigator.clipboard.writeText(freshKey).then(() => toast.success("Key copied"))}>
                    <Copy className="size-3.5" /> Copy
                  </Button>
                </div>
              </div>
            </motion.div>
          )}

          <div className="space-y-2">
            {(keys ?? []).length === 0 && (
              <p className="text-sm text-muted-foreground">No keys yet — generate one to start.</p>
            )}
            {(keys ?? []).map((k) => (
              <div key={k._id} className="flex flex-wrap items-center gap-3 rounded-lg border border-border/60 px-3 py-2.5">
                <KeyRound className="size-4 text-muted-foreground" />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">{k.name}</span>
                  <span className="block font-mono text-xs text-muted-foreground">{k.prefix}…</span>
                </span>
                {k.lastUsedAt && (
                  <span className="text-xs text-muted-foreground">
                    last used {new Date(k.lastUsedAt).toLocaleDateString()}
                  </span>
                )}
                {k.revoked ? (
                  <Badge variant="outline" className="rounded-full text-muted-foreground">revoked</Badge>
                ) : (
                  <Badge variant="outline" className="rounded-full border-primary/40 bg-primary/10 text-[10px] text-primary">active</Badge>
                )}
                {!k.revoked && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="rounded-full"
                    onClick={() => void revokeKey({ id: k._id }).then(() => toast.success("Key revoked"))}
                  >
                    Revoke
                  </Button>
                )}
                <Button
                  variant="ghost"
                  size="icon"
                  className="rounded-full text-muted-foreground hover:text-destructive"
                  onClick={() => void deleteKey({ id: k._id as Id<"apiKeys"> }).then(() => toast.success("Key deleted"))}
                  aria-label="Delete key"
                >
                  <Trash2 className="size-4" />
                </Button>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Endpoint reference */}
      <Card className="border-border/60 bg-card/60">
        <CardContent className="space-y-4 p-6">
          <div>
            <p className="font-semibold tracking-tight">HTTP API reference</p>
            <p className="text-sm text-muted-foreground">
              Base URL: <code className="rounded bg-secondary/50 px-1.5 py-0.5 font-mono text-xs">{apiBase}</code>{" "}
              — authenticate with <code className="rounded bg-secondary/50 px-1.5 py-0.5 font-mono text-xs">Authorization: Bearer cs_…</code>
            </p>
          </div>
          <div className="space-y-1.5">
            {ENDPOINTS.map((e) => (
              <div key={e.path} className="flex flex-wrap items-center gap-3 rounded-lg border border-border/60 px-3 py-2">
                <Badge
                  variant="outline"
                  className={`w-14 justify-center rounded-full font-mono text-[10px] ${
                    e.method === "POST"
                      ? "border-primary/40 bg-primary/10 text-primary"
                      : "border-border bg-muted text-muted-foreground"
                  }`}
                >
                  {e.method}
                </Badge>
                <code className="font-mono text-xs">{e.path}</code>
                <span className="min-w-0 flex-1 truncate text-xs text-muted-foreground">{e.desc}</span>
              </div>
            ))}
          </div>
          <CodeBlock>{curlSnippet}</CodeBlock>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* CLI */}
        <Card className="border-border/60 bg-card/60">
          <CardContent className="space-y-3 p-6">
            <p className="flex items-center gap-2 font-semibold tracking-tight">
              <Terminal className="size-4 text-primary" /> crackscope CLI
            </p>
            <p className="text-sm text-muted-foreground">
              Point the CLI at your base URL with any active key — scan from the terminal or a CI
              job and fail builds on critical findings.
            </p>
            <CodeBlock>{cliSnippet}</CodeBlock>
          </CardContent>
        </Card>

        {/* CI webhook */}
        <Card className="border-border/60 bg-card/60">
          <CardContent className="space-y-3 p-6">
            <p className="flex items-center gap-2 font-semibold tracking-tight">
              <Webhook className="size-4 text-primary" /> CI webhook
            </p>
            <p className="text-sm text-muted-foreground">
              Any CI system can trigger a re-scan — the repo must have a schedule in the Scheduled
              tab. GitHub Actions example:
            </p>
            <CodeBlock>{ciSnippet}</CodeBlock>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
