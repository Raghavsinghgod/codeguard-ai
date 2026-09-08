// CrackScope Part 21 — scheduled scan execution (Node action).
// Runs every due schedule for the caller: fetches the repo files, re-runs the
// CrackScope engine server-side, saves the scan, diffs against the previous
// run, and records a drift alert. Optionally emails a digest via Resend
// (same RESEND_API_KEY setup as the Part 20 report center).
"use node";

import { getAuthUserId } from "@convex-dev/auth/server";
import { action } from "./_generated/server";
import { v } from "convex/values";
import { internal } from "./_generated/api";
import { scan } from "../lib/scanner";
import { diffScanResults } from "../lib/diff";

type ScanInput = { name: string; content: string };

const MAX_FILES = 40;
const MAX_FILE_BYTES = 200 * 1024;
const SCANNABLE_EXT = new Set([
  "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "rb", "go", "java", "php",
  "cs", "cpp", "cc", "c", "h", "hpp", "rs", "kt", "swift", "sql", "yml",
  "yaml", "env", "ini", "toml", "sh", "bash", "html", "vue", "svelte",
  "properties", "conf", "json",
]);
const SKIP_DIR_PARTS = [
  "node_modules/", "vendor/", "dist/", "build/", ".min.", "__tests__",
  "__pycache__/", ".git/", "coverage/", "target/release",
];
const DEP_MANIFESTS = new Set(["package.json", "package-lock.json", "requirements.txt"]);

function isScannable(path: string, size?: number): boolean {
  if (size !== undefined && size > MAX_FILE_BYTES) return false;
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  if (!SCANNABLE_EXT.has(ext) && !DEP_MANIFESTS.has(path.split("/").pop() ?? "")) return false;
  if (path.includes(".min.")) return false;
  const lower = `/${path.toLowerCase()}`;
  return !SKIP_DIR_PARTS.some((p) => lower.includes(p));
}

function looksBinary(text: string): boolean {
  if (text.includes("\u0000")) return true;
  const slice = text.slice(0, 2000);
  let ctrl = 0;
  for (let i = 0; i < slice.length; i++) {
    const c = slice.charCodeAt(i);
    if (c < 9 || (c > 13 && c < 32)) ctrl++;
  }
  return slice.length > 0 && ctrl / slice.length > 0.1;
}

async function ghJson(url: string): Promise<unknown> {
  const res = await fetch(url, { headers: { Accept: "application/vnd.github+json" } });
  if (res.status === 403 || res.status === 429) {
    throw new Error("GitHub rate limit reached (unauthenticated). Try again later.");
  }
  if (res.status === 404) throw new Error("GitHub repo not found — check the URL (public repos only).");
  if (!res.ok) throw new Error(`GitHub request failed (${res.status})`);
  return res.json();
}

async function fetchRepoFiles(owner: string, repo: string, branch?: string): Promise<ScanInput[]> {
  let ref = branch;
  if (!ref) {
    const info = (await ghJson(`https://api.github.com/repos/${owner}/${repo}`)) as {
      default_branch?: string;
    };
    ref = info.default_branch || "main";
  }
  const tree = (await ghJson(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`,
  )) as { tree?: Array<{ path: string; type: string; size?: number }> };

  const candidates = (tree.tree ?? [])
    .filter((e) => e.type === "blob" && isScannable(e.path, e.size))
    .slice(0, MAX_FILES * 3);

  const inputs: ScanInput[] = [];
  const base = `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/`;
  for (const entry of candidates) {
    if (inputs.length >= MAX_FILES) break;
    try {
      const res = await fetch(base + entry.path.split("/").map(encodeURIComponent).join("/"));
      if (!res.ok) continue;
      const text = await res.text();
      if (looksBinary(text)) continue;
      inputs.push({ name: entry.path, content: text });
    } catch {
      // Skip unreachable blobs.
    }
  }
  if (inputs.length === 0) throw new Error("No scannable source files found in that repo.");
  return inputs;
}

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

export const runDue = action({
  args: { notify: v.optional(v.boolean()) },
  handler: async (ctx, { notify }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");

    const due = await ctx.runQuery(internal.schedules.collectDue, {});
    const results: { scheduleId: string; repo: string; ok: boolean; message: string }[] = [];
    const alerts: { verdict: string; repo: string; detail: string; at: number }[] = [];

    for (const s of due) {
      try {
        const inputs = await fetchRepoFiles(s.owner, s.repo, s.branch ?? undefined);
        const res = scan(inputs);

        const scanId = await ctx.runMutation(internal.schedules.saveScanInternal, {
          name: `${s.repo} (scheduled)`,
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
        });

        let verdict: "regressed" | "improved" | "unchanged" | "mixed" | "first_run" = "first_run";
        let scoreDelta = 0;
        let addedCount = 0;
        let fixedCount = 0;
        let worstAdded: string | null = null;
        let detail = `First scheduled run — score ${res.score}/100 (${res.grade}), ${res.findings.length} findings.`;

        const prevScan = s.lastScanId
          ? await ctx.runQuery(internal.schedules.scanForDiff, { scanId: s.lastScanId })
          : null;
        if (prevScan) {
          const diff = diffScanResults(
            {
              score: prevScan.score,
              grade: prevScan.grade as never,
              filesScanned: prevScan.filesScanned,
              linesScanned: prevScan.linesScanned,
              languages: [],
              counts: {
                critical: prevScan.critical,
                high: prevScan.high,
                medium: prevScan.medium,
                low: prevScan.low,
                info: prevScan.info,
              },
              findings: prevScan.findings as never,
              durationMs: 0,
            },
            res,
          );
          verdict = diff.verdict;
          scoreDelta = diff.scoreDelta;
          addedCount = diff.added.length;
          fixedCount = diff.fixed.length;
          worstAdded = diff.added.length
            ? diff.added
                .slice()
                .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))[0]
                .severity
            : null;
          const arrow = scoreDelta > 0 ? "+" : "";
          detail =
            verdict === "unchanged"
              ? `No drift — score steady at ${res.score}/100.`
              : `${verdict}: score ${arrow}${scoreDelta} → ${res.score}/100, +${addedCount} new / -${fixedCount} fixed.`;
        }

        await ctx.runMutation(internal.schedules.recordAlert, {
          scheduleId: s._id,
          scanId,
          verdict,
          scoreDelta,
          added: addedCount,
          fixed: fixedCount,
          worstAdded: worstAdded ?? undefined,
          detail,
        });
        alerts.push({ verdict, repo: s.repoUrl, detail, at: Date.now() });

        results.push({ scheduleId: s._id, repo: s.repoUrl, ok: true, message: detail });
      } catch (e) {
        const message = e instanceof Error ? e.message : "Run failed";
        await ctx.runMutation(internal.schedules.recordRunFailure, { id: s._id, status: message });
        results.push({ scheduleId: s._id, repo: s.repoUrl, ok: false, message });
      }
    }

    // Optional digest email (best-effort; never affects run results).
    if (notify && alerts.length > 0) {
      const apiKey = process.env.RESEND_API_KEY;
      if (apiKey) {
        const user = await ctx.runQuery(internal.schedules.userForDigest, {});
        const email = user?.email;
        if (email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          const regressed = alerts.filter((a) => a.verdict === "regressed").length;
          const improved = alerts.filter((a) => a.verdict === "improved").length;
          const subject = `CrackScope digest: ${alerts.length} scheduled run${alerts.length === 1 ? "" : "s"} — ${regressed} regressed, ${improved} improved`;
          const items = alerts
            .map(
              (a) =>
                `<div style="border-left:3px solid ${a.verdict === "regressed" ? "#f43f5e" : a.verdict === "improved" ? "#22c55e" : "#38bdf8"};padding:8px 14px;margin-bottom:10px;background:#14171b;border-radius:0 8px 8px 0">
  <p style="margin:0;font-size:13px;font-weight:600;color:#ffffff">${a.repo} — ${a.verdict}</p>
  <p style="margin:2px 0 0;font-size:12px;color:#8a9096">${a.detail}</p>
</div>`,
            )
            .join("");
          const html = `<!doctype html><html><body style="margin:0;background:#0b0d10;font-family:ui-sans-serif,system-ui,sans-serif;color:#e7e9ea">
<div style="max-width:560px;margin:0 auto;padding:32px 24px">
  <p style="font-size:11px;letter-spacing:0.2em;text-transform:uppercase;color:#8a9096;margin:0 0 8px">CrackScope · scheduled scan digest</p>
  <h1 style="font-size:22px;margin:0 0 20px;color:#ffffff">${alerts.length} drift alert${alerts.length === 1 ? "" : "s"}</h1>
  ${items}
  <p style="margin-top:24px;padding-top:16px;border-top:1px solid #262b31;font-size:11px;color:#6b7178">Confidential — generated by CrackScope scheduled attack simulation.</p>
</div>
</body></html>`;
          try {
            await fetch("https://api.resend.com/emails", {
              method: "POST",
              headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
              body: JSON.stringify({
                from: "CrackScope Alerts <onboarding@resend.dev>",
                to: [email],
                subject,
                html,
              }),
            });
          } catch {
            // Digest email is best-effort.
          }
        }
      }
    }

    return results;
  },
});
