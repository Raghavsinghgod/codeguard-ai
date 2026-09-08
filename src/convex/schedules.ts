// CrackScope Part 21 — scheduled & recurring scans backend.
// A schedule re-scans a public GitHub repo on a cadence (daily/weekly).
// The heavy lifting (fetch + re-scan + diff) happens in the Node action in
// scheduleRuns.ts; this module holds the queries and mutations both the UI
// and the action use. Runs are fired client-side: the dashboard checks for
// due schedules on load and calls scheduleRuns.runDue.
import { getAuthUserId } from "@convex-dev/auth/server";
import { internalMutation, internalQuery, mutation, query } from "./_generated/server";
import { v } from "convex/values";

// ---------- queries ----------

export const listSchedules = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return [];
    const rows = await ctx.db
      .query("scanSchedules")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .collect();
    const out = [];
    for (const s of rows) {
      const lastScan = s.lastScanId ? await ctx.db.get(s.lastScanId) : null;
      out.push({
        _id: s._id,
        repoUrl: s.repoUrl,
        frequency: s.frequency,
        nextRunAt: s.nextRunAt,
        lastRunAt: s.lastRunAt ?? null,
        lastStatus: s.lastStatus ?? null,
        lastScanId: s.lastScanId ?? null,
        lastScore: lastScan?.score ?? null,
        lastGrade: lastScan?.grade ?? null,
        enabled: s.enabled,
      });
    }
    out.sort((a, b) => a.nextRunAt - b.nextRunAt);
    return out;
  },
});

/** Latest drift alerts across all schedules (most recent first). */
export const listAlerts = query({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return [];
    const rows = await ctx.db
      .query("driftAlerts")
      .withIndex("by_user_time", (q) => q.eq("userId", userId))
      .order("desc")
      .take(limit ?? 20);
    const out = [];
    for (const a of rows) {
      const scan = await ctx.db.get(a.scanId);
      out.push({
        _id: a._id,
        scanId: a.scanId,
        scanName: scan?.name ?? "(deleted)",
        verdict: a.verdict,
        scoreDelta: a.scoreDelta,
        added: a.added,
        fixed: a.fixed,
        worstAdded: a.worstAdded ?? null,
        detail: a.detail,
        at: a.at,
        seen: a.seen,
      });
    }
    return out;
  },
});

/** Unread alert count — drives the dashboard nudge badge. */
export const unreadCount = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return 0;
    const rows = await ctx.db
      .query("driftAlerts")
      .withIndex("by_user_time", (q) => q.eq("userId", userId))
      .order("desc")
      .take(50);
    return rows.filter((r) => !r.seen).length;
  },
});

/** How many schedules are due right now (drives the "run due scans" nudge). */
export const dueCount = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return 0;
    const rows = await ctx.db
      .query("scanSchedules")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .filter((q) => q.eq(q.field("enabled"), true))
      .collect();
    const now = Date.now();
    return rows.filter((r) => r.nextRunAt <= now).length;
  },
});

// ---------- schedule mutations ----------

function nextRun(frequency: "daily" | "weekly", from = Date.now()): number {
  const d = new Date(from);
  if (frequency === "daily") d.setDate(d.getDate() + 1);
  else d.setDate(d.getDate() + 7);
  return d.getTime();
}

function parseRepo(input: string): { owner: string; repo: string; branch?: string; display: string } | null {
  const raw = input.trim().replace(/^git@github\.com:/, "https://github.com/").replace(/\.git$/, "");
  const m = raw.match(/github\.com\/([^/\s]+)\/([^/\s?#]+)(?:\/tree\/([^/\s?#]+))?/i);
  if (m) {
    return { owner: m[1], repo: m[2], branch: m[3], display: `${m[1]}/${m[2]}` };
  }
  const short = raw.match(/^([\w.-]+)\/([\w.-]+)$/);
  if (short) return { owner: short[1], repo: short[2], display: `${short[1]}/${short[2]}` };
  return null;
}

export const createSchedule = mutation({
  args: {
    repoUrl: v.string(),
    frequency: v.union(v.literal("daily"), v.literal("weekly")),
  },
  handler: async (ctx, { repoUrl, frequency }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const target = parseRepo(repoUrl);
    if (!target) throw new Error("Enter a GitHub URL, or owner/repo, or owner/repo/tree/branch.");
    return await ctx.db.insert("scanSchedules", {
      userId,
      repoUrl: target.display,
      owner: target.owner,
      repo: target.repo,
      branch: target.branch,
      frequency,
      nextRunAt: nextRun(frequency),
      enabled: true,
      createdAt: Date.now(),
    });
  },
});

export const toggleSchedule = mutation({
  args: { id: v.id("scanSchedules") },
  handler: async (ctx, { id }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const s = await ctx.db.get(id);
    if (!s || s.userId !== userId) throw new Error("Schedule not found");
    await ctx.db.patch(id, { enabled: !s.enabled });
  },
});

export const deleteSchedule = mutation({
  args: { id: v.id("scanSchedules") },
  handler: async (ctx, { id }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const s = await ctx.db.get(id);
    if (!s || s.userId !== userId) throw new Error("Schedule not found");
    await ctx.db.delete(id);
  },
});

export const markAlertsSeen = mutation({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const rows = await ctx.db
      .query("driftAlerts")
      .withIndex("by_user_time", (q) => q.eq("userId", userId))
      .order("desc")
      .take(50);
    for (const r of rows) {
      if (!r.seen) await ctx.db.patch(r._id, { seen: true });
    }
  },
});

// ---------- internal helpers used by the Node action (scheduleRuns.ts) ----------
// Actions cannot touch ctx.db, so reads go through internal queries and
// outcomes are recorded through internal mutations.

export const collectDue = internalQuery({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return [];
    const rows = await ctx.db
      .query("scanSchedules")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .filter((q) => q.eq(q.field("enabled"), true))
      .collect();
    const now = Date.now();
    return rows
      .filter((r) => r.nextRunAt <= now)
      .map((r) => ({
        _id: r._id,
        repoUrl: r.repoUrl,
        owner: r.owner,
        repo: r.repo,
        branch: r.branch ?? null,
        lastScanId: r.lastScanId ?? null,
      }));
  },
});

export const scanForDiff = internalQuery({
  args: { scanId: v.id("scans") },
  handler: async (ctx, { scanId }) => {
    return await ctx.db.get(scanId);
  },
});

export const userForDigest = internalQuery({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return null;
    return await ctx.db.get(userId);
  },
});

export const saveScanInternal = internalMutation({
  args: {
    name: v.string(),
    score: v.number(),
    grade: v.string(),
    filesScanned: v.number(),
    linesScanned: v.number(),
    critical: v.number(),
    high: v.number(),
    medium: v.number(),
    low: v.number(),
    info: v.number(),
    findings: v.array(
      v.object({
        ruleId: v.string(),
        title: v.string(),
        severity: v.union(
          v.literal("critical"),
          v.literal("high"),
          v.literal("medium"),
          v.literal("low"),
          v.literal("info"),
        ),
        category: v.string(),
        owasp: v.string(),
        file: v.string(),
        line: v.number(),
        snippet: v.string(),
        description: v.string(),
        remediation: v.string(),
        payload: v.string(),
      }),
    ),
  },
  handler: async (ctx, args) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    return await ctx.db.insert("scans", { userId, createdAt: Date.now(), ...args });
  },
});

export const recordAlert = internalMutation({
  args: {
    scheduleId: v.id("scanSchedules"),
    scanId: v.id("scans"),
    verdict: v.union(
      v.literal("regressed"),
      v.literal("improved"),
      v.literal("unchanged"),
      v.literal("mixed"),
      v.literal("first_run"),
    ),
    scoreDelta: v.number(),
    added: v.number(),
    fixed: v.number(),
    worstAdded: v.optional(v.string()),
    detail: v.string(),
  },
  handler: async (ctx, a) => {
    const schedule = await ctx.db.get(a.scheduleId);
    if (!schedule) return;
    const now = Date.now();
    await ctx.db.insert("driftAlerts", {
      userId: schedule.userId,
      scheduleId: a.scheduleId,
      scanId: a.scanId,
      verdict: a.verdict,
      scoreDelta: a.scoreDelta,
      added: a.added,
      fixed: a.fixed,
      worstAdded: a.worstAdded,
      detail: a.detail,
      at: now,
      seen: false,
    });
    await ctx.db.patch(a.scheduleId, {
      lastRunAt: now,
      lastStatus: a.detail,
      lastScanId: a.scanId,
      nextRunAt: nextRun(schedule.frequency, now),
    });
  },
});

export const recordRunFailure = internalMutation({
  args: { id: v.id("scanSchedules"), status: v.string() },
  handler: async (ctx, { id, status }) => {
    const schedule = await ctx.db.get(id);
    const frequency = schedule?.frequency ?? "weekly";
    await ctx.db.patch(id, {
      lastRunAt: Date.now(),
      lastStatus: status,
      nextRunAt: nextRun(frequency, Date.now()),
    });
  },
});
