// CrackScope Part 25 — internal helpers backing the public HTTP API.
// Kept out of the "use node" action file: queries/mutations must run in
// Convex's default runtime. resolveKey authenticates API keys by hash.
import { internalQuery, internalMutation } from "./_generated/server";
import { v } from "convex/values";
import type { Finding } from "../lib/scanner";

export const resolveKey = internalQuery({
  args: { keyHash: v.string() },
  handler: async (ctx, { keyHash }) => {
    const row = await ctx.db
      .query("apiKeys")
      .withIndex("by_hash", (q) => q.eq("keyHash", keyHash))
      .unique();
    if (!row || row.revoked) return null;
    return { userId: row.userId, keyId: row._id };
  },
});

export const touchKey = internalMutation({
  args: { id: v.id("apiKeys") },
  handler: async (ctx, { id }) => {
    await ctx.db.patch(id, { lastUsedAt: Date.now() });
  },
});

export const saveApiScan = internalMutation({
  args: {
    userId: v.id("users"),
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
        severity: v.string(),
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
    const { userId, ...rest } = args;
    return ctx.db.insert("scans", {
      userId,
      createdAt: Date.now(),
      ...rest,
      findings: rest.findings.map((f) => ({ ...f, severity: f.severity as Finding["severity"] })),
    });
  },
});

export const listUserScans = internalQuery({
  args: { userId: v.id("users") },
  handler: async (ctx, { userId }) => {
    return ctx.db
      .query("scans")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .order("desc")
      .take(25);
  },
});

export const getUserScan = internalQuery({
  args: { userId: v.id("users"), scanId: v.id("scans") },
  handler: async (ctx, { userId, scanId }) => {
    const row = await ctx.db.get(scanId);
    if (!row || row.userId !== userId) return null;
    return row;
  },
});

export const findSchedule = internalQuery({
  args: { userId: v.id("users"), owner: v.string(), repo: v.string() },
  handler: async (ctx, { userId, owner, repo }) => {
    const rows = await ctx.db
      .query("scanSchedules")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .collect();
    return rows.find((r) => r.owner === owner && r.repo === repo)?._id ?? null;
  },
});

export const queueSchedule = internalMutation({
  args: { id: v.id("scanSchedules"), note: v.string() },
  handler: async (ctx, { id, note }) => {
    await ctx.db.patch(id, { nextRunAt: Date.now(), lastStatus: note });
  },
});
