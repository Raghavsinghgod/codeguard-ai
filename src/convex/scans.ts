import { getAuthUserId } from "@convex-dev/auth/server";
import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

const findingValidator = v.object({
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
});

export const saveScan = mutation({
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
    findings: v.array(findingValidator),
  },
  handler: async (ctx, args) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const createdAt = Date.now();
    const id = await ctx.db.insert("scans", { userId, createdAt, ...args });
    return id;
  },
});

export const listScans = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return [];
    return await ctx.db
      .query("scans")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .order("desc")
      .take(50);
  },
});

export const getScan = query({
  args: { id: v.id("scans") },
  handler: async (ctx, { id }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return null;
    const scan = await ctx.db.get(id);
    if (!scan || scan.userId !== userId) return null;
    return scan;
  },
});

export const deleteScan = mutation({
  args: { id: v.id("scans") },
  handler: async (ctx, { id }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const scan = await ctx.db.get(id);
    if (!scan || scan.userId !== userId) throw new Error("Scan not found");
    await ctx.db.delete(id);
  },
});
