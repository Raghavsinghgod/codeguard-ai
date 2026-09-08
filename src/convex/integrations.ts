// CrackScope Part 22 — integrations backend (queries, mutations, internal
// helpers). Outgoing webhook endpoints (Slack-style incoming webhooks,
// Discord, custom receivers) receive scan and drift-alert notifications.
// The actual HTTP delivery runs in the Node action in
// integrationDelivery.ts; incoming GitHub webhooks live in
// integrationWebhooks.ts.
import { getAuthUserId } from "@convex-dev/auth/server";
import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

// ---------- queries ----------

export const listEndpoints = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return [];
    const rows = await ctx.db
      .query("webhookEndpoints")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .collect();
    return rows
      .map((r) => ({
        _id: r._id,
        name: r.name,
        url: r.url,
        hasSecret: r.secretHash !== undefined,
        events: r.events,
        enabled: r.enabled,
        lastStatus: r.lastStatus ?? null,
        lastDeliveryAt: r.lastDeliveryAt ?? null,
        createdAt: r.createdAt,
      }))
      .sort((a, b) => a.createdAt - b.createdAt);
  },
});

export const listDeliveries = query({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return [];
    const rows = await ctx.db
      .query("webhookDeliveries")
      .withIndex("by_user_time", (q) => q.eq("userId", userId))
      .order("desc")
      .take(limit ?? 15);
    const out = [];
    for (const d of rows) {
      const endpoint = await ctx.db.get(d.endpointId);
      out.push({
        _id: d._id,
        endpointName: endpoint?.name ?? "(deleted endpoint)",
        event: d.event,
        status: d.status,
        ok: d.ok,
        detail: d.detail,
        at: d.at,
      });
    }
    return out;
  },
});

// ---------- endpoint mutations ----------

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const createEndpoint = mutation({
  args: {
    name: v.string(),
    url: v.string(),
    secret: v.optional(v.string()),
    events: v.array(v.union(v.literal("scan"), v.literal("drift"), v.literal("critical"))),
  },
  handler: async (ctx, { name, url, secret, events }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    if (!name.trim()) throw new Error("Give the endpoint a name");
    if (!/^https:\/\/.+/.test(url.trim())) throw new Error("Endpoint URL must be https://");
    if (events.length === 0) throw new Error("Pick at least one event to receive");
    if (secret && secret.length < 8) throw new Error("Secret must be at least 8 characters");
    return await ctx.db.insert("webhookEndpoints", {
      userId,
      name: name.trim(),
      url: url.trim(),
      // Store sha256(secret); the Node delivery action signs payloads with
      // this hash so the raw secret is never recoverable from the database.
      secretHash: secret ? await sha256Hex(secret) : undefined,
      events,
      enabled: true,
      createdAt: Date.now(),
    });
  },
});

export const toggleEndpoint = mutation({
  args: { id: v.id("webhookEndpoints") },
  handler: async (ctx, { id }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const e = await ctx.db.get(id);
    if (!e || e.userId !== userId) throw new Error("Endpoint not found");
    await ctx.db.patch(id, { enabled: !e.enabled });
  },
});

export const deleteEndpoint = mutation({
  args: { id: v.id("webhookEndpoints") },
  handler: async (ctx, { id }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const e = await ctx.db.get(id);
    if (!e || e.userId !== userId) throw new Error("Endpoint not found");
    await ctx.db.delete(id);
  },
});

// ---------- internal helpers used by integrationDelivery.ts (Node action) ----------

import { internalQuery } from "./_generated/server";
import { internalMutation } from "./_generated/server";

export const endpointForActor = internalQuery({
  args: { id: v.id("webhookEndpoints") },
  handler: async (ctx, { id }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return null;
    const e = await ctx.db.get(id);
    if (!e || e.userId !== userId) return null;
    return { name: e.name, url: e.url, secretHash: e.secretHash ?? null };
  },
});

export const collectEndpoints = internalQuery({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return [];
    const rows = await ctx.db
      .query("webhookEndpoints")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .filter((q) => q.eq(q.field("enabled"), true))
      .collect();
    return rows.map((r) => ({
      _id: r._id,
      name: r.name,
      url: r.url,
      secretHash: r.secretHash ?? null,
      events: r.events as string[],
    }));
  },
});

export const pendingAlerts = internalQuery({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return [];
    const rows = await ctx.db
      .query("driftAlerts")
      .withIndex("by_user_time", (q) => q.eq("userId", userId))
      .order("desc")
      .take(25);
    const out = [];
    for (const a of rows) {
      if (a.seen) continue;
      const scan = await ctx.db.get(a.scanId);
      out.push({
        _id: a._id,
        scanName: scan?.name ?? "(deleted)",
        verdict: a.verdict,
        scoreDelta: a.scoreDelta,
        added: a.added,
        fixed: a.fixed,
        worstAdded: a.worstAdded ?? null,
        detail: a.detail,
        at: a.at,
      });
    }
    return out;
  },
});

export const markAlertsDispatched = internalMutation({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return;
    const rows = await ctx.db
      .query("driftAlerts")
      .withIndex("by_user_time", (q) => q.eq("userId", userId))
      .order("desc")
      .take(25);
    for (const r of rows) {
      if (!r.seen) await ctx.db.patch(r._id, { seen: true });
    }
  },
});

export const recordDelivery = internalMutation({
  args: {
    endpointId: v.id("webhookEndpoints"),
    event: v.string(),
    status: v.number(),
    ok: v.boolean(),
    detail: v.string(),
  },
  handler: async (ctx, { endpointId, event, status, ok, detail }) => {
    const endpoint = await ctx.db.get(endpointId);
    if (!endpoint) return;
    const now = Date.now();
    await ctx.db.insert("webhookDeliveries", {
      userId: endpoint.userId,
      endpointId,
      event,
      status,
      ok,
      detail,
      at: now,
    });
    await ctx.db.patch(endpointId, { lastStatus: detail, lastDeliveryAt: now });
  },
});
