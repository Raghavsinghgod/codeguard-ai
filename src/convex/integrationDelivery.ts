// CrackScope Part 22 — outgoing webhook delivery (Node action).
// "use node" is required for createHmac (payload signing). Handles test
// deliveries and the drift-alert digest fan-out to all enabled endpoints.
"use node";

import { createHmac } from "node:crypto";
import { getAuthUserId } from "@convex-dev/auth/server";
import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import { v } from "convex/values";

interface DeliveryEndpoint {
  _id: string;
  name: string;
  url: string;
  secretHash: string | null;
  events: string[];
}

interface PendingAlert {
  _id: string;
  scanName: string;
  verdict: string;
  scoreDelta: number;
  added: number;
  fixed: number;
  worstAdded: string | null;
  detail: string;
  at: number;
}

function shouldDeliver(events: string[], verdict: string, worstAdded: string | null): boolean {
  if (events.includes("drift")) return true;
  if (events.includes("critical")) {
    return verdict === "regressed" || worstAdded === "critical";
  }
  return false;
}

/** POSTs the payload with an optional HMAC signature. Never throws. */
async function deliver(
  url: string,
  secretHash: string | null,
  payload: unknown,
): Promise<{ status: number; ok: boolean; detail: string }> {
  const body = JSON.stringify(payload);
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (secretHash) {
    // The stored value is sha256(secret); signing with the hash keeps the raw
    // secret out of every delivery path. Receivers verify HMAC(body) keyed
    // with the same secret they registered (sha256 matched client-side).
    headers["x-crackscope-signature"] = createHmac("sha256", secretHash).update(body).digest("hex");
  }
  try {
    const res = await fetch(url, { method: "POST", headers, body });
    return {
      status: res.status,
      ok: res.ok,
      detail: res.ok ? `delivered (${res.status})` : `receiver responded ${res.status}`,
    };
  } catch {
    return { status: 0, ok: false, detail: "network error reaching the endpoint" };
  }
}

/** Fires a test payload at one endpoint so the user can verify wiring. */
export const sendTest = action({
  args: { id: v.id("webhookEndpoints") },
  handler: async (ctx, { id }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const endpoint = await ctx.runQuery(internal.integrations.endpointForActor, { id });
    if (!endpoint) throw new Error("Endpoint not found");
    const payload = {
      event: "test",
      source: "crackscope",
      text: `CrackScope test delivery to "${endpoint.name}" — wiring looks good.`,
      at: new Date().toISOString(),
    };
    const { status, ok, detail } = await deliver(endpoint.url, endpoint.secretHash, payload);
    await ctx.runMutation(internal.integrations.recordDelivery, {
      endpointId: id,
      event: "test",
      status,
      ok,
      detail,
    });
    if (!ok) throw new Error(detail);
  },
});

/**
 * Delivers every unread drift alert to every matching enabled endpoint.
 * Called from the Scheduled tab after runDue. Best-effort per endpoint:
 * one failing receiver never blocks the others.
 */
export const dispatchDue = action({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");

    const endpoints = (await ctx.runQuery(internal.integrations.collectEndpoints, {})) as DeliveryEndpoint[];
    if (endpoints.length === 0) return [];

    const alerts = (await ctx.runQuery(internal.integrations.pendingAlerts, {})) as PendingAlert[];
    if (alerts.length === 0) return [];

    const results: { endpointId: string; endpointName: string; ok: boolean; detail: string }[] = [];
    for (const endpoint of endpoints) {
      const relevant = alerts.filter((a) => shouldDeliver(endpoint.events, a.verdict, a.worstAdded));
      if (relevant.length === 0) continue;
      // One consolidated payload per endpoint (single POST, Slack-friendly).
      const payload = {
        event: "drift.alert",
        source: "crackscope",
        text:
          relevant.length === 1
            ? `CrackScope drift: ${relevant[0].scanName} — ${relevant[0].detail}`
            : `CrackScope drift: ${relevant.length} scheduled scans drifted — ${relevant
                .map((a) => `${a.scanName}: ${a.detail}`)
                .join(" · ")}`,
        alerts: relevant.map((a) => ({
          scan: a.scanName,
          verdict: a.verdict,
          scoreDelta: a.scoreDelta,
          added: a.added,
          fixed: a.fixed,
          worstAdded: a.worstAdded,
          detail: a.detail,
          at: new Date(a.at).toISOString(),
        })),
        at: new Date().toISOString(),
      };
      const { status, ok, detail } = await deliver(endpoint.url, endpoint.secretHash, payload);
      await ctx.runMutation(internal.integrations.recordDelivery, {
        endpointId: endpoint._id as never,
        event: "drift.alert",
        status,
        ok,
        detail,
      });
      results.push({ endpointId: endpoint._id, endpointName: endpoint.name, ok, detail });
    }

    if (results.length > 0) {
      await ctx.runMutation(internal.integrations.markAlertsDispatched, {});
    }
    return results;
  },
});
