// CrackScope Part 20 — report center backend.
// Branded report profiles (client-facing company, accent color, footer) and
// scheduled email delivery of pentest reports via Resend. Schedules are
// fired client-side: the dashboard checks for due schedules on load and calls
// deliverDue, which sends each due report and rolls the next send time.
import { getAuthUserId } from "@convex-dev/auth/server";
import { action, internalMutation, internalQuery, mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { internal } from "./_generated/api";

const ACCENTS = ["#22c55e", "#38bdf8", "#a78bfa", "#f59e0b", "#f43f5e"] as const;

// ---------- queries ----------

export const listProfiles = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return [];
    return await ctx.db
      .query("reportProfiles")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .collect();
  },
});

export const listSchedules = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return [];
    const rows = await ctx.db
      .query("reportSchedules")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .collect();
    const out = [];
    for (const s of rows) {
      const scan = await ctx.db.get(s.scanId);
      out.push({
        _id: s._id,
        scanId: s.scanId,
        scanName: scan?.name ?? "(deleted scan)",
        scanScore: scan?.score ?? null,
        profileId: s.profileId ?? null,
        recipients: s.recipients,
        frequency: s.frequency,
        nextSendAt: s.nextSendAt,
        lastSentAt: s.lastSentAt ?? null,
        lastStatus: s.lastStatus ?? null,
        enabled: s.enabled,
      });
    }
    out.sort((a, b) => a.nextSendAt - b.nextSendAt);
    return out;
  },
});

/** How many schedules are due right now (drives the "deliver due reports" nudge). */
export const dueCount = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return 0;
    const rows = await ctx.db
      .query("reportSchedules")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .filter((q) => q.eq(q.field("enabled"), true))
      .collect();
    const now = Date.now();
    return rows.filter((r) => r.nextSendAt <= now).length;
  },
});

// ---------- profile mutations ----------

export const saveProfile = mutation({
  args: {
    id: v.optional(v.id("reportProfiles")),
    name: v.string(),
    company: v.string(),
    accent: v.string(),
    footer: v.string(),
  },
  handler: async (ctx, { id, name, company, accent, footer }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    if (!name.trim() || !company.trim()) throw new Error("Profile and company names are required");
    if (!ACCENTS.includes(accent as (typeof ACCENTS)[number])) throw new Error("Invalid accent color");
    if (id) {
      const existing = await ctx.db.get(id);
      if (!existing || existing.userId !== userId) throw new Error("Profile not found");
      await ctx.db.patch(id, { name: name.trim(), company: company.trim(), accent, footer: footer.trim() });
      return id;
    }
    return await ctx.db.insert("reportProfiles", {
      userId,
      name: name.trim(),
      company: company.trim(),
      accent,
      footer: footer.trim(),
      createdAt: Date.now(),
    });
  },
});

export const deleteProfile = mutation({
  args: { id: v.id("reportProfiles") },
  handler: async (ctx, { id }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const profile = await ctx.db.get(id);
    if (!profile || profile.userId !== userId) throw new Error("Profile not found");
    // Detach any schedules pointing at this profile.
    const schedules = await ctx.db
      .query("reportSchedules")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .filter((q) => q.eq(q.field("profileId"), id))
      .collect();
    for (const s of schedules) await ctx.db.patch(s._id, { profileId: undefined });
    await ctx.db.delete(id);
  },
});

// ---------- schedule mutations ----------

function nextSend(frequency: "weekly" | "monthly", from = Date.now()): number {
  const d = new Date(from);
  if (frequency === "weekly") d.setDate(d.getDate() + 7);
  else d.setMonth(d.getMonth() + 1);
  return d.getTime();
}

export const createSchedule = mutation({
  args: {
    scanId: v.id("scans"),
    profileId: v.optional(v.id("reportProfiles")),
    recipients: v.array(v.string()),
    frequency: v.union(v.literal("weekly"), v.literal("monthly")),
  },
  handler: async (ctx, { scanId, profileId, recipients, frequency }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const scan = await ctx.db.get(scanId);
    if (!scan || scan.userId !== userId) throw new Error("Scan not found");
    const emails = recipients.map((r) => r.trim()).filter(Boolean);
    if (emails.length === 0) throw new Error("Add at least one recipient email");
    for (const email of emails) {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error(`Invalid email: ${email}`);
    }
    if (profileId) {
      const profile = await ctx.db.get(profileId);
      if (!profile || profile.userId !== userId) throw new Error("Profile not found");
    }
    return await ctx.db.insert("reportSchedules", {
      userId,
      scanId,
      profileId,
      recipients: emails,
      frequency,
      nextSendAt: nextSend(frequency),
      enabled: true,
      createdAt: Date.now(),
    });
  },
});

export const toggleSchedule = mutation({
  args: { id: v.id("reportSchedules") },
  handler: async (ctx, { id }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const s = await ctx.db.get(id);
    if (!s || s.userId !== userId) throw new Error("Schedule not found");
    await ctx.db.patch(id, { enabled: !s.enabled });
  },
});

export const deleteSchedule = mutation({
  args: { id: v.id("reportSchedules") },
  handler: async (ctx, { id }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const s = await ctx.db.get(id);
    if (!s || s.userId !== userId) throw new Error("Schedule not found");
    await ctx.db.delete(id);
  },
});

// ---------- delivery ----------

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/**
 * Sends every due schedule for the caller. Returns a per-schedule status so
 * the UI can surface what happened without throwing on partial failures.
 * Requires RESEND_API_KEY in the Keys/API keys tab.
 */
export const deliverDue = action({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) {
      throw new Error(
        "Email delivery is not configured yet. Add a RESEND_API_KEY in the project's Keys/API keys tab (free signup at resend.com), then try again.",
      );
    }

    // Actions have no ctx.db — pull due schedules and their scans via queries.
    const due = await ctx.runQuery(internal.reports.collectDue, {});

    const results: { scheduleId: string; scanName: string; ok: boolean; message: string }[] = [];
    for (const s of due) {
      const scan = await ctx.runQuery(internal.reports.scanForSchedule, { scanId: s.scanId });
      if (!scan) {
        await ctx.runMutation(internal.reports.disableSchedule, { id: s._id, status: "scan deleted" });
        results.push({ scheduleId: s._id, scanName: "(deleted)", ok: false, message: "scan deleted — schedule disabled" });
        continue;
      }
      const profile = s.profileId
        ? await ctx.runQuery(internal.reports.profileForSchedule, { profileId: s.profileId })
        : null;
      const company = profile?.company ?? "CrackScope";
      const accent = profile?.accent ?? "#22c55e";
      const footer = profile?.footer ?? "Confidential — generated by CrackScope automated attack simulation.";
      const total = scan.critical + scan.high + scan.medium + scan.low;

      const html = `<!doctype html><html><body style="margin:0;background:#0b0d10;font-family:ui-sans-serif,system-ui,sans-serif;color:#e7e9ea">
<div style="max-width:560px;margin:0 auto;padding:32px 24px">
  <p style="font-size:11px;letter-spacing:0.2em;text-transform:uppercase;color:#8a9096;margin:0 0 8px">${escapeHtml(company)} · scheduled pentest report</p>
  <h1 style="font-size:22px;margin:0 0 4px;color:#ffffff">${escapeHtml(scan.name)}</h1>
  <p style="font-size:13px;color:#8a9096;margin:0 0 20px">score ${scan.score}/100 · grade ${escapeHtml(scan.grade)} · ${scan.findings.length} finding${scan.findings.length === 1 ? "" : "s"}</p>
  <div style="border-radius:12px;background:#14171b;border:1px solid #262b31;padding:16px 20px;margin-bottom:16px">
    <p style="margin:0 0 10px;font-size:13px;font-weight:600;color:#ffffff">Severity breakdown</p>
    <p style="margin:0;font-size:13px;color:#c8ccd0;line-height:1.8">
      <span style="color:${accent};font-weight:700">${scan.critical}</span> critical ·
      <span style="color:#f59e0b;font-weight:700">${scan.high}</span> high ·
      <span style="color:#eab308;font-weight:700">${scan.medium}</span> medium ·
      <span style="color:#38bdf8;font-weight:700">${scan.low}</span> low · ${total} total
    </p>
  </div>
  ${scan.findings.slice(0, 5).map((f) => `<div style="border-left:3px solid ${accent};padding:8px 14px;margin-bottom:10px;background:#14171b;border-radius:0 8px 8px 0">
    <p style="margin:0;font-size:13px;font-weight:600;color:#ffffff">${escapeHtml(f.title)}</p>
    <p style="margin:2px 0 0;font-size:12px;color:#8a9096;font-family:ui-monospace,monospace">${escapeHtml(f.file)}:${f.line} · ${f.severity}</p>
  </div>`).join("")}
  ${scan.findings.length > 5 ? `<p style="font-size:12px;color:#8a9096">+ ${scan.findings.length - 5} more findings — open CrackScope for the full report.</p>` : ""}
  <p style="margin-top:24px;padding-top:16px;border-top:1px solid #262b31;font-size:11px;color:#6b7178">${escapeHtml(footer)}</p>
</div>
</body></html>`;

      try {
        const res = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${apiKey}`,
          },
          body: JSON.stringify({
            from: "CrackScope Reports <onboarding@resend.dev>",
            to: s.recipients,
            subject: `[${company}] Pentest report: ${scan.name} — score ${scan.score}/100`,
            html,
          }),
        });
        if (!res.ok) {
          const body = await res.text().catch(() => "");
          const message =
            res.status === 401 || res.status === 403
              ? "Resend rejected the API key — check RESEND_API_KEY"
              : res.status === 422
                ? `Resend rejected a recipient (verify your domain to send beyond your own email): ${body.slice(0, 140)}`
                : `Resend error ${res.status}`;
          await ctx.runMutation(internal.reports.recordDelivery, { id: s._id, ok: false, status: message });
          results.push({ scheduleId: s._id, scanName: scan.name, ok: false, message });
          continue;
        }
        await ctx.runMutation(internal.reports.recordDelivery, { id: s._id, ok: true, status: "sent" });
        results.push({ scheduleId: s._id, scanName: scan.name, ok: true, message: "sent" });
      } catch {
        const message = "Network error reaching Resend";
        await ctx.runMutation(internal.reports.recordDelivery, { id: s._id, ok: false, status: message });
        results.push({ scheduleId: s._id, scanName: scan.name, ok: false, message });
      }
    }
    return results;
  },
});

// Internal helpers: actions cannot touch ctx.db, so reads go through queries
// and outcomes are recorded through internal mutations.
export const collectDue = internalQuery({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return [];
    const rows = await ctx.db
      .query("reportSchedules")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .filter((q) => q.eq(q.field("enabled"), true))
      .collect();
    const now = Date.now();
    return rows
      .filter((r) => r.nextSendAt <= now)
      .map((r) => ({ _id: r._id, scanId: r.scanId, profileId: r.profileId ?? null, recipients: r.recipients }));
  },
});

export const scanForSchedule = internalQuery({
  args: { scanId: v.id("scans") },
  handler: async (ctx, { scanId }) => {
    return await ctx.db.get(scanId);
  },
});

export const profileForSchedule = internalQuery({
  args: { profileId: v.id("reportProfiles") },
  handler: async (ctx, { profileId }) => {
    return await ctx.db.get(profileId);
  },
});

export const recordDelivery = internalMutation({
  args: { id: v.id("reportSchedules"), ok: v.boolean(), status: v.string() },
  handler: async (ctx, { id, ok, status }) => {
    await ctx.db.patch(id, {
      lastSentAt: Date.now(),
      lastStatus: status,
      nextSendAt: nextSend("weekly", Date.now()),
      enabled: ok,
    });
  },
});

export const disableSchedule = internalMutation({
  args: { id: v.id("reportSchedules"), status: v.string() },
  handler: async (ctx, { id, status }) => {
    await ctx.db.patch(id, { enabled: false, lastStatus: status });
  },
});
