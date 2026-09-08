// CrackScope Part 19 — team workspaces backend.
// Multi-member projects with roles (owner / admin / member), join-code
// invites, shared scans, and an activity feed. All mutations are
// ownership/role-checked; queries are scoped to workspaces the caller is a
// member of. Role hierarchy: owner > admin > member.
import { getAuthUserId } from "@convex-dev/auth/server";
import { query, mutation } from "./_generated/server";
import { v } from "convex/values";
import type { Doc, Id } from "./_generated/dataModel";

const ROLE_RANK: Record<string, number> = { owner: 3, admin: 2, member: 1 };

async function requireMember(
  ctx: any,
  workspaceId: Id<"workspaces">,
  minRole: "member" | "admin" | "owner",
): Promise<Doc<"workspaceMembers">> {
  const userId = await getAuthUserId(ctx);
  if (userId === null) throw new Error("Not authenticated");
  const membership = await ctx.db
    .query("workspaceMembers")
    .withIndex("by_workspace_user", (q: any) =>
      q.eq("workspaceId", workspaceId).eq("userId", userId),
    )
    .first();
  if (!membership) throw new Error("You are not a member of this workspace");
  if (ROLE_RANK[membership.role] < ROLE_RANK[minRole]) {
    throw new Error(`Requires ${minRole} role`);
  }
  return membership;
}

async function logActivity(
  ctx: any,
  workspaceId: Id<"workspaces">,
  userId: Id<"users">,
  kind:
    | "workspace_created"
    | "member_joined"
    | "member_removed"
    | "role_changed"
    | "scan_shared"
    | "scan_unshared"
    | "triage_updated",
  detail: string,
) {
  await ctx.db.insert("workspaceActivity", {
    workspaceId,
    userId,
    kind,
    detail,
    at: Date.now(),
  });
}

// ---------- queries ----------

export const listMyWorkspaces = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return [];
    const memberships = await ctx.db
      .query("workspaceMembers")
      .filter((q: any) => q.eq(q.field("userId"), userId))
      .collect();
    const out = [];
    for (const m of memberships) {
      const ws = await ctx.db.get(m.workspaceId);
      if (!ws) continue;
      out.push({ _id: ws._id, name: ws.name, role: m.role, ownerId: ws.ownerId });
    }
    return out;
  },
});

export const listMembers = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, { workspaceId }) => {
    await requireMember(ctx, workspaceId, "member");
    const members = await ctx.db
      .query("workspaceMembers")
      .withIndex("by_workspace", (q: any) => q.eq("workspaceId", workspaceId))
      .collect();
    const out = [];
    for (const m of members) {
      const user = await ctx.db.get(m.userId);
      out.push({
        _id: m._id,
        userId: m.userId,
        role: m.role,
        name: user?.name ?? user?.email ?? "Unknown",
        email: user?.email ?? null,
      });
    }
    return out;
  },
});

export const listInvites = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, { workspaceId }) => {
    await requireMember(ctx, workspaceId, "admin");
    return await ctx.db
      .query("workspaceInvites")
      .withIndex("by_workspace", (q: any) => q.eq("workspaceId", workspaceId))
      .collect();
  },
});

export const listSharedScans = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, { workspaceId }) => {
    await requireMember(ctx, workspaceId, "member");
    const shares = await ctx.db
      .query("workspaceScans")
      .withIndex("by_workspace", (q: any) => q.eq("workspaceId", workspaceId))
      .collect();
    const out = [];
    for (const s of shares) {
      const scan = await ctx.db.get(s.scanId);
      if (!scan) continue;
      const sharer = await ctx.db.get(s.sharedBy);
      out.push({
        shareId: s._id,
        scanId: s.scanId,
        sharedAt: s.sharedAt,
        sharedByName: sharer?.name ?? sharer?.email ?? "Unknown",
        name: scan.name,
        createdAt: scan.createdAt,
        score: scan.score,
        grade: scan.grade,
        critical: scan.critical,
        high: scan.high,
        medium: scan.medium,
        low: scan.low,
        findingsCount: scan.findings.length,
      });
    }
    out.sort((a: any, b: any) => b.sharedAt - a.sharedAt);
    return out;
  },
});

export const getSharedScan = query({
  args: { workspaceId: v.id("workspaces"), scanId: v.id("scans") },
  handler: async (ctx, { workspaceId, scanId }) => {
    await requireMember(ctx, workspaceId, "member");
    const share = await ctx.db
      .query("workspaceScans")
      .withIndex("by_workspace", (q: any) => q.eq("workspaceId", workspaceId))
      .collect()
      .then((rows: any[]) => rows.find((r) => r.scanId === scanId));
    if (!share) throw new Error("Scan is not shared with this workspace");
    return await ctx.db.get(scanId);
  },
});

export const listActivity = query({
  args: { workspaceId: v.id("workspaces"), limit: v.optional(v.number()) },
  handler: async (ctx, { workspaceId, limit }) => {
    await requireMember(ctx, workspaceId, "member");
    const rows = await ctx.db
      .query("workspaceActivity")
      .withIndex("by_workspace_time", (q: any) => q.eq("workspaceId", workspaceId))
      .order("desc")
      .take(limit ?? 50);
    const out = [];
    for (const row of rows) {
      const user = await ctx.db.get(row.userId);
      out.push({
        _id: row._id,
        kind: row.kind,
        detail: row.detail,
        at: row.at,
        userName: user?.name ?? user?.email ?? "Unknown",
      });
    }
    return out;
  },
});

// ---------- mutations ----------

export const createWorkspace = mutation({
  args: { name: v.string() },
  handler: async (ctx, { name }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const trimmed = name.trim();
    if (!trimmed || trimmed.length > 60) throw new Error("Workspace name must be 1-60 characters");
    const workspaceId = await ctx.db.insert("workspaces", {
      name: trimmed,
      ownerId: userId,
      createdAt: Date.now(),
    });
    await ctx.db.insert("workspaceMembers", {
      workspaceId,
      userId,
      role: "owner",
      joinedAt: Date.now(),
    });
    await logActivity(ctx, workspaceId, userId, "workspace_created", `created the workspace`);
    return workspaceId;
  },
});

export const deleteWorkspace = mutation({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, { workspaceId }) => {
    const membership = await requireMember(ctx, workspaceId, "owner");
    const ws = await ctx.db.get(workspaceId);
    if (!ws) throw new Error("Workspace not found");
    // Clean up all workspace rows.
    for (const table of ["workspaceMembers", "workspaceInvites", "workspaceScans", "workspaceActivity"] as const) {
      const rows = await ctx.db
        .query(table)
        .filter((q: any) => q.eq(q.field("workspaceId"), workspaceId))
        .collect();
      for (const row of rows) await ctx.db.delete(row._id);
    }
    await ctx.db.delete(workspaceId);
    return { name: ws.name, role: membership.role };
  },
});

export const createInvite = mutation({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, { workspaceId }) => {
    await requireMember(ctx, workspaceId, "admin");
    // 8-char unambiguous join code.
    const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let code = "";
    for (let i = 0; i < 8; i++) {
      code += alphabet[Math.floor(Math.random() * alphabet.length)];
    }
    await ctx.db.insert("workspaceInvites", {
      workspaceId,
      code,
      createdBy: (await getAuthUserId(ctx))!,
      createdAt: Date.now(),
    });
    await logActivity(ctx, workspaceId, (await getAuthUserId(ctx))!, "member_joined", "generated an invite code");
    return code;
  },
});

export const joinWorkspace = mutation({
  args: { code: v.string() },
  handler: async (ctx, { code }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const invite = await ctx.db
      .query("workspaceInvites")
      .withIndex("by_code", (q: any) => q.eq("code", code.trim().toUpperCase()))
      .first();
    if (!invite) throw new Error("Invalid invite code");
    const existing = await ctx.db
      .query("workspaceMembers")
      .withIndex("by_workspace_user", (q: any) =>
        q.eq("workspaceId", invite.workspaceId).eq("userId", userId),
      )
      .first();
    if (existing) return { workspaceId: invite.workspaceId, alreadyMember: true };
    await ctx.db.insert("workspaceMembers", {
      workspaceId: invite.workspaceId,
      userId,
      role: "member",
      joinedAt: Date.now(),
    });
    const user = await ctx.db.get(userId);
    await logActivity(
      ctx,
      invite.workspaceId,
      userId,
      "member_joined",
      `joined with invite code`,
    );
    void user;
    return { workspaceId: invite.workspaceId, alreadyMember: false };
  },
});

export const removeMember = mutation({
  args: { workspaceId: v.id("workspaces"), membershipId: v.id("workspaceMembers") },
  handler: async (ctx, { workspaceId, membershipId }) => {
    const actor = await requireMember(ctx, workspaceId, "admin");
    const target = await ctx.db.get(membershipId);
    if (!target || target.workspaceId !== workspaceId) throw new Error("Member not found");
    if (target.role === "owner") throw new Error("The workspace owner cannot be removed");
    if (ROLE_RANK[target.role] >= ROLE_RANK[actor.role] && actor.role !== "owner") {
      throw new Error("You can only remove members with a lower role than yours");
    }
    if (target.userId === actor.userId) throw new Error("Use leave instead of removing yourself");
    await ctx.db.delete(membershipId);
    await logActivity(ctx, workspaceId, actor.userId, "member_removed", "removed a member");
  },
});

export const changeRole = mutation({
  args: { workspaceId: v.id("workspaces"), membershipId: v.id("workspaceMembers"), role: v.union(v.literal("admin"), v.literal("member")) },
  handler: async (ctx, { workspaceId, membershipId, role }) => {
    const actor = await requireMember(ctx, workspaceId, "owner");
    const target = await ctx.db.get(membershipId);
    if (!target || target.workspaceId !== workspaceId) throw new Error("Member not found");
    if (target.role === "owner") throw new Error("The owner's role cannot be changed");
    await ctx.db.patch(membershipId, { role });
    await logActivity(ctx, workspaceId, actor.userId, "role_changed", `changed a member's role to ${role}`);
  },
});

export const leaveWorkspace = mutation({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, { workspaceId }) => {
    const membership = await requireMember(ctx, workspaceId, "member");
    if (membership.role === "owner") {
      throw new Error("Owners cannot leave — delete the workspace instead");
    }
    await ctx.db.delete(membership._id);
    await logActivity(ctx, workspaceId, membership.userId, "member_removed", "left the workspace");
  },
});

export const shareScan = mutation({
  args: { workspaceId: v.id("workspaces"), scanId: v.id("scans") },
  handler: async (ctx, { workspaceId, scanId }) => {
    const actor = await requireMember(ctx, workspaceId, "admin");
    const scan = await ctx.db.get(scanId);
    if (!scan) throw new Error("Scan not found");
    // Only the scan's owner (or workspace owner) may share it.
    if (scan.userId !== actor.userId) {
      const ws = await ctx.db.get(workspaceId);
      if (ws?.ownerId !== actor.userId) {
        throw new Error("You can only share your own scans");
      }
    }
    const existing = await ctx.db
      .query("workspaceScans")
      .withIndex("by_workspace", (q: any) => q.eq("workspaceId", workspaceId))
      .collect()
      .then((rows: any[]) => rows.find((r) => r.scanId === scanId));
    if (existing) return existing._id;
    const shareId = await ctx.db.insert("workspaceScans", {
      workspaceId,
      scanId,
      sharedBy: actor.userId,
      sharedAt: Date.now(),
    });
    await logActivity(ctx, workspaceId, actor.userId, "scan_shared", `shared scan "${scan.name}"`);
    return shareId;
  },
});

export const unshareScan = mutation({
  args: { workspaceId: v.id("workspaces"), scanId: v.id("scans") },
  handler: async (ctx, { workspaceId, scanId }) => {
    const actor = await requireMember(ctx, workspaceId, "admin");
    const share = await ctx.db
      .query("workspaceScans")
      .withIndex("by_workspace", (q: any) => q.eq("workspaceId", workspaceId))
      .collect()
      .then((rows: any[]) => rows.find((r) => r.scanId === scanId));
    if (!share) throw new Error("Scan is not shared");
    await ctx.db.delete(share._id);
    await logActivity(ctx, workspaceId, actor.userId, "scan_unshared", "unshared a scan");
  },
});
