// CrackScope Part 22 — incoming GitHub webhook receiver.
// Two public HTTP routes on the Convex site URL:
//   POST /api/webhooks/github/:userId — per-user receiver URL shown in the UI.
//     Handles `ping` (handshake) and `push` events.
//   POST /api/webhooks/github — auto-registration helper: if the payload's
//     repository matches a scanSchedules row, the delivery is processed for
//     that row's owner.
//
// Security: verifies GitHub's HMAC-SHA256 signature header
// (x-hub-signature-256: sha256=<hex>) against the signing secret stored on
// the matching scanSchedules row (githubSecret). Invalid signatures are
// rejected with 401 before any processing.
//
// Push handling: updates the schedule's branch metadata (branches can move)
// and pulls the next run to now, so the next drift check covers the new
// commit as soon as the runner fires it.
import { httpAction, internalMutation, internalQuery } from "./_generated/server";
import { internal } from "./_generated/api";
import { v } from "convex/values";

async function verifySignature(
  rawBody: string,
  secret: string,
  header: string | null,
): Promise<boolean> {
  if (!header?.startsWith("sha256=")) return false;
  const provided = header.slice("sha256=".length);
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(rawBody));
  const expected = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (expected.length !== provided.length) return false;
  // Constant-time-ish compare (lengths already matched).
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ provided.charCodeAt(i);
  return diff === 0;
}

function extractRepo(
  payload: Record<string, unknown>,
): { owner: string; repo: string; branch: string | null } | null {
  const repository = payload.repository as Record<string, unknown> | undefined;
  if (!repository) return null;
  const fullName = typeof repository.full_name === "string" ? repository.full_name : null;
  if (!fullName) return null;
  const [owner, repo] = fullName.split("/");
  if (!owner || !repo) return null;
  const ref = typeof payload.ref === "string" ? payload.ref : null;
  const branch = ref?.startsWith("refs/heads/") ? ref.slice("refs/heads/".length) : null;
  return { owner, repo, branch };
}

export const resolveByUserAndRepo = internalQuery({
  args: { userId: v.id("users"), owner: v.string(), repo: v.string() },
  handler: async (ctx, { userId, owner, repo }) => {
    const rows = await ctx.db
      .query("scanSchedules")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .collect();
    const row = rows.find((r) => r.owner === owner && r.repo === repo);
    return row ? { _id: row._id, githubSecret: row.githubSecret ?? null } : null;
  },
});

export const resolveGlobal = internalQuery({
  args: { owner: v.string(), repo: v.string() },
  handler: async (ctx, { owner, repo }) => {
    const rows = await ctx.db.query("scanSchedules").collect();
    const row = rows.find((r) => r.owner === owner && r.repo === repo);
    return row ? { _id: row._id, githubSecret: row.githubSecret ?? null } : null;
  },
});

export const touch = internalMutation({
  args: {
    id: v.id("scanSchedules"),
    branch: v.optional(v.string()),
    status: v.string(),
    runNow: v.boolean(),
  },
  handler: async (ctx, { id, branch, status, runNow }) => {
    const patch: { branch?: string; lastStatus: string; nextRunAt?: number } = { lastStatus: status };
    if (branch !== undefined) patch.branch = branch;
    if (runNow) patch.nextRunAt = Date.now();
    await ctx.db.patch(id, patch);
  },
});

interface RunContext {
  runQuery: (fn: unknown, args: unknown) => Promise<{ _id: unknown; githubSecret: string | null } | null>;
  runMutation: (fn: unknown, args: unknown) => Promise<unknown>;
}

async function handleGithubWebhook(
  ctx: RunContext,
  request: Request,
  userIdHint: string | null,
): Promise<Response> {
  const raw = await request.text();
  const event = request.headers.get("x-github-event");
  const signature = request.headers.get("x-hub-signature-256");
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return new Response("bad json", { status: 400 });
  }

  const target = extractRepo(payload);
  if (!target) return new Response("ignored", { status: 200 });

  // Resolve the schedule row (and thus the signing secret) before verifying.
  const schedule = userIdHint
    ? await ctx.runQuery(resolveByUserAndRepo, { userId: userIdHint, owner: target.owner, repo: target.repo })
    : await ctx.runQuery(resolveGlobal, { owner: target.owner, repo: target.repo });
  if (!schedule) return new Response("unknown repository", { status: 404 });

  const secret = schedule.githubSecret;
  if (!secret || !(await verifySignature(raw, secret, signature))) {
    return new Response("invalid signature", { status: 401 });
  }

  if (event === "ping") {
    await ctx.runMutation(touch, {
      id: schedule._id,
      status: "GitHub webhook connected",
      runNow: false,
    });
    return new Response(JSON.stringify({ ok: true, mode: "ping" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (event === "push") {
    await ctx.runMutation(touch, {
      id: schedule._id,
      status: `push received (${target.branch ?? "default branch"}) — re-scan queued`,
      runNow: true,
      branch: target.branch ?? undefined,
    });
    return new Response(JSON.stringify({ ok: true, mode: "push", queued: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  return new Response("ignored event", { status: 200 });
}

/** Per-user receiver: POST /api/webhooks/github/:userId */
export const githubUserWebhook = httpAction(async (ctx, request) => {
  const url = new URL(request.url);
  const userId = url.pathname.split("/").pop() ?? null;
  return handleGithubWebhook(ctx as unknown as RunContext, request, userId);
});

/** Auto-registration receiver: POST /api/webhooks/github */
export const githubAutoWebhook = httpAction(async (ctx, request) => {
  return handleGithubWebhook(ctx as unknown as RunContext, request, null);
});
