// CrackScope Part 25 — public HTTP API for programmatic access & CI.
// Routes on the Convex site URL (all under /api/v1), authenticated with
// `Authorization: Bearer cs_...` API keys (sha256-verified against apiKeys):
//
//   POST /api/v1/scan        { repo: "owner/repo" | URL, branch?, save? }
//                            → runs the engine on a public GitHub repo, saves
//                              the scan, returns score + findings JSON.
//   GET  /api/v1/scans       → last 25 saved scans (summary).
//   GET  /api/v1/scans/:id   → one scan by id (must belong to the key owner).
//   POST /api/v1/ci/webhook  CI receiver: { repository: { full_name }, ref? }
//                            queues a re-scan on the owner's matching
//                            scanSchedules row (generic automation entry).
//
// Runs in Convex's default runtime: fetch + Web Crypto + the pure-TS engine
// all work there, and httpAction cannot be defined in a "use node" file.
import { httpAction } from "./_generated/server";
import { internal } from "./_generated/api";
import { scan } from "../lib/scanner";

interface AuthResult {
  userId: string;
  keyId: string;
}

interface ActionCtx {
  runQuery: (fn: unknown, args: unknown) => Promise<unknown>;
  runMutation: (fn: unknown, args: unknown) => Promise<unknown>;
}

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function keyHashOf(provided: string | null): Promise<string | null> {
  if (!provided) return null;
  const raw = provided.replace(/^Bearer\s+/i, "").trim();
  if (!raw.startsWith("cs_")) return null;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function authenticate(
  ctx: ActionCtx,
  request: Request,
): Promise<AuthResult | null> {
  const keyHash = await keyHashOf(request.headers.get("authorization"));
  if (!keyHash) return null;
  return (await ctx.runQuery(internal.publicApiInternals.resolveKey, { keyHash })) as AuthResult | null;
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "Content-Type": "application/json" },
  });

const unauthorized = () =>
  json({ error: "unauthorized — supply an API key via 'Authorization: Bearer cs_...'" }, 401);

// ---------- repo fetching (mirrors scheduleRuns.ts) ----------

type RepoInput = { name: string; content: string };

const MAX_FILES = 40;

async function ghJson(url: string): Promise<unknown> {
  const res = await fetch(url, { headers: { Accept: "application/vnd.github+json" } });
  if (res.status === 404) throw new ApiError(404, "GitHub repo not found — check the repo (public repos only).");
  if (res.status === 403 || res.status === 429)
    throw new ApiError(429, "GitHub rate limit reached — try again later.");
  if (!res.ok) throw new ApiError(502, `GitHub request failed (${res.status}).`);
  return res.json();
}

async function fetchRepoFiles(owner: string, repo: string, branch?: string): Promise<RepoInput[]> {
  let ref = branch;
  if (!ref) {
    const info = (await ghJson(`https://api.github.com/repos/${owner}/${repo}`)) as {
      default_branch?: string;
    };
    ref = info.default_branch || "main";
  }
  const tree = (await ghJson(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`,
  )) as { tree?: Array<{ path: string; type: string }> };

  const candidates = (tree.tree ?? []).filter((e) => e.type === "blob").slice(0, MAX_FILES * 3);
  const inputs: RepoInput[] = [];
  const base = `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/`;
  for (const entry of candidates) {
    if (inputs.length >= MAX_FILES) break;
    try {
      const res = await fetch(base + entry.path.split("/").map(encodeURIComponent).join("/"));
      if (!res.ok) continue;
      const text = await res.text();
      if (text.includes("\u0000")) continue;
      inputs.push({ name: entry.path, content: text });
    } catch {
      // skip unreachable blobs
    }
  }
  if (inputs.length === 0) throw new ApiError(422, "No scannable source files found in that repo.");
  return inputs;
}

function parseRepoTarget(repo: string): { owner: string; repo: string } | null {
  const cleaned = repo
    .replace(/^https?:\/\/github\.com\//i, "")
    .replace(/\.git$/i, "")
    .replace(/\/tree\/.*$/i, "");
  const parts = cleaned.split("/").filter(Boolean);
  if (parts.length !== 2) return null;
  return { owner: parts[0], repo: parts[1] };
}

// ---------- route handlers ----------

/** POST /api/v1/scan — { repo, branch?, save? } */
export const apiScan = httpAction(async (ctx, request) => {
  const actx = ctx as unknown as ActionCtx;
  const auth = await authenticate(actx, request);
  if (!auth) return unauthorized();

  let body: { repo?: string; branch?: string; save?: boolean };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  const target = body.repo ? parseRepoTarget(body.repo) : null;
  if (!target) return json({ error: "provide 'repo' as owner/repo or a github.com URL" }, 400);

  try {
    const inputs = await fetchRepoFiles(target.owner, target.repo, body.branch);
    const result = scan(inputs);

    let scanId: string | null = null;
    if (body.save !== false) {
      scanId = (await actx.runMutation(internal.publicApiInternals.saveApiScan, {
        userId: auth.userId,
        name: `${target.owner}/${target.repo} (api)`,
        score: result.score,
        grade: result.grade,
        filesScanned: result.filesScanned,
        linesScanned: result.linesScanned,
        critical: result.counts.critical,
        high: result.counts.high,
        medium: result.counts.medium,
        low: result.counts.low,
        info: result.counts.info,
        findings: result.findings,
      })) as string;
    }

    await actx.runMutation(internal.publicApiInternals.touchKey, { id: auth.keyId });

    return json({
      scanId,
      repo: `${target.owner}/${target.repo}`,
      branch: body.branch ?? "default",
      score: result.score,
      grade: result.grade,
      filesScanned: result.filesScanned,
      linesScanned: result.linesScanned,
      counts: result.counts,
      findings: result.findings,
    });
  } catch (e) {
    if (e instanceof ApiError) return json({ error: e.message }, e.status);
    return json({ error: e instanceof Error ? e.message : "scan failed" }, 500);
  }
});

/** GET /api/v1/scans — list latest scans for the key owner. */
export const apiListScans = httpAction(async (ctx, request) => {
  const actx = ctx as unknown as ActionCtx;
  const auth = await authenticate(actx, request);
  if (!auth) return unauthorized();

  const rows = (await actx.runQuery(internal.publicApiInternals.listUserScans, {
    userId: auth.userId,
  })) as Array<{
    _id: string;
    name: string;
    createdAt: number;
    score: number;
    grade: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  }>;

  await actx.runMutation(internal.publicApiInternals.touchKey, { id: auth.keyId });

  return json({
    scans: rows.map((s) => ({
      id: s._id,
      name: s.name,
      createdAt: new Date(s.createdAt).toISOString(),
      score: s.score,
      grade: s.grade,
      counts: { critical: s.critical, high: s.high, medium: s.medium, low: s.low, info: s.info },
    })),
  });
});

/** GET /api/v1/scans/:id */
export const apiGetScan = httpAction(async (ctx, request) => {
  const actx = ctx as unknown as ActionCtx;
  const auth = await authenticate(actx, request);
  if (!auth) return unauthorized();

  const rawId = new URL(request.url).pathname.split("/").pop() ?? "";
  type ApiScanRow = {
    _id: string;
    name: string;
    createdAt: number;
    score: number;
    grade: string;
    findings: unknown;
  };
  let row: ApiScanRow | null = null;
  try {
    row = (await actx.runQuery(internal.publicApiInternals.getUserScan, {
      userId: auth.userId,
      scanId: rawId as never,
    })) as ApiScanRow | null;
  } catch {
    // Malformed id (not a valid Convex document id) → treat as not found.
    return json({ error: "scan not found" }, 404);
  }
  if (!row) return json({ error: "scan not found" }, 404);

  await actx.runMutation(internal.publicApiInternals.touchKey, { id: auth.keyId });

  return json({ ...row, createdAt: new Date(row.createdAt).toISOString() });
});

/** POST /api/v1/ci/webhook — generic CI trigger: queue a re-scan. */
export const apiCiWebhook = httpAction(async (ctx, request) => {
  const actx = ctx as unknown as ActionCtx;
  const auth = await authenticate(actx, request);
  if (!auth) return unauthorized();

  let body: { repository?: { full_name?: string }; ref?: string; repo?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }

  const fullName = body.repository?.full_name ?? body.repo ?? null;
  if (!fullName) return json({ error: "provide repository.full_name or repo (owner/name)" }, 400);
  const [owner, repo] = fullName.split("/");
  if (!owner || !repo) return json({ error: "could not parse owner/name" }, 400);

  let scheduleId: string | null = null;
  try {
    scheduleId = (await actx.runQuery(internal.publicApiInternals.findSchedule, {
      userId: auth.userId,
      owner,
      repo,
    })) as string | null;
  } catch {
    scheduleId = null;
  }
  if (!scheduleId) {
    return json(
      { error: `no scan schedule for ${owner}/${repo} — create one in the Scheduled tab first`, queued: false },
      404,
    );
  }

  const branch = body.ref?.startsWith("refs/heads/") ? body.ref.slice("refs/heads/".length) : body.ref;
  await actx.runMutation(internal.publicApiInternals.queueSchedule, {
    id: scheduleId,
    note: `CI trigger${branch ? ` (${branch})` : ""} — re-scan queued`,
  });
  await actx.runMutation(internal.publicApiInternals.touchKey, { id: auth.keyId });

  return json({ ok: true, queued: true, repo: `${owner}/${repo}` });
});
