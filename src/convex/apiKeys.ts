// CrackScope Part 25 — public API key management.
// Keys look like `cs_<40 hex chars>`. Only the SHA-256 hash is stored; the
// plaintext is returned exactly once at creation. Auth uses Web Crypto (no
// node:crypto) so queries/mutations stay in Convex's default runtime.
import { getAuthUserId } from "@convex-dev/auth/server";
import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const listKeys = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) return [];
    return await ctx.db
      .query("apiKeys")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .order("desc")
      .collect();
  },
});

export const createKey = mutation({
  args: { name: v.string() },
  handler: async (ctx, { name }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const secret = [...crypto.getRandomValues(new Uint8Array(20))]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const fullKey = `cs_${secret}`;
    const keyHash = await sha256Hex(fullKey);
    await ctx.db.insert("apiKeys", {
      userId,
      name: name.trim() || "api-key",
      keyHash,
      prefix: fullKey.slice(0, 10),
      revoked: false,
      createdAt: Date.now(),
    });
    return fullKey; // shown once in the UI
  },
});

export const revokeKey = mutation({
  args: { id: v.id("apiKeys") },
  handler: async (ctx, { id }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const row = await ctx.db.get(id);
    if (!row || row.userId !== userId) throw new Error("Key not found");
    await ctx.db.patch(id, { revoked: true });
  },
});

export const deleteKey = mutation({
  args: { id: v.id("apiKeys") },
  handler: async (ctx, { id }) => {
    const userId = await getAuthUserId(ctx);
    if (userId === null) throw new Error("Not authenticated");
    const row = await ctx.db.get(id);
    if (!row || row.userId !== userId) throw new Error("Key not found");
    await ctx.db.delete(id);
  },
});
