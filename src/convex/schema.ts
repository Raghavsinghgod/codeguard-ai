import { authTables } from "@convex-dev/auth/server";
import { defineSchema, defineTable } from "convex/server";
import { Infer, v } from "convex/values";

// default user roles. can add / remove based on the project as needed
export const ROLES = {
  ADMIN: "admin",
  USER: "user",
  MEMBER: "member",
} as const;

export const roleValidator = v.union(
  v.literal(ROLES.ADMIN),
  v.literal(ROLES.USER),
  v.literal(ROLES.MEMBER),
);
export type Role = Infer<typeof roleValidator>;

const schema = defineSchema(
  {
    // default auth tables using convex auth.
    ...authTables, // do not remove or modify

    // the users table is the default users table that is brought in by the authTables
    users: defineTable({
      name: v.optional(v.string()), // name of the user. do not remove
      image: v.optional(v.string()), // image of the user. do not remove
      email: v.optional(v.string()), // email of the user. do not remove
      emailVerificationTime: v.optional(v.number()), // email verification time. do not remove
      isAnonymous: v.optional(v.boolean()), // is the user anonymous. do not remove

      role: v.optional(roleValidator), // role of the user. do not remove
    }).index("email", ["email"]), // index for the email. do not remove or modify

    // add other tables here

    // Security scan results produced by the CrackScope attack-simulation engine.
    scans: defineTable({
      userId: v.id("users"),
      name: v.string(),
      createdAt: v.number(),
      score: v.number(), // 0-100 security score
      grade: v.string(), // A-F
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
      aiAnalysis: v.optional(v.string()), // Part 8: raw JSON of the AI deep analysis
    }).index("by_user", ["userId"]),
    // aiAnalysis field: raw JSON string of the Part 8 AI deep analysis
    // (narrative, verdicts, fix priorities) attached to a scan.

    //    // Part 11: per-finding triage state (false positives, accepted risk,
    // notes, owners). One row per (scanId, findingKey = "ruleId|file|line").
    triage: defineTable({
      userId: v.id("users"),
      scanId: v.id("scans"),
      key: v.string(),
      status: v.union(
        v.literal("open"),
        v.literal("false_positive"),
        v.literal("accepted_risk"),
      ),
      note: v.optional(v.string()),
      owner: v.optional(v.string()),
      updatedAt: v.number(),
    }).index("by_scan", ["scanId"]),

    // tableName: defineTable({
    //   ...
    //   // table fields
    // }).index("by_field", ["field"])

    // Part 19: team workspaces. A workspace groups users; members carry a
    // per-workspace role. Scans can be shared into a workspace so the whole
    // team sees reports and triage state.
    workspaces: defineTable({
      name: v.string(),
      ownerId: v.id("users"),
      createdAt: v.number(),
    }).index("by_owner", ["ownerId"]),

    workspaceMembers: defineTable({
      workspaceId: v.id("workspaces"),
      userId: v.id("users"),
      // owner: full control (delete workspace, remove members, change roles)
      // admin: share scans, remove members, change roles below admin
      // member: view shared scans and triage
      role: v.union(v.literal("owner"), v.literal("admin"), v.literal("member")),
      joinedAt: v.number(),
    })
      .index("by_workspace", ["workspaceId"])
      .index("by_workspace_user", ["workspaceId", "userId"]),

    workspaceInvites: defineTable({
      workspaceId: v.id("workspaces"),
      code: v.string(), // short join code shared out-of-band
      createdBy: v.id("users"),
      createdAt: v.number(),
    })
      .index("by_workspace", ["workspaceId"])
      .index("by_code", ["code"]),

    workspaceScans: defineTable({
      workspaceId: v.id("workspaces"),
      scanId: v.id("scans"),
      sharedBy: v.id("users"),
      sharedAt: v.number(),
    })
      .index("by_workspace", ["workspaceId"])
      .index("by_scan", ["scanId"]),

    workspaceActivity: defineTable({
      workspaceId: v.id("workspaces"),
      userId: v.id("users"),
      kind: v.union(
        v.literal("workspace_created"),
        v.literal("member_joined"),
        v.literal("member_removed"),
        v.literal("role_changed"),
        v.literal("scan_shared"),
        v.literal("scan_unshared"),
        v.literal("triage_updated"),
      ),
      detail: v.string(),
      at: v.number(),
    }).index("by_workspace_time", ["workspaceId", "at"]),
  },
  {
    schemaValidation: false,
  },
);

export default schema;
