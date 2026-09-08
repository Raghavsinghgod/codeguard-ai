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

    // Part 20: report center. A profile holds client-facing branding applied
    // to exported/scheduled reports; a schedule delivers a scan's report by
    // email on a recurring cadence.
    reportProfiles: defineTable({
      userId: v.id("users"),
      name: v.string(), // profile label, e.g. "Acme Corp brand"
      company: v.string(), // client-facing company name on the report
      accent: v.string(), // accent color (any CSS color string)
      footer: v.string(), // footer line, e.g. confidentiality notice
      createdAt: v.number(),
    }).index("by_user", ["userId"]),

    reportSchedules: defineTable({
      userId: v.id("users"),
      scanId: v.id("scans"),
      profileId: v.optional(v.id("reportProfiles")),
      recipients: v.array(v.string()),
      frequency: v.union(v.literal("weekly"), v.literal("monthly")),
      nextSendAt: v.number(),
      lastSentAt: v.optional(v.number()),
      lastStatus: v.optional(v.string()),
      enabled: v.boolean(),
      createdAt: v.number(),
    })
      .index("by_user", ["userId"])
      .index("by_due", ["enabled", "nextSendAt"]),

    // Part 21: scheduled & recurring scans. A schedule re-scans a public
    // GitHub repo on a cadence; each run diffs against the previous run and
    // records drift alerts (regressions / fixes / new critical findings).
    scanSchedules: defineTable({
      userId: v.id("users"),
      repoUrl: v.string(), // as entered, for display
      owner: v.string(),
      repo: v.string(),
      branch: v.optional(v.string()),
      frequency: v.union(v.literal("daily"), v.literal("weekly")),
      nextRunAt: v.number(),
      lastRunAt: v.optional(v.number()),
      lastStatus: v.optional(v.string()),
      lastScanId: v.optional(v.id("scans")),
      githubSecret: v.optional(v.string()), // GitHub webhook signing secret (plaintext; used to verify x-hub-signature-256)
      enabled: v.boolean(),
      createdAt: v.number(),
    })
      .index("by_user", ["userId"])
      .index("by_due", ["enabled", "nextRunAt"]),

    driftAlerts: defineTable({
      userId: v.id("users"),
      scheduleId: v.id("scanSchedules"),
      scanId: v.id("scans"),
      verdict: v.union(
        v.literal("regressed"),
        v.literal("improved"),
        v.literal("unchanged"),
        v.literal("mixed"),
        v.literal("first_run"),
      ),
      scoreDelta: v.number(), // current - previous (positive = improvement)
      added: v.number(),
      fixed: v.number(),
      worstAdded: v.optional(v.string()), // severity of the worst new finding
      detail: v.string(),
      at: v.number(),
      seen: v.boolean(),
    })
      .index("by_user_time", ["userId", "at"])
      .index("by_schedule", ["scheduleId"]),

    // Part 22: integrations. Outgoing webhook endpoints (Slack-style) receive
    // scan and drift-alert notifications; delivery log records the last
    // outcome per endpoint. Incoming GitHub webhooks re-scan repos on push.
    webhookEndpoints: defineTable({
      userId: v.id("users"),
      name: v.string(), // display label, e.g. "#security-alerts"
      url: v.string(), // https:// URL of the receiver
      secretHash: v.optional(v.string()), // sha256 of the signing secret
      events: v.array(
        v.union(v.literal("scan"), v.literal("drift"), v.literal("critical")),
      ),
      enabled: v.boolean(),
      lastStatus: v.optional(v.string()),
      lastDeliveryAt: v.optional(v.number()),
      createdAt: v.number(),
    }).index("by_user", ["userId"]),

    webhookDeliveries: defineTable({
      userId: v.id("users"),
      endpointId: v.id("webhookEndpoints"),
      event: v.string(), // "scan.completed" | "drift.alert" | "critical.finding"
      status: v.number(), // HTTP status (0 = network error)
      ok: v.boolean(),
      detail: v.string(),
      at: v.number(),
    })
      .index("by_user_time", ["userId", "at"])
      .index("by_endpoint_time", ["endpointId", "at"]),

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
