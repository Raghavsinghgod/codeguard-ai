// CrackScope Part 8 — AI deep analysis action.
// Runs on the Convex Node runtime ("use node") and calls an OpenAI-compatible
// LLM inference API (Novita) with the scan report, returning a structured
// deep analysis. Requires NOVITA_API_KEY (optional NOVITA_MODEL override),
// configured through the project's Keys/API keys tab.
"use node";

import { action } from "./_generated/server";
import { v } from "convex/values";
import { getAuthUserId } from "@convex-dev/auth/server";
import { buildAnalysisPrompt, parseDeepAnalysis } from "../lib/ai";

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

const DEFAULT_MODEL = "deepseek/deepseek-chat-v3-0324";
const API_URL = "https://api.novita.ai/v3/openai/chat/completions";

export const deepAnalysis = action({
  args: {
    name: v.string(),
    score: v.number(),
    grade: v.string(),
    filesScanned: v.number(),
    linesScanned: v.number(),
    findings: v.array(findingValidator),
  },
  handler: async (_ctx, args) => {
    const apiKey = process.env.NOVITA_API_KEY;
    if (!apiKey) {
      throw new Error(
        "AI analysis is not configured yet. Add a NOVITA_API_KEY in the project's Keys/API keys tab (free signup at novita.ai) and run the analysis again.",
      );
    }

    const { system, user } = buildAnalysisPrompt(args.name, {
      score: args.score,
      grade: args.grade as never,
      filesScanned: args.filesScanned,
      linesScanned: args.linesScanned,
      languages: [],
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      findings: args.findings as never,
      durationMs: 0,
    });

    const model = process.env.NOVITA_MODEL || DEFAULT_MODEL;

    let res: Response;
    try {
      res = await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: "system", content: system },
            { role: "user", content: user },
          ],
          temperature: 0.3,
          max_tokens: 2048,
          response_format: { type: "json_object" },
        }),
      });
    } catch {
      throw new Error("Could not reach the AI inference service. Check your connection and try again.");
    }

    if (res.status === 401 || res.status === 403) {
      throw new Error("The AI API rejected the NOVITA_API_KEY. Check the key in the Keys/API keys tab.");
    }
    if (res.status === 429) {
      throw new Error("AI rate limit reached — wait a moment and try again.");
    }
    if (!res.ok) {
      throw new Error(`AI request failed (${res.status}). Try again shortly.`);
    }

    const data = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const content = data.choices?.[0]?.message?.content ?? "";
    if (!content) {
      throw new Error("The AI returned an empty analysis. Try again.");
    }

    return parseDeepAnalysis(content);
  },
});
