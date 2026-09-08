import { httpRouter } from "convex/server";
import { auth } from "./auth";
import { githubUserWebhook, githubAutoWebhook } from "./integrationWebhooks";
import { apiScan, apiListScans, apiGetScan, apiCiWebhook } from "./publicApi";

const http = httpRouter();

auth.addHttpRoutes(http);

// Part 22 — incoming GitHub webhook receivers.
http.route({
  path: "/api/webhooks/github",
  method: "POST",
  handler: githubAutoWebhook,
});

http.route({
  pathPrefix: "/api/webhooks/github/",
  method: "POST",
  handler: githubUserWebhook,
});

// Part 25 — public API & CI automation endpoints.
http.route({
  path: "/api/v1/scan",
  method: "POST",
  handler: apiScan,
});

http.route({
  path: "/api/v1/scans",
  method: "GET",
  handler: apiListScans,
});

http.route({
  pathPrefix: "/api/v1/scans/",
  method: "GET",
  handler: apiGetScan,
});

http.route({
  path: "/api/v1/ci/webhook",
  method: "POST",
  handler: apiCiWebhook,
});

export default http;
