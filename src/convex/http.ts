import { httpRouter } from "convex/server";
import { auth } from "./auth";
import { githubUserWebhook, githubAutoWebhook } from "./integrationWebhooks";

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

export default http;
