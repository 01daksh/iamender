import { createServer } from "node:http";
import { AwsIamender } from "./aws.js";
import { loadConfig } from "./config.js";
import { analyzeAccount } from "./review.js";
import { createApprovalSession, trueForgeStatus } from "./trueforge.js";
import { decideApproval, getApproval, requestApproval } from "./approval.js";

const port = Number(process.env.IAMENDER_API_PORT ?? 8787);

function sendJson(response: import("node:http").ServerResponse, status: number, body: unknown) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "http://127.0.0.1:5173",
  });
  response.end(JSON.stringify(body));
}

async function readBody(request: import("node:http").IncomingMessage) {
  let body = "";
  for await (const chunk of request) body += chunk;
  return body ? JSON.parse(body) as { findingId?: string } : {};
}

createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", `http://${request.headers.host}`);
  const path = url.pathname;
  if (request.method === "GET" && path === "/api/health") {
    const config = loadConfig();
    sendJson(response, 200, { ok: true, mode: config.localMode ? "localstack" : "aws" });
    return;
  }
  if (request.method === "GET" && path === "/api/reviews") {
    try {
      const config = loadConfig();
      const reviews = await analyzeAccount(new AwsIamender(config), config.localMode);
      sendJson(response, 200, { reviews, generatedAt: new Date().toISOString(), mode: config.localMode ? "localstack" : "aws" });
    } catch (error) {
      sendJson(response, 500, { error: error instanceof Error ? error.message : "Unable to analyze IAM permissions." });
    }
    return;
  }
  if (request.method === "GET" && path === "/api/trueforge/status") {
    try {
      sendJson(response, 200, await trueForgeStatus());
    } catch (error) {
      sendJson(response, 503, { error: error instanceof Error ? error.message : "TrueForge is unavailable." });
    }
    return;
  }
  if (request.method === "GET" && path === "/api/approvals") {
    const findingId = url.searchParams.get("findingId");
    if (!findingId) { sendJson(response, 400, { error: "findingId is required." }); return; }
    sendJson(response, 200, { approval: getApproval(findingId) });
    return;
  }
  if (request.method === "POST" && path === "/api/approvals") {
    try {
      const body = await readBody(request);
      const config = loadConfig();
      const review = (await analyzeAccount(new AwsIamender(config), config.localMode)).find((item) => item.id === body.findingId);
      if (!review) throw new Error("That IAMender finding no longer exists. Refresh and try again.");
      sendJson(response, 201, { approval: requestApproval(review) });
    } catch (error) {
      sendJson(response, 400, { error: error instanceof Error ? error.message : "Unable to request approval." });
    }
    return;
  }
  const decisionMatch = path.match(/^\/api\/approvals\/([^/]+)\/decision$/);
  if (request.method === "POST" && decisionMatch) {
    try {
      const body = await readBody(request) as { action?: "approve" | "reject"; findingId?: string };
      if (body.action !== "approve" && body.action !== "reject") throw new Error("Use approve or reject for this guarded review.");
      const config = loadConfig();
      const findingId = decodeURIComponent(decisionMatch[1]);
      const review = (await analyzeAccount(new AwsIamender(config), config.localMode)).find((item) => item.id === findingId);
      if (!review) throw new Error("That IAMender finding no longer exists. Refresh and try again.");
      sendJson(response, 200, { approval: await decideApproval(review, body.action, new AwsIamender(config)) });
    } catch (error) {
      sendJson(response, 400, { error: error instanceof Error ? error.message : "Unable to record the approval decision." });
    }
    return;
  }
  if (request.method === "POST" && path === "/api/trueforge/approval-sessions") {
    try {
      const body = await readBody(request);
      if (!body.findingId) throw new Error("A findingId is required to open an approval review.");
      const config = loadConfig();
      const reviews = await analyzeAccount(new AwsIamender(config), config.localMode);
      const review = reviews.find((item) => item.id === body.findingId);
      if (!review) throw new Error("That IAMender finding no longer exists. Refresh the review and try again.");
      if (review.status !== "ready_for_approval") throw new Error("This finding needs more evidence before it can enter a TrueForge approval review.");
      sendJson(response, 201, await createApprovalSession(review));
    } catch (error) {
      sendJson(response, 400, { error: error instanceof Error ? error.message : "Unable to create a TrueForge approval review." });
    }
    return;
  }
  sendJson(response, 404, { error: "Not found" });
}).listen(port, "127.0.0.1", () => {
  console.log(`IAMender API listening at http://127.0.0.1:${port}`);
});
