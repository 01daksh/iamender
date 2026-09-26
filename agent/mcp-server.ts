import express from "express";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { AwsIamender, type PolicyDocument } from "./aws.js";
import { loadConfig, requireApprovedWrite } from "./config.js";
import { analyzeAccount } from "./review.js";

const port = Number(process.env.IAMENDER_MCP_PORT ?? 8788);
const toText = (value: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] });

async function callTool(name: string, args: Record<string, unknown>) {
  const config = loadConfig();
  const aws = new AwsIamender(config);
  if (name === "scan_iam") return aws.scanRoles();
  if (name === "analyze_findings") return analyzeAccount(aws, config.localMode);
  if (name === "validate_policy") return aws.validate(args.policyDocument as PolicyDocument);
  if (name === "simulate_policy") return aws.simulate(args.policyDocument as PolicyDocument, args.actions as string[], args.resources as string[]);
  if (name === "verify_lambda") return aws.verifyLambda(String(args.functionName), {});
  if (name === "apply_policy_version") {
    const policyArn = String(args.policyArn);
    requireApprovedWrite(config, "trueforge:native-tool-approval", policyArn);
    return aws.createApprovedPolicyVersion(policyArn, args.policyDocument as PolicyDocument);
  }
  if (name === "rollback_policy_version") {
    const policyArn = String(args.policyArn);
    requireApprovedWrite(config, "trueforge:native-tool-approval", policyArn);
    return aws.rollback(policyArn, String(args.previousVersionId));
  }
  throw new Error(`Unknown IAMender tool: ${name}`);
}

function createIamenderMcp() {
  const server = new McpServer({ name: "iamender-tools", version: "0.1.0" });
  const readOnly = { readOnlyHint: true, destructiveHint: false };
  const destructive = { readOnlyHint: false, destructiveHint: true, idempotentHint: false };
  server.registerTool("scan_iam", { description: "Read IAM roles and identify wildcard, administrator-like, and dormant access. This never changes IAM.", annotations: readOnly }, async () => toText(await callTool("scan_iam", {})));
  server.registerTool("analyze_findings", { description: "Collect evidence, rank risk and spend authority, draft supported least-privilege proposals, and produce blast-radius briefs. This never changes IAM.", annotations: readOnly }, async () => toText(await callTool("analyze_findings", {})));
  server.registerTool("validate_policy", { description: "Validate a proposed IAM policy. This never changes IAM.", inputSchema: { policyDocument: z.record(z.string(), z.unknown()) }, annotations: readOnly }, async ({ policyDocument }) => toText(await callTool("validate_policy", { policyDocument })));
  server.registerTool("simulate_policy", { description: "Rehearse proposed allow and deny decisions. This never changes IAM.", inputSchema: { policyDocument: z.record(z.string(), z.unknown()), actions: z.array(z.string()), resources: z.array(z.string()) }, annotations: readOnly }, async ({ policyDocument, actions, resources }) => toText(await callTool("simulate_policy", { policyDocument, actions, resources })));
  server.registerTool("verify_lambda", { description: "Invoke the sandbox Lambda verification path. This never changes IAM.", inputSchema: { functionName: z.string() }, annotations: readOnly }, async ({ functionName }) => toText(await callTool("verify_lambda", { functionName })));
  server.registerTool("apply_policy_version", { description: "Create and activate a new version of the designated IAM policy. Requires TrueForge human approval and IAMender write mode.", inputSchema: { policyArn: z.string(), policyDocument: z.record(z.string(), z.unknown()) }, annotations: destructive }, async ({ policyArn, policyDocument }) => toText(await callTool("apply_policy_version", { policyArn, policyDocument })));
  server.registerTool("rollback_policy_version", { description: "Restore an earlier version of the designated IAM policy. Requires TrueForge human approval and IAMender write mode.", inputSchema: { policyArn: z.string(), previousVersionId: z.string() }, annotations: destructive }, async ({ policyArn, previousVersionId }) => toText(await callTool("rollback_policy_version", { policyArn, previousVersionId })));
  return server;
}

const app = express();
app.use(express.json());
const transports = new Map<string, StreamableHTTPServerTransport>();
app.get("/health", (_request, response) => {
  const config = loadConfig();
  response.json({ ok: true, service: "iamender-tools", writeEnabled: config.allowWrite });
});
app.post("/mcp", async (request, response) => {
  try {
    const requestedId = request.headers["mcp-session-id"];
    const sessionId = Array.isArray(requestedId) ? requestedId[0] : requestedId;
    const existing = sessionId ? transports.get(sessionId) : undefined;
    if (existing) {
      await existing.handleRequest(request, response, request.body);
      return;
    }
    if (!sessionId && isInitializeRequest(request.body)) {
      const server = createIamenderMcp();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (createdId) => { transports.set(createdId, transport); },
      });
      server.server.onclose = () => {
        if (transport.sessionId) transports.delete(transport.sessionId);
      };
      await server.connect(transport);
      await transport.handleRequest(request, response, request.body);
      return;
    }
    response.status(400).json({ jsonrpc: "2.0", id: null, error: { code: -32000, message: "A valid MCP session ID is required." } });
  } catch (error) {
    if (!response.headersSent) response.status(500).json({ jsonrpc: "2.0", id: null, error: { code: -32603, message: error instanceof Error ? error.message : "IAMender MCP error" } });
  }
});
app.get("/mcp", async (request, response) => {
  const requestedId = request.headers["mcp-session-id"];
  const sessionId = Array.isArray(requestedId) ? requestedId[0] : requestedId;
  const transport = sessionId ? transports.get(sessionId) : undefined;
  if (!transport) { response.status(400).send("Invalid or missing MCP session ID."); return; }
  await transport.handleRequest(request, response);
});
app.delete("/mcp", async (request, response) => {
  const requestedId = request.headers["mcp-session-id"];
  const sessionId = Array.isArray(requestedId) ? requestedId[0] : requestedId;
  const transport = sessionId ? transports.get(sessionId) : undefined;
  if (!transport) { response.status(400).send("Invalid or missing MCP session ID."); return; }
  await transport.handleRequest(request, response);
});
export function startMcpServer() {
  return app.listen(port, "127.0.0.1", () => console.log(`IAMender MCP listening at http://127.0.0.1:${port}/mcp`));
}

if (process.argv[1]?.endsWith("mcp-server.ts")) startMcpServer();
