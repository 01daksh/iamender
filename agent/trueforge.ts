import "dotenv/config";
import type { ReviewCase } from "./review.js";

const baseUrl = (process.env.IAMENDER_TRUEFORGE_URL ?? "http://localhost:8790").replace(/\/$/, "");
const model = process.env.IAMENDER_TRUEFORGE_MODEL;
const mcpUrl = process.env.IAMENDER_MCP_URL ?? "http://127.0.0.1:8788/mcp";

export async function iamenderToolsStatus() {
  const healthUrl = new URL("/health", mcpUrl);
  try {
    const response = await fetch(healthUrl, { signal: AbortSignal.timeout(2_500) });
    const body = await response.json() as { ok?: boolean; writeEnabled?: boolean };
    return { ready: response.ok && body.ok === true, writeEnabled: body.writeEnabled === true };
  } catch {
    return { ready: false, writeEnabled: false };
  }
}

async function api(path: string, init?: RequestInit) {
  const response = await fetch(`${baseUrl}${path}`, { ...init, headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) } });
  const body = await response.json() as { data?: unknown; error?: { message?: string } };
  if (!response.ok) throw new Error(body.error?.message ?? `TrueForge returned ${response.status}`);
  return body;
}

export async function trueForgeStatus() {
  const models = await api("/api/v1/models") as { data: { name: string }[] };
  const mcp = await iamenderToolsStatus();
  return { url: baseUrl, configuredModel: model ?? null, availableModels: models.data.map((item) => item.name), mcp, ready: Boolean(model && models.data.some((item) => item.name === model) && mcp.ready) };
}

export async function ensureIamenderAgent() {
  const status = await trueForgeStatus();
  if (!status.ready || !model) throw new Error(`TrueForge needs IAMENDER_TRUEFORGE_MODEL. Available models: ${status.availableModels.join(", ") || "none configured"}.`);
  const mcpManifest = { type: "remote", name: "iamender-tools", url: mcpUrl, description: "IAMender local IAM evidence, policy simulation, approved apply, rollback, and Lambda verification tools." };
  const configured = await api("/api/v1/settings/mcp-servers") as { data: { name: string }[] };
  if (!configured.data.some((item) => item.name === "iamender-tools")) await api("/api/v1/settings/mcp-servers", { method: "POST", body: JSON.stringify({ manifest: mcpManifest }) });
  const agents = await api("/api/v1/agents?agent_name=iamender") as { data: { name: string; id: string }[] };
  const existing = agents.data.find((agent) => agent.name === "iamender");
  if (existing) return existing;
  const instructions = "You are IAMender, an IAM safety agent. Analyze before proposing. Never invent observed access. Explain security risk, spend authority, evidence confidence, exact retained and removed access, blast radius, validation, and rollback. Use analyze_findings first. You may call read-only tools freely. Never call apply_policy_version or rollback_policy_version unless the user asks for that exact change after reviewing the evidence. Those tools always require a TrueForge human approval event. In LocalStack mode, state that CloudTrail, Access Analyzer, and AWS policy simulation are unavailable.";
  const created = await api("/api/v1/agents", { method: "POST", body: JSON.stringify({ name: "iamender", description: "Evidence-backed IAM least-privilege review with human-gated policy versions and rollback.", manifest: { model: { name: model, params: { reasoning_effort: "medium" } }, instructions, mcp_servers: [{ name: "iamender-tools", enable_tools: ["@all"], require_approval_for_tools: ["apply_policy_version", "rollback_policy_version"] }] } }) }) as { data: { id: string; name: string } };
  return created.data;
}

export async function createApprovalSession(review: ReviewCase) {
  const tools = await iamenderToolsStatus();
  if (!tools.ready) throw new Error("IAMender tools are offline. Start `npm run agent:server`, wait for the Tool service status to turn ready, then retry.");
  await ensureIamenderAgent();
  const session = await api("/api/v1/sessions", { method: "POST", body: JSON.stringify({ agent: { name: "iamender" }, metadata: { iamenderFinding: review.id, mode: "approval-review" } }) }) as { data: { id: string } };
  await api(`/api/v1/sessions/${session.data.id}/turns`, { method: "POST", body: JSON.stringify({ stream: false, previous_turn_id: "none", input: [{ type: "user.message", content: `The user has reviewed the IAMender finding for ${review.identity} and requests this exact, scoped change. First use analyze_findings. Then validate and simulate the evidence-backed least-privilege proposal for this role. If the proposal is the scoped policy for ${review.policyArns.join(", ")}, call apply_policy_version with exactly that policy ARN and the generated proposed policy document. Do not change any other identity or resource. The destructive tool must pause for TrueForge native human approval; after requesting it, wait for the human decision and report the result.` }] }) });
  return { sessionId: session.data.id, traceUrl: `${baseUrl}/sessions/${encodeURIComponent(session.data.id)}` };
}
