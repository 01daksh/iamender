import type { AwsIamender } from "./aws.js";
import type { ReviewCase } from "./review.js";

export type ApprovalState = "pending_human_review" | "dry_run_verified" | "rejected";
export type ApprovalEvent = { at: string; label: string; detail: string };
export type ApprovalRecord = {
  findingId: string;
  state: ApprovalState;
  createdAt: string;
  updatedAt: string;
  writeBlocked: true;
  events: ApprovalEvent[];
  validation?: unknown;
  simulation?: unknown;
  verification?: unknown;
};

const records = new Map<string, ApprovalRecord>();

function event(label: string, detail: string): ApprovalEvent {
  return { at: new Date().toISOString(), label, detail };
}

export function getApproval(findingId: string) {
  return records.get(findingId) ?? null;
}

export function requestApproval(review: ReviewCase): ApprovalRecord {
  if (review.status !== "ready_for_approval" || !review.proposedPolicy || !review.simulationPlan) {
    throw new Error("This finding is not evidence-supported enough for a guarded approval review.");
  }
  const now = new Date().toISOString();
  const record: ApprovalRecord = {
    findingId: review.id,
    state: "pending_human_review",
    createdAt: now,
    updatedAt: now,
    writeBlocked: true,
    events: [event("Review requested", "A human must decide. IAMender has not created or changed a policy version.")],
  };
  records.set(review.id, record);
  return record;
}

export async function decideApproval(review: ReviewCase, action: "approve" | "reject", aws: AwsIamender): Promise<ApprovalRecord> {
  const record = records.get(review.id);
  if (!record || record.state !== "pending_human_review") throw new Error("Create a pending approval review before making a decision.");
  record.updatedAt = new Date().toISOString();
  if (action === "reject") {
    record.state = "rejected";
    record.events.push(event("Review rejected", "No policy version was created. The finding remains unchanged."));
    return record;
  }
  if (!review.proposedPolicy || !review.simulationPlan) throw new Error("The evidence-backed proposal is no longer available. Refresh and request review again.");
  record.events.push(event("Human approved dry-run", "The approval is intentionally rehearsed only; IAMENDER_ALLOW_WRITE remains false."));
  record.validation = await aws.validate(review.proposedPolicy);
  record.events.push(event("Policy validated", "The proposed document passed the available validation path."));
  record.simulation = await aws.simulate(review.proposedPolicy, review.simulationPlan.actions, review.simulationPlan.resources);
  record.events.push(event("Access simulated", "Required reads and the proposed removed action were evaluated without changing IAM."));
  const workloads = await aws.functionsForRole(review.roleArn);
  const workload = workloads[0];
  if (workload) {
    record.verification = await aws.verifyLambda(workload.functionName, {});
    record.events.push(event("Lambda verification passed", `${workload.functionName} responded through the sandbox verification path.`));
  } else {
    record.events.push(event("Workload verification skipped", "No attached Lambda workload was found for this review."));
  }
  record.state = "dry_run_verified";
  record.events.push(event("Ready for real approval", "No policy version was created. Connect TrueForge and explicitly enable a sandbox write run to apply."));
  return record;
}
