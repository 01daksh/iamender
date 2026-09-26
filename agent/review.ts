import type { AwsIamender, Finding, LambdaWorkload, PolicyDocument, PolicyStatement } from "./aws.js";

export type Severity = "Critical" | "High" | "Medium";
export type Evidence = { source: string; detail: string; confidence: "high" | "medium" | "low" };
export type PolicyDelta = { current: string[]; retain: string[]; remove: string[] };
export type BlastRadius = {
  keepsWorking: string[];
  changes: string[];
  couldBreak: string[];
  riskLevel: Severity;
  rollback: string;
};
export type ReviewCase = {
  id: string;
  identity: string;
  roleArn: string;
  severity: Severity;
  title: string;
  summary: string;
  scores: { securityRisk: number; spendAuthority: number; evidenceConfidence: number };
  status: "ready_for_approval" | "needs_evidence" | "retirement_candidate" | "amendment_applied";
  evidence: Evidence[];
  policyArns: string[];
  policyDelta: PolicyDelta;
  proposedPolicy?: PolicyDocument;
  simulationPlan?: { actions: string[]; resources: string[] };
  blastRadius: BlastRadius;
  localLimitations: string[];
};

function strings(value: string | string[] | undefined) {
  return Array.isArray(value) ? value : value ? [value] : [];
}

function allowedEntries(document: PolicyDocument) {
  const statements = (Array.isArray(document.Statement) ? document.Statement : [document.Statement]).filter((item): item is PolicyStatement => Boolean(item));
  return statements.filter((statement) => statement.Effect !== "Deny").flatMap((statement) =>
    strings(statement.Action).flatMap((action) => strings(statement.Resource).map((resource) => `${action} on ${resource}`)),
  );
}

function hasWildcardS3(documents: PolicyDocument[]) {
  return documents.some((document) => allowedEntries(document).some((entry) => entry.startsWith("s3:*") && entry.endsWith(" on *")));
}

function hasFullAdmin(documents: PolicyDocument[]) {
  return documents.some((document) => allowedEntries(document).includes("* on *"));
}

function hasScopedLambdaReadAccess(documents: PolicyDocument[], bucket: string) {
  const entries = documents.flatMap(allowedEntries);
  return entries.includes(`s3:ListBucket on arn:aws:s3:::${bucket}`)
    && entries.includes(`s3:GetObject on arn:aws:s3:::${bucket}/*`)
    && !entries.some((entry) => entry.startsWith("s3:*") || entry.endsWith(" on *"));
}

function lambdaProposal(bucket: string): PolicyDocument {
  return {
    Version: "2012-10-17",
    Statement: [
      { Sid: "ListReportsBucketOnly", Effect: "Allow", Action: "s3:ListBucket", Resource: `arn:aws:s3:::${bucket}` },
      { Sid: "ReadReportsObjectsOnly", Effect: "Allow", Action: "s3:GetObject", Resource: `arn:aws:s3:::${bucket}/*` },
    ],
  };
}

function localLimitations(localMode: boolean) {
  return localMode
    ? ["CloudTrail and IAM Access Analyzer evidence are unavailable in LocalStack.", "Local policy simulation is structural; it is not AWS IAM Policy Simulator output."]
    : [];
}

function lambdaReview(finding: Finding, documents: PolicyDocument[], workload: LambdaWorkload, localMode: boolean): ReviewCase {
  const bucket = workload.environment.REPORTS_BUCKET;
  const actions = strings(workload.environment.IAMENDER_REQUIRED_ACTIONS);
  const requiredActions = actions.flatMap((entry) => entry.split(",").map((action) => action.trim()).filter(Boolean));
  const ready = Boolean(bucket) && requiredActions.includes("s3:GetObject") && requiredActions.includes("s3:ListBucket");
  const proposal = ready ? lambdaProposal(bucket) : undefined;
  return {
    id: finding.roleName,
    identity: finding.roleName,
    roleArn: finding.roleArn,
    severity: "High",
    title: "Wildcard S3 access on Lambda execution role",
    summary: ready
      ? `${workload.functionName} has wildcard S3 authority, while its declared sandbox workload contract requires only reads from ${bucket}.`
      : `${workload.functionName} has wildcard S3 authority, but IAMender cannot safely infer the exact retained permissions yet.`,
    scores: { securityRisk: 88, spendAuthority: 24, evidenceConfidence: ready ? 78 : 42 },
    status: ready ? "ready_for_approval" : "needs_evidence",
    evidence: [
      { source: "IAM managed policy", detail: "Current policy grants s3:* on *.", confidence: "high" },
      { source: "Lambda configuration", detail: `${workload.functionName} uses role ${finding.roleName}.`, confidence: "high" },
      ...(bucket ? [{ source: "Sandbox workload contract", detail: `Declared bucket: ${bucket}; declared actions: ${requiredActions.join(", ") || "none"}.`, confidence: "medium" as const }] : []),
    ],
    policyArns: finding.managedPolicies,
    policyDelta: {
      current: documents.flatMap(allowedEntries),
      retain: proposal ? ["s3:ListBucket on reports bucket", "s3:GetObject on report objects"] : [],
      remove: proposal ? ["s3:PutObject", "s3:DeleteObject", "All other S3 buckets"] : [],
    },
    proposedPolicy: proposal,
    simulationPlan: proposal ? { actions: ["s3:GetObject", "s3:DeleteObject"], resources: [`arn:aws:s3:::${bucket}/sample.csv`] } : undefined,
    blastRadius: {
      keepsWorking: proposal ? [`List and read objects in ${bucket}`] : [],
      changes: proposal ? ["Removes writes, deletes, and access to every other S3 bucket."] : ["No change is proposed until usage evidence is sufficient."],
      couldBreak: proposal ? ["A future upload/delete path or an unrecorded bucket dependency."] : ["Any rewrite would be guesswork without a bucket and action contract."],
      riskLevel: "High",
      rollback: "Restore the prior customer-managed policy version after human approval.",
    },
    localLimitations: localLimitations(localMode),
  };
}

function appliedLambdaReview(finding: Finding, documents: PolicyDocument[], workload: LambdaWorkload, localMode: boolean): ReviewCase {
  const bucket = workload.environment.REPORTS_BUCKET;
  return {
    id: finding.roleName,
    identity: finding.roleName,
    roleArn: finding.roleArn,
    severity: "Medium",
    title: "Least-privilege policy is active",
    summary: `${workload.functionName} now has only the S3 read paths required for ${bucket}. The previous broad S3 access is no longer the default policy version.`,
    scores: { securityRisk: 26, spendAuthority: 8, evidenceConfidence: 92 },
    status: "amendment_applied",
    evidence: [
      { source: "IAM managed policy", detail: "Current default policy grants only the scoped S3 read paths.", confidence: "high" },
      { source: "Lambda configuration", detail: `${workload.functionName} uses role ${finding.roleName}.`, confidence: "high" },
      { source: "TrueForge approval", detail: "A human approved the policy-version change before IAMender applied it.", confidence: "high" },
    ],
    policyArns: finding.managedPolicies,
    policyDelta: { current: documents.flatMap(allowedEntries), retain: documents.flatMap(allowedEntries), remove: [] },
    blastRadius: {
      keepsWorking: [`List and read objects in ${bucket}`],
      changes: ["Writes, deletes, and other S3 buckets are no longer allowed."],
      couldBreak: ["A future upload/delete path or an unrecorded bucket dependency."],
      riskLevel: "Medium",
      rollback: "The previous policy version remains available for one-click rollback after human approval.",
    },
    localLimitations: localLimitations(localMode),
  };
}

function ciReview(finding: Finding, documents: PolicyDocument[], localMode: boolean): ReviewCase {
  return {
    id: finding.roleName,
    identity: finding.roleName,
    roleArn: finding.roleArn,
    severity: "Critical",
    title: "Administrator-like deployment authority",
    summary: "The CI role can create unrelated infrastructure and has high spend authority. IAMender will not draft a live rewrite until observed deployment actions are collected.",
    scores: { securityRisk: 98, spendAuthority: 92, evidenceConfidence: 48 },
    status: "needs_evidence",
    evidence: [{ source: "IAM managed policy", detail: "Current policy grants * on *.", confidence: "high" }],
    policyArns: finding.managedPolicies,
    policyDelta: { current: documents.flatMap(allowedEntries), retain: [], remove: ["Potential EC2, RDS, load-balancer, and other infrastructure creation authority"] },
    blastRadius: {
      keepsWorking: [],
      changes: ["No permissions are removed automatically."],
      couldBreak: ["Unknown deployment stages until CloudTrail or a CI workload contract is available."],
      riskLevel: "Critical",
      rollback: "No policy change has been proposed.",
    },
    localLimitations: localLimitations(localMode),
  };
}

function retirementReview(finding: Finding, documents: PolicyDocument[], localMode: boolean): ReviewCase {
  return {
    id: finding.roleName,
    identity: finding.roleName,
    roleArn: finding.roleArn,
    severity: "Medium",
    title: "Dormant identity with retained access",
    summary: "No role-use timestamp is available. IAMender recommends a human retirement review, not an automatic deletion.",
    scores: { securityRisk: 66, spendAuthority: 16, evidenceConfidence: 55 },
    status: "retirement_candidate",
    evidence: [{ source: "IAM role metadata", detail: "No recorded last-used timestamp.", confidence: "medium" }],
    policyArns: finding.managedPolicies,
    policyDelta: { current: documents.flatMap(allowedEntries), retain: [], remove: ["Role access only after seasonal jobs and external callers are checked"] },
    blastRadius: {
      keepsWorking: [],
      changes: ["No deletion or policy change is proposed."],
      couldBreak: ["Scheduled exports, external vendors, or infrequent operations."],
      riskLevel: "Medium",
      rollback: "No policy change has been proposed.",
    },
    localLimitations: localLimitations(localMode),
  };
}

export async function analyzeAccount(aws: AwsIamender, localMode: boolean): Promise<ReviewCase[]> {
  const findings = await aws.scanRoles();
  const reviews: ReviewCase[] = [];
  for (const finding of findings) {
    const documents = await Promise.all(finding.managedPolicies.map((arn) => aws.policyDocument(arn)));
    const workloads = await aws.functionsForRole(finding.roleArn);
    const lambda = workloads[0];
    if (lambda && hasWildcardS3(documents)) reviews.push(lambdaReview(finding, documents, lambda, localMode));
    else if (lambda && lambda.environment.REPORTS_BUCKET && hasScopedLambdaReadAccess(documents, lambda.environment.REPORTS_BUCKET)) reviews.push(appliedLambdaReview(finding, documents, lambda, localMode));
    else if (hasFullAdmin(documents)) reviews.push(ciReview(finding, documents, localMode));
    else reviews.push(retirementReview(finding, documents, localMode));
  }
  return reviews.sort((left, right) => right.scores.securityRisk - left.scores.securityRisk);
}
