import { AccessAnalyzerClient, ValidatePolicyCommand } from "@aws-sdk/client-accessanalyzer";
import { CloudTrailClient, LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import { IAMClient, CreatePolicyVersionCommand, GetPolicyCommand, GetPolicyVersionCommand, ListAttachedRolePoliciesCommand, ListRolesCommand, SetDefaultPolicyVersionCommand, SimulateCustomPolicyCommand } from "@aws-sdk/client-iam";
import { InvokeCommand, LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import type { IamenderConfig } from "./config.js";

export type PolicyStatement = { Effect?: string; Action?: string | string[]; Resource?: string | string[]; [key: string]: unknown };
export type PolicyDocument = { Version?: string; Statement?: PolicyStatement | PolicyStatement[] };

export type Finding = {
  roleArn: string;
  roleName: string;
  managedPolicies: string[];
  riskSignals: string[];
};

export type LambdaWorkload = {
  functionName: string;
  roleArn: string;
  environment: Record<string, string>;
};

export class AwsIamender {
  private readonly iam: IAMClient;
  private readonly analyzer: AccessAnalyzerClient;
  private readonly cloudTrail: CloudTrailClient;
  private readonly lambda: LambdaClient;
  private readonly sts: STSClient;

  constructor(private readonly config: IamenderConfig) {
    const options = {
      region: config.region,
      endpoint: config.endpointUrl,
      credentials: config.endpointUrl ? { accessKeyId: "localstack", secretAccessKey: "localstack" } : undefined,
    };
    this.iam = new IAMClient(options);
    this.analyzer = new AccessAnalyzerClient(options);
    this.cloudTrail = new CloudTrailClient(options);
    this.lambda = new LambdaClient(options);
    this.sts = new STSClient(options);
  }

  async identity() {
    return this.sts.send(new GetCallerIdentityCommand({}));
  }

  async scanRoles(): Promise<Finding[]> {
    const findings: Finding[] = [];
    let marker: string | undefined;
    do {
      const page = await this.iam.send(new ListRolesCommand({ Marker: marker, MaxItems: 100 }));
      for (const role of page.Roles ?? []) {
        if (!role.Arn || !role.RoleName || role.Path?.startsWith("/aws-service-role/")) continue;
        const attached = await this.iam.send(new ListAttachedRolePoliciesCommand({ RoleName: role.RoleName }));
        const managedPolicies = (attached.AttachedPolicies ?? []).map((policy) => policy.PolicyArn).filter((arn): arn is string => Boolean(arn));
        const riskSignals: string[] = [];
        for (const arn of managedPolicies) {
          if (arn.endsWith(":policy/AdministratorAccess")) riskSignals.push("AdministratorAccess attached");
          try {
            const document = await this.policyDocument(arn);
            const statements = Array.isArray(document.Statement) ? document.Statement : [document.Statement];
            for (const statement of statements) {
              if (!statement) continue;
              const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
              const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
              if (actions.includes("*") && resources.includes("*")) riskSignals.push("Full administrative wildcard policy");
              else if (actions.some((action) => typeof action === "string" && action.endsWith(":*")) && resources.includes("*")) {
                riskSignals.push("Service-wide wildcard access");
              }
            }
          } catch {
            riskSignals.push("Policy document could not be inspected");
          }
        }
        if (!role.RoleLastUsed?.LastUsedDate) riskSignals.push("No recorded role use; review before retirement");
        if (riskSignals.length > 0) findings.push({ roleArn: role.Arn, roleName: role.RoleName, managedPolicies, riskSignals });
      }
      marker = page.IsTruncated ? page.Marker : undefined;
    } while (marker);
    return findings;
  }

  async policyDocument(policyArn: string): Promise<PolicyDocument> {
    const policy = await this.iam.send(new GetPolicyCommand({ PolicyArn: policyArn }));
    const versionId = policy.Policy?.DefaultVersionId;
    if (!versionId) throw new Error(`No default version found for ${policyArn}`);
    const version = await this.iam.send(new GetPolicyVersionCommand({ PolicyArn: policyArn, VersionId: versionId }));
    if (!version.PolicyVersion?.Document) throw new Error(`No policy document found for ${policyArn}`);
    const rawDocument = version.PolicyVersion.Document;
    if (typeof rawDocument === "string") {
      return JSON.parse(decodeURIComponent(rawDocument)) as PolicyDocument;
    }
    return rawDocument as PolicyDocument;
  }

  async validate(document: PolicyDocument) {
    if (this.config.localMode) {
      return {
        findings: [],
        note: "LocalStack mode performs structural validation only. Run this against real AWS for Access Analyzer validation.",
        validJson: typeof document === "object" && Boolean(document.Version) && Boolean(document.Statement),
      };
    }
    return this.analyzer.send(new ValidatePolicyCommand({ policyDocument: JSON.stringify(document), policyType: "IDENTITY_POLICY" }));
  }

  async simulate(document: PolicyDocument, actions: string[], resources: string[]) {
    if (this.config.localMode) {
      const statements = (Array.isArray(document.Statement) ? document.Statement : [document.Statement]).filter((statement): statement is PolicyStatement => Boolean(statement));
      const matches = (patterns: string | string[] | undefined, value: string) => (Array.isArray(patterns) ? patterns : [patterns]).some((pattern) => {
        if (typeof pattern !== "string") return false;
        const expression = `^${pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`;
        return new RegExp(expression, "i").test(value);
      });
      const evaluationResults = actions.flatMap((action) => resources.map((resource) => {
        let allowed = false;
        let explicitlyDenied = false;
        for (const statement of statements) {
          if (!matches(statement.Action, action) || !matches(statement.Resource, resource)) continue;
          if (statement.Effect === "Deny") explicitlyDenied = true;
          if (statement.Effect === "Allow") allowed = true;
        }
        return {
          EvalActionName: action,
          EvalResourceName: resource,
          EvalDecision: explicitlyDenied ? "explicitDeny" : allowed ? "allowed" : "implicitDeny",
        };
      }));
      return {
        EvaluationResults: evaluationResults,
        note: "Local structural simulation. Use AWS IAM Policy Simulator for final cloud validation.",
      };
    }
    return this.iam.send(new SimulateCustomPolicyCommand({ PolicyInputList: [JSON.stringify(document)], ActionNames: actions, ResourceArns: resources }));
  }

  async cloudTrailEvents(roleName: string) {
    if (this.config.localMode) return { Events: [], note: `CloudTrail evidence is unavailable in LocalStack for ${roleName}.` };
    return this.cloudTrail.send(new LookupEventsCommand({ LookupAttributes: [{ AttributeKey: "Username", AttributeValue: roleName }], MaxResults: 50 }));
  }

  async functionsForRole(roleArn: string): Promise<LambdaWorkload[]> {
    const workloads: LambdaWorkload[] = [];
    let marker: string | undefined;
    do {
      const page = await this.lambda.send(new ListFunctionsCommand({ Marker: marker, MaxItems: 50 }));
      for (const fn of page.Functions ?? []) {
        if (!fn.FunctionName || fn.Role !== roleArn) continue;
        workloads.push({ functionName: fn.FunctionName, roleArn, environment: fn.Environment?.Variables ?? {} });
      }
      marker = page.NextMarker;
    } while (marker);
    return workloads;
  }

  async createApprovedPolicyVersion(policyArn: string, document: PolicyDocument) {
    return this.iam.send(new CreatePolicyVersionCommand({ PolicyArn: policyArn, PolicyDocument: JSON.stringify(document), SetAsDefault: true }));
  }

  async rollback(policyArn: string, previousVersionId: string) {
    return this.iam.send(new SetDefaultPolicyVersionCommand({ PolicyArn: policyArn, VersionId: previousVersionId }));
  }

  async verifyLambda(functionName: string, payload: unknown) {
    const result = await this.lambda.send(new InvokeCommand({ FunctionName: functionName, InvocationType: "RequestResponse", Payload: Buffer.from(JSON.stringify(payload)) }));
    const text = result.Payload ? Buffer.from(result.Payload).toString("utf8") : undefined;
    let response: unknown = text;
    try { response = text ? JSON.parse(text) : undefined; } catch { /* Preserve a non-JSON Lambda response as text. */ }
    return { statusCode: result.StatusCode, functionError: result.FunctionError, response };
  }
}
