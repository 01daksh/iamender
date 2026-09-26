import "dotenv/config";

export type IamenderConfig = {
  region: string;
  profile?: string;
  accountId?: string;
  endpointUrl?: string;
  localMode: boolean;
  allowWrite: boolean;
  targetPolicyArn?: string;
};

export function loadConfig(): IamenderConfig {
  const profile = process.env.AWS_PROFILE;
  const endpointUrl = process.env.IAMENDER_AWS_ENDPOINT_URL;
  const localMode = process.env.IAMENDER_LOCAL_MODE === "true";
  const region = process.env.AWS_REGION ?? (localMode ? "us-east-1" : "ap-south-1");

  if (!profile && !endpointUrl) {
    throw new Error("AWS_PROFILE is required. Configure a local SSO/profile; do not use access keys in this project.");
  }

  if (localMode && !endpointUrl) throw new Error("IAMENDER_LOCAL_MODE requires IAMENDER_AWS_ENDPOINT_URL.");

  return {
    profile,
    region,
    accountId: process.env.AWS_ACCOUNT_ID || undefined,
    endpointUrl,
    localMode,
    allowWrite: process.env.IAMENDER_ALLOW_WRITE === "true",
    targetPolicyArn: process.env.IAMENDER_TARGET_POLICY_ARN || undefined,
  };
}

export function requireApprovedWrite(config: IamenderConfig, approvalId: string | undefined, policyArn: string) {
  if (!config.allowWrite) throw new Error("Writes are disabled. Set IAMENDER_ALLOW_WRITE=true only for an approved sandbox run.");
  if (!approvalId) throw new Error("A TrueForge approval ID is required before IAMender can write to AWS.");
  if (!config.targetPolicyArn) throw new Error("IAMENDER_TARGET_POLICY_ARN must be configured for the approved sandbox policy.");
  if (policyArn !== config.targetPolicyArn) throw new Error("IAMender may modify only IAMENDER_TARGET_POLICY_ARN in v1.");
}
