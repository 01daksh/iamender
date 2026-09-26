import { readFile } from "node:fs/promises";
import { CreatePolicyCommand, CreateRoleCommand, GetPolicyCommand, GetRoleCommand, IAMClient, AttachRolePolicyCommand } from "@aws-sdk/client-iam";
import { CreateBucketCommand, HeadBucketCommand, S3Client } from "@aws-sdk/client-s3";
import { CreateFunctionCommand, GetFunctionCommand, LambdaClient, UpdateFunctionConfigurationCommand } from "@aws-sdk/client-lambda";
import { loadConfig } from "../agent/config.js";

const accountId = "000000000000";
const bucket = "iamender-reports";
const lambdaName = "iamender-report-lambda";
const trustPolicy = JSON.stringify({
  Version: "2012-10-17",
  Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }],
});

const policies = [
  {
    name: "IamenderLambdaReportBroadS3",
    role: "lambda-report-role",
    document: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "s3:*", Resource: "*" }] },
  },
  {
    name: "IamenderCiDeployAdminLike",
    role: "ci-deploy-role",
    document: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] },
  },
  {
    name: "IamenderLegacyExportRead",
    role: "legacy-export-role",
    document: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: ["s3:GetObject", "s3:ListBucket"], Resource: ["arn:aws:s3:::iamender-reports", "arn:aws:s3:::iamender-reports/*"] }] },
  },
];

async function exists(check: () => Promise<unknown>) {
  try { await check(); return true; } catch { return false; }
}

async function main() {
  const config = loadConfig();
  if (!config.localMode || !config.endpointUrl) throw new Error("Seeding is allowed only in explicit LocalStack mode.");
  const options = { region: config.region, endpoint: config.endpointUrl, credentials: { accessKeyId: "localstack", secretAccessKey: "localstack" } };
  const iam = new IAMClient(options);
  const s3 = new S3Client({ ...options, forcePathStyle: true });
  const lambda = new LambdaClient(options);

  if (!await exists(() => s3.send(new HeadBucketCommand({ Bucket: bucket })))) await s3.send(new CreateBucketCommand({ Bucket: bucket }));

  for (const item of policies) {
    const policyArn = `arn:aws:iam::${accountId}:policy/${item.name}`;
    if (!await exists(() => iam.send(new GetPolicyCommand({ PolicyArn: policyArn })))) {
      await iam.send(new CreatePolicyCommand({ PolicyName: item.name, PolicyDocument: JSON.stringify(item.document) }));
    }
    if (!await exists(() => iam.send(new GetRoleCommand({ RoleName: item.role })))) {
      await iam.send(new CreateRoleCommand({ RoleName: item.role, AssumeRolePolicyDocument: trustPolicy }));
    }
    await iam.send(new AttachRolePolicyCommand({ RoleName: item.role, PolicyArn: policyArn }));
  }

  if (!await exists(() => lambda.send(new GetFunctionCommand({ FunctionName: lambdaName })))) {
    const code = await readFile(".localstack-artifacts/iamender-report-lambda.zip");
    await lambda.send(new CreateFunctionCommand({
      FunctionName: lambdaName,
      Runtime: "nodejs22.x",
      Handler: "index.handler",
      Role: `arn:aws:iam::${accountId}:role/lambda-report-role`,
      Code: { ZipFile: code },
      Environment: { Variables: { REPORTS_BUCKET: bucket, IAMENDER_REQUIRED_ACTIONS: "s3:GetObject,s3:ListBucket" } },
      Timeout: 10,
    }));
  }
  await lambda.send(new UpdateFunctionConfigurationCommand({
    FunctionName: lambdaName,
    Environment: { Variables: { REPORTS_BUCKET: bucket, IAMENDER_REQUIRED_ACTIONS: "s3:GetObject,s3:ListBucket" } },
  }));

  console.log(JSON.stringify({ endpoint: config.endpointUrl, bucket, lambdaName, roles: policies.map(({ role }) => role), targetPolicyArn: `arn:aws:iam::${accountId}:policy/IamenderLambdaReportBroadS3` }, null, 2));
}

main().catch((error: unknown) => { console.error(error instanceof Error ? error.message : error); process.exitCode = 1; });
