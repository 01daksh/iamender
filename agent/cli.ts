import { readFile } from "node:fs/promises";
import { loadConfig, requireApprovedWrite } from "./config.js";
import { AwsIamender, type PolicyDocument } from "./aws.js";
import { analyzeAccount } from "./review.js";

const [command, ...args] = process.argv.slice(2);

function flag(name: string) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

async function readPolicy(path: string | undefined): Promise<PolicyDocument> {
  if (!path) throw new Error("Pass --policy path/to/proposed-policy.json");
  return JSON.parse(await readFile(path, "utf8")) as PolicyDocument;
}

async function main() {
  const config = loadConfig();
  const aws = new AwsIamender(config);

  if (command === "identity") console.log(JSON.stringify(await aws.identity(), null, 2));
  else if (command === "scan") console.log(JSON.stringify(await aws.scanRoles(), null, 2));
  else if (command === "analyze") console.log(JSON.stringify(await analyzeAccount(aws, config.localMode), null, 2));
  else if (command === "validate") console.log(JSON.stringify(await aws.validate(await readPolicy(flag("--policy"))), null, 2));
  else if (command === "simulate") {
    const actions = (flag("--actions") ?? "").split(",").filter(Boolean);
    const resources = (flag("--resources") ?? "*").split(",").filter(Boolean);
    console.log(JSON.stringify(await aws.simulate(await readPolicy(flag("--policy")), actions, resources), null, 2));
  } else if (command === "apply") {
    const policyArn = flag("--policy-arn");
    if (!policyArn) throw new Error("Pass --policy-arn");
    requireApprovedWrite(config, flag("--approval-id"), policyArn);
    console.log(JSON.stringify(await aws.createApprovedPolicyVersion(policyArn, await readPolicy(flag("--policy"))), null, 2));
  } else if (command === "rollback") {
    const policyArn = flag("--policy-arn");
    const versionId = flag("--version-id");
    if (!policyArn || !versionId) throw new Error("Pass --policy-arn and --version-id");
    requireApprovedWrite(config, flag("--approval-id"), policyArn);
    console.log(JSON.stringify(await aws.rollback(policyArn, versionId), null, 2));
  } else if (command === "verify-lambda") {
    const functionName = flag("--function-name");
    if (!functionName) throw new Error("Pass --function-name");
    console.log(JSON.stringify(await aws.verifyLambda(functionName, {}), null, 2));
  } else {
    throw new Error("Commands: identity, scan, analyze, validate, simulate, apply, rollback, verify-lambda");
  }
}

main().catch((error: unknown) => { console.error(error instanceof Error ? error.message : error); process.exitCode = 1; });
