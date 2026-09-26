# IAMender — Judge Demo Script

**Suggested length:** 6–8 minutes  
**Demo goal:** show a risky IAM policy becoming a verified, least-privilege policy only after a human approval.

## Before the judges arrive

Have these running and visible only when useful:

- IAMender frontend: `http://localhost:5173`
- TrueForge: `http://localhost:8790`
- LocalStack IAM sandbox

In IAMender, click **Check services**. All three indicators should be ready: LocalStack, IAMender tools, and TrueForge. Keep `IAMENDER_ALLOW_WRITE=false` until immediately before the final approved apply run.

## 1. Opening — the problem (0:00–0:40)

**Show:** IAMender home page.

**Say:**

> IAM permissions tend to grow over time. A role gets `AdministratorAccess` for a temporary deployment, a Lambda gets `s3:*` while someone is debugging, and those permissions remain long after the original need disappears.
>
> The hard part is not detecting a wildcard. The hard part is answering: “Can I remove it without breaking production?” Teams often leave risky permissions untouched because they cannot safely answer that question.
>
> IAMender is an agent that turns that question into an evidence-backed, human-approved, reversible IAM change.

## 2. Show the risk queue (0:40–1:25)

**Show:** the three cards in the priority queue.

**Say:**

> IAMender begins by scanning identities and ranking findings rather than presenting a flat policy dump. In this sandbox it found three different categories of risk.
>
> First, `ci-deploy-role` has administrator-like authority. Second, `lambda-report-role` has broad S3 access. Third, `legacy-export-role` is a dormant identity that needs a retirement review.

### What counts as risky?

**Say:**

> We use two kinds of signals: policy risk signals and workload evidence.
>
> At scan time, IAMender flags `Action: "*"` with `Resource: "*"`, service wildcards such as `s3:*` on `*`, administrator policies, and roles with no recorded recent use. These are risk signals, not automatic deletion decisions.
>
> The agent only proposes a least-privilege rewrite when it has evidence of what the workload actually needs.

## 3. Demonstrate refusal when evidence is weak (1:25–1:55)

**Action:** click `ci-deploy-role`.

**Say:**

> This CI role can create unrelated infrastructure, so its security and spend risk are high. But IAMender does not pretend to know the correct replacement policy. Without observed deployment actions or a CI workload contract, it marks this as **Needs evidence**.
>
> This is intentional. A good security agent must know when not to act.

## 4. Select the actionable Lambda finding (1:55–3:05)

**Action:** click `lambda-report-role`.

**Say:**

> This is the remediation candidate. The current attached policy is `s3:*` on `*`: every S3 action against every bucket.
>
> IAMender connects the role to `iamender-report-lambda`, then reads the workload contract. The Lambda declares one bucket, `iamender-reports`, and two required operations: `s3:ListBucket` and `s3:GetObject`.
>
> The comparison is simple and explainable: the current policy grants every S3 operation everywhere; the workload evidence supports only listing one bucket and reading its objects.

**Point to:** Evidence Profile, Policy Delta, Permission Surface, and blast-radius cards.

**Say:**

> The score is not a mysterious model decision. In our demo, the high security score comes from the wildcard S3 policy; spend authority measures whether the role can create or modify costly infrastructure; and evidence confidence comes from the role-to-Lambda relationship plus the explicit bucket and action contract.
>
> The policy delta makes the proposed change reviewable: these are the permissions we retain, and these are the writes, deletes, and cross-bucket permissions we remove.

## 5. Explain the inputs and production-grade criteria (3:05–3:45)

**Say:**

> In this LocalStack demo, IAMender uses the attached managed policy, its default policy version, the role ARN, the Lambda role relationship, the Lambda environment contract, and the declared bucket and required actions.
>
> In a real AWS account, we extend that evidence with IAM Access Analyzer validation, IAM service-last-accessed data, CloudTrail API history, IAM Policy Simulator results, resource tags, permission boundaries, and workload ownership metadata.
>
> The rule is: a wildcard is a reason to investigate. It becomes a removable permission only when the evidence supports a narrower replacement.

## 6. Explain the blast radius (3:45–4:20)

**Point to:** Keeps Working, What Changes, Watch For.

**Say:**

> The blast-radius brief is the heart of IAMender. It answers the reviewer’s real questions in plain language.
>
> The Lambda will keep listing and reading reports from `iamender-reports`. It will lose upload, delete, and access to other buckets. The remaining uncertainty is an unrecorded future upload or delete path.
>
> We do not hide that uncertainty. We surface it before a person approves anything.

## 7. Explain the safety boundary and TrueForge trace (4:20–5:20)

**Action:** point to the service status and click **Review approval run**. Move to the TrueForge session.

**Say:**

> The IAMender frontend is the reviewer’s decision workspace. TrueForge is the execution and approval layer.
>
> This is the TrueForge execution trace — not an application error stack trace. It records the agent’s tool calls and makes the process inspectable: scan IAM, analyze evidence, validate the proposed document, simulate the permitted and denied actions, and verify the Lambda.
>
> The agent can use read-only tools freely. It cannot silently change IAM. The write tool, `apply_policy_version`, is classified as destructive and requires a native TrueForge human approval.

**If the agent is waiting for a clear instruction, say/type in TrueForge:**

> I have reviewed the proposed scoped S3 policy for lambda-report-role. Apply exactly that policy version and nothing else.

## 8. Human approval and policy apply (5:20–6:10)

**Action:** show the pending `apply_policy_version` call and its exact policy document. Enable the short approved LocalStack write run only at this moment, then click **Allow** in TrueForge.

**Say before clicking Allow:**

> This is the last control point. The reviewer sees the exact target policy ARN and the exact replacement document. Only this policy is in scope; no other role, bucket, or account can be modified by this run.
>
> Iamender creates a new IAM policy version rather than overwriting history. The old version remains available for rollback.

**Action:** click **Allow**.

**Say:**

> The human approval has now authorized one scoped policy-version change. IAMender applies it and then verifies the report Lambda still works.

## 9. Verify and show the changed frontend state (6:10–6:55)

**Action:** return to IAMender, click **Refresh live data**, select `lambda-report-role`.

**Say:**

> IAMender has re-read the live policy. The finding has changed from a high-risk wildcard to **Least-privilege policy is active**.
>
> We can see the two permissions now in effect: list this bucket and read objects in this bucket. The Lambda verification passed, and the earlier policy version remains rollback-ready.

## 10. Close (6:55–7:20)

**Say:**

> IAMender does not just identify risky IAM. It closes the full loop: find the risk, gather evidence, draft the smallest safe policy, explain the blast radius, wait for human approval, apply a reversible versioned change, and verify the workload.
>
> That is how IAM cleanup becomes something a platform or security team can actually approve instead of postpone.

## Technical Q&A cheat sheet

### “What exact parameters does IAMender inspect?”

> The key inputs are the role ARN and trust relationship, attached managed and inline policies, policy-version documents, actions, resources, effects, conditions, permission boundaries, role-last-used data, workload-to-role attachments, Lambda environment configuration, declared resource contracts, CloudTrail events, service-last-accessed data, Access Analyzer results, and policy simulation results.

### “How are the risk scores decided?”

> Security risk increases for administrator scope, action/resource wildcards, cross-service authority, sensitive-resource reach, and dormant identities. Spend authority increases for permissions that can create, resize, or run chargeable infrastructure. Evidence confidence increases when observed usage, a workload contract, resource scope, and simulation all agree. A score supports prioritisation; it never replaces the approval gate.

### “What does OpenAI do?”

> OpenAI turns structured IAM evidence into a readable least-privilege proposal and blast-radius brief. AWS and IAMender validate the policy structure and simulation inputs. The model cannot independently write IAM; TrueForge requires human approval before the destructive tool executes.

### “Why LocalStack?”

> It gives us a safe, reproducible AWS-like sandbox where we can demonstrate real IAM policy versions, Lambda invocation, and rollback without touching a customer account. In production, the same agent uses real AWS APIs and adds CloudTrail, Access Analyzer, and IAM Policy Simulator evidence.

### “What happens if the evidence is incomplete?”

> IAMender labels the finding `Needs evidence` and does not draft or apply a rewrite. The CI role in this demo demonstrates that behaviour.

### “How does rollback work?”

> IAMender retains the old customer-managed policy version. A rollback sets that earlier version as default, and it goes through the same TrueForge human approval gate.
