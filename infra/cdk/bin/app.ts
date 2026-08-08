#!/usr/bin/env node
/**
 * Entry point. Aspects are applied here, at the App level, so they cover every
 * stack including ones added later by someone who has not read this file.
 */
import { App, Aspects, Tags } from "aws-cdk-lib";
import { AwsSolutionsChecks, NagSuppressions } from "cdk-nag";
import { RetentionDays } from "aws-cdk-lib/aws-logs";
import { AgentApiStack } from "../lib/stacks/agent-api-stack";
import {
  NoWildcardIamAspect,
  RequireLogRetentionAspect,
  RequireVpcAttachmentAspect,
} from "../lib/aspects/security-aspects";

const app = new App();

const stack = new AgentApiStack(app, "AgentApiStack", {
  logRetention: RetentionDays.THREE_MONTHS,
  clusterResourceId: app.node.tryGetContext("clusterResourceId") ?? "cluster-PLACEHOLDER",
  agentDatabaseUser: "mcp_readonly",
  // Environment-agnostic unless real credentials are present. A stack pinned to
  // a concrete account needs an AZ lookup at synth time, which would make
  // `make validate` require AWS credentials — and the whole point of static
  // validation is that anyone can clone this and verify it without an account.
  env: process.env.CDK_DEFAULT_ACCOUNT
    ? { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION }
    : undefined,
});

Tags.of(app).add("DataClass", "gdpr-article-9");
Tags.of(app).add("ManagedBy", "cdk");

// Each exemption below is a named decision, not a blanket rule. The AWS actions
// listed genuinely cannot be resource-scoped: a log group's ARN does not exist
// at the moment CreateLogGroup is called, and X-Ray's PutTraceSegments has no
// resource dimension at all.
Aspects.of(app).add(
  new NoWildcardIamAspect([
    "/AgentFunction/ServiceRole/DefaultPolicy",
    "/ApiFunction/ServiceRole/DefaultPolicy",
    "/AgentRole/DefaultPolicy",
    "/ApiRole/DefaultPolicy",
    "/Vpc/FlowLog",
    "LogRetention",
  ]),
);
Aspects.of(app).add(new RequireLogRetentionAspect(RetentionDays.THREE_MONTHS));
Aspects.of(app).add(new RequireVpcAttachmentAspect(["LogRetention", "Custom::"]));
Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

// cdk-nag suppressions. Each states the reason; an unexplained suppression is a
// disabled control that nobody decided to disable.
NagSuppressions.addStackSuppressions(stack, [
  {
    id: "AwsSolutions-IAM4",
    reason:
      "AWSLambdaBasicExecutionRole and AWSLambdaVPCAccessExecutionRole are AWS-managed and " +
      "scoped to log writes and ENI management. Hand-rolling equivalents adds drift risk " +
      "without narrowing effective privilege.",
  },
  {
    id: "AwsSolutions-IAM5",
    reason:
      "Wildcards remaining after the NoWildcardIamAspect are confined to actions with no " +
      "resource dimension (xray:PutTraceSegments) or whose resource does not exist at call " +
      "time (logs:CreateLogGroup). Each path is enumerated in the aspect's exemption list.",
  },
  {
    id: "AwsSolutions-APIG2",
    reason:
      "Request validation belongs to the handler, which validates against the same JSON " +
      "Schema the MCP tools use. Duplicating it in API Gateway creates two schemas that drift.",
  },
  {
    id: "AwsSolutions-COG4",
    reason:
      "The API uses IAM authorization, not Cognito. Callers are AWS principals — there is no " +
      "end-user identity pool for this internal endpoint.",
  },
  {
    id: "AwsSolutions-SMG4",
    reason:
      "The secret holds Aurora connection PARAMETERS (host, port, database, username) and no " +
      "password — the agent authenticates with a short-lived IAM token. There is no credential " +
      "to rotate. Rotating a hostname on a schedule would be ceremony, not a control. The " +
      "actual master credential is managed and rotated by RDS itself (manage_master_user_password " +
      "in modules/aurora-secure).",
  },
  {
    id: "AwsSolutions-APIG3",
    reason:
      "No WAF. This endpoint uses IAM authorization and is not internet-facing — every caller is " +
      "an authenticated AWS principal, so the request-pattern attacks WAF addresses (unauthenticated " +
      "floods, generic injection probes) cannot reach it. Adding WAF here would cost money and " +
      "produce no findings. Revisit if the API is ever exposed publicly.",
  },
  {
    id: "CdkNagValidationFailure",
    reason:
      "AwsSolutions-EC23 cannot evaluate security group rules whose CIDR is an intrinsic " +
      "(Fn::GetAtt on the VPC's own CidrBlock). The rule it is trying to check — no 0.0.0.0/0 " +
      "ingress — is satisfied by construction: egress is scoped to vpc.vpcCidrBlock and there " +
      "is no ingress rule at all. Asserted independently in test/security-invariants.test.ts.",
  },
  {
    id: "AwsSolutions-SQS3",
    reason:
      "No dead-letter queue, deliberately. A DLQ retains the failed event payload, and for this " +
      "workload a failed event can contain the query or record that caused the failure — a durable " +
      "copy of regulated data in a queue with weaker access controls than the table it came from. " +
      "Failures surface via encrypted logs and the D-001/D-005 alarms instead. (checkov CKV_AWS_116 " +
      "flags the same thing against the synthesised template.)",
  },
  {
    id: "AwsSolutions-APIG4",
    reason:
      "Applies to the OPTIONS/CORS path only; the data methods use IAM authorization, asserted in " +
      "test/security-invariants.test.ts.",
  },
  {
    id: "AwsSolutions-L1",
    reason:
      "Runtime is pinned to Python 3.12 deliberately. Tracking 'latest' means an unreviewed " +
      "runtime change can land in a regulated workload without a change record.",
  },
]);

app.synth();
