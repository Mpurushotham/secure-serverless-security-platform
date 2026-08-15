#!/usr/bin/env node
import { App, Aspects, Tags } from "aws-cdk-lib";
import { AwsSolutionsChecks, NagSuppressions } from "cdk-nag";
import { RetentionDays } from "aws-cdk-lib/aws-logs";
import {
  NoWildcardIamAspect,
  RequireApiAuthorizerAspect,
  RequireDeadLetterQueueAspect,
  RequireLogRetentionAspect,
  RequireReservedConcurrencyAspect,
  RequireTableCustomerKeyAspect,
} from "@ssp/cdk-security";

import { OrdersApiStack } from "../lib/orders-api-stack";

const app = new App();

// Deployment is a deliberate act. Keying off CDK_DEFAULT_ACCOUNT would mean any
// developer with an AWS session pins the stack, triggers an availability-zone
// lookup, and writes the account id into a committed cdk.context.json — which
// is exactly what happened once in infra/cdk. Nothing in the toolchain sets
// SSP_DEPLOY_ACCOUNT.
const deployAccount = app.node.tryGetContext("account") ?? process.env.SSP_DEPLOY_ACCOUNT;
const deployRegion =
  app.node.tryGetContext("region") ?? process.env.SSP_DEPLOY_REGION ?? "eu-north-1";

const stack = new OrdersApiStack(app, "OrdersApiStack", {
  logRetention: RetentionDays.THREE_MONTHS,
  env: deployAccount ? { account: deployAccount, region: deployRegion } : undefined,
});

Tags.of(app).add("Workload", "orders-api");
Tags.of(app).add("ManagedBy", "cdk");

// Each exemption is a named decision. The actions listed genuinely cannot be
// resource-scoped: a log group's ARN does not exist when CreateLogGroup is
// called, and X-Ray's PutTraceSegments has no resource dimension at all.
Aspects.of(app).add(
  new NoWildcardIamAspect([
    "OrdersFunction/ServiceRole/DefaultPolicy",
    "LogRetention",
  ]),
);
Aspects.of(app).add(new RequireLogRetentionAspect(RetentionDays.THREE_MONTHS));
Aspects.of(app).add(new RequireApiAuthorizerAspect());
Aspects.of(app).add(new RequireReservedConcurrencyAspect(["LogRetention"]));
Aspects.of(app).add(new RequireTableCustomerKeyAspect());
Aspects.of(app).add(new RequireDeadLetterQueueAspect());
Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

NagSuppressions.addStackSuppressions(stack, [
  {
    id: "AwsSolutions-IAM4",
    reason:
      "AWSLambdaBasicExecutionRole is the managed policy for CloudWatch Logs write. " +
      "Replacing it with an inline equivalent produces the same permissions with more " +
      "code to keep correct, and no narrowing is available: a log group ARN does not " +
      "exist at the moment CreateLogGroup is called.",
  },
  {
    id: "AwsSolutions-IAM5",
    reason:
      "Wildcards remaining after NoWildcardIamAspect are the CDK-generated grants for " +
      "the table's own ARN suffix (index access) and X-Ray, which has no resource " +
      "dimension. The aspect's exemption list names each path.",
  },
  {
    id: "AwsSolutions-APIG2",
    reason:
      "Request validation IS configured, on the POST method that accepts a body. " +
      "cdk-nag checks for a stage-level setting that does not express per-method " +
      "validators.",
  },
  {
    id: "AwsSolutions-COG2",
    reason:
      "MFA is REQUIRED on the user pool with OTP as the only second factor. SMS is " +
      "disabled deliberately — SIM-swap makes it the weakest widely-deployed factor.",
  },
  {
    id: "AwsSolutions-SQS3",
    reason:
      "WorkerDlq IS the dead-letter queue. RequireDeadLetterQueueAspect exempts queues " +
      "whose id ends in Dlq for the same reason: a DLQ for a DLQ is infinite regress.",
  },
  {
    id: "AwsSolutions-L1",
    reason:
      "Pinned to NODEJS_22_X rather than tracking latest. A runtime that changes under " +
      "a deploy is a change nobody reviewed; upgrades are a deliberate PR, and the " +
      "deprecated-runtime finding in platform/00-discovery catches drift.",
  },
]);
