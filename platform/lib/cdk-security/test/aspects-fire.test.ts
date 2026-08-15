/**
 * Proves that each Aspect actually *fires* — not merely that a compliant stack
 * synthesises cleanly.
 *
 * Why this test exists: every Aspect here dispatches on `instanceof`
 * (`node instanceof iam.CfnPolicy`, `node instanceof lambda.CfnFunction`, …).
 * If this package and the consuming app ever resolve to *different* copies of
 * `aws-cdk-lib` or `constructs` — trivially easy to cause with a nested
 * `node_modules`, a `file:` dependency, or a version conflict — every one of
 * those checks silently returns false. The Aspects then visit every node,
 * match nothing, raise nothing, and synth goes green.
 *
 * That is the worst possible failure mode for a security control: it does not
 * break, it evaporates. A passing invariant suite would keep reporting success.
 *
 * So: each test below builds a construct that *must* be rejected, and asserts
 * the rejection. If the packaging ever regresses, these fail while everything
 * else stays green — which is exactly the signal we want.
 */

import { App, Aspects, Stack } from "aws-cdk-lib";
import { Annotations as AssertAnnotations, Match, Template } from "aws-cdk-lib/assertions";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";

import {
  NoWildcardIamAspect,
  RequireApiAuthorizerAspect,
  RequireDeadLetterQueueAspect,
  RequireReservedConcurrencyAspect,
  RequireTableCustomerKeyAspect,
  RequireLogRetentionAspect,
  RequirePermissionBoundaryAspect,
  RequireVpcAttachmentAspect,
} from "../src";

/** Synthesises and returns every error annotation raised on the stack. */
function errorsFrom(stack: Stack): string[] {
  // Match.anyValue(): we assert that an error was raised, not its exact wording.
  // Pinning the message text would make this fail on a copy-edit, which trains
  // people to ignore it.
  const messages = AssertAnnotations.fromStack(stack).findError("*", Match.anyValue());
  return messages.map((m) => JSON.stringify(m.entry.data));
}

describe("aspects are wired and dispatching", () => {
  test("NoWildcardIamAspect rejects Action:*", () => {
    const stack = new Stack(new App(), "WildcardAction");
    new iam.Role(stack, "R", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      inlinePolicies: {
        bad: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              actions: ["*"],
              resources: ["arn:aws:s3:::example/*"],
            }),
          ],
        }),
      },
    });
    Aspects.of(stack).add(new NoWildcardIamAspect());

    const errors = errorsFrom(stack);
    expect(errors.join(" ")).toMatch(/Wildcard IAM action/);
  });

  test("NoWildcardIamAspect rejects Resource:*", () => {
    const stack = new Stack(new App(), "WildcardResource");
    new iam.Role(stack, "R", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      inlinePolicies: {
        bad: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({ actions: ["s3:GetObject"], resources: ["*"] }),
          ],
        }),
      },
    });
    Aspects.of(stack).add(new NoWildcardIamAspect());

    expect(errorsFrom(stack).join(" ")).toMatch(/Wildcard IAM resource/);
  });

  test("NoWildcardIamAspect allows Deny with * — a ceiling is not a grant", () => {
    const stack = new Stack(new App(), "DenyStar");
    new iam.Role(stack, "R", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      inlinePolicies: {
        ceiling: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.DENY,
              actions: ["*"],
              resources: ["*"],
            }),
          ],
        }),
      },
    });
    Aspects.of(stack).add(new NoWildcardIamAspect());

    expect(errorsFrom(stack)).toHaveLength(0);
  });

  test("NoWildcardIamAspect honours an explicit path exemption", () => {
    const stack = new Stack(new App(), "Exempt");
    new iam.Role(stack, "ExemptedRole", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      inlinePolicies: {
        bad: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({ actions: ["xray:PutTraceSegments"], resources: ["*"] }),
          ],
        }),
      },
    });
    Aspects.of(stack).add(new NoWildcardIamAspect(["ExemptedRole"]));

    expect(errorsFrom(stack)).toHaveLength(0);
  });

  test("RequireLogRetentionAspect rejects a log group with no retention", () => {
    const stack = new Stack(new App(), "NoRetention");
    new logs.CfnLogGroup(stack, "LG", {});
    Aspects.of(stack).add(new RequireLogRetentionAspect(logs.RetentionDays.THREE_MONTHS));

    expect(errorsFrom(stack).join(" ")).toMatch(/has no retention/);
  });

  test("RequireLogRetentionAspect rejects retention beyond the ceiling", () => {
    const stack = new Stack(new App(), "TooLong");
    new logs.CfnLogGroup(stack, "LG", { retentionInDays: 3653 });
    Aspects.of(stack).add(new RequireLogRetentionAspect(logs.RetentionDays.THREE_MONTHS));

    expect(errorsFrom(stack).join(" ")).toMatch(/exceeding the/);
  });

  test("RequireVpcAttachmentAspect rejects a function with no vpcConfig", () => {
    const stack = new Stack(new App(), "NoVpc");
    new lambda.Function(stack, "F", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "index.handler",
      code: lambda.Code.fromInline("def handler(e,c): return {}"),
    });
    Aspects.of(stack).add(new RequireVpcAttachmentAspect());

    expect(errorsFrom(stack).join(" ")).toMatch(/not VPC-attached/);
  });

  test("RequirePermissionBoundaryAspect applies a boundary rather than only complaining", () => {
    const stack = new Stack(new App(), "Boundary");
    const role = new iam.Role(stack, "R", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
    });
    const boundary = "arn:aws:iam::123456789012:policy/Boundary";
    Aspects.of(stack).add(new RequirePermissionBoundaryAspect(boundary));

    // Force synthesis so the aspect visits, then read the produced template.
    Template.fromStack(stack).hasResourceProperties("AWS::IAM::Role", {
      PermissionsBoundary: boundary,
    });
    expect(role).toBeDefined();
  });
});

describe("api and workload aspects fire", () => {
  test("RequireApiAuthorizerAspect rejects a method with no authorizer", () => {
    const stack = new Stack(new App(), "NoAuth");
    const api = new (require("aws-cdk-lib/aws-apigateway").RestApi)(stack, "Api");
    api.root.addMethod("GET");
    Aspects.of(stack).add(new RequireApiAuthorizerAspect());
    expect(errorsFrom(stack).join(" ")).toMatch(/has no authorizer/);
  });

  test("RequireApiAuthorizerAspect exempts CORS preflight", () => {
    // OPTIONS is unauthenticated by specification: browsers send it without
    // credentials, and the preflight response carries no data.
    const stack = new Stack(new App(), "Preflight");
    const api = new (require("aws-cdk-lib/aws-apigateway").RestApi)(stack, "Api");
    api.root.addMethod("OPTIONS");
    Aspects.of(stack).add(new RequireApiAuthorizerAspect());
    expect(errorsFrom(stack)).toHaveLength(0);
  });

  test("RequireReservedConcurrencyAspect rejects an unbounded function", () => {
    const stack = new Stack(new App(), "Unbounded");
    new lambda.Function(stack, "F", {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "index.handler",
      code: lambda.Code.fromInline("exports.handler = async () => ({});"),
    });
    Aspects.of(stack).add(new RequireReservedConcurrencyAspect());
    expect(errorsFrom(stack).join(" ")).toMatch(/no reserved concurrency/);
  });

  test("RequireTableCustomerKeyAspect rejects an AWS-owned key", () => {
    const dynamodb = require("aws-cdk-lib/aws-dynamodb");
    const stack = new Stack(new App(), "OwnedKey");
    new dynamodb.Table(stack, "T", {
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
    });
    Aspects.of(stack).add(new RequireTableCustomerKeyAspect());
    expect(errorsFrom(stack).join(" ")).toMatch(/customer-managed KMS key/);
  });

  test("RequireDeadLetterQueueAspect rejects a queue with no DLQ", () => {
    const sqs = require("aws-cdk-lib/aws-sqs");
    const stack = new Stack(new App(), "NoDlq");
    new sqs.Queue(stack, "WorkQueue");
    Aspects.of(stack).add(new RequireDeadLetterQueueAspect());
    expect(errorsFrom(stack).join(" ")).toMatch(/no dead-letter queue/);
  });

  test("RequireDeadLetterQueueAspect exempts the DLQ itself, matching on path", () => {
    // Regression test. The exemption originally matched on node id, but for an
    // L2 Queue the CfnQueue id is always "Resource" — so it never matched and
    // the aspect fired on the very DLQ it was meant to exempt. Caught on the
    // golden-path API's first synth.
    const sqs = require("aws-cdk-lib/aws-sqs");
    const stack = new Stack(new App(), "DlqExempt");
    new sqs.Queue(stack, "WorkerDlq");
    Aspects.of(stack).add(new RequireDeadLetterQueueAspect());
    expect(errorsFrom(stack)).toHaveLength(0);
  });
});
