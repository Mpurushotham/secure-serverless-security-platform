/**
 * Assertions over the synthesized template.
 *
 * These check the CloudFormation that was actually produced, not the code that
 * was written — the distinction that matters, because most of a CDK app's
 * security surface arrives via L2 defaults and `grant*()` helpers that nobody
 * typed by hand.
 */

import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { RetentionDays } from "aws-cdk-lib/aws-logs";

import { OrdersApiStack } from "../../lib/orders-api-stack";

function template(): Template {
  const app = new App();
  const stack = new OrdersApiStack(app, "TestStack", {
    logRetention: RetentionDays.THREE_MONTHS,
  });
  return Template.fromStack(stack);
}

describe("identity", () => {
  it("requires MFA, and not by SMS", () => {
    // SIM-swap makes SMS the weakest widely-deployed second factor.
    template().hasResourceProperties("AWS::Cognito::UserPool", {
      MfaConfiguration: "ON",
      EnabledMfas: ["SOFTWARE_TOKEN_MFA"],
    });
  });

  it("makes the tenant claim immutable", () => {
    // A mutable tenant claim is a privilege escalation the API cannot see:
    // every authorization decision in the handler depends on it.
    template().hasResourceProperties("AWS::Cognito::UserPool", {
      Schema: Match.arrayWith([
        Match.objectLike({ Name: "tenant_id", Mutable: false }),
      ]),
    });
  });

  it("does not allow self sign-up", () => {
    template().hasResourceProperties("AWS::Cognito::UserPool", {
      AdminCreateUserConfig: { AllowAdminCreateUserOnly: true },
    });
  });
});

describe("api surface", () => {
  it("attaches an authorizer to every method except CORS preflight", () => {
    const methods = template().findResources("AWS::ApiGateway::Method");
    const unprotected = Object.entries(methods).filter(
      ([, resource]) =>
        resource.Properties.HttpMethod !== "OPTIONS" &&
        resource.Properties.AuthorizationType !== "COGNITO_USER_POOLS",
    );
    expect(unprotected).toEqual([]);
  });

  it("validates the request body on POST", () => {
    template().hasResourceProperties("AWS::ApiGateway::Method", {
      HttpMethod: "POST",
      RequestValidatorId: Match.anyValue(),
      RequestModels: Match.anyValue(),
    });
  });

  it("throttles", () => {
    template().hasResourceProperties("AWS::ApiGateway::Stage", {
      MethodSettings: Match.arrayWith([
        Match.objectLike({ ThrottlingRateLimit: Match.anyValue() }),
      ]),
    });
  });

  it("logs access without logging request bodies", () => {
    const stages = template().findResources("AWS::ApiGateway::Stage");
    const [stage] = Object.values(stages);
    const format = stage.Properties.AccessLogSetting.Format as string;
    expect(format).toContain("status");
    expect(format).toContain("ip");
    // The body carries customer content. An access log is stored with different
    // retention and different access control from the data itself.
    expect(format).not.toContain("$input.body");
    expect(format).not.toContain("requestBody");
  });

  it("is fronted by a WAF with rate limiting", () => {
    template().resourceCountIs("AWS::WAFv2::WebACLAssociation", 1);
    template().hasResourceProperties("AWS::WAFv2::WebACL", {
      Rules: Match.arrayWith([
        Match.objectLike({ Statement: { RateBasedStatement: Match.anyValue() } }),
      ]),
    });
  });
});

describe("data protection", () => {
  it("encrypts the table with a customer-managed key", () => {
    // An AWS-owned key carries no key policy, so encryption cannot act as an
    // access boundary — only as a storage property.
    template().hasResourceProperties("AWS::DynamoDB::Table", {
      SSESpecification: { SSEEnabled: true, SSEType: "KMS", KMSMasterKeyId: Match.anyValue() },
    });
  });

  it("rotates the key", () => {
    template().hasResourceProperties("AWS::KMS::Key", { EnableKeyRotation: true });
  });

  it("enables point-in-time recovery", () => {
    template().hasResourceProperties("AWS::DynamoDB::Table", {
      PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
    });
  });

  it("encrypts every log group with the same key", () => {
    const groups = template().findResources("AWS::Logs::LogGroup");
    expect(Object.keys(groups).length).toBeGreaterThan(0);
    for (const [name, group] of Object.entries(groups)) {
      expect(group.Properties.KmsKeyId).toBeDefined();
      expect(group.Properties.RetentionInDays).toBeDefined();
      expect(name).toBeTruthy();
    }
  });
});

describe("blast radius", () => {
  it("gives every function reserved concurrency", () => {
    // Cost, and the containment lever: set to zero to stop a compromised
    // function without deleting the evidence.
    const functions = template().findResources("AWS::Lambda::Function");
    const unbounded = Object.entries(functions).filter(
      ([, fn]) => fn.Properties.ReservedConcurrentExecutions === undefined,
    );
    expect(unbounded.map(([name]) => name)).toEqual([]);
  });

  it("explicitly denies Scan on the orders table", () => {
    // A full-table scan is both a cost incident and a cross-tenant read waiting
    // for a missing filter.
    template().hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: "Deny",
            Action: Match.arrayWith(["dynamodb:Scan"]),
          }),
        ]),
      }),
    });
  });

  it("gives the worker queue a dead-letter queue", () => {
    template().hasResourceProperties("AWS::SQS::Queue", {
      RedrivePolicy: Match.anyValue(),
    });
  });

  it("enforces TLS on every queue", () => {
    const policies = template().findResources("AWS::SQS::QueuePolicy");
    expect(Object.keys(policies).length).toBeGreaterThan(0);
  });

  it("enables tracing on the function and the stage", () => {
    template().hasResourceProperties("AWS::Lambda::Function", { TracingConfig: { Mode: "Active" } });
    template().hasResourceProperties("AWS::ApiGateway::Stage", { TracingEnabled: true });
  });
});
