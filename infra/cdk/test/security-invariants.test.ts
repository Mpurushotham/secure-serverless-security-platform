/**
 * Tests that assert the *security* properties of the synthesised template.
 *
 * These are not "does it deploy" tests. Each one pins an invariant that would
 * be easy to regress in a hurry and hard to notice in review — the agent role
 * gaining write access, a Lambda losing its VPC attachment, log retention
 * quietly reverting to "never expire".
 */
import { App } from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { RetentionDays } from "aws-cdk-lib/aws-logs";
import { AgentApiStack } from "../lib/stacks/agent-api-stack";

function synth(): Template {
  const app = new App();
  const stack = new AgentApiStack(app, "TestStack", {
    logRetention: RetentionDays.THREE_MONTHS,
    clusterResourceId: "cluster-TESTID",
    agentDatabaseUser: "mcp_readonly",
    env: { account: "123456789012", region: "eu-north-1" },
  });
  return Template.fromStack(stack);
}

describe("network isolation", () => {
  test("no NAT gateway — the Lambdas have no route to the internet", () => {
    synth().resourceCountIs("AWS::EC2::NatGateway", 0);
  });

  test("every Lambda is VPC-attached", () => {
    const template = synth();
    const functions = template.findResources("AWS::Lambda::Function");
    const attached = Object.entries(functions).filter(
      ([, fn]) => fn.Properties?.VpcConfig !== undefined,
    );
    expect(attached.length).toBe(Object.keys(functions).length);
    expect(attached.length).toBeGreaterThan(0);
  });

  test("VPC flow logs are enabled", () => {
    synth().resourceCountIs("AWS::EC2::FlowLog", 1);
  });
});

describe("agent least privilege", () => {
  test("rds-db:connect is scoped to one database user, not a wildcard", () => {
    const template = synth();
    const policies = template.findResources("AWS::IAM::Policy");
    const connect = Object.values(policies).flatMap((p) =>
      (p.Properties?.PolicyDocument?.Statement ?? []).filter(
        (s: { Action?: string | string[] }) =>
          JSON.stringify(s.Action ?? "").includes("rds-db:connect"),
      ),
    );
    expect(connect.length).toBeGreaterThan(0);
    for (const statement of connect) {
      const rendered = JSON.stringify(statement.Resource);
      expect(rendered).toContain("mcp_readonly");
      expect(rendered).not.toContain('"*"');
    }
  });

  test("the agent role explicitly denies snapshot and IAM paths", () => {
    const template = synth();
    const policies = template.findResources("AWS::IAM::Policy");
    const denies = Object.values(policies).flatMap((p) =>
      (p.Properties?.PolicyDocument?.Statement ?? []).filter(
        (s: { Effect?: string }) => s.Effect === "Deny",
      ),
    );
    const actions = JSON.stringify(denies);
    expect(actions).toContain("rds:CreateDBClusterSnapshot");
    expect(actions).toContain("iam:*");
  });

  test("agent and application do not share an execution role", () => {
    const template = synth();
    const functions = template.findResources("AWS::Lambda::Function");
    const roles = Object.values(functions).map((fn) => JSON.stringify(fn.Properties?.Role));
    expect(new Set(roles).size).toBe(roles.length);
  });
});

describe("data protection", () => {
  test("no log group retains indefinitely", () => {
    const template = synth();
    const groups = template.findResources("AWS::Logs::LogGroup");
    expect(Object.keys(groups).length).toBeGreaterThan(0);
    for (const group of Object.values(groups)) {
      expect(group.Properties?.RetentionInDays).toBeDefined();
      expect(group.Properties?.RetentionInDays).toBeLessThanOrEqual(90);
    }
  });

  test("API Gateway does not log request/response bodies", () => {
    synth().hasResourceProperties("AWS::ApiGateway::Stage", {
      MethodSettings: Match.arrayWith([Match.objectLike({ DataTraceEnabled: false })]),
    });
  });

  test("unmasking is disabled in the deployed environment", () => {
    synth().hasResourceProperties("AWS::Lambda::Function", {
      Environment: { Variables: Match.objectLike({ MCP_ALLOW_UNMASK: "false" }) },
    });
  });

  test("KMS key rotation is enabled", () => {
    synth().hasResourceProperties("AWS::KMS::Key", { EnableKeyRotation: true });
  });
});

describe("api surface", () => {
  test("the endpoint requires IAM authorization", () => {
    synth().hasResourceProperties("AWS::ApiGateway::Method", {
      AuthorizationType: "AWS_IAM",
    });
  });
});
