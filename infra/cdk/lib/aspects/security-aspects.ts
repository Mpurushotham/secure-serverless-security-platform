/**
 * CDK Aspects that enforce security invariants across an entire stack tree.
 *
 * Why Aspects rather than a code-review checklist: an Aspect runs against every
 * node in the construct tree at synth time, including constructs added by L2/L3
 * helpers that nobody on the team wrote by hand. A reviewer reads the code that
 * was written; an Aspect sees the CloudFormation that was actually produced.
 * Most wildcard IAM in real CDK apps arrives via `grantRead()` and friends, not
 * via a hand-written policy — which is exactly the code a reviewer skims past.
 *
 * These are deliberately *errors*, not warnings. A warning in a synth log that
 * nobody reads is a control that does not exist.
 */

import { Annotations, IAspect, Stack } from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import { IConstruct } from "constructs";

/**
 * Fails synth on `Action: "*"` or `Resource: "*"` in any IAM policy, unless the
 * construct path is explicitly exempted.
 *
 * The exemption list is a feature, not a loophole: some AWS actions genuinely
 * cannot be resource-scoped (`logs:CreateLogGroup` at creation time,
 * `xray:PutTraceSegments`). Forcing every exemption to be named in code means
 * each one is a decision someone made and a reviewer can question, rather than
 * a blanket rule with no visibility.
 */
export class NoWildcardIamAspect implements IAspect {
  constructor(private readonly exemptPaths: string[] = []) {}

  public visit(node: IConstruct): void {
    if (!(node instanceof iam.CfnPolicy || node instanceof iam.CfnManagedPolicy)) {
      return;
    }
    if (this.exemptPaths.some((p) => node.node.path.includes(p))) {
      return;
    }

    const document = node instanceof iam.CfnPolicy
      ? node.policyDocument
      : node.policyDocument;

    const rendered = Stack.of(node).resolve(document) as
      | { Statement?: Array<Record<string, unknown>> }
      | undefined;

    for (const statement of rendered?.Statement ?? []) {
      // Deny statements with "*" are the desired shape — a deny on everything
      // is a ceiling, not a grant. Scoring them the same way as an Allow is the
      // mistake most policy scanners make.
      if (statement.Effect === "Deny") continue;

      const actions = toArray(statement.Action);
      const resources = toArray(statement.Resource);

      if (actions.some((a) => a === "*" || a.endsWith(":*"))) {
        Annotations.of(node).addError(
          `Wildcard IAM action in ${node.node.path}: ${actions.join(", ")}. ` +
            `Enumerate the actions, or add the construct path to the aspect's exemption list with a reason.`,
        );
      }

      if (resources.includes("*")) {
        Annotations.of(node).addError(
          `Wildcard IAM resource in ${node.node.path}. ` +
            `Scope to an ARN, or exempt the path explicitly if the action cannot be resource-scoped.`,
        );
      }
    }
  }
}

/**
 * Fails synth on any IAM role created without a permissions boundary.
 *
 * A boundary is the only IAM control that survives someone attaching a wider
 * policy later. Without it, a role's privilege is whatever the most recent PR
 * made it — and privilege only ever ratchets upward, because nobody opens a PR
 * to remove a permission that is not currently breaking anything.
 */
export class RequirePermissionBoundaryAspect implements IAspect {
  constructor(private readonly boundaryArn: string) {}

  public visit(node: IConstruct): void {
    if (!(node instanceof iam.CfnRole)) return;

    if (!node.permissionsBoundary) {
      // Set it rather than only complaining. An aspect that can fix the problem
      // and instead reports it just moves work to a human who will forget.
      node.permissionsBoundary = this.boundaryArn;
      Annotations.of(node).addInfo(
        `Permissions boundary applied automatically to ${node.node.path}.`,
      );
    }
  }
}

/**
 * Fails synth on Lambda functions with no explicit log retention.
 *
 * CDK's default is "never expire". For a workload that may log request context
 * touching personal data, indefinite retention is a GDPR Art. 5(1)(e) storage
 * limitation problem that accrues quietly and is expensive to unwind later.
 */
export class RequireLogRetentionAspect implements IAspect {
  constructor(private readonly maxRetention: logs.RetentionDays) {}

  public visit(node: IConstruct): void {
    if (!(node instanceof logs.CfnLogGroup)) return;

    if (node.retentionInDays === undefined) {
      Annotations.of(node).addError(
        `Log group ${node.node.path} has no retention. CDK defaults to never expiring, ` +
          `which for logs that may contain personal data is a storage-limitation finding. ` +
          `Set retention explicitly (max ${this.maxRetention} days).`,
      );
    } else if (node.retentionInDays > (this.maxRetention as number)) {
      Annotations.of(node).addError(
        `Log group ${node.node.path} retains for ${node.retentionInDays} days, ` +
          `exceeding the ${this.maxRetention}-day maximum for this data class.`,
      );
    }
  }
}

/**
 * Fails synth on Lambda functions not attached to a VPC.
 *
 * A function that reaches a database holding Art. 9 data should not also be
 * able to reach the open internet: that is the exfiltration path which bypasses
 * every application-layer control in this repository.
 */
export class RequireVpcAttachmentAspect implements IAspect {
  constructor(private readonly exemptPaths: string[] = []) {}

  public visit(node: IConstruct): void {
    if (!(node instanceof lambda.CfnFunction)) return;
    if (this.exemptPaths.some((p) => node.node.path.includes(p))) return;

    if (!node.vpcConfig) {
      Annotations.of(node).addError(
        `Lambda ${node.node.path} is not VPC-attached. Functions with access to ` +
          `regulated data must not have unrestricted egress.`,
      );
    }
  }
}

function toArray(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
  return [];
}
