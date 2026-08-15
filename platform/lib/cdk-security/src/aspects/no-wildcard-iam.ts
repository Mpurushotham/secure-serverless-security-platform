import { Annotations, IAspect, Stack } from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import { IConstruct } from "constructs";

import { toArray } from "../util";

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
    if (this.exemptPaths.some((p) => node.node.path.includes(p))) {
      return;
    }

    // Three places a policy document can live, and all three must be checked.
    //
    // The third one is the reason this list exists. An earlier version of this
    // aspect matched only CfnPolicy and CfnManagedPolicy — the shapes produced
    // by `grant*()` and `addToPolicy()`. But a document passed straight into
    // `new iam.Role(..., { inlinePolicies })` is emitted *inside* the
    // AWS::IAM::Role resource and never becomes a CfnPolicy node at all. The
    // aspect visited it, matched nothing, and reported success.
    //
    // That is a bypass anyone could hit by accident, using the most obvious
    // API in the library, and it was caught by asking the aspect to prove it
    // fires rather than assuming a clean synth meant a clean stack. See
    // test/aspects-fire.test.ts.
    if (node instanceof iam.CfnPolicy || node instanceof iam.CfnManagedPolicy) {
      this.check(node, node.policyDocument);
      return;
    }

    if (node instanceof iam.CfnRole) {
      for (const policy of toPolicyList(Stack.of(node).resolve(node.policies))) {
        // `resolve()` on CfnRole.policies yields the CDK *prop* shape
        // (`policyDocument`), not the rendered CloudFormation shape
        // (`PolicyDocument`). Accept either: the CFN casing is what appears if
        // the role was declared with an escape hatch or raw overrides.
        this.check(node, policy.policyDocument ?? policy.PolicyDocument);
      }
    }
  }

  private check(node: IConstruct, document: unknown): void {
    const rendered = Stack.of(node as never).resolve(document) as
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

interface ResolvedInlinePolicy {
  policyDocument?: unknown;
  PolicyDocument?: unknown;
}

/**
 * `CfnRole.policies` is `IResolvable | Array<PolicyProperty | IResolvable>`.
 * After resolution the useful shape is an array of objects carrying a policy
 * document; anything else is an unresolved token we cannot inspect, and is
 * skipped rather than guessed at.
 */
function toPolicyList(resolved: unknown): ResolvedInlinePolicy[] {
  if (!Array.isArray(resolved)) return [];
  return resolved.filter(
    (p): p is ResolvedInlinePolicy => typeof p === "object" && p !== null,
  );
}
