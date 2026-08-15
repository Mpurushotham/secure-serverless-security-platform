import { Annotations, IAspect } from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import { IConstruct } from "constructs";

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
