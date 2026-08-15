import { Annotations, IAspect } from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda";
import { IConstruct } from "constructs";

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
