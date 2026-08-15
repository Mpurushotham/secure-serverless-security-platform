import { Annotations, IAspect } from "aws-cdk-lib";
import * as logs from "aws-cdk-lib/aws-logs";
import { IConstruct } from "constructs";

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
