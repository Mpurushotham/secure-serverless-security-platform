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
 *
 * This package is the single copy. It is consumed by `infra/cdk` (the agent
 * reference app) and by `platform/11-serverless/cdk` (the golden-path API).
 * Duplicated security controls drift; one copy does not.
 */

export { NoWildcardIamAspect } from "./aspects/no-wildcard-iam";
export { RequirePermissionBoundaryAspect } from "./aspects/require-permission-boundary";
export { RequireLogRetentionAspect } from "./aspects/require-log-retention";
export { RequireVpcAttachmentAspect } from "./aspects/require-vpc-attachment";
export {
  RequireApiAuthorizerAspect,
  RequireDeadLetterQueueAspect,
  RequireReservedConcurrencyAspect,
  RequireTableCustomerKeyAspect,
} from "./aspects/api-and-workload";
