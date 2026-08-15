/**
 * The Aspects moved to `platform/lib/cdk-security` so that this app and the
 * golden-path API app in `platform/11-serverless` enforce the *same* controls
 * from the *same* source. Two copies of a security control is two controls, and
 * the second one is always the one nobody updated.
 *
 * This path is preserved as a re-export rather than deleted: `bin/app.ts` and
 * the twelve invariant tests import from here, and moving a file is not a
 * reason to churn the call sites of a control.
 */

export {
  NoWildcardIamAspect,
  RequireLogRetentionAspect,
  RequirePermissionBoundaryAspect,
  RequireVpcAttachmentAspect,
} from "@ssp/cdk-security";
