import { Annotations, IAspect } from "aws-cdk-lib";
import * as apigw from "aws-cdk-lib/aws-apigateway";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as sqs from "aws-cdk-lib/aws-sqs";
import { IConstruct } from "constructs";

/**
 * Fails synth on an API Gateway method with no authorizer.
 *
 * This is finding APP-001 turned into a control. Discovery found two live API
 * stages with no authorizer attached, which leaves authorization entirely to
 * the function — so a handler that returns before its own check, or a new route
 * added by someone who did not know the convention, is simply open.
 *
 * `OPTIONS` is exempt because CORS preflight is unauthenticated by
 * specification: browsers send it without credentials, and requiring auth
 * breaks every cross-origin call while protecting nothing — the preflight
 * response carries no data.
 */
export class RequireApiAuthorizerAspect implements IAspect {
  constructor(private readonly exemptPaths: string[] = []) {}

  public visit(node: IConstruct): void {
    if (!(node instanceof apigw.CfnMethod)) return;
    if (this.exemptPaths.some((p) => node.node.path.includes(p))) return;
    if (node.httpMethod === "OPTIONS") return;

    const authorizationType = node.authorizationType;
    const hasAuthorizer =
      Boolean(node.authorizerId) ||
      (authorizationType !== undefined && authorizationType !== "NONE");

    if (!hasAuthorizer) {
      Annotations.of(node).addError(
        `API method ${node.node.path} (${node.httpMethod}) has no authorizer. ` +
          `Authorization would then be entirely the function's responsibility, with ` +
          `nothing in front of it that fails closed.`,
      );
    }
  }
}

/**
 * Fails synth on a Lambda function with no reserved concurrency.
 *
 * Two reasons, and the second is the one people forget:
 *
 *  1. An unbounded function is a denial-of-wallet target — and, if it reaches a
 *     database, a way to exhaust connections until unrelated workloads fail.
 *  2. Reserved concurrency is the containment lever during an incident. Setting
 *     it to zero stops a compromised function *without* deleting it, which
 *     preserves the code, configuration and logs an investigation needs. A
 *     function with no reservation cannot be stopped that way — the only
 *     options are deleting it or racing it. Both destroy evidence.
 *
 * See docs/05-incident-response/02-guardduty-cryptomining.md, which contains
 * exactly this containment step.
 */
export class RequireReservedConcurrencyAspect implements IAspect {
  constructor(private readonly exemptPaths: string[] = []) {}

  public visit(node: IConstruct): void {
    if (!(node instanceof lambda.CfnFunction)) return;
    if (this.exemptPaths.some((p) => node.node.path.includes(p))) return;

    if (node.reservedConcurrentExecutions === undefined) {
      Annotations.of(node).addError(
        `Lambda ${node.node.path} has no reserved concurrency. Beyond cost, this is ` +
          `the containment lever: setting it to zero stops a compromised function ` +
          `without deleting the evidence.`,
      );
    }
  }
}

/**
 * Fails synth on a DynamoDB table encrypted with anything but a customer key.
 *
 * The default is an AWS-owned key, which cannot carry a key policy. That
 * matters more than "is it encrypted": with an AWS-owned key, encryption is a
 * storage property and nothing else. With a customer-managed key it becomes an
 * access boundary — you can deny `kms:Decrypt` to a principal that has
 * `dynamodb:GetItem`, and the read fails.
 *
 * This is finding DAT-003 as a control: the assessed account had zero
 * customer-managed keys, so no data store there could use encryption that way.
 */
export class RequireTableCustomerKeyAspect implements IAspect {
  public visit(node: IConstruct): void {
    if (!(node instanceof dynamodb.CfnTable)) return;

    const specification = node.sseSpecification as
      | { sseEnabled?: boolean; kmsMasterKeyId?: unknown; sseType?: string }
      | undefined;

    if (!specification?.sseEnabled || !specification.kmsMasterKeyId) {
      Annotations.of(node).addError(
        `Table ${node.node.path} does not use a customer-managed KMS key. An ` +
          `AWS-owned key carries no key policy, so encryption cannot act as an ` +
          `access boundary — only as a storage property.`,
      );
    }
  }
}

/**
 * Fails synth on an SQS queue with no dead-letter queue.
 *
 * A queue without one silently drops messages after the redrive limit. For an
 * ordinary workload that is a reliability bug; for a security-relevant event
 * stream it is worse, because the evidence of what was dropped is dropped with
 * it. The DLQ is where a poison message waits to be looked at.
 *
 * Dead-letter queues themselves are exempt — a DLQ for a DLQ is an infinite
 * regress, and the recursion has to stop at the queue nobody redrives from.
 */
export class RequireDeadLetterQueueAspect implements IAspect {
  constructor(private readonly exemptSuffixes: string[] = ["Dlq", "DeadLetter"]) {}

  public visit(node: IConstruct): void {
    if (!(node instanceof sqs.CfnQueue)) return;

    // Match on the queue's OWN name — which for an L2 `Queue` lives on the
    // parent construct, because the underlying CfnQueue is always called
    // "Resource".
    //
    // Two bugs were needed to arrive here, both worth keeping in mind:
    //   * Matching `node.node.id` never matched anything, so the aspect fired
    //     on the very DLQ it was meant to exempt.
    //   * Matching the whole path with `includes` matched far too much — a
    //     stack named `NoDlq` exempted every queue inside it, silently
    //     disabling the control for the entire stack.
    // Same lesson as the snapshot redactor: an over-broad substring match on
    // a name is a control that stops firing without failing.
    const own = node.node.scope?.node.id ?? node.node.id;
    if (this.exemptSuffixes.some((suffix) => own.endsWith(suffix))) return;

    if (!node.redrivePolicy) {
      Annotations.of(node).addError(
        `Queue ${node.node.path} has no dead-letter queue. Messages that fail ` +
          `repeatedly are dropped silently, taking the evidence of what failed ` +
          `with them.`,
      );
    }
  }
}
