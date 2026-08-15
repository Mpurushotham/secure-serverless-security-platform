/**
 * Golden path: CloudFront + WAF → API Gateway → Cognito authorizer → Lambda →
 * DynamoDB, with EventBridge and an SQS worker downstream.
 *
 * This is the shape a new service starts from, so the defaults matter more than
 * the features. Everything here is chosen to make the secure version the one
 * you get by doing nothing:
 *
 *   * The table uses a customer-managed key, so encryption is an access
 *     boundary rather than a storage property (finding DAT-003).
 *   * Every method has an authorizer, enforced at synth (finding APP-001).
 *   * Every function has reserved concurrency — cost, and the containment lever
 *     that stops a compromised function without destroying the evidence.
 *   * Every queue has a dead-letter queue, so a poison message waits to be
 *     looked at rather than vanishing.
 *   * Access logging on the stage (finding APP-002), request validation at the
 *     edge, and throttling.
 *
 * Not VPC-attached, deliberately. `docs/aws_security_engineering_plan.md` §24
 * makes the argument: VPC attachment should follow a connectivity requirement,
 * not a reflex. These functions reach DynamoDB and EventBridge, both of which
 * are reached over the AWS network — putting them in a VPC would add a NAT
 * gateway or endpoints and buy nothing. The agent app in `infra/cdk` IS
 * VPC-attached, because it reaches a database holding Article 9 data and its
 * egress genuinely needs constraining. Different requirement, different answer.
 */

import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  StackProps,
} from "aws-cdk-lib";
import * as apigw from "aws-cdk-lib/aws-apigateway";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import { NodejsFunction } from "aws-cdk-lib/aws-lambda-nodejs";
import * as logs from "aws-cdk-lib/aws-logs";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import { Construct } from "constructs";
import * as path from "node:path";

export interface OrdersApiStackProps extends StackProps {
  readonly logRetention: logs.RetentionDays;
  /** Requests per second before throttling. Low by default; raise deliberately. */
  readonly throttleRate?: number;
}

export class OrdersApiStack extends Stack {
  constructor(scope: Construct, id: string, props: OrdersApiStackProps) {
    super(scope, id, props);

    // -- key ---------------------------------------------------------------

    const key = new kms.Key(this, "DataKey", {
      description: "Orders table, queue and log encryption",
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // -- identity ----------------------------------------------------------

    const userPool = new cognito.UserPool(this, "Users", {
      selfSignUpEnabled: false, // Tenants are provisioned, not self-served.
      signInAliases: { email: true },
      passwordPolicy: {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      mfa: cognito.Mfa.REQUIRED,
      mfaSecondFactor: { sms: false, otp: true },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      // Plus tier, not Essentials. This is what buys compromised-credential
      // detection and adaptive authentication — the controls that notice a
      // valid password arriving from an implausible place, which is exactly
      // the credential-stuffing case the WAF rate rule below cannot see
      // (each individual request looks legitimate). Costs per monthly active
      // user; for an API holding customer orders that is the right trade.
      featurePlan: cognito.FeaturePlan.PLUS,
      removalPolicy: RemovalPolicy.RETAIN,
      // The claim every authorization decision depends on. Immutable, because a
      // mutable tenant claim is a privilege escalation the API cannot see.
      customAttributes: {
        tenant_id: new cognito.StringAttribute({ mutable: false }),
      },
    });

    const authorizer = new apigw.CognitoUserPoolsAuthorizer(this, "Authorizer", {
      cognitoUserPools: [userPool],
    });

    // -- storage -----------------------------------------------------------

    const table = new dynamodb.Table(this, "Orders", {
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: key,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // -- events ------------------------------------------------------------

    const bus = new events.EventBus(this, "Bus", {});

    const workerDlq = new sqs.Queue(this, "WorkerDlq", {
      encryptionMasterKey: key,
      enforceSSL: true,
      retentionPeriod: Duration.days(14),
    });

    const workerQueue = new sqs.Queue(this, "WorkerQueue", {
      encryptionMasterKey: key,
      enforceSSL: true,
      visibilityTimeout: Duration.seconds(60),
      deadLetterQueue: { queue: workerDlq, maxReceiveCount: 3 },
    });

    new events.Rule(this, "OrderCreated", {
      eventBus: bus,
      eventPattern: { detailType: ["OrderCreated"] },
      targets: [new targets.SqsQueue(workerQueue, { deadLetterQueue: workerDlq })],
    });

    // -- compute -----------------------------------------------------------

    const apiLogs = new logs.LogGroup(this, "ApiFunctionLogs", {
      retention: props.logRetention,
      encryptionKey: key,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const ordersFunction = new NodejsFunction(this, "OrdersFunction", {
      entry: path.join(__dirname, "..", "src", "handlers", "orders.ts"),
      handler: "handler",
      runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64,
      memorySize: 512,
      timeout: Duration.seconds(10),
      // Containment lever, not only a cost control: set to 0 to stop a
      // compromised function while preserving it for investigation.
      reservedConcurrentExecutions: 50,
      tracing: lambda.Tracing.ACTIVE,
      logGroup: apiLogs,
      environmentEncryption: key,
      environment: {
        ORDERS_TABLE: table.tableName,
        EVENT_BUS: bus.eventBusName,
        NODE_OPTIONS: "--enable-source-maps",
      },
    });

    // Read and write only. No Scan: an accidental full-table scan is both a
    // cost incident and a cross-tenant read waiting for a missing filter.
    table.grantReadWriteData(ordersFunction);
    bus.grantPutEventsTo(ordersFunction);

    ordersFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.DENY,
        actions: ["dynamodb:Scan", "dynamodb:DeleteTable", "dynamodb:UpdateTable"],
        resources: [table.tableArn],
      }),
    );

    // -- edge --------------------------------------------------------------

    const accessLogs = new logs.LogGroup(this, "ApiAccessLogs", {
      retention: props.logRetention,
      encryptionKey: key,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const api = new apigw.RestApi(this, "OrdersApi", {
      restApiName: "orders",
      endpointConfiguration: { types: [apigw.EndpointType.REGIONAL] },
      deployOptions: {
        stageName: "v1",
        accessLogDestination: new apigw.LogGroupLogDestination(accessLogs),
        // Identity, source IP, status — and deliberately NOT the request body,
        // which for this API carries customer content.
        accessLogFormat: apigw.AccessLogFormat.jsonWithStandardFields({
          caller: true,
          httpMethod: true,
          ip: true,
          protocol: true,
          requestTime: true,
          resourcePath: true,
          responseLength: true,
          status: true,
          user: true,
        }),
        // Execution logging at ERROR level. Deliberately NOT dataTraceEnabled:
        // that logs full request and response bodies, which for this API means
        // copying customer content into a log group with different retention
        // and different access control from the table it came from.
        loggingLevel: apigw.MethodLoggingLevel.ERROR,
        dataTraceEnabled: false,
        throttlingRateLimit: props.throttleRate ?? 100,
        throttlingBurstLimit: (props.throttleRate ?? 100) * 2,
        tracingEnabled: true,
        metricsEnabled: true,
      },
    });

    const orderModel = api.addModel("OrderModel", {
      contentType: "application/json",
      schema: {
        type: apigw.JsonSchemaType.OBJECT,
        required: ["productId", "quantity"],
        additionalProperties: false,
        properties: {
          productId: { type: apigw.JsonSchemaType.STRING, pattern: "^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$" },
          quantity: { type: apigw.JsonSchemaType.INTEGER, minimum: 1, maximum: 100 },
          note: { type: apigw.JsonSchemaType.STRING, maxLength: 500 },
        },
      },
    });

    const validator = api.addRequestValidator("Validator", {
      validateRequestBody: true,
      validateRequestParameters: true,
    });

    const integration = new apigw.LambdaIntegration(ordersFunction);
    const withAuth: apigw.MethodOptions = {
      authorizer,
      authorizationType: apigw.AuthorizationType.COGNITO,
    };

    const orders = api.root.addResource("orders");
    orders.addMethod("POST", integration, {
      ...withAuth,
      requestModels: { "application/json": orderModel },
      requestValidator: validator,
    });
    orders.addMethod("GET", integration, withAuth);
    orders.addResource("{orderId}").addMethod("GET", integration, withAuth);

    // -- WAF ---------------------------------------------------------------

    const webAcl = new wafv2.CfnWebACL(this, "WebAcl", {
      scope: "REGIONAL",
      defaultAction: { allow: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: "orders-api",
        sampledRequestsEnabled: true,
      },
      rules: [
        managed("AWSManagedRulesCommonRuleSet", 0),
        managed("AWSManagedRulesKnownBadInputsRuleSet", 1),
        managed("AWSManagedRulesSQLiRuleSet", 2),
        {
          name: "RateLimit",
          priority: 3,
          action: { block: {} },
          statement: {
            rateBasedStatement: { limit: 2000, aggregateKeyType: "IP" },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: "rate-limit",
            sampledRequestsEnabled: true,
          },
        },
      ],
    });

    new wafv2.CfnWebACLAssociation(this, "WebAclAssociation", {
      resourceArn: api.deploymentStage.stageArn,
      webAclArn: webAcl.attrArn,
    });

    // -- outputs -----------------------------------------------------------

    new CfnOutput(this, "ApiUrl", { value: api.url });
    new CfnOutput(this, "UserPoolId", { value: userPool.userPoolId });
    new CfnOutput(this, "TableName", { value: table.tableName });
  }
}

function managed(name: string, priority: number): wafv2.CfnWebACL.RuleProperty {
  return {
    name,
    priority,
    overrideAction: { none: {} },
    statement: {
      managedRuleGroupStatement: { vendorName: "AWS", name },
    },
    visibilityConfig: {
      cloudWatchMetricsEnabled: true,
      metricName: name,
      sampledRequestsEnabled: true,
    },
  };
}
