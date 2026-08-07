/**
 * The serverless workload the MCP agent reads from.
 *
 * This is APT's stated architecture in miniature: API Gateway in front of
 * VPC-attached Lambdas talking to Aurora, with the agent's data path treated as
 * a separate, more constrained principal than the application's own.
 *
 * The security decision that shapes everything here is that **the agent's
 * Lambda and the application's Lambda do not share an execution role.** It
 * would be simpler to give one role both sets of permissions and let the code
 * decide what to do. That collapses the trust boundary: a prompt injection in
 * the agent path would then execute with the application's write access. Two
 * roles cost one extra construct and make the boundary real rather than
 * conventional.
 */

import {
  aws_apigateway as apigw,
  aws_ec2 as ec2,
  aws_iam as iam,
  aws_kms as kms,
  aws_lambda as lambda,
  aws_logs as logs,
  aws_secretsmanager as secrets,
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  StackProps,
} from "aws-cdk-lib";
import { Construct } from "constructs";

export interface AgentApiStackProps extends StackProps {
  /** Retention for all log groups in this stack. */
  readonly logRetention: logs.RetentionDays;
  /** Aurora cluster resource ID, for scoping rds-db:connect. */
  readonly clusterResourceId: string;
  /** The single database user the agent may authenticate as. */
  readonly agentDatabaseUser: string;
}

export class AgentApiStack extends Stack {
  public readonly agentFunction: lambda.Function;
  public readonly apiFunction: lambda.Function;

  constructor(scope: Construct, id: string, props: AgentApiStackProps) {
    super(scope, id, props);

    // --- Network ---------------------------------------------------------
    // Isolated subnets, not private-with-egress. A NAT gateway would give the
    // Lambdas a route to the internet, which is the exfiltration path we are
    // trying not to have. Everything they legitimately need is an interface
    // endpoint below.
    const vpc = new ec2.Vpc(this, "Vpc", {
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [
        { name: "isolated", subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 24 },
      ],
      flowLogs: {
        // Flow logs are how "the agent's function tried to reach an unexpected
        // address" becomes visible at all. Without them the isolated subnet is
        // a claim rather than something you can verify after an incident.
        all: {
          trafficType: ec2.FlowLogTrafficType.ALL,
          destination: ec2.FlowLogDestination.toCloudWatchLogs(
            new logs.LogGroup(this, "FlowLogs", {
              retention: props.logRetention,
              removalPolicy: RemovalPolicy.RETAIN,
            }),
          ),
        },
      },
    });

    for (const [name, service] of [
      ["SecretsEndpoint", ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER],
      ["LogsEndpoint", ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS],
      ["KmsEndpoint", ec2.InterfaceVpcEndpointAwsService.KMS],
      ["BedrockEndpoint", ec2.InterfaceVpcEndpointAwsService.BEDROCK_RUNTIME],
    ] as const) {
      vpc.addInterfaceEndpoint(name, { service, privateDnsEnabled: true });
    }

    const key = new kms.Key(this, "Key", {
      enableKeyRotation: true,
      description: "Encryption for the agent API stack",
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const dbSecret = new secrets.Secret(this, "DbConnection", {
      description: "Aurora connection parameters (no password; IAM auth)",
      encryptionKey: key,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const lambdaSg = new ec2.SecurityGroup(this, "LambdaSg", {
      vpc,
      description: "Agent and API Lambdas",
      allowAllOutbound: false, // egress is enumerated, not assumed
    });
    lambdaSg.addEgressRule(
      ec2.Peer.ipv4(vpc.vpcCidrBlock),
      ec2.Port.tcp(443),
      "HTTPS to VPC interface endpoints",
    );
    lambdaSg.addEgressRule(
      ec2.Peer.ipv4(vpc.vpcCidrBlock),
      ec2.Port.tcp(5432),
      "PostgreSQL to Aurora",
    );

    // --- The agent's execution role --------------------------------------
    // Separate from the application's, and narrower. See the class comment.
    const agentRole = new iam.Role(this, "AgentRole", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      description: "MCP agent - read-only access to masked data only",
    });

    // Scoped to one database user on one cluster resource ID. The resource ID
    // rather than the cluster name: a name can be recreated, the resource ID
    // cannot.
    agentRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "ConnectAsReadOnlyDatabaseUser",
        actions: ["rds-db:connect"],
        resources: [
          `arn:aws:rds-db:${this.region}:${this.account}:dbuser:${props.clusterResourceId}/${props.agentDatabaseUser}`,
        ],
      }),
    );

    // Explicit denies on the role itself. The permission boundary (applied by
    // the aspect in bin/app.ts) is the ceiling; these are defence in depth for
    // the specific actions that would undo this design.
    agentRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "DenyDataExfiltrationPaths",
        effect: iam.Effect.DENY,
        actions: [
          "rds:CreateDBClusterSnapshot",
          "rds:CopyDBClusterSnapshot",
          "s3:PutObject",
          "iam:*",
        ],
        resources: ["*"],
      }),
    );

    const agentLogGroup = new logs.LogGroup(this, "AgentLogs", {
      retention: props.logRetention,
      encryptionKey: key,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.agentFunction = new lambda.Function(this, "AgentFunction", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "index.handler",
      code: lambda.Code.fromInline(
        "def handler(event, context):\n"
        + "    # Placeholder. The real implementation is the MCP server in\n"
        + "    # mcp-servers/rds_readonly_mcp/, which is deliberately not\n"
        + "    # inlined here: this stack exists to pin the *shape* of the\n"
        + "    # deployment, not to duplicate the server.\n"
        + "    return {'statusCode': 200, 'body': 'ok'}\n",
      ),
      role: agentRole,
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      securityGroups: [lambdaSg],
      timeout: Duration.seconds(30),
      memorySize: 512,
      logGroup: agentLogGroup,
      environmentEncryption: key,
      environment: {
        MCP_DB_SECRET_ARN: dbSecret.secretArn,
        // Off unless a deployment decision says otherwise. Never a tool
        // argument the model can set for itself.
        MCP_ALLOW_UNMASK: "false",
      },
      // A dead-letter queue would silently retain failed event payloads, which
      // for this workload can contain query text. Failures are surfaced via
      // logs and alarms instead.
      reservedConcurrentExecutions: 10,
    });
    dbSecret.grantRead(agentRole);
    key.grantDecrypt(agentRole);

    // --- The application's role and function ------------------------------
    const apiRole = new iam.Role(this, "ApiRole", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      description: "Application API - separate trust boundary from the agent",
    });

    const apiLogGroup = new logs.LogGroup(this, "ApiLogs", {
      retention: props.logRetention,
      encryptionKey: key,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.apiFunction = new lambda.Function(this, "ApiFunction", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "index.handler",
      code: lambda.Code.fromInline(
        "def handler(event, context):\n    return {'statusCode': 200, 'body': 'ok'}\n",
      ),
      role: apiRole,
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      securityGroups: [lambdaSg],
      timeout: Duration.seconds(10),
      memorySize: 256,
      logGroup: apiLogGroup,
      environmentEncryption: key,
      reservedConcurrentExecutions: 50,
    });

    // --- API ---------------------------------------------------------------
    const accessLogs = new logs.LogGroup(this, "ApiAccessLogs", {
      retention: props.logRetention,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const api = new apigw.RestApi(this, "Api", {
      restApiName: "pharmacy-api",
      description: "Application API. The agent path is not exposed here.",
      deployOptions: {
        stageName: "prod",
        loggingLevel: apigw.MethodLoggingLevel.ERROR,
        // Deliberately false. Request/response logging on an endpoint serving
        // pharmacy data would write personal data into CloudWatch, which is the
        // same mistake as enabling full query logging on the database.
        dataTraceEnabled: false,
        metricsEnabled: true,
        tracingEnabled: true,
        throttlingBurstLimit: 100,
        throttlingRateLimit: 50,
        accessLogDestination: new apigw.LogGroupLogDestination(accessLogs),
        accessLogFormat: apigw.AccessLogFormat.jsonWithStandardFields({
          caller: false,
          httpMethod: true,
          ip: true,
          protocol: true,
          requestTime: true,
          resourcePath: true,
          responseLength: true,
          status: true,
          user: true,
        }),
      },
    });

    const orders = api.root.addResource("orders");
    orders.addMethod("GET", new apigw.LambdaIntegration(this.apiFunction), {
      authorizationType: apigw.AuthorizationType.IAM,
    });

    new CfnOutput(this, "ApiUrl", { value: api.url });
    new CfnOutput(this, "AgentRoleArn", { value: agentRole.roleArn });
    new CfnOutput(this, "VpcId", { value: vpc.vpcId });
  }
}
