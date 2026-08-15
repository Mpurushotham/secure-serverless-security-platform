/**
 * Orders API — create, get, list.
 *
 * The security properties worth reading, in the order they matter:
 *
 *  1. **Tenant comes from the token, never the request.** There is no code path
 *     that reads a tenant from a path parameter, query string or body.
 *  2. **Authorization is checked after the fetch, and the response is 404.**
 *     Filtering by tenant in the query would make a miss and a cross-tenant hit
 *     indistinguishable, so the attempt would never appear in a log. Fetching
 *     then comparing makes it observable; returning 404 rather than 403 keeps
 *     it from being an enumeration oracle. Both, not one.
 *  3. **Errors never carry internal detail to the caller.** The client gets a
 *     stable code; the log gets the reason. This is the same split as
 *     `mcp_core.errors` — `public_message` versus `internal_detail`.
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
} from "@aws-sdk/lib-dynamodb";
import { randomUUID } from "node:crypto";

import { Caller, Forbidden, Unauthenticated, assertOwns, callerFrom } from "../lib/authorization";
import { log } from "../lib/logging";
import { InvalidRequest, parseOrder } from "../lib/validation";

const TABLE = process.env.ORDERS_TABLE ?? "";
const client = DynamoDBDocumentClient.from(new DynamoDBClient({}));

interface OrderRecord {
  pk: string;
  sk: string;
  orderId: string;
  tenantId: string;
  productId: string;
  quantity: number;
  note?: string;
  createdAt: string;
  createdBy: string;
}

function respond(statusCode: number, body: unknown): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
      // Belt and braces with the CloudFront response-headers policy: a direct
      // call to the API origin bypasses CloudFront entirely.
      "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
      "x-content-type-options": "nosniff",
      "cache-control": "no-store",
    },
    body: JSON.stringify(body),
  };
}

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const started = Date.now();
  const requestId = event.requestContext?.requestId;
  let caller: Caller | undefined;

  try {
    caller = callerFrom(event);

    switch (`${event.httpMethod} ${event.resource}`) {
      case "POST /orders":
        return await createOrder(event, caller, requestId);
      case "GET /orders/{orderId}":
        return await getOrder(event, caller, requestId);
      case "GET /orders":
        return await listOrders(caller, requestId);
      default:
        // Reachable only if a route is added to the API without a handler
        // case. Refusing beats falling through to whichever branch is first.
        log({ event: "route.unknown", outcome: "refused", statusCode: 404, requestId });
        return respond(404, { message: "Not found" });
    }
  } catch (error) {
    return handleError(error, caller, requestId, Date.now() - started);
  }
}

async function createOrder(
  event: APIGatewayProxyEvent,
  caller: Caller,
  requestId?: string,
): Promise<APIGatewayProxyResult> {
  const input = parseOrder(event.body);
  const orderId = randomUUID();

  const record: OrderRecord = {
    pk: `TENANT#${caller.tenantId}`,
    sk: `ORDER#${orderId}`,
    orderId,
    tenantId: caller.tenantId,
    productId: input.productId,
    quantity: input.quantity,
    ...(input.note === undefined ? {} : { note: input.note }),
    createdAt: new Date().toISOString(),
    createdBy: caller.subject,
  };

  await client.send(
    new PutCommand({
      TableName: TABLE,
      Item: record,
      // Idempotency and a guard against a UUID collision overwriting a real
      // order. Cheap, and the failure mode it prevents is silent data loss.
      ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
    }),
  );

  log({
    event: "order.created",
    outcome: "ok",
    subject: caller.subject,
    tenantId: caller.tenantId,
    resourceId: orderId,
    statusCode: 201,
    requestId,
  });

  return respond(201, { orderId, createdAt: record.createdAt });
}

async function getOrder(
  event: APIGatewayProxyEvent,
  caller: Caller,
  requestId?: string,
): Promise<APIGatewayProxyResult> {
  const orderId = event.pathParameters?.orderId;
  if (!orderId) throw new InvalidRequest("orderId is required");

  // Fetched by the caller's own partition key. The subsequent assertOwns is
  // therefore belt-and-braces against a future change to this query — and it
  // is the branch that turns a cross-tenant attempt into a log line.
  const result = await client.send(
    new GetCommand({
      TableName: TABLE,
      Key: { pk: `TENANT#${caller.tenantId}`, sk: `ORDER#${orderId}` },
    }),
  );

  const record = result.Item as OrderRecord | undefined;
  if (!record) {
    log({
      event: "order.read",
      outcome: "refused",
      subject: caller.subject,
      tenantId: caller.tenantId,
      resourceId: orderId,
      statusCode: 404,
      detail: "not found in caller's tenant",
      requestId,
    });
    return respond(404, { message: "Not found" });
  }

  assertOwns(caller, record.tenantId);

  log({
    event: "order.read",
    outcome: "ok",
    subject: caller.subject,
    tenantId: caller.tenantId,
    resourceId: orderId,
    statusCode: 200,
    requestId,
  });

  return respond(200, project(record));
}

async function listOrders(caller: Caller, requestId?: string): Promise<APIGatewayProxyResult> {
  const result = await client.send(
    new QueryCommand({
      TableName: TABLE,
      KeyConditionExpression: "pk = :pk",
      ExpressionAttributeValues: { ":pk": `TENANT#${caller.tenantId}` },
      Limit: 50,
    }),
  );

  const items = ((result.Items ?? []) as OrderRecord[]).map(project);
  log({
    event: "order.list",
    outcome: "ok",
    subject: caller.subject,
    tenantId: caller.tenantId,
    statusCode: 200,
    requestId,
  });
  return respond(200, { orders: items, count: items.length });
}

/**
 * Response projection — OWASP API3, broken object property level authorization.
 *
 * An allowlist, so a column added to the table later is not returned to clients
 * by default. The same principle as the column-level grants in
 * `mcp-servers/rds_readonly_mcp/sql/02-masked-views.sql`: what the caller may
 * see is enumerated, not filtered.
 */
function project(record: OrderRecord): Record<string, unknown> {
  return {
    orderId: record.orderId,
    productId: record.productId,
    quantity: record.quantity,
    note: record.note,
    createdAt: record.createdAt,
  };
}

function handleError(
  error: unknown,
  caller: Caller | undefined,
  requestId: string | undefined,
  durationMs: number,
): APIGatewayProxyResult {
  const detail = error instanceof Error ? error.message : String(error);

  if (error instanceof Unauthenticated) {
    log({ event: "auth.rejected", outcome: "refused", statusCode: 401, detail, requestId, durationMs });
    return respond(401, { message: "Unauthorized" });
  }

  if (error instanceof Forbidden) {
    // The log records the cross-tenant attempt; the caller gets 404. Telling an
    // attacker that an ID exists but belongs to someone else is an enumeration
    // oracle, and the distinction belongs in the audit trail, not the response.
    log({
      event: "authz.cross_tenant_attempt",
      outcome: "refused",
      subject: caller?.subject,
      tenantId: caller?.tenantId,
      statusCode: 404,
      detail,
      requestId,
      durationMs,
    });
    return respond(404, { message: "Not found" });
  }

  if (error instanceof InvalidRequest) {
    log({ event: "request.invalid", outcome: "refused", statusCode: 400, detail, requestId, durationMs });
    return respond(400, { message: "Invalid request", reason: detail });
  }

  // Anything unrecognised: the caller gets nothing beyond a request id. An
  // exception message can carry a table name, a key, or a fragment of data.
  log({
    event: "request.error",
    outcome: "error",
    subject: caller?.subject,
    statusCode: 500,
    detail,
    requestId,
    durationMs,
  });
  return respond(500, { message: "Internal error", requestId });
}
