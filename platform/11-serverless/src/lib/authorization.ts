/**
 * Object-level authorization — the control static analysis cannot see.
 *
 * OWASP API1:2023, Broken Object Level Authorization, is the risk that survives
 * every other control in this repository. The IAM is correct, the code is
 * syntactically fine, the API has an authorizer, the token is valid — and user
 * A can read user B's order by changing an ID in the path.
 *
 * Nothing in a scanner finds that. `checkov` sees infrastructure, `bandit` sees
 * dangerous calls, `cdk-nag` sees the template. All of them pass on a handler
 * that reads whatever ID it was given. The only thing that finds it is a test
 * that authenticates as one tenant and asks for another tenant's resource, and
 * asserts **403 rather than 200** — see `test/security/`.
 *
 * The design decision that makes it hard to get wrong: the tenant is taken from
 * the *authorizer claims*, never from the request. A tenant id in a path, query
 * string, body or header is attacker-controlled. This module has no function
 * that accepts one.
 */

import type { APIGatewayProxyEvent } from "aws-lambda";

export class Unauthenticated extends Error {}
export class Forbidden extends Error {}

export interface Caller {
  /** Subject from the verified token. The only trusted identity in the request. */
  readonly subject: string;
  /** Tenant the caller belongs to, from token claims — never from the request. */
  readonly tenantId: string;
  readonly scopes: readonly string[];
}

/**
 * Extract the caller from the authorizer's claims.
 *
 * Throws rather than returning null. A handler that forgets to check a nullable
 * return still runs; a handler that forgets to catch does not — and the failure
 * is a 500 the monitoring notices rather than an unauthenticated read that
 * nothing notices.
 */
export function callerFrom(event: APIGatewayProxyEvent): Caller {
  const claims = event.requestContext?.authorizer?.claims as
    | Record<string, string>
    | undefined;

  if (!claims?.sub) {
    throw new Unauthenticated("no verified subject on the request");
  }

  // `custom:tenant_id` is set by the identity provider at token issue. If it is
  // absent the token is valid but unusable here, and that is a refusal rather
  // than a default: defaulting a tenant is how one becomes "public".
  const tenantId = claims["custom:tenant_id"];
  if (!tenantId) {
    throw new Unauthenticated("token carries no tenant claim");
  }

  return {
    subject: claims.sub,
    tenantId,
    scopes: (claims.scope ?? "").split(" ").filter(Boolean),
  };
}

/**
 * Assert the caller may act on a resource belonging to `ownerTenantId`.
 *
 * Called *after* the record is fetched, which is deliberate and worth stating
 * because the alternative looks safer and is not. Filtering the query by tenant
 * alone means a miss and a cross-tenant hit are indistinguishable — both return
 * "not found" — so the bug is invisible in tests and in logs. Fetching, then
 * comparing, makes the cross-tenant attempt an observable, alertable event.
 *
 * The response to the caller is still 404, not 403: telling an attacker that an
 * ID exists but belongs to someone else is an enumeration oracle. The
 * distinction is preserved in the log, not in the response.
 */
export function assertOwns(caller: Caller, ownerTenantId: string): void {
  if (caller.tenantId !== ownerTenantId) {
    throw new Forbidden(
      `caller in tenant ${caller.tenantId} attempted access to a resource in ` +
        `tenant ${ownerTenantId}`,
    );
  }
}

export function hasScope(caller: Caller, required: string): boolean {
  return caller.scopes.includes(required);
}
