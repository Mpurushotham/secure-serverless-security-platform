/**
 * Object-level authorization — the risk no scanner finds.
 *
 * OWASP API1:2023. The code is syntactically fine, the IAM is correct, the
 * authorizer is attached, the token is valid — and user A reads user B's order
 * by changing an ID. checkov, bandit and cdk-nag all pass on that handler.
 *
 * These are the tests that do not.
 */

import type { APIGatewayProxyEvent } from "aws-lambda";

import {
  Forbidden,
  Unauthenticated,
  assertOwns,
  callerFrom,
  hasScope,
} from "../../src/lib/authorization";

function event(claims?: Record<string, string>, overrides: object = {}): APIGatewayProxyEvent {
  return {
    requestContext: claims ? { authorizer: { claims } } : {},
    ...overrides,
  } as unknown as APIGatewayProxyEvent;
}

describe("caller identity comes from the token, never the request", () => {
  it("reads the subject and tenant from verified claims", () => {
    const caller = callerFrom(
      event({ sub: "user-1", "custom:tenant_id": "tenant-a", scope: "orders:read orders:write" }),
    );
    expect(caller.subject).toBe("user-1");
    expect(caller.tenantId).toBe("tenant-a");
    expect(caller.scopes).toEqual(["orders:read", "orders:write"]);
  });

  it("refuses a request with no authorizer context", () => {
    expect(() => callerFrom(event())).toThrow(Unauthenticated);
  });

  it("refuses a token with no subject", () => {
    expect(() => callerFrom(event({ "custom:tenant_id": "tenant-a" }))).toThrow(Unauthenticated);
  });

  it("refuses a valid token carrying no tenant claim, rather than defaulting one", () => {
    // Defaulting a tenant is how one of them quietly becomes "public".
    expect(() => callerFrom(event({ sub: "user-1" }))).toThrow(Unauthenticated);
  });

  it("ignores a tenant supplied in the path, query or body", () => {
    // The attack: send a tenant you do not belong to and hope something reads
    // it. There is no code path that does — this asserts the shape stays that
    // way, since the regression would be someone "helpfully" adding one.
    const caller = callerFrom(
      event(
        { sub: "user-1", "custom:tenant_id": "tenant-a" },
        {
          pathParameters: { tenantId: "tenant-b" },
          queryStringParameters: { tenantId: "tenant-b" },
          headers: { "x-tenant-id": "tenant-b" },
          body: JSON.stringify({ tenantId: "tenant-b" }),
        },
      ),
    );
    expect(caller.tenantId).toBe("tenant-a");
  });
});

describe("cross-tenant access is refused", () => {
  const caller = { subject: "user-1", tenantId: "tenant-a", scopes: [] };

  it("allows access to a resource in the caller's own tenant", () => {
    expect(() => assertOwns(caller, "tenant-a")).not.toThrow();
  });

  it("refuses access to a resource in another tenant", () => {
    expect(() => assertOwns(caller, "tenant-b")).toThrow(Forbidden);
  });

  it("names both tenants in the error, because the log is where that belongs", () => {
    // The caller gets 404 — telling an attacker an ID exists but belongs to
    // someone else is an enumeration oracle. The detail goes to the audit
    // trail instead, and this asserts it is actually there to be logged.
    try {
      assertOwns(caller, "tenant-b");
      throw new Error("expected Forbidden");
    } catch (error) {
      expect((error as Error).message).toContain("tenant-a");
      expect((error as Error).message).toContain("tenant-b");
    }
  });

  it("does not treat a tenant id as a prefix match", () => {
    expect(() => assertOwns({ ...caller, tenantId: "tenant-a" }, "tenant-ab")).toThrow(Forbidden);
    expect(() => assertOwns({ ...caller, tenantId: "tenant" }, "tenant-a")).toThrow(Forbidden);
  });
});

describe("scopes", () => {
  it("matches exactly, not by prefix", () => {
    const caller = { subject: "s", tenantId: "t", scopes: ["orders:read"] };
    expect(hasScope(caller, "orders:read")).toBe(true);
    expect(hasScope(caller, "orders:readwrite")).toBe(false);
    expect(hasScope(caller, "orders")).toBe(false);
  });
});
