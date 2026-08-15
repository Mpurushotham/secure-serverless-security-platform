import { InvalidRequest, parseOrder } from "../../src/lib/validation";

describe("request validation", () => {
  const valid = JSON.stringify({ productId: "prod-123", quantity: 2 });

  it("accepts a well-formed order", () => {
    expect(parseOrder(valid)).toEqual({ productId: "prod-123", quantity: 2 });
  });

  it.each([
    ["empty body", null],
    ["not JSON", "{nope"],
    ["a JSON array", "[]"],
    ["a bare string", '"hello"'],
    ["missing productId", JSON.stringify({ quantity: 1 })],
    ["missing quantity", JSON.stringify({ productId: "prod-1" })],
    ["non-integer quantity", JSON.stringify({ productId: "prod-1", quantity: 1.5 })],
    ["quantity below range", JSON.stringify({ productId: "prod-1", quantity: 0 })],
    ["quantity above range", JSON.stringify({ productId: "prod-1", quantity: 101 })],
    ["quantity as string", JSON.stringify({ productId: "prod-1", quantity: "2" })],
    ["productId too short", JSON.stringify({ productId: "ab", quantity: 1 })],
    ["productId with a slash", JSON.stringify({ productId: "../../etc", quantity: 1 })],
    ["productId with a space", JSON.stringify({ productId: "prod 1", quantity: 1 })],
  ])("refuses %s", (_name, body) => {
    expect(() => parseOrder(body as string | null)).toThrow(InvalidRequest);
  });

  it("refuses an oversized body before parsing it", () => {
    // Parsing first would mean spending CPU on whatever was sent.
    expect(() => parseOrder("x".repeat(17 * 1024))).toThrow(/too large/);
  });

  it("refuses a note beyond the maximum", () => {
    const body = JSON.stringify({ productId: "prod-1", quantity: 1, note: "x".repeat(501) });
    expect(() => parseOrder(body)).toThrow(InvalidRequest);
  });

  it("drops fields it does not know about", () => {
    // OWASP API3, mass assignment. An allowlist, so a column added to the table
    // later cannot be set by a client that guesses its name.
    const body = JSON.stringify({
      productId: "prod-1",
      quantity: 1,
      tenantId: "tenant-b",
      isAdmin: true,
      price: 0,
    });
    expect(parseOrder(body)).toEqual({ productId: "prod-1", quantity: 1 });
  });
});
