import { redact } from "../../src/lib/logging";

/**
 * The leak assertions, in the same spirit as the 27 over the live MCP
 * transcript in mcp-servers/tests/test_no_pii_leakage.py. A log line is a copy
 * of the data, stored somewhere with different access controls.
 */
describe("log redaction", () => {
  it.each([
    ["personnummer, hyphenated", "patient 19850101-1234 ordered", "[personnummer]"],
    ["personnummer, plain", "id 8501011234 here", "[personnummer]"],
    ["email", "contact alice@example.com now", "[email]"],
    ["card number", "card 4111 1111 1111 1111 used", "[card]"],
    ["AWS access key", "key AKIAIOSFODNN7EXAMPLE leaked", "[aws-key]"],
    ["JWT", "token eyJhbGciOi.eyJzdWIi.SflKxwRJ here", "[jwt]"],
  ])("redacts a %s", (_name, input, token) => {
    const out = redact(input);
    expect(out).toContain(token);
    expect(out).not.toMatch(/19850101-1234|alice@example\.com|4111|AKIAIOSFODNN7EXAMPLE|eyJhbGciOi/);
  });

  it("leaves ordinary text alone", () => {
    expect(redact("order 12 created for product prod-1")).toBe(
      "order 12 created for product prod-1",
    );
  });

  it("redacts every occurrence, not just the first", () => {
    const out = redact("a@x.com and b@y.com");
    expect(out).not.toContain("a@x.com");
    expect(out).not.toContain("b@y.com");
  });
});
