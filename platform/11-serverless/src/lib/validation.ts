/**
 * Request validation, applied before anything touches storage.
 *
 * API Gateway request models reject malformed JSON at the edge, which is the
 * right first layer. This is the second: the function validates again, because
 * the model can be edited, a new route can be added without one, and a direct
 * invoke bypasses the API entirely.
 *
 * The ecommerce-platform reference makes this point about unit tests covering
 * "unreachable" defensive branches, and it applies to the branch itself: the
 * check should exist even where the platform is expected to make it
 * unreachable. See platform/docs/references.md.
 */

export class InvalidRequest extends Error {}

export interface OrderInput {
  readonly productId: string;
  readonly quantity: number;
  readonly note?: string;
}

const PRODUCT_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$/;
const MAX_NOTE = 500;

export function parseOrder(body: string | null): OrderInput {
  if (!body) throw new InvalidRequest("empty body");
  if (body.length > 16 * 1024) throw new InvalidRequest("body too large");

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new InvalidRequest("body is not valid JSON");
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new InvalidRequest("body must be a JSON object");
  }

  const input = parsed as Record<string, unknown>;

  const productId = input.productId;
  if (typeof productId !== "string" || !PRODUCT_ID.test(productId)) {
    throw new InvalidRequest("productId must match ^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$");
  }

  const quantity = input.quantity;
  if (typeof quantity !== "number" || !Number.isInteger(quantity)) {
    throw new InvalidRequest("quantity must be an integer");
  }
  if (quantity < 1 || quantity > 100) {
    throw new InvalidRequest("quantity must be between 1 and 100");
  }

  const note = input.note;
  if (note !== undefined) {
    if (typeof note !== "string") throw new InvalidRequest("note must be a string");
    if (note.length > MAX_NOTE) throw new InvalidRequest(`note exceeds ${MAX_NOTE} characters`);
  }

  // Only the fields named above survive. Anything else the client sent is
  // dropped rather than stored — mass assignment is OWASP API3, and the fix is
  // an allowlist, not a denylist of fields somebody remembered.
  return { productId, quantity, ...(note === undefined ? {} : { note }) };
}
