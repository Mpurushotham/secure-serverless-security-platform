/**
 * Normalises the IAM policy-document shape, where `Action` and `Resource` may
 * each be a bare string or an array. Anything that is neither is dropped rather
 * than coerced — an unresolved CDK token in a policy is not a string we can
 * usefully compare, and pretending otherwise produces false confidence.
 */
export function toArray(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
  return [];
}
