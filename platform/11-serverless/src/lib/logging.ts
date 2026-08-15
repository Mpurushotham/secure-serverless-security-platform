/**
 * Structured logging that cannot accidentally emit personal data.
 *
 * The rule from docs/04-ai-secure-coding-policy.md and the AWS guidance both:
 * never put customer content in a log line. The usual implementation is a
 * convention plus a code review, which holds until the day someone logs the
 * whole request object while debugging and nobody notices in the diff.
 *
 * So this module has no function that accepts arbitrary objects. `log()` takes
 * a fixed set of fields, and anything free-form goes through `redact()` first.
 * Making the unsafe thing unavailable is more durable than documenting it.
 */

const REDACTIONS: Array<[RegExp, string]> = [
  // Swedish personal identity numbers, the Art. 9 identifier in this domain.
  [/\b\d{6,8}[-+]?\d{4}\b/g, "[personnummer]"],
  [/\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b/g, "[email]"],
  // Payment card shapes, before Luhn — a false positive costs nothing here.
  [/\b(?:\d[ -]?){13,19}\b/g, "[card]"],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b/g, "[aws-key]"],
  [/\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/g, "[jwt]"],
];

export function redact(value: string): string {
  return REDACTIONS.reduce((acc, [pattern, token]) => acc.replace(pattern, token), value);
}

export interface LogFields {
  readonly event: string;
  readonly outcome: "ok" | "refused" | "error";
  /** Subject from the token. An opaque identifier, not a name or an email. */
  readonly subject?: string;
  readonly tenantId?: string;
  readonly resourceId?: string;
  readonly statusCode?: number;
  readonly durationMs?: number;
  /** Free-form. Redacted before emission. */
  readonly detail?: string;
  readonly requestId?: string;
}

export function log(fields: LogFields): void {
  const line = {
    ...fields,
    detail: fields.detail ? redact(fields.detail) : undefined,
    ts: new Date().toISOString(),
  };
  // One JSON object per line: CloudWatch parses it, and a metric filter can
  // count `outcome="refused"` without a regex over prose.
  process.stdout.write(JSON.stringify(line) + "\n");
}
