-- Masking at the database, not in the application.
--
-- Masking in Python would mean the raw personnummer crosses the network into
-- the server process, sits in a result buffer, and is one logging statement or
-- one crash dump away from disclosure. Masking in a view means the plaintext
-- never leaves the engine for this role: `mcp_readonly` has no SELECT on the
-- base tables at all.
--
-- `security_barrier` matters and is easy to miss: without it the planner may
-- push a caller-supplied predicate *beneath* the view's own filtering, letting
-- a crafted WHERE clause act as an oracle on the hidden columns. It is the
-- difference between a view that masks and a view that appears to.
--
-- The masks are deterministic (same input -> same output) so joins and
-- distinct-counts still work for analytics, but not reversible without the
-- salt. Analytical utility is preserved; identity is not recoverable.

SET search_path TO pharmacy, public;

-- The salt lives in Secrets Manager in AWS and is injected at deploy time.
-- A hardcoded salt would make the hashes a rainbow-table exercise: the
-- personnummer space is small enough to enumerate exhaustively.
CREATE OR REPLACE FUNCTION pharmacy.mask_token(value text, salt text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT substr(encode(sha256((salt || value)::bytea), 'hex'), 1, 12);
$$;

CREATE OR REPLACE FUNCTION pharmacy.mask_email(value text, salt text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    -- Preserve the domain: useful for aggregate analysis, harmless on its own.
    SELECT pharmacy.mask_token(value, salt) || '@' || split_part(value, '@', 2);
$$;

CREATE OR REPLACE VIEW pharmacy.v_customers_masked
WITH (security_barrier = true) AS
SELECT
    c.id,
    pharmacy.mask_token(c.personnummer,
        coalesce(current_setting('pharmacy.mask_salt', true), 'dev-only-salt')) AS personnummer_masked,
    -- Given name only. A full name plus a postal code is re-identifying in a
    -- country of ten million people.
    split_part(c.full_name, ' ', 1)                                             AS given_name,
    pharmacy.mask_email(c.email,
        coalesce(current_setting('pharmacy.mask_salt', true), 'dev-only-salt')) AS email_masked,
    -- Last two digits only: enough to confirm a match, not enough to dial.
    CASE WHEN c.phone IS NULL THEN NULL
         ELSE '+46*******' || right(c.phone, 2) END                             AS phone_masked,
    -- Postal code truncated to the 3-digit district. Full codes in sparse
    -- rural areas can identify a single household.
    left(c.postal_code, 3) || 'XX'                                              AS postal_district,
    c.city,
    c.created_at
FROM pharmacy.customers c;

-- `security_invoker = true` (PostgreSQL 15+) is the fix for a real bypass this
-- repository hit and captured. Without it the view executes as its OWNER; the
-- owner here is a superuser, superusers bypass RLS unconditionally, and the
-- consent policy on the base table was therefore never evaluated. The DDL
-- looked correct and enforced nothing.
--
-- With security_invoker the view runs as the calling role, so RLS applies.
-- The trade-off is that the caller now needs privileges on the base table —
-- which is why 01-roles.sql grants SELECT at COLUMN level, withholding
-- prescriber_hsa_id and consent_analytics. Row filtering and column filtering
-- are both enforced by the engine; the view only handles masking and
-- generalisation on top.
CREATE OR REPLACE VIEW pharmacy.v_prescriptions_masked
WITH (security_barrier = true, security_invoker = true) AS
SELECT
    p.id,
    p.customer_id,
    p.medication,
    p.dosage,
    -- Date generalised to the month. Exact prescription dates combined with a
    -- postal district are a well-known re-identification vector.
    date_trunc('month', p.issued_at)::date                                      AS issued_month
    --
    -- NOTE — prescriber_hsa_id is deliberately absent, not merely masked.
    -- Under `security_invoker` the view reads with the CALLER's privileges, so
    -- emitting a masked prescriber would require granting the caller SELECT on
    -- the raw column — and a column the agent can read is a column the agent
    -- can read directly from the base table, mask or no mask.
    --
    -- The trade-off is explicit: we lose per-prescriber analytics through this
    -- path in exchange for the prescriber's identity being unreachable rather
    -- than obfuscated. If that analytic need is real, the correct answer is a
    -- SECURITY DEFINER aggregate function returning counts only — never a
    -- row-level column grant.
FROM pharmacy.prescriptions p;   -- RLS on the base table now genuinely applies

GRANT SELECT ON pharmacy.v_customers_masked     TO mcp_readonly;
GRANT SELECT ON pharmacy.v_prescriptions_masked TO mcp_readonly;

-- The mask functions are SECURITY INVOKER (the default) on purpose: they must
-- not become a way to run code with the owner's privileges.
GRANT EXECUTE ON FUNCTION pharmacy.mask_token(text, text) TO mcp_readonly;
GRANT EXECUTE ON FUNCTION pharmacy.mask_email(text, text) TO mcp_readonly;
