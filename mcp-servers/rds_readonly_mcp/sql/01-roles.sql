-- The last line of defence: a database role the agent cannot escape.
--
-- Everything in guardrails.py is bypassable in principle — a parser bug, an
-- unescaped path, a logic error. This file is what holds when that happens.
-- If the application layer is fully compromised, `mcp_readonly` still cannot
-- write, cannot read secrets, and cannot run for more than five seconds.
--
-- Design decisions worth defending in review:
--
--   NOINHERIT            -- the role does not silently absorb privileges from
--                           any role it is later granted. Privilege creep via
--                           group membership is how "read-only" accounts stop
--                           being read-only over time.
--   No table-level SELECT on customers/prescriptions -- the agent reads the
--                           MASKED VIEWS only. Access to raw PII is not
--                           guarded, it is absent.
--   RLS on prescriptions -- consent is enforced by the engine, not by a WHERE
--                           clause the agent could omit. GDPR Art. 6/9 lawful
--                           basis becomes a row filter.
--   statement_timeout    -- bounds "SELECT * FROM huge_table CROSS JOIN ..."
--                           as both a DoS and an exfiltration primitive.
--   default_transaction_read_only -- belt and braces with the missing grants.

SET search_path TO pharmacy, public;

-- Password is injected by the harness; never literal in version control.
-- In AWS this role authenticates with IAM database authentication instead
-- (rds_iam), so no password exists to leak. See 03-aurora-notes.sql.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mcp_readonly') THEN
        EXECUTE format(
            'CREATE ROLE mcp_readonly LOGIN NOINHERIT PASSWORD %L',
            coalesce(current_setting('custom.mcp_password', true), 'change-me-in-harness')
        );
    END IF;
END
$$;

-- Strip the PUBLIC pseudo-role first. By default every role can create objects
-- in `public` and connect to every database; least privilege starts by taking
-- that back rather than by adding grants on top of it.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE pharmadb FROM PUBLIC;

GRANT CONNECT ON DATABASE pharmadb TO mcp_readonly;
GRANT USAGE   ON SCHEMA pharmacy   TO mcp_readonly;

-- Explicitly NOT granted: CREATE on any schema, TEMPORARY on the database,
-- EXECUTE on functions, and SELECT on customers / prescriptions base tables.

-- Non-sensitive operational tables: direct SELECT is fine.
GRANT SELECT ON pharmacy.products    TO mcp_readonly;
GRANT SELECT ON pharmacy.orders      TO mcp_readonly;
GRANT SELECT ON pharmacy.order_items TO mcp_readonly;

-- Row-level security: consent as an engine-enforced filter.
ALTER TABLE pharmacy.prescriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pharmacy.prescriptions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS prescriptions_analytics_consent ON pharmacy.prescriptions;
CREATE POLICY prescriptions_analytics_consent
    ON pharmacy.prescriptions
    FOR SELECT
    TO mcp_readonly
    USING (consent_analytics = true);

-- COLUMN-LEVEL grants on prescriptions.
--
-- This pairs with `security_invoker = true` on v_prescriptions_masked and the
-- combination is load-bearing. A view normally executes with its OWNER's
-- privileges; because these objects are owned by a superuser, RLS was silently
-- bypassed when read through the view — the policy above existed and did
-- nothing. The first run of scripts/db_privilege_proof.sh caught exactly that:
-- all four prescription rows were visible, including the two without consent.
--
-- With security_invoker the view runs as `mcp_readonly`, so the policy applies
-- — but the invoker then needs its own privileges on the base table. Granting
-- SELECT at COLUMN level rather than table level keeps the sensitive columns
-- unreachable while letting RLS do its job:
--   * prescriber_hsa_id  -- withheld: the prescriber is a natural person too
--   * consent_analytics  -- withheld: never let the filter column be read, or
--                           its absence becomes an oracle for the hidden rows
GRANT SELECT (id, customer_id, medication, dosage, issued_at)
    ON pharmacy.prescriptions TO mcp_readonly;

-- Session limits. ALTER ROLE ... SET applies on every login for this role, so
-- the agent cannot opt out the way a per-session SET would allow.
ALTER ROLE mcp_readonly SET statement_timeout = '5s';
ALTER ROLE mcp_readonly SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE mcp_readonly SET default_transaction_read_only = on;
ALTER ROLE mcp_readonly SET search_path = 'pharmacy';
-- Do not let the agent's queries be logged with their parameter values into a
-- log file that has weaker access controls than the table itself.
ALTER ROLE mcp_readonly SET log_statement = 'none';

-- Future tables must be opted IN, never inherited by default. Without this,
-- tomorrow's `CREATE TABLE patient_notes` is silently readable by the agent.
ALTER DEFAULT PRIVILEGES IN SCHEMA pharmacy REVOKE ALL ON TABLES FROM mcp_readonly;
