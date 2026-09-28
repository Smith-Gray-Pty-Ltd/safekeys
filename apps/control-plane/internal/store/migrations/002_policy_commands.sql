-- Migration 002: command allowlists on policy rules.
--
-- safekeys/output-control: a policy rule may bind the commands a resolve may
-- run — an executable path pattern plus argument patterns (path.Match globs).
-- NULL means the rule carries no command restriction; the sidecar's backstop
-- denylist and the MCP deny-by-default rule apply per safekeys/output-control
-- when no commands are set.
--
-- The column is jsonb: an array of {"exec": string, "args": [string...]}.
--
-- Postgres does not allow subqueries in CHECK constraints, so full per-element
-- validation lives in the API layer on write (apps/control-plane
-- handlePutPolicy) and in the sidecar's strict parse on read — a malformed
-- document fails closed, never silently unrestricted. The constraint here
-- pins the top-level shape only: an array (possibly empty).

ALTER TABLE policy_rules
    ADD COLUMN IF NOT EXISTS commands jsonb;

ALTER TABLE policy_rules
    DROP CONSTRAINT IF EXISTS policy_commands_shape;
ALTER TABLE policy_rules
    ADD CONSTRAINT policy_commands_shape CHECK (
        commands IS NULL OR jsonb_typeof(commands) = 'array'
    );