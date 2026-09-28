-- Migration 002: command allowlists on policy rules.
--
-- safekeys/output-control: a policy rule may bind the commands a resolve may
-- run — an exact executable path pattern plus argument patterns (path.Match
-- globs). NULL means the rule carries no command restriction; the sidecar's
-- backstop denylist and the MCP deny-by-default rule apply per
-- safekeys/output-control when no commands are set.
--
-- The column is jsonb: an array of {"exec": string, "args": [string...]}.
-- Validation happens on write (API layer) and on read (sidecar's localpolicy
-- parses strictly); a malformed document must fail closed, not be treated as
-- unrestricted.

ALTER TABLE policy_rules
    ADD COLUMN IF NOT EXISTS commands jsonb;

-- Shape check: when present, commands must be an array of objects each
-- carrying a non-empty exec string and (optionally) an array of pattern
-- strings. Applied only to new/updated rows; existing rows have NULL.
ALTER TABLE policy_rules
    DROP CONSTRAINT IF EXISTS policy_commands_shape;
ALTER TABLE policy_rules
    ADD CONSTRAINT policy_commands_shape CHECK (
        commands IS NULL OR
        jsonb_typeof(commands) = 'array' AND
        NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements(commands) AS c
            WHERE jsonb_typeof(c) <> 'object'
               OR NOT (c ->> 'exec' IS NOT NULL AND jsonb_typeof(c -> 'exec') = 'string' AND length(c ->> 'exec') > 0)
               OR NOT (c -> 'args' IS NULL OR jsonb_typeof(c -> 'args') = 'array')
        )
    );