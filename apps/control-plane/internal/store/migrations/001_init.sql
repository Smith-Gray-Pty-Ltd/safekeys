-- Safekeys control plane schema (v1)
--
-- Implements .usm/services/control-plane-db.usm.
--
-- INVARIANT: no table has a column capable of holding plaintext, an unwrapped
-- DEK, or a KEK. There is deliberately no wrapped_dek column — the wrapped DEK
-- lives in the folder manifest, so the database holds no key-shaped data at all.
-- wrapping_kid is an identifier, not material.

CREATE TABLE IF NOT EXISTS objects (
    id              text PRIMARY KEY,
    folder_id       text,
    owner_principal text NOT NULL,
    content_type    text,
    wrapping_kid    text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz,
    CONSTRAINT objects_id_format CHECK (id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$')
);

CREATE INDEX IF NOT EXISTS objects_owner_idx  ON objects (owner_principal);
CREATE INDEX IF NOT EXISTS objects_folder_idx ON objects (folder_id);

CREATE TABLE IF NOT EXISTS tokens (
    jti        text PRIMARY KEY,
    sid        text NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    iss        text NOT NULL,
    sub        text,
    scope      text[] NOT NULL,
    aud        text NOT NULL,
    nbf        timestamptz NOT NULL,
    exp        timestamptz NOT NULL,
    issued_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CONSTRAINT tokens_jti_format CHECK (jti ~ '^[A-Za-z0-9_-]+$'),
    CONSTRAINT tokens_scope_nonempty CHECK (array_length(scope, 1) >= 1),
    CONSTRAINT tokens_time_order CHECK (nbf <= exp),
    CONSTRAINT tokens_scope_closed CHECK (
        scope <@ ARRAY['read','unwrap','inject-env','inject-file','sign']::text[]
    )
);

CREATE INDEX IF NOT EXISTS tokens_sid_idx ON tokens (sid);
CREATE INDEX IF NOT EXISTS tokens_exp_idx ON tokens (exp);

-- The denylist lookup that runs on every resolve. Partial so it stays small:
-- it holds only actively revoked ids, which is why v1 stores a denylist rather
-- than an allowlist of live tokens.
CREATE INDEX IF NOT EXISTS tokens_revoked_idx ON tokens (jti) WHERE revoked_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS audit (
    id        bigserial PRIMARY KEY,
    at        timestamptz NOT NULL DEFAULT now(),
    event     text NOT NULL,
    jti       text,
    sid       text,
    principal text,
    host      text,
    scope     text,
    outcome   text NOT NULL,
    reason    text,
    detail    jsonb,
    CONSTRAINT audit_event_closed CHECK (
        event IN ('issue','revoke','resolve','deny','policy_deny')
    ),
    CONSTRAINT audit_outcome_closed CHECK (outcome IN ('allowed','denied'))
);

CREATE INDEX IF NOT EXISTS audit_sid_idx ON audit (sid);
CREATE INDEX IF NOT EXISTS audit_jti_idx ON audit (jti);
CREATE INDEX IF NOT EXISTS audit_at_idx  ON audit (at);

-- Immutability by grant, not by convention. A compromised application cannot
-- rewrite history. (Roles are created by the bootstrap migration.)
REVOKE UPDATE, DELETE ON audit FROM PUBLIC;

CREATE TABLE IF NOT EXISTS policy_rules (
    id               text PRIMARY KEY,
    effect           text NOT NULL,
    principal        text,
    sid              text,
    scope            text[] NOT NULL,
    aud              text,
    injection_method text,
    priority         integer NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT policy_effect_closed CHECK (effect IN ('allow','deny')),
    CONSTRAINT policy_scope_nonempty CHECK (array_length(scope, 1) >= 1),
    CONSTRAINT policy_scope_closed CHECK (
        scope <@ ARRAY['read','unwrap','inject-env','inject-file','sign']::text[]
    ),
    CONSTRAINT policy_injection_closed CHECK (
        injection_method IS NULL OR injection_method IN ('env','file','socket','exec')
    )
);

CREATE INDEX IF NOT EXISTS policy_priority_idx ON policy_rules (priority DESC);
