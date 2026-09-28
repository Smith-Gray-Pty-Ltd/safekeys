package store

import _ "embed"

// Migrations is the embedded v1 schema, applied at boot.
//
// It is idempotent (CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT EXISTS,
// ADD COLUMN IF NOT EXISTS), so startup is safe on an existing database.
//
//go:embed migrations/001_init.sql
var Migrations string

// Migrations002 adds command allowlists to policy rules
// (safekeys/output-control). Idempotent like Migrations.
//
//go:embed migrations/002_policy_commands.sql
var Migrations002 string
