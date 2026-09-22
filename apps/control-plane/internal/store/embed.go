package store

import _ "embed"

// Migrations is the embedded v1 schema, applied at boot.
//
// It is idempotent (CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT EXISTS), so
// startup is safe on an existing database.
//
//go:embed migrations/001_init.sql
var Migrations string
