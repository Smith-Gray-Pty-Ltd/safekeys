// Package store is the Postgres persistence layer for the control plane.
//
// It implements the data model in .usm/services/control-plane-db.usm. The
// central invariant: no table has a column capable of holding plaintext, an
// unwrapped DEK, or a KEK. The audit table is append-only — immutability is
// enforced by database grant, not by application convention.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the database handle.
type Store struct{ db *sql.DB }

// New wraps an open *sql.DB.
func New(db *sql.DB) *Store { return &Store{db: db} }

// DB exposes the handle for migrations and health checks.
func (s *Store) DB() *sql.DB { return s.db }

// ─── Domain types ───────────────────────────────────────────────────────────

// Object is a registered secret object. See control-plane-db: objects.
type Object struct {
	ID             string
	FolderID       string
	OwnerPrincipal string
	ContentType    string
	WrappingKID    string
	CreatedAt      time.Time
	RevokedAt      *time.Time
}

// Token is an issued capability token record. See control-plane-db: tokens.
//
// Note there is no plaintext or key material here; the wrapped DEK lives in the
// folder manifest and the KEK lives in the key store.
type Token struct {
	JTI       string
	SID       string
	Iss       string
	Sub       string
	Scope     []string
	Aud       string
	Nbf       time.Time
	Exp       time.Time
	IssuedAt  time.Time
	RevokedAt *time.Time
}

// AuditEvent is one append-only record. Metadata only — never a secret.
type AuditEvent struct {
	ID        int64
	At        time.Time
	Event     string
	JTI       string
	SID       string
	Principal string
	Host      string
	Scope     string
	Outcome   string
	Reason    string
	Detail    map[string]any
}

// PolicyRule is a resolution policy rule. See control-plane-db: policy_rules.
type PolicyRule struct {
	ID              string
	Effect          string // "allow" | "deny"
	Principal       string
	SID             string
	Scope           []string
	Aud             string
	InjectionMethod string
	Priority        int
	CreatedAt       time.Time
}

// Audit event names.
const (
	EventIssue      = "issue"
	EventRevoke     = "revoke"
	EventResolve    = "resolve"
	EventDeny       = "deny"
	EventPolicyDeny = "policy_deny"
)

// ─── Objects ────────────────────────────────────────────────────────────────

// CreateObject registers a new secret object.
func (s *Store) CreateObject(ctx context.Context, o Object) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO objects (id, folder_id, owner_principal, content_type, wrapping_kid)
		VALUES ($1, NULLIF($2,''), $3, NULLIF($4,''), $5)`,
		o.ID, o.FolderID, o.OwnerPrincipal, o.ContentType, o.WrappingKID)
	return err
}

// GetObject loads an object by id.
func (s *Store) GetObject(ctx context.Context, id string) (*Object, error) {
	var o Object
	err := s.db.QueryRowContext(ctx, `
		SELECT id, COALESCE(folder_id,''), owner_principal, COALESCE(content_type,''),
		       wrapping_kid, created_at, revoked_at
		FROM objects WHERE id = $1`, id).
		Scan(&o.ID, &o.FolderID, &o.OwnerPrincipal, &o.ContentType, &o.WrappingKID, &o.CreatedAt, &o.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// ListObjects returns objects owned by principal (all when principal is "").
func (s *Store) ListObjects(ctx context.Context, principal string) ([]Object, error) {
	q := `SELECT id, COALESCE(folder_id,''), owner_principal, COALESCE(content_type,''),
	             wrapping_kid, created_at, revoked_at FROM objects`
	var args []any
	if principal != "" {
		q += ` WHERE owner_principal = $1`
		args = append(args, principal)
	}
	q += ` ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Object
	for rows.Next() {
		var o Object
		if err := rows.Scan(&o.ID, &o.FolderID, &o.OwnerPrincipal, &o.ContentType, &o.WrappingKID, &o.CreatedAt, &o.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ─── Tokens ─────────────────────────────────────────────────────────────────

// CreateToken records an issued token.
func (s *Store) CreateToken(ctx context.Context, t Token) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tokens (jti, sid, iss, sub, scope, aud, nbf, exp, issued_at)
		VALUES ($1, $2, $3, NULLIF($4,''), $5, $6, $7, $8, $9)`,
		t.JTI, t.SID, t.Iss, t.Sub, t.Scope, t.Aud, t.Nbf, t.Exp, t.IssuedAt)
	return err
}

// RevokeToken sets revoked_at on a token. Idempotent: revoking an
// already-revoked jti is not an error — see contract idempotent-issue-and-revoke.
func (s *Store) RevokeToken(ctx context.Context, jti string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE tokens SET revoked_at = now()
		WHERE jti = $1 AND revoked_at IS NULL`, jti)
	return err
}

// IsRevoked reports whether a jti is on the denylist. This is the lookup that
// runs on every resolve; it is served by the partial index
// `tokens(jti) WHERE revoked_at IS NOT NULL`.
func (s *Store) IsRevoked(ctx context.Context, jti string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM tokens WHERE jti=$1 AND revoked_at IS NOT NULL`, jti).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ListTokens returns tokens for an object (all when sid is "").
func (s *Store) ListTokens(ctx context.Context, sid string) ([]Token, error) {
	q := `SELECT jti, sid, iss, COALESCE(sub,''), scope, aud, nbf, exp, issued_at, revoked_at FROM tokens`
	var args []any
	if sid != "" {
		q += ` WHERE sid = $1`
		args = append(args, sid)
	}
	q += ` ORDER BY issued_at DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.JTI, &t.SID, &t.Iss, &t.Sub, &t.Scope, &t.Aud, &t.Nbf, &t.Exp, &t.IssuedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ─── Policy ─────────────────────────────────────────────────────────────────

// UpsertPolicyRule inserts or replaces a policy rule.
func (s *Store) UpsertPolicyRule(ctx context.Context, r PolicyRule) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO policy_rules (id, effect, principal, sid, scope, aud, injection_method, priority)
		VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),$5,NULLIF($6,''),NULLIF($7,''),$8)
		ON CONFLICT (id) DO UPDATE SET
			effect=EXCLUDED.effect, principal=EXCLUDED.principal, sid=EXCLUDED.sid,
			scope=EXCLUDED.scope, aud=EXCLUDED.aud,
			injection_method=EXCLUDED.injection_method, priority=EXCLUDED.priority`,
		r.ID, r.Effect, r.Principal, r.SID, r.Scope, r.Aud, r.InjectionMethod, r.Priority)
	return err
}

// ListPolicyRules returns rules ordered for evaluation (highest priority first).
func (s *Store) ListPolicyRules(ctx context.Context) ([]PolicyRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, effect, COALESCE(principal,''), COALESCE(sid,''), scope,
		       COALESCE(aud,''), COALESCE(injection_method,''), priority, created_at
		FROM policy_rules ORDER BY priority DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicyRule
	for rows.Next() {
		var r PolicyRule
		if err := rows.Scan(&r.ID, &r.Effect, &r.Principal, &r.SID, &r.Scope, &r.Aud, &r.InjectionMethod, &r.Priority, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ─── Audit ──────────────────────────────────────────────────────────────────

// AppendAudit writes an append-only audit record.
//
// secretShapedKeys are rejected before insert so a caller cannot accidentally
// persist a value in detail — defence in depth for the invariant that the audit
// log never contains secret material.
func (s *Store) AppendAudit(ctx context.Context, e AuditEvent) error {
	if err := validateDetail(e.Detail); err != nil {
		return err
	}
	var detail any
	if len(e.Detail) > 0 {
		b, err := json.Marshal(e.Detail)
		if err != nil {
			return err
		}
		detail = b
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit (at, event, jti, sid, principal, host, scope, outcome, reason, detail)
		VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),$8,NULLIF($9,''),$10)`,
		e.At, e.Event, e.JTI, e.SID, e.Principal, e.Host, e.Scope, e.Outcome, e.Reason, detail)
	return err
}

// secretShapedDetailKeys must never appear in an audit detail payload.
var secretShapedDetailKeys = []string{
	"value", "secret", "plaintext", "dek", "kek", "unwrapped_key", "master_key", "password", "token",
}

func validateDetail(d map[string]any) error {
	for k := range d {
		for _, bad := range secretShapedDetailKeys {
			if equalFoldASCII(k, bad) {
				return fmt.Errorf("audit detail may not contain secret-shaped key %q", k)
			}
		}
	}
	return nil
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// QueryAudit returns audit records matching the filter.
func (s *Store) QueryAudit(ctx context.Context, sid, jti string, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := `SELECT id, at, event, COALESCE(jti,''), COALESCE(sid,''), COALESCE(principal,''),
	             COALESCE(host,''), COALESCE(scope,''), outcome, COALESCE(reason,''), detail
	      FROM audit WHERE 1=1`
	var args []any
	if sid != "" {
		args = append(args, sid)
		q += fmt.Sprintf(" AND sid = $%d", len(args))
	}
	if jti != "" {
		args = append(args, jti)
		q += fmt.Sprintf(" AND jti = $%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args))

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var detail []byte
		if err := rows.Scan(&e.ID, &e.At, &e.Event, &e.JTI, &e.SID, &e.Principal, &e.Host, &e.Scope, &e.Outcome, &e.Reason, &detail); err != nil {
			return nil, err
		}
		if len(detail) > 0 {
			_ = json.Unmarshal(detail, &e.Detail)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
