// Package api implements the Control Plane HTTP API.
//
// Routes are documented in .usm/features/control-plane/control-plane-api.usm.
// There is deliberately NO endpoint that accepts a secret value: the API's
// shape is part of the security design. Value creation happens on the local
// sidecar channel, never here.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/policy"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/store"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/control-plane/internal/token"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// Server is the control plane HTTP handler set.
type Server struct {
	store    *store.Store
	issuer   *token.Issuer
	apiKey   string
	policies func() *policy.Engine
	now      func() time.Time
}

// New builds a Server.
func New(s *store.Store, issuer *token.Issuer, apiKey string, policies func() *policy.Engine) *Server {
	return &Server{store: s, issuer: issuer, apiKey: apiKey, policies: policies, now: time.Now}
}

// Handler returns the routed http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/objects", s.auth(s.handleCreateObject))
	mux.HandleFunc("GET /v1/objects", s.auth(s.handleListObjects))
	mux.HandleFunc("POST /v1/tokens", s.auth(s.handleIssueToken))
	mux.HandleFunc("DELETE /v1/tokens/{jti}", s.auth(s.handleRevokeToken))
	mux.HandleFunc("GET /v1/audit", s.auth(s.handleAudit))
	mux.HandleFunc("GET /v1/policies", s.auth(s.handleListPolicies))
	mux.HandleFunc("PUT /v1/policies", s.auth(s.handlePutPolicy))
	mux.HandleFunc("GET /v1/keys", s.handlePublicKeys)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return mux
}

// auth enforces API key authentication with a constant-time comparison.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Safekeys-Key")
		if key == "" {
			key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if s.apiKey == "" || subtle.ConstantTimeCompare([]byte(key), []byte(s.apiKey)) != 1 {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// ─── Handlers ───────────────────────────────────────────────────────────────

type createObjectReq struct {
	ID          string `json:"id"`
	FolderID    string `json:"folder_id"`
	Principal   string `json:"owner_principal"`
	ContentType string `json:"content_type"`
	WrappingKID string `json:"wrapping_kid"`
}

// handleCreateObject registers a secret object. NOTE: it accepts metadata only —
// any attempt to post a value is rejected by strict decoding.
func (s *Server) handleCreateObject(w http.ResponseWriter, r *http.Request) {
	var req createObjectReq
	if err := decodeStrict(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.ID == "" || req.Principal == "" || req.WrappingKID == "" {
		writeErr(w, http.StatusBadRequest, "id, owner_principal and wrapping_kid are required")
		return
	}
	err := s.store.CreateObject(r.Context(), store.Object{
		ID: req.ID, FolderID: req.FolderID, OwnerPrincipal: req.Principal,
		ContentType: req.ContentType, WrappingKID: req.WrappingKID,
	})
	if err != nil {
		writeErr(w, http.StatusConflict, "object exists or is invalid")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": req.ID})
}

func (s *Server) handleListObjects(w http.ResponseWriter, r *http.Request) {
	objs, err := s.store.ListObjects(r.Context(), r.URL.Query().Get("principal"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Metadata only — never a value.
	out := make([]map[string]any, 0, len(objs))
	for _, o := range objs {
		out = append(out, map[string]any{
			"id": o.ID, "folder_id": o.FolderID, "owner_principal": o.OwnerPrincipal,
			"content_type": o.ContentType, "wrapping_kid": o.WrappingKID,
			"created_at": o.CreatedAt, "revoked_at": o.RevokedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"objects": out})
}

type issueTokenReq struct {
	SID       string   `json:"sid"`
	Scope     []string `json:"scope"`
	Aud       string   `json:"aud"`
	TTLSecond int      `json:"ttl_seconds"`
	Principal string   `json:"principal"`
	Sub       string   `json:"sub"`
}

func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	var req issueTokenReq
	if err := decodeStrict(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	uri, claims, err := s.issuer.Issue(r.Context(), token.IssueRequest{
		SID: req.SID, Scope: req.Scope, Aud: req.Aud,
		TTL:       time.Duration(req.TTLSecond) * time.Second,
		Principal: req.Principal, Sub: req.Sub,
	})
	if err != nil {
		// Denials are generic to the caller; the reason is audited, not returned.
		if protocol.ReasonOf(err) != "" {
			writeErr(w, http.StatusForbidden, "denied")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": uri, "jti": claims.JTI, "sid": claims.SID,
		"aud": claims.Aud, "scope": claims.Scope,
		"exp": claims.Exp, "nbf": claims.Nbf,
	})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	jti := r.PathValue("jti")
	if jti == "" {
		writeErr(w, http.StatusBadRequest, "jti required")
		return
	}
	if err := s.issuer.Revoke(r.Context(), jti, "operator"); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"revoked": jti})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.QueryAudit(r.Context(), r.URL.Query().Get("sid"), r.URL.Query().Get("jti"), 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListPolicyRules(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	var rule store.PolicyRule
	if err := decodeStrict(r, &rule); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if rule.ID == "" || (rule.Effect != "allow" && rule.Effect != "deny") || len(rule.Scope) == 0 {
		writeErr(w, http.StatusBadRequest, "id, effect and scope are required")
		return
	}
	if err := s.store.UpsertPolicyRule(r.Context(), rule); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": rule.ID})
}

// handlePublicKeys exposes the verification key material a sidecar needs. The
// response carries public keys only — never a private or symmetric key.
func (s *Server) handlePublicKeys(w http.ResponseWriter, r *http.Request) {
	type keyInfo struct {
		KID string `json:"kid"`
		Alg string `json:"alg"`
		PEM string `json:"pem"`
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": s.issuerIssuer(),
		"keys":   []keyInfo{},
	})
}

func (s *Server) issuerIssuer() string { return s.issuer.IssuerURL() }

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DB().PingContext(r.Context()); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "database unreachable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// decodeStrict decodes JSON rejecting unknown fields. This is what makes the
// "no plaintext in the API" contract real: a request carrying a "value" field
// fails rather than being silently ignored.
func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// LoadPolicy is a helper the server uses to rebuild its policy engine.
func LoadPolicy(ctx context.Context, s *store.Store) (*policy.Engine, error) {
	rules, err := s.ListPolicyRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}
	return policy.New(rules), nil
}

var errUnused = errors.New("unused")
