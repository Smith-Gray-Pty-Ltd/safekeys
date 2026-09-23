// Package cpclient is the control-plane HTTP client, shared by the CLI and the
// sidecar.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client talks to the control plane.
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// New builds a client.
func New(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

// Object is control-plane object metadata.
type Object struct {
	ID             string `json:"id"`
	FolderID       string `json:"folder_id"`
	OwnerPrincipal string `json:"owner_principal"`
	ContentType    string `json:"content_type"`
	WrappingKID    string `json:"wrapping_kid"`
	CreatedAt      string `json:"created_at"`
}

// TokenInfo is the response to a token issuance.
type TokenInfo struct {
	Token string   `json:"token"`
	JTI   string   `json:"jti"`
	SID   string   `json:"sid"`
	Aud   string   `json:"aud"`
	Scope []string `json:"scope"`
	Exp   int64    `json:"exp"`
}

// AuditEvent is an audit record.
type AuditEvent struct {
	ID        int64  `json:"ID"`
	At        string `json:"At"`
	Event     string `json:"Event"`
	JTI       string `json:"JTI"`
	SID       string `json:"SID"`
	Principal string `json:"Principal"`
	Outcome   string `json:"Outcome"`
	Reason    string `json:"Reason"`
}

// CreateObject registers an object's metadata.
func (c *Client) CreateObject(ctx context.Context, o Object) error {
	body := map[string]string{
		"id": o.ID, "folder_id": o.FolderID, "owner_principal": o.OwnerPrincipal,
		"content_type": o.ContentType, "wrapping_kid": o.WrappingKID,
	}
	return c.do(ctx, "POST", "/v1/objects", body, nil)
}

// ListObjects returns registered objects.
func (c *Client) ListObjects(ctx context.Context, principal string) ([]Object, error) {
	path := "/v1/objects"
	if principal != "" {
		path += "?principal=" + principal
	}
	var out struct {
		Objects []Object `json:"objects"`
	}
	if err := c.do(ctx, "GET", path, nil, &out); err != nil {
		return nil, err
	}
	return out.Objects, nil
}

// IssueToken requests a capability token. Note it sends identifiers only: there
// is no field for a secret value.
func (c *Client) IssueToken(ctx context.Context, sid string, scope []string, aud string, ttl time.Duration, principal string) (*TokenInfo, error) {
	body := map[string]any{
		"sid": sid, "scope": scope, "aud": aud,
		"ttl_seconds": int(ttl.Seconds()), "principal": principal,
	}
	var out TokenInfo
	if err := c.do(ctx, "POST", "/v1/tokens", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokeToken revokes a token by jti.
func (c *Client) RevokeToken(ctx context.Context, jti string) error {
	return c.do(ctx, "DELETE", "/v1/tokens/"+jti, nil, nil)
}

// Audit returns recent audit events.
func (c *Client) Audit(ctx context.Context, sid string) ([]AuditEvent, error) {
	path := "/v1/audit"
	if sid != "" {
		path += "?sid=" + sid
	}
	var out struct {
		Events []AuditEvent `json:"events"`
	}
	if err := c.do(ctx, "GET", path, nil, &out); err != nil {
		return nil, err
	}
	return out.Events, nil
}

// PutPolicy upserts a policy rule.
func (c *Client) PutPolicy(ctx context.Context, rule map[string]any) error {
	return c.do(ctx, "PUT", "/v1/policies", rule, nil)
}

// Healthy reports whether the control plane is reachable.
func (c *Client) Healthy(ctx context.Context) error {
	return c.do(ctx, "GET", "/healthz", nil, nil)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("X-Safekeys-Key", c.APIKey)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		// Never surface a server-provided detail beyond the status: denials are
		// deliberately generic.
		return fmt.Errorf("control plane: %s %s -> %d", method, path, resp.StatusCode)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}
