// Package created implements the sidecar's secret-creation path.
//
// It implements .usm/features/lifecycle/secret-creation.usm, and is the one flow
// that touches plaintext. The critical property: plaintext travels from the
// caller directly to the sidecar over the local socket and is encrypted here.
// It never passes through model context, a log, or a tool argument.
//
// The caller supplies a SOURCE (a file path or an explicit byte stream), never a
// literal value in a model-authored argument. That distinction is what keeps a
// model from ever holding the secret.
package created

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	cpclient "github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/cpclient"
	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// KeyWrapper wraps a DEK under a KEK held outside this process.
type KeyWrapper interface {
	Wrap(kid string, dek []byte) (string, error)
	Unwrap(kid, wrapped string) ([]byte, error)
}

// Registry registers a new object's metadata with the control plane and mints a
// token for it. Both operations carry identifiers only.
type Registry interface {
	CreateObject(ctx context.Context, o cpclient.Object) error
	IssueToken(ctx context.Context, sid string, scope []string, aud string, ttl time.Duration, principal string) (*cpclient.TokenInfo, error)
}

// Request asks for a secret to be created.
//
// Exactly one of SourceFile or Value may be set. SourceFile is strongly
// preferred: it is a path the sidecar reads itself, so a model authoring the
// call never has the bytes.
type Request struct {
	ObjectID    string   // optional; generated when empty
	SourceFile  string   // path the sidecar reads (preferred)
	Value       []byte   // explicit bytes; used only by direct CLI/stdio paths
	ContentType string   // hint
	Scope       []string // token scopes to request
	Audience    string   // token audience
	TTL         time.Duration
	Principal   string
	FolderRoot  string // where the ciphertext folder is written
}

// Result is what the caller receives. It contains NO plaintext field — there is
// nowhere for a value to travel.
type Result struct {
	ObjectID string   `json:"object_id"`
	Folder   string   `json:"folder"`
	Token    string   `json:"token"`
	JTI      string   `json:"jti,omitempty"`
	Expires  int64    `json:"expires,omitempty"`
	Scope    []string `json:"scope,omitempty"`
}

// Creator performs secret creation.
type Creator struct {
	Wrapper    KeyWrapper
	KID        string
	Registry   Registry
	FolderRoot string
	// DefaultPrincipal is used when a request does not name one. The control
	// plane requires an owner for attribution, and the sidecar is the component
	// that knows which principal it is acting for.
	DefaultPrincipal string
	// DefaultAudience is used when a request does not name one. It must match
	// the sidecar's own audience so the minted token is usable locally.
	DefaultAudience string
	Now             func() time.Time
}

// Create reads the value, encrypts it, writes the folder, registers the object,
// and mints a token. It returns only a token and a path.
func (c *Creator) Create(ctx context.Context, req Request) (*Result, error) {
	if c.Wrapper == nil || c.Registry == nil {
		return nil, protocol.NewDenial(protocol.ReasonMalformed)
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}

	// ── 1. Obtain the plaintext. It is read HERE, in the sidecar, from a
	// caller-supplied source — never received as a model-authored literal.
	var plaintext []byte
	switch {
	case req.SourceFile != "":
		b, err := os.ReadFile(req.SourceFile)
		if err != nil {
			return nil, protocol.NewDenial(protocol.ReasonMalformed)
		}
		plaintext = b
	case len(req.Value) > 0:
		plaintext = req.Value
	default:
		return nil, protocol.NewDenial(protocol.ReasonMalformed)
	}
	secure := protocol.SecureBufferFrom(plaintext)
	defer secure.Release()
	if secure.Len() == 0 {
		return nil, protocol.NewDenial(protocol.ReasonMalformed)
	}

	// ── 2. Identify the object.
	objID := req.ObjectID
	if objID == "" {
		id, err := protocol.NewID("obj")
		if err != nil {
			return nil, err
		}
		objID = id
	}

	// ── 3. Generate a fresh DEK and encrypt locally. The plaintext is discarded
	// from memory after this point.
	dek, err := protocol.NewDEK()
	if err != nil {
		return nil, err
	}
	defer protocol.Zero(dek)

	ciphertext, err := protocol.EncryptObject(protocol.AlgAES256GCM, dek, secure.Bytes())
	if err != nil {
		return nil, err
	}

	// ── 4. Wrap the DEK under the KEK, which never leaves the key store.
	wrapped, err := c.Wrapper.Wrap(c.KID, dek)
	if err != nil {
		return nil, protocol.NewDenial(protocol.ReasonKeystoreUnreachable)
	}

	// ── 5. Write the folder: ciphertext + manifest + secret-free README.
	root := req.FolderRoot
	if root == "" {
		root = c.FolderRoot
	}
	folderDir := filepath.Join(root, objID)
	contentType := req.ContentType
	if contentType == "" {
		contentType = "text/plain"
	}
	m := &protocol.Manifest{
		Safekeys: protocol.Version,
		Objects: []protocol.ManifestObject{{
			ID: objID, Path: "objects/" + objID + ".enc",
			Alg: protocol.AlgAES256GCM, WrappedKey: wrapped, WrappingKID: c.KID,
			ContentType: contentType,
		}},
	}
	if err := protocol.WriteFolder(folderDir, m, map[string][]byte{objID: ciphertext}, "Safekeys folder for "+objID); err != nil {
		return nil, err
	}

	// ── 6. Register metadata and mint a token. Identifiers only.
	principal := req.Principal
	if principal == "" {
		principal = c.DefaultPrincipal
	}
	if principal == "" {
		// Attribution is required by the control plane, so a request with no
		// principal is malformed rather than silently unowned.
		return nil, protocol.NewDenial(protocol.ReasonMalformed)
	}
	if err := c.Registry.CreateObject(ctx, cpclient.Object{
		ID: objID, FolderID: objID, OwnerPrincipal: principal,
		ContentType: contentType, WrappingKID: c.KID,
	}); err != nil {
		return nil, fmt.Errorf("register object: %w", err)
	}
	scope := req.Scope
	if len(scope) == 0 {
		scope = []string{protocol.ScopeInjectEnv, protocol.ScopeRead}
	}
	audience := req.Audience
	if audience == "" {
		audience = c.DefaultAudience
	}
	if audience == "" {
		return nil, protocol.NewDenial(protocol.ReasonMalformed)
	}
	info, err := c.Registry.IssueToken(ctx, objID, scope, audience, req.TTL, principal)
	if err != nil {
		return nil, fmt.Errorf("issue token: %w", err)
	}

	_ = now
	// The caller receives a token and a path — never the value.
	return &Result{
		ObjectID: objID,
		Folder:   folderDir,
		Token:    info.Token,
		JTI:      info.JTI,
		Expires:  info.Exp,
		Scope:    info.Scope,
	}, nil
}
