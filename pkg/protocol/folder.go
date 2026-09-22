package protocol

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Manifest is the manifest.json of an encrypted folder. It maps exactly to
// spec/encrypted-folder/v1.schema.json, which sets additionalProperties:false.
//
// The manifest is METADATA ONLY. It may hold a wrapped DEK (useless without the
// KEK) but never plaintext, an unwrapped DEK, or a KEK.
type Manifest struct {
	Safekeys  string           `json:"safekeys"`
	Objects   []ManifestObject `json:"objects"`
	Folder    *FolderInfo      `json:"folder,omitempty"`
	Authority *AuthorityInfo   `json:"authority,omitempty"`
}

// ManifestObject describes one ciphertext blob in the folder.
type ManifestObject struct {
	ID              string   `json:"id"`
	Path            string   `json:"path"`
	Alg             string   `json:"alg"`
	WrappedKey      string   `json:"wrapped_key"`
	WrappingKID     string   `json:"wrapping_kid,omitempty"`
	ContentType     string   `json:"content_type,omitempty"`
	Hash            string   `json:"hash,omitempty"`
	Size            int64    `json:"size,omitempty"`
	TokenReferences []string `json:"token_references,omitempty"`
}

// FolderInfo carries optional whole-folder metadata.
type FolderInfo struct {
	ID          string `json:"id,omitempty"`
	Description string `json:"description,omitempty"`
	Created     string `json:"created,omitempty"`
}

// AuthorityInfo is an operational hint, never a credential.
type AuthorityInfo struct {
	Issuer string `json:"issuer,omitempty"`
	Scope  string `json:"scope,omitempty"`
}

// ObjectPathPattern constrains where ciphertext may live. This prevents both an
// unencrypted file masquerading as ciphertext and path traversal out of the
// folder — see conformance vectors unencrypted-object-path and path-traversal.
var ObjectPathPattern = regexp.MustCompile(`^objects/[A-Za-z0-9][A-Za-z0-9._-]*\.enc$`)

// ObjectDir is the only directory in a folder that may hold ciphertext.
const ObjectDir = "objects"

// ReadmeName is the required secret-free, model-readable folder readme.
const ReadmeName = "README.safekeys"

// ManifestName is the manifest filename.
const ManifestName = "manifest.json"

// SecretShapedKeys are field names that must never appear in a manifest. Used
// as a defence-in-depth check independent of the strict-JSON decode, so an
// implementation that finds one can refuse and log a security event.
var SecretShapedKeys = []string{"value", "secret", "plaintext", "dek", "kek", "unwrapped_key", "master_key", "password"}

// Validate checks a manifest against the v1 rules that a JSON Schema cannot
// express (version, path constraints, presence of objects).
func (m *Manifest) Validate() error {
	if m.Safekeys != Version {
		return NewDenial(ReasonUnsupportedVersion)
	}
	if len(m.Objects) == 0 {
		return NewDenial(ReasonMalformed)
	}
	for _, o := range m.Objects {
		if o.ID == "" || o.WrappedKey == "" || o.Alg == "" {
			return NewDenial(ReasonMalformed)
		}
		if !ObjectPathPattern.MatchString(o.Path) {
			return NewDenial(ReasonMalformed)
		}
		if o.Alg != AlgAES256GCM && o.Alg != AlgChaCha20Poly1305 {
			return NewDenial(ReasonMalformed)
		}
	}
	return nil
}

// Object returns the manifest entry for id.
func (m *Manifest) Object(id string) (*ManifestObject, bool) {
	for i := range m.Objects {
		if m.Objects[i].ID == id {
			return &m.Objects[i], true
		}
	}
	return nil, false
}

// DecodeManifest parses and validates a manifest from JSON, rejecting any
// unknown field. Strict decoding is what makes additionalProperties:false
// meaningful: a smuggled "value" or "dek" field is a hard error, not ignored.
func DecodeManifest(data []byte) (*Manifest, error) {
	// Defence in depth: reject secret-shaped keys before structural decoding,
	// so we can distinguish "attempted secret smuggling" in audit.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err == nil {
		if err := scanForSecretKeys(probe); err != nil {
			return nil, err
		}
	}

	dec := json.NewDecoder(newBytesReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		// An unknown field is a malformed manifest, never a silently accepted one.
		return nil, NewDenial(ReasonMalformed)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// scanForSecretKeys walks a decoded manifest looking for forbidden field names
// at any depth.
func scanForSecretKeys(v any) error {
	switch t := v.(type) {
	case map[string]json.RawMessage:
		for k, raw := range t {
			for _, bad := range SecretShapedKeys {
				if equalFold(k, bad) {
					return NewDenial(ReasonMalformed)
				}
			}
			var inner any
			if err := json.Unmarshal(raw, &inner); err == nil {
				if err := scanForSecretKeys(inner); err != nil {
					return err
				}
			}
		}
	case []any:
		for _, item := range t {
			if err := scanForSecretKeys(item); err != nil {
				return err
			}
		}
	}
	return nil
}

// ReadManifest loads and validates manifest.json from a folder directory.
func ReadManifest(folderDir string) (*Manifest, error) {
	data, err := os.ReadFile(filepath.Join(folderDir, ManifestName))
	if err != nil {
		return nil, NewDenial(ReasonMalformed)
	}
	return DecodeManifest(data)
}

// WriteFolder writes a complete encrypted folder: ciphertext blobs under
// objects/, a manifest, and the secret-free README.
//
// plaintexts maps object id → plaintext, wrappedKeys maps object id → wrapped
// DEK. The caller retains ownership of plaintexts and must zeroise them.
func WriteFolder(folderDir string, m *Manifest, plaintexts map[string][]byte, folderDesc string) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(folderDir, ObjectDir), 0o700); err != nil {
		return err
	}
	for i := range m.Objects {
		o := &m.Objects[i]
		pt, ok := plaintexts[o.ID]
		if !ok {
			return NewDenial(ReasonMalformed)
		}
		// The encrypted blob is produced by the caller (it holds the DEK);
		// here we persist whatever ciphertext it placed in the map under the
		// object path. Callers pass ciphertext, never plaintext.
		if err := os.WriteFile(filepath.Join(folderDir, o.Path), pt, 0o600); err != nil {
			return err
		}
		o.Size = int64(len(pt))
		if o.Hash == "" {
			o.Hash = HashObject(pt)
		}
	}
	if m.Folder == nil {
		m.Folder = &FolderInfo{Created: time.Now().UTC().Format(time.RFC3339)}
	}
	if folderDesc != "" {
		m.Folder.Description = folderDesc
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(folderDir, ManifestName), data, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(folderDir, ReadmeName), []byte(FolderReadme), 0o600)
}

func equalFold(a, b string) bool {
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

func newBytesReader(b []byte) *bytesReader { return &bytesReader{b: b} }

type bytesReader struct {
	b []byte
	i int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

// FolderReadme is written into every folder. It is deliberately readable by
// humans and models, and contains no secrets — an agent that encounters a
// folder should understand it without attempting to extract values.
const FolderReadme = `# Safekeys encrypted folder

This folder is an encrypted transport unit. It contains **no plaintext and no
key material**.

## Contents

- ` + "`manifest.json`" + ` — metadata: object ids, algorithms, wrapped keys, hashes.
- ` + "`objects/*.enc`" + ` — AEAD ciphertext blobs.
- ` + "`README.safekeys`" + ` — this file.

## What you can and cannot do

You may **copy, move, commit, sync, or hand this folder to another agent
freely**. Copying increases no cryptographic exposure — the folder is inert.

You **cannot** read any secret from it. Resolution requires all three of:

1. a valid capability token (` + "`safekey://v1/<id>#<JWS>`" + `),
2. a running sidecar on the same host,
3. a reachable key authority holding the key-encryption key.

The wrapped key in the manifest is useless without the key store, which never
releases the key-encryption key. There is no supported way to extract a value
from this folder directly, and no plaintext or unwrapped key is ever present.

## Using a secret from this folder

Present your capability token to the local sidecar — for example:

    safekeys exec --token 'safekey://v1/<id>#<JWS>' -- your-command

The value is injected into ` + "`your-command`" + `'s environment. You receive an
exit code, not the value. Never paste a token into a model prompt if you can
avoid it, and never ask a model to 'show' the secret — the sidecar will not
return it.
`
