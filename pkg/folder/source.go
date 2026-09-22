// Package folder implements a resolve source over local folder directories.
//
// A single configured root can hold many folders, one per object, each with its
// own manifest.json. Load resolves sid to a folder by trying:
//
//	<root>/<sid>/manifest.json   (the common layout — one folder per object)
//	<root>/manifest.json         (a root that IS a single folder)
//
// It is deliberately read-only about resolution: it reads the manifest and the
// ciphertext and can do nothing further. The wrapped key it returns is useless
// without the key store.
package folder

import (
	"context"
	"os"
	"path/filepath"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/protocol"
)

// Source resolves objects from a folder root.
type Source struct {
	Dir    string
	loader func(dir string) (*protocol.Manifest, error)
}

// New builds a Source for a folder root.
func New(dir string) *Source {
	return &Source{Dir: dir, loader: protocol.ReadManifest}
}

// Load returns the manifest entry and ciphertext for sid.
func (s *Source) Load(ctx context.Context, sid string) (*protocol.ManifestObject, []byte, error) {
	dir, m, err := s.find(sid)
	if err != nil {
		return nil, nil, err
	}
	obj, ok := m.Object(sid)
	if !ok {
		return nil, nil, protocol.NewDenial(protocol.ReasonMalformed)
	}
	// Re-validate the path even though the manifest was validated on load: this
	// is the last line of defence against traversal reaching the filesystem.
	if !protocol.ObjectPathPattern.MatchString(obj.Path) {
		return nil, nil, protocol.NewDenial(protocol.ReasonMalformed)
	}
	ct, err := os.ReadFile(filepath.Join(dir, obj.Path))
	if err != nil {
		return nil, nil, protocol.NewDenial(protocol.ReasonMalformed)
	}
	return obj, ct, nil
}

// find locates the folder holding sid and returns its manifest.
func (s *Source) find(sid string) (string, *protocol.Manifest, error) {
	// One folder per object, under the root.
	perObj := filepath.Join(s.Dir, sid)
	if isDir(perObj) {
		if m, err := s.loader(perObj); err == nil {
			if _, ok := m.Object(sid); ok {
				return perObj, m, nil
			}
		}
	}
	// The root itself is a single folder.
	if m, err := s.loader(s.Dir); err == nil {
		if _, ok := m.Object(sid); ok {
			return s.Dir, m, nil
		}
	}
	return "", nil, protocol.NewDenial(protocol.ReasonMalformed)
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
