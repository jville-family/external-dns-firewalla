package listener

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jville-family/external-dns-firewalla/internal/webhook"
)

// Key uniquely identifies a managed endpoint.
type Key struct {
	DNSName       string
	RecordType    string
	SetIdentifier string
}

// State is the in-memory map of managed records.
type State map[Key]*webhook.Endpoint

// Store persists State as JSON.
type Store struct {
	path string
}

// NewStore creates a Store for the given path.
func NewStore(path string) *Store {
	return &Store{path: path}
}

// KeyOf builds a Key from an endpoint.
func KeyOf(ep *webhook.Endpoint) Key {
	return Key{
		DNSName:       strings.ToLower(strings.TrimSuffix(ep.DNSName, ".")),
		RecordType:    strings.ToUpper(ep.RecordType),
		SetIdentifier: ep.SetIdentifier,
	}
}

// Load reads state from disk. Missing file yields empty state; corrupt file errors.
func (s *Store) Load() (State, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return State{}, nil
		}
		return nil, err
	}
	var list []*webhook.Endpoint
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("corrupt state file %s: %w", s.path, err)
	}
	st := make(State, len(list))
	for _, ep := range list {
		if ep == nil {
			continue
		}
		st[KeyOf(ep)] = ep
	}
	return st, nil
}

// Save atomically writes state to disk with mode 0600.
func (s *Store) Save(st State) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	list := make([]*webhook.Endpoint, 0, len(st))
	for _, ep := range st {
		list = append(list, ep)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicWrite(s.path, data, 0o600)
}

// ApplyDiff applies Create, UpdateNew (via UpdateOld keys), and Delete to state.
func ApplyDiff(st State, changes *webhook.Changes) State {
	out := make(State, len(st))
	for k, v := range st {
		out[k] = v
	}
	if changes == nil {
		return out
	}
	for _, ep := range changes.Create {
		if ep == nil {
			continue
		}
		cp := *ep
		out[KeyOf(&cp)] = &cp
	}
	// Updates: remove UpdateOld keys, insert UpdateNew.
	for _, ep := range changes.UpdateOld {
		if ep == nil {
			continue
		}
		delete(out, KeyOf(ep))
	}
	for _, ep := range changes.UpdateNew {
		if ep == nil {
			continue
		}
		cp := *ep
		out[KeyOf(&cp)] = &cp
	}
	for _, ep := range changes.Delete {
		if ep == nil {
			continue
		}
		delete(out, KeyOf(ep))
	}
	return out
}

// Equal reports whether two states contain the same endpoints (by key and content).
func Equal(a, b State) bool {
	if len(a) != len(b) {
		return false
	}
	for k, ea := range a {
		eb, ok := b[k]
		if !ok {
			return false
		}
		ja, _ := json.Marshal(ea)
		jb, _ := json.Marshal(eb)
		if string(ja) != string(jb) {
			return false
		}
	}
	return true
}

// Endpoints returns a slice of all endpoints in state.
func (st State) Endpoints() []*webhook.Endpoint {
	out := make([]*webhook.Endpoint, 0, len(st))
	for _, ep := range st {
		out = append(out, ep)
	}
	return out
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
