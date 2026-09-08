package listener_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jville-family/external-dns-firewalla/internal/listener"
	"github.com/jville-family/external-dns-firewalla/internal/webhook"
)

func TestLoadMissingYieldsEmpty(t *testing.T) {
	dir := t.TempDir()
	s := listener.NewStore(filepath.Join(dir, "state.json"))
	st, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 0 {
		t.Fatalf("want empty, got %d", len(st))
	}
}

func TestLoadCorruptErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := listener.NewStore(path)
	if _, err := s.Load(); err == nil {
		t.Fatal("corrupt state must error, not yield empty")
	}
}

func TestApplyDiffCreateUpdateDelete(t *testing.T) {
	st := listener.State{}
	changes := &webhook.Changes{
		Create: []*webhook.Endpoint{
			{DNSName: "a.app.lan", RecordType: "A", Targets: []string{"10.0.0.1"}, SetIdentifier: "s1"},
		},
	}
	st = listener.ApplyDiff(st, changes)
	if len(st) != 1 {
		t.Fatalf("after create: %d", len(st))
	}

	changes = &webhook.Changes{
		UpdateOld: []*webhook.Endpoint{
			{DNSName: "a.app.lan", RecordType: "A", Targets: []string{"10.0.0.1"}, SetIdentifier: "s1"},
		},
		UpdateNew: []*webhook.Endpoint{
			{DNSName: "a.app.lan", RecordType: "A", Targets: []string{"10.0.0.2"}, SetIdentifier: "s1", Labels: map[string]string{"owner": "ed"}},
		},
	}
	st = listener.ApplyDiff(st, changes)
	ep := st[listener.KeyOf(changes.UpdateNew[0])]
	if ep.Targets[0] != "10.0.0.2" || ep.Labels["owner"] != "ed" {
		t.Fatalf("update failed: %+v", ep)
	}

	changes = &webhook.Changes{
		Delete: []*webhook.Endpoint{
			{DNSName: "a.app.lan", RecordType: "A", SetIdentifier: "s1"},
		},
	}
	st = listener.ApplyDiff(st, changes)
	if len(st) != 0 {
		t.Fatalf("after delete: %d", len(st))
	}
}

func TestDeleteNonexistentNoop(t *testing.T) {
	st := listener.State{}
	st = listener.ApplyDiff(st, &webhook.Changes{
		Delete: []*webhook.Endpoint{{DNSName: "missing.app.lan", RecordType: "A"}},
	})
	if len(st) != 0 {
		t.Fatal("expected empty")
	}
}

func TestJSONRoundTripPreservesFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := listener.NewStore(path)

	ep := &webhook.Endpoint{
		DNSName:       "a.app.lan",
		RecordType:    "TXT",
		Targets:       []string{"heritage=external-dns"},
		SetIdentifier: "id1",
		RecordTTL:     60,
		Labels:        map[string]string{"owner": "default"},
		ProviderSpecific: webhook.ProviderSpecific{
			{Name: "aws/weight", Value: "100"},
		},
	}
	st := listener.State{listener.KeyOf(ep): ep}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	got := loaded[listener.KeyOf(ep)]
	if got == nil {
		t.Fatal("missing endpoint")
	}
	raw, _ := json.Marshal(got)
	want, _ := json.Marshal(ep)
	if string(raw) != string(want) {
		t.Fatalf("round-trip mismatch\ngot  %s\nwant %s", raw, want)
	}
}

func TestAtomicWritePermsAndNoTmp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := listener.NewStore(path)
	ep := &webhook.Endpoint{DNSName: "a.app.lan", RecordType: "A", Targets: []string{"10.0.0.1"}}
	if err := s.Save(listener.State{listener.KeyOf(ep): ep}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("perms %o, want 0600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" || len(e.Name()) > 10 && e.Name()[len(e.Name())-4:] == ".tmp" {
			t.Fatalf("leftover tmp: %s", e.Name())
		}
		if containsTmp(e.Name()) {
			t.Fatalf("leftover tmp: %s", e.Name())
		}
	}
}

func containsTmp(name string) bool {
	for i := 0; i+4 <= len(name); i++ {
		if name[i:i+4] == ".tmp" {
			return true
		}
	}
	return name != "" && (len(name) >= 4 && name[len(name)-4:] == ".tmp")
}
