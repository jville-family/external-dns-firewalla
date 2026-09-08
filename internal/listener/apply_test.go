package listener_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jville-family/external-dns-firewalla/internal/listener"
	"github.com/jville-family/external-dns-firewalla/internal/webhook"
)

type fakeReloader struct {
	calls atomic.Int32
	err   error
}

func (f *fakeReloader) Reload(context.Context) error {
	f.calls.Add(1)
	return f.err
}

func newApplier(t *testing.T, r listener.Reloader) (*listener.Applier, string, string) {
	t.Helper()
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	dnsDir := filepath.Join(root, "dnsmasq_local")
	cfg := listener.Config{
		StateDir:   stateDir,
		DnsmasqDir: dnsDir,
		ConfName:   "k8s-external-dns.conf",
	}
	a := listener.NewApplier(cfg, r)
	return a, stateDir, dnsDir
}

func TestApplyCreatesDirsAndReloadsOnce(t *testing.T) {
	r := &fakeReloader{}
	a, stateDir, dnsDir := newApplier(t, r)

	changed, err := a.Apply(context.Background(), &webhook.Changes{
		Create: []*webhook.Endpoint{
			{DNSName: "plex.app.lan", RecordType: "A", Targets: []string{"10.0.0.5"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected change")
	}
	if r.calls.Load() != 1 {
		t.Fatalf("reloads=%d want 1", r.calls.Load())
	}
	if _, err := os.Stat(filepath.Join(stateDir, "state.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dnsDir, "k8s-external-dns.conf")); err != nil {
		t.Fatal(err)
	}
}

func TestApplyNoopSecondCall(t *testing.T) {
	r := &fakeReloader{}
	a, stateDir, dnsDir := newApplier(t, r)
	chg := &webhook.Changes{
		Create: []*webhook.Endpoint{
			{DNSName: "plex.app.lan", RecordType: "A", Targets: []string{"10.0.0.5"}},
		},
	}
	if _, err := a.Apply(context.Background(), chg); err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(stateDir, "state.json")
	confPath := filepath.Join(dnsDir, "k8s-external-dns.conf")
	si, _ := os.Stat(statePath)
	ci, _ := os.Stat(confPath)
	time.Sleep(20 * time.Millisecond) // ensure mtime would change if rewritten

	changed, err := a.Apply(context.Background(), chg)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("second identical apply must be no-op")
	}
	if r.calls.Load() != 1 {
		t.Fatalf("reloads=%d want 1", r.calls.Load())
	}
	si2, _ := os.Stat(statePath)
	ci2, _ := os.Stat(confPath)
	if !si.ModTime().Equal(si2.ModTime()) || si.Size() != si2.Size() {
		t.Fatal("state.json was rewritten on no-op")
	}
	if !ci.ModTime().Equal(ci2.ModTime()) || ci.Size() != ci2.Size() {
		t.Fatal("conf was rewritten on no-op")
	}
}

func TestApplyEmptyChangesNoop(t *testing.T) {
	r := &fakeReloader{}
	a, _, _ := newApplier(t, r)
	changed, err := a.Apply(context.Background(), &webhook.Changes{})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("empty changes must be no-op")
	}
	if r.calls.Load() != 0 {
		t.Fatalf("reloads=%d", r.calls.Load())
	}
}

func TestApplyMkdirAllMissingDnsmasqDir(t *testing.T) {
	r := &fakeReloader{}
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	dnsDir := filepath.Join(root, "missing", "dnsmasq_local")
	a := listener.NewApplier(listener.Config{
		StateDir: stateDir, DnsmasqDir: dnsDir, ConfName: "k8s-external-dns.conf",
	}, r)
	_, err := a.Apply(context.Background(), &webhook.Changes{
		Create: []*webhook.Endpoint{
			{DNSName: "a.app.lan", RecordType: "A", Targets: []string{"10.0.0.1"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dnsDir, "k8s-external-dns.conf")); err != nil {
		t.Fatal(err)
	}
}

func TestApplyReloadFailurePersistsState(t *testing.T) {
	r := &fakeReloader{err: errors.New("systemctl failed")}
	a, stateDir, _ := newApplier(t, r)
	_, err := a.Apply(context.Background(), &webhook.Changes{
		Create: []*webhook.Endpoint{
			{DNSName: "a.app.lan", RecordType: "A", Targets: []string{"10.0.0.1"}},
		},
	})
	if err == nil {
		t.Fatal("expected reload error")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "state.json")); err != nil {
		t.Fatal("state must persist even when reload fails")
	}
	// Retry with working reloader should no-op (state already applied).
	r2 := &fakeReloader{}
	a2 := listener.NewApplier(listener.Config{
		StateDir:   stateDir,
		DnsmasqDir: filepath.Join(filepath.Dir(stateDir), "dnsmasq_local"),
		ConfName:   "k8s-external-dns.conf",
	}, r2)
	changed, err := a2.Apply(context.Background(), &webhook.Changes{
		Create: []*webhook.Endpoint{
			{DNSName: "a.app.lan", RecordType: "A", Targets: []string{"10.0.0.1"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("retry after persisted state should be no-op")
	}
}
