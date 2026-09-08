package listener_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jville-family/external-dns-firewalla/internal/hmacauth"
	"github.com/jville-family/external-dns-firewalla/internal/listener"
	"github.com/jville-family/external-dns-firewalla/internal/webhook"
)

func TestQueueFullReturns503(t *testing.T) {
	block := make(chan struct{})
	r := &blockingReloader{block: block}
	s := newTestServerWith(t, 1, r)
	defer s.Shutdown(context.Background())

	started := make(chan struct{})
	go func() {
		close(started)
		req := signedReq(t, s.secret, http.MethodPost, "/records", createBody("a.app.lan", "10.0.0.1", "1"))
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
	}()
	<-started
	time.Sleep(30 * time.Millisecond)

	queued := make(chan int, 1)
	go func() {
		req := signedReq(t, s.secret, http.MethodPost, "/records", createBody("b.app.lan", "10.0.0.2", "2"))
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		queued <- rr.Code
	}()
	time.Sleep(30 * time.Millisecond)

	req := signedReq(t, s.secret, http.MethodGet, "/records", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d want 503", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
	close(block)
	<-queued
}

func TestSerialExecution(t *testing.T) {
	var mu sync.Mutex
	type interval struct{ start, end time.Time }
	var intervals []interval

	r := &slowReloader{onCall: func() {
		start := time.Now()
		time.Sleep(15 * time.Millisecond)
		end := time.Now()
		mu.Lock()
		intervals = append(intervals, interval{start, end})
		mu.Unlock()
	}}
	s := newTestServerWith(t, 8, r)
	defer s.Shutdown(context.Background())

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := strconv.Itoa(i)
			req := signedReq(t, s.secret, http.MethodPost, "/records", createBody("host.app.lan", "10.0.0.1", id))
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, req)
		}(i)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < len(intervals); i++ {
		for j := i + 1; j < len(intervals); j++ {
			a, b := intervals[i], intervals[j]
			if a.start.Before(b.end) && b.start.Before(a.end) {
				t.Fatalf("intervals overlap: %+v and %+v", a, b)
			}
		}
	}
}

func TestReadAfterWrite(t *testing.T) {
	s := newTestServerWith(t, 8, &fakeReloader{})
	defer s.Shutdown(context.Background())

	req := signedReq(t, s.secret, http.MethodPost, "/records", createBody("plex.app.lan", "10.0.0.5", ""))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("apply code=%d body=%s", rr.Code, rr.Body.String())
	}

	req2 := signedReq(t, s.secret, http.MethodGet, "/records", nil)
	rr2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("read code=%d body=%s", rr2.Code, rr2.Body.String())
	}
	var eps []*webhook.Endpoint
	if err := json.Unmarshal(rr2.Body.Bytes(), &eps); err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].DNSName != "plex.app.lan" {
		t.Fatalf("unexpected: %+v", eps)
	}
}

func TestShutdownNoGoroutineLeak(t *testing.T) {
	runtime.GC()
	before := runtime.NumGoroutine()
	s := newTestServerWith(t, 4, &fakeReloader{})
	_ = s.Shutdown(context.Background())
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()
	if after > before+5 {
		t.Fatalf("goroutines before=%d after=%d", before, after)
	}
}

func TestHealthWritableAndNoDiskWrites(t *testing.T) {
	s := newTestServerWith(t, 4, &fakeReloader{})
	defer s.Shutdown(context.Background())

	dir := s.dnsDir
	snap := snapshotDir(t, dir)

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	assertSnapshotUnchanged(t, dir, snap)
}

func TestHealthUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	root := t.TempDir()
	dnsDir := filepath.Join(root, "dnsmasq_local")
	if err := os.MkdirAll(dnsDir, 0o500); err != nil {
		t.Fatal(err)
	}
	srv := listener.NewServer(listener.ServerConfig{
		Config: listener.Config{
			StateDir:   filepath.Join(root, "state"),
			DnsmasqDir: dnsDir,
			ConfName:   "k8s-external-dns.conf",
		},
		Secret:       []byte("secret"),
		AllowDomains: []string{"app.lan"},
		QueueSize:    4,
		Reloader:     &fakeReloader{},
		Access: func(path string) error {
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			if info.Mode().Perm()&0o200 == 0 {
				return os.ErrPermission
			}
			return nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.StartWorker(ctx)

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d want 503", rr.Code)
	}
	_ = srv.Shutdown(context.Background())
}

type blockingReloader struct {
	block chan struct{}
}

func (b *blockingReloader) Reload(context.Context) error {
	<-b.block
	return nil
}

type slowReloader struct {
	onCall func()
}

func (s *slowReloader) Reload(context.Context) error {
	if s.onCall != nil {
		s.onCall()
	}
	return nil
}

type testServer struct {
	*listener.Server
	secret string
	dnsDir string
}

func newTestServerWith(t *testing.T, queueSize int, r listener.Reloader) *testServer {
	t.Helper()
	root := t.TempDir()
	secret := "test-secret"
	dnsDir := filepath.Join(root, "dnsmasq_local")
	_ = os.MkdirAll(dnsDir, 0o755)
	_ = os.MkdirAll(filepath.Join(root, "state"), 0o755)
	srv := listener.NewServer(listener.ServerConfig{
		Config: listener.Config{
			StateDir:   filepath.Join(root, "state"),
			DnsmasqDir: dnsDir,
			ConfName:   "k8s-external-dns.conf",
		},
		Secret:       []byte(secret),
		AllowDomains: []string{"app.lan"},
		QueueSize:    queueSize,
		Reloader:     r,
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv.StartWorker(ctx)
	return &testServer{Server: srv, secret: secret, dnsDir: dnsDir}
}

func createBody(name, ip, setID string) []byte {
	ep := map[string]any{
		"dnsName": name, "recordType": "A", "targets": []string{ip},
	}
	if setID != "" {
		ep["setIdentifier"] = setID
	}
	b, _ := json.Marshal(map[string]any{"Create": []any{ep}})
	return b
}

func signedReq(t *testing.T, secret, method, path string, body []byte) *http.Request {
	t.Helper()
	ts := time.Now()
	sig := hmacauth.Sign([]byte(secret), ts, method, path, body)
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	}
	r.Header.Set(hmacauth.HeaderTimestamp, strconv.FormatInt(ts.Unix(), 10))
	r.Header.Set(hmacauth.HeaderSignature, sig)
	return r
}

type dirSnap map[string]snapInfo

type snapInfo struct {
	size  int64
	mtime time.Time
}

func snapshotDir(t *testing.T, dir string) dirSnap {
	t.Helper()
	out := dirSnap{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = snapInfo{size: info.Size(), mtime: info.ModTime()}
	}
	return out
}

func assertSnapshotUnchanged(t *testing.T, dir string, before dirSnap) {
	t.Helper()
	after := snapshotDir(t, dir)
	if len(after) != len(before) {
		t.Fatalf("dir entries changed: before=%v after=%v", before, after)
	}
	for name, bi := range before {
		ai, ok := after[name]
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if ai.size != bi.size || !ai.mtime.Equal(bi.mtime) {
			t.Fatalf("%s changed", name)
		}
	}
}
