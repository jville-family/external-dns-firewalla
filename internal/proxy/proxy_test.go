package proxy_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jville-family/external-dns-firewalla/internal/hmacauth"
	"github.com/jville-family/external-dns-firewalla/internal/proxy"
	"github.com/jville-family/external-dns-firewalla/internal/webhook"
)

func TestNegotiate(t *testing.T) {
	p := newProxy(t, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	rr := httptest.NewRecorder()
	p.WebhookHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != webhook.MediaType {
		t.Fatalf("content-type=%q", ct)
	}
	var df webhook.DomainFilter
	if err := json.Unmarshal(rr.Body.Bytes(), &df); err != nil {
		t.Fatal(err)
	}
	if len(df.Filters) == 0 {
		t.Fatal("expected filters")
	}
}

func TestGetRecords(t *testing.T) {
	eps := []*webhook.Endpoint{{DNSName: "plex.app.lan", RecordType: "A", Targets: []string{"10.0.0.5"}}}
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifyHMAC(t, r, []byte("secret"))
		_ = json.NewEncoder(w).Encode(eps)
	}))
	defer listener.Close()
	p := newProxy(t, listener)

	rr := httptest.NewRecorder()
	p.WebhookHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/records", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	var got []*webhook.Endpoint
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].DNSName != "plex.app.lan" {
		t.Fatalf("%+v", got)
	}
}

func TestPostRecords204AndFilters(t *testing.T) {
	var mu sync.Mutex
	var gotBody []byte
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifyHMAC(t, r, []byte("secret"))
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = body
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer listener.Close()
	p := newProxy(t, listener)

	changes := webhook.Changes{
		Create: []*webhook.Endpoint{
			{DNSName: "plex.app.lan", RecordType: "A", Targets: []string{"10.0.0.5"}},
			{DNSName: "evil.com", RecordType: "A", Targets: []string{"1.2.3.4"}},
		},
	}
	body, _ := json.Marshal(changes)
	rr := httptest.NewRecorder()
	p.WebhookHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/records", bytes.NewReader(body)))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if !bytes.Contains(gotBody, []byte("plex.app.lan")) {
		t.Fatalf("missing allowed domain: %s", gotBody)
	}
	if bytes.Contains(gotBody, []byte("evil.com")) {
		t.Fatalf("forwarded disallowed domain: %s", gotBody)
	}
}

func TestListenerDownIs5xx(t *testing.T) {
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := listener.URL
	listener.Close()

	p := proxy.New(proxy.Config{
		ListenerURL:  url,
		Secret:       []byte("secret"),
		AllowDomains: []string{"app.lan"},
	})
	rr := httptest.NewRecorder()
	p.WebhookHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/records", nil))
	if rr.Code < 500 {
		t.Fatalf("code=%d want 5xx", rr.Code)
	}
}

func TestAdjustEndpoints(t *testing.T) {
	p := newProxy(t, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	eps := []*webhook.Endpoint{
		{DNSName: "plex.app.lan", RecordType: "a", Targets: []string{"10.0.0.5"}},
		{DNSName: "evil.com", RecordType: "A", Targets: []string{"1.1.1.1"}},
	}
	body, _ := json.Marshal(eps)
	rr := httptest.NewRecorder()
	p.WebhookHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/adjustendpoints", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d", rr.Code)
	}
	var out []*webhook.Endpoint
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out) != 1 || out[0].RecordType != "A" {
		t.Fatalf("%+v", out)
	}
}

func TestReadinessMatrix(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer healthy.Close()

	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unhealthy.Close()

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()

	cases := []struct {
		name string
		url  string
		code int
		to   time.Duration
	}{
		{"healthy", healthy.URL, http.StatusOK, time.Second},
		{"unhealthy", unhealthy.URL, http.StatusServiceUnavailable, time.Second},
		{"timeout", slow.URL, http.StatusServiceUnavailable, 50 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := proxy.New(proxy.Config{
				ListenerURL:    tc.url,
				Secret:         []byte("secret"),
				AllowDomains:   []string{"app.lan"},
				HealthTimeout:  tc.to,
			})
			rr := httptest.NewRecorder()
			p.HealthHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz/ready", nil))
			if rr.Code != tc.code {
				t.Fatalf("code=%d want %d", rr.Code, tc.code)
			}
			// liveness always OK
			rr2 := httptest.NewRecorder()
			p.HealthHandler().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/healthz", nil))
			if rr2.Code != http.StatusOK {
				t.Fatalf("liveness=%d", rr2.Code)
			}
		})
	}

	t.Run("down", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		url := s.URL
		s.Close()
		p := proxy.New(proxy.Config{ListenerURL: url, Secret: []byte("secret"), AllowDomains: []string{"app.lan"}})
		rr := httptest.NewRecorder()
		p.HealthHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz/ready", nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("code=%d", rr.Code)
		}
	})
}

func newProxy(t *testing.T, listener *httptest.Server) *proxy.Server {
	t.Helper()
	return proxy.New(proxy.Config{
		ListenerURL:  listener.URL,
		Secret:       []byte("secret"),
		AllowDomains: []string{"app.lan"},
	})
}

func verifyHMAC(t *testing.T, r *http.Request, secret []byte) {
	t.Helper()
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	ts := r.Header.Get(hmacauth.HeaderTimestamp)
	sig := r.Header.Get(hmacauth.HeaderSignature)
	v := &hmacauth.Verifier{Secret: secret, Now: time.Now, MaxSkew: 10 * time.Second}
	if err := v.Verify(r.Method, r.URL.Path, body, ts, sig); err != nil {
		t.Fatalf("hmac: %v (ts=%s sig=%s)", err, ts, sig)
	}
	_ = strconv.FormatInt(time.Now().Unix(), 10)
	if !strings.HasPrefix(r.URL.Path, "/") {
		t.Fatal("path")
	}
}
