package hmacauth_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jville-family/external-dns-firewalla/internal/hmacauth"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{"ok":true}`)
	ts := time.Unix(1_700_000_000, 0)

	sig := hmacauth.Sign(secret, ts, http.MethodPost, "/records", body)
	v := &hmacauth.Verifier{Secret: secret, Now: func() time.Time { return ts }, MaxSkew: 10 * time.Second}
	if err := v.Verify(http.MethodPost, "/records", body, strconv.FormatInt(ts.Unix(), 10), sig); err != nil {
		t.Fatal(err)
	}
}

func TestRejectWrongSecret(t *testing.T) {
	ts := time.Unix(1_700_000_000, 0)
	body := []byte("x")
	sig := hmacauth.Sign([]byte("a"), ts, http.MethodGet, "/records", body)
	v := &hmacauth.Verifier{Secret: []byte("b"), Now: func() time.Time { return ts }, MaxSkew: 10 * time.Second}
	if err := v.Verify(http.MethodGet, "/records", body, strconv.FormatInt(ts.Unix(), 10), sig); err == nil {
		t.Fatal("expected error")
	}
}

func TestRejectTamperedBody(t *testing.T) {
	secret := []byte("s")
	ts := time.Unix(1_700_000_000, 0)
	sig := hmacauth.Sign(secret, ts, http.MethodPost, "/records", []byte("good"))
	v := &hmacauth.Verifier{Secret: secret, Now: func() time.Time { return ts }, MaxSkew: 10 * time.Second}
	if err := v.Verify(http.MethodPost, "/records", []byte("evil"), strconv.FormatInt(ts.Unix(), 10), sig); err == nil {
		t.Fatal("expected error")
	}
}

func TestRejectMalformed(t *testing.T) {
	secret := []byte("s")
	ts := time.Unix(1_700_000_000, 0)
	v := &hmacauth.Verifier{Secret: secret, Now: func() time.Time { return ts }, MaxSkew: 10 * time.Second}
	if err := v.Verify(http.MethodGet, "/records", nil, "not-a-number", "abcd"); err == nil {
		t.Fatal("expected error for bad timestamp")
	}
	if err := v.Verify(http.MethodGet, "/records", nil, strconv.FormatInt(ts.Unix(), 10), "zz"); err == nil {
		t.Fatal("expected error for non-hex signature")
	}
	if err := v.Verify(http.MethodGet, "/records", nil, "", ""); err == nil {
		t.Fatal("expected error for missing headers")
	}
}

func TestReplayMethodPathSwap(t *testing.T) {
	secret := []byte("s")
	ts := time.Unix(1_700_000_000, 0)
	body := []byte("{}")
	sig := hmacauth.Sign(secret, ts, http.MethodGet, "/records", body)
	v := &hmacauth.Verifier{Secret: secret, Now: func() time.Time { return ts }, MaxSkew: 10 * time.Second}

	if err := v.Verify(http.MethodPost, "/records", body, strconv.FormatInt(ts.Unix(), 10), sig); err == nil {
		t.Fatal("GET signature must not work for POST")
	}
	if err := v.Verify(http.MethodGet, "/other", body, strconv.FormatInt(ts.Unix(), 10), sig); err == nil {
		t.Fatal("path swap must fail")
	}
}

func TestDriftWindow(t *testing.T) {
	secret := []byte("s")
	base := time.Unix(1_700_000_000, 0)
	body := []byte("x")
	sig := hmacauth.Sign(secret, base, http.MethodGet, "/records", body)
	tsHeader := strconv.FormatInt(base.Unix(), 10)

	cases := []struct {
		skew time.Duration
		ok   bool
	}{
		{-11 * time.Second, false},
		{-10 * time.Second, true},
		{-9 * time.Second, true},
		{0, true},
		{9 * time.Second, true},
		{10 * time.Second, true},
		{11 * time.Second, false},
	}
	for _, tc := range cases {
		t.Run(tc.skew.String(), func(t *testing.T) {
			v := &hmacauth.Verifier{
				Secret:  secret,
				Now:     func() time.Time { return base.Add(tc.skew) },
				MaxSkew: 10 * time.Second,
			}
			err := v.Verify(http.MethodGet, "/records", body, tsHeader, sig)
			if tc.ok && err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestMiddlewareHealthExempt(t *testing.T) {
	secret := []byte("s")
	v := &hmacauth.Verifier{Secret: secret, Now: time.Now, MaxSkew: 10 * time.Second}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/records", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := v.Middleware(mux)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("health without auth: %d", rr.Code)
	}

	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/records", nil))
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("records without auth: %d", rr2.Code)
	}
}

func TestMiddlewareAcceptsSigned(t *testing.T) {
	secret := []byte("s")
	ts := time.Unix(1_700_000_000, 0)
	body := []byte(`{"a":1}`)
	sig := hmacauth.Sign(secret, ts, http.MethodPost, "/records", body)
	v := &hmacauth.Verifier{Secret: secret, Now: func() time.Time { return ts }, MaxSkew: 10 * time.Second}

	var gotBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/records", func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	h := v.Middleware(mux)

	req := httptest.NewRequest(http.MethodPost, "/records", bytes.NewReader(body))
	req.Header.Set(hmacauth.HeaderTimestamp, strconv.FormatInt(ts.Unix(), 10))
	req.Header.Set(hmacauth.HeaderSignature, sig)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("code=%d", rr.Code)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("body not preserved")
	}
}
