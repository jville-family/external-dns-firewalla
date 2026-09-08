package hmacauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// HeaderTimestamp is the unix-seconds request time used for HMAC and replay protection.
	HeaderTimestamp = "X-Request-Timestamp"
	// HeaderSignature is the hex-encoded HMAC-SHA256 of the canonical request.
	HeaderSignature = "X-Signature"
)

// Verifier checks HMAC-SHA256 request signatures.
type Verifier struct {
	Secret  []byte
	Now     func() time.Time
	MaxSkew time.Duration
}

// Sign produces a hex-encoded HMAC-SHA256 over the canonical string.
func Sign(secret []byte, ts time.Time, method, path string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical(ts.Unix(), method, path, body)))
	return hex.EncodeToString(mac.Sum(nil))
}

func canonical(unix int64, method, path string, body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%d\n%s\n%s\n%s", unix, method, path, hex.EncodeToString(sum[:]))
}

// Verify checks timestamp drift and signature.
func (v *Verifier) Verify(method, path string, body []byte, tsHeader, sigHeader string) error {
	if tsHeader == "" || sigHeader == "" {
		return fmt.Errorf("missing auth headers")
	}
	unix, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	now := v.Now()
	skew := now.Sub(time.Unix(unix, 0))
	if skew < 0 {
		skew = -skew
	}
	maxSkew := v.MaxSkew
	if maxSkew == 0 {
		maxSkew = 10 * time.Second
	}
	if skew > maxSkew {
		return fmt.Errorf("timestamp outside allowed window")
	}
	sig, err := hex.DecodeString(sigHeader)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	mac := hmac.New(sha256.New, v.Secret)
	_, _ = mac.Write([]byte(canonical(unix, method, path, body)))
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// Middleware enforces HMAC auth on all paths except those ending with /health
// or equal to /health.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isHealthPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(strings.NewReader(string(body)))

		if err := v.Verify(r.Method, r.URL.Path, body, r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderSignature)); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isHealthPath(p string) bool {
	return p == "/health" || strings.HasSuffix(p, "/health")
}
