package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jville-family/external-dns-firewalla/internal/hmacauth"
	"github.com/jville-family/external-dns-firewalla/internal/validate"
	"github.com/jville-family/external-dns-firewalla/internal/webhook"
)

// Config configures the webhook proxy.
type Config struct {
	ListenerURL   string
	Secret        []byte
	AllowDomains  []string
	HealthTimeout time.Duration
	HTTPClient    *http.Client
}

// Server implements the external-dns webhook provider API.
type Server struct {
	cfg    Config
	client *http.Client
}

// New constructs a proxy Server.
func New(cfg Config) *Server {
	if cfg.HealthTimeout == 0 {
		cfg.HealthTimeout = 2 * time.Second
	}
	c := cfg.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	return &Server{cfg: cfg, client: c}
}

// WebhookHandler serves negotiation, records, and adjustendpoints on port 8888.
func (s *Server) WebhookHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleNegotiate)
	mux.HandleFunc("/records", s.handleRecords)
	mux.HandleFunc("/adjustendpoints", s.handleAdjust)
	return mux
}

// HealthHandler serves /healthz and /healthz/ready on port 8080.
func (s *Server) HealthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/healthz/ready", s.handleReady)
	return mux
}

func (s *Server) handleNegotiate(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", webhook.MediaType)
	_ = json.NewEncoder(w).Encode(webhook.DomainFilter{Filters: s.cfg.AllowDomains})
}

func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		body, status, err := s.forward(r.Context(), http.MethodGet, "/records", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if status >= 500 {
			http.Error(w, string(body), http.StatusBadGateway)
			return
		}
		if status >= 400 {
			http.Error(w, string(body), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	case http.MethodPost:
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var changes webhook.Changes
		if err := json.Unmarshal(raw, &changes); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		filtered := webhook.Changes{
			Create:    validate.FilterEndpoints(changes.Create, s.cfg.AllowDomains),
			UpdateOld: validate.FilterEndpoints(changes.UpdateOld, s.cfg.AllowDomains),
			UpdateNew: validate.FilterEndpoints(changes.UpdateNew, s.cfg.AllowDomains),
			Delete:    validate.FilterEndpoints(changes.Delete, s.cfg.AllowDomains),
		}
		payload, _ := json.Marshal(filtered)
		_, status, err := s.forward(r.Context(), http.MethodPost, "/records", payload)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if status >= 400 {
			http.Error(w, "listener error", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdjust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var eps []*webhook.Endpoint
	if err := json.NewDecoder(r.Body).Decode(&eps); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	out := validate.FilterEndpoints(eps, s.cfg.AllowDomains)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.HealthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.cfg.ListenerURL, "/")+"/health", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "listener unhealthy", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) forward(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	url := strings.TrimRight(s.cfg.ListenerURL, "/") + path
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, 0, err
	}
	ts := time.Now()
	req.Header.Set(hmacauth.HeaderTimestamp, fmt.Sprintf("%d", ts.Unix()))
	req.Header.Set(hmacauth.HeaderSignature, hmacauth.Sign(s.cfg.Secret, ts, method, path, body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return respBody, resp.StatusCode, nil
}
