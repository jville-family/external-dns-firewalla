package listener

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jville-family/external-dns-firewalla/internal/hmacauth"
	"github.com/jville-family/external-dns-firewalla/internal/validate"
	"github.com/jville-family/external-dns-firewalla/internal/webhook"
)

// JobKind distinguishes read vs write jobs.
type JobKind int

const (
	// JobRead is a serialized state read.
	JobRead JobKind = iota
	// JobWrite is a serialized ApplyChanges write.
	JobWrite
)

// Job is a unit of work for the serial worker.
type Job struct {
	Kind     JobKind
	Changes  *webhook.Changes
	ResultCh chan JobResult
}

// JobResult is returned to the HTTP handler.
type JobResult struct {
	Endpoints []*webhook.Endpoint
	Err       error
	Status    int
}

// AccessFunc checks write permission on a path without writing.
type AccessFunc func(path string) error

// ServerConfig configures the HTTP listener.
type ServerConfig struct {
	Config
	Secret       []byte
	AllowDomains []string
	QueueSize    int
	Reloader     Reloader
	Access       AccessFunc
	Logger       *slog.Logger
}

// Server is the Firewalla listener HTTP server.
type Server struct {
	cfg      ServerConfig
	applier  *Applier
	queue    chan Job
	verifier *hmacauth.Verifier
	handler  http.Handler
	depth    atomic.Int32
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewServer builds a Server.
func NewServer(cfg ServerConfig) *Server {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 8
	}
	if cfg.Access == nil {
		cfg.Access = func(path string) error {
			return syscall.Access(path, 0x2) // W_OK
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Reloader == nil {
		cfg.Reloader = SystemctlReloader{}
	}
	s := &Server{
		cfg:     cfg,
		applier: NewApplier(cfg.Config, cfg.Reloader),
		queue:   make(chan Job, cfg.QueueSize),
		stop:    make(chan struct{}),
		verifier: &hmacauth.Verifier{
			Secret:  cfg.Secret,
			Now:     time.Now,
			MaxSkew: 10 * time.Second,
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/records", s.handleRecords)
	s.handler = s.verifier.Middleware(mux)
	return s
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.handler }

// SetReloader replaces the reloader (tests).
func (s *Server) SetReloader(r Reloader) {
	s.applier.reloader = r
	s.cfg.Reloader = r
}

// QueueDepth returns current queued job count estimate.
func (s *Server) QueueDepth() int { return int(s.depth.Load()) }

// StartWorker launches the serial worker in a background goroutine.
func (s *Server) StartWorker(ctx context.Context) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runWorker(ctx)
	}()
}

// RunWorker runs the serial worker on the calling goroutine until Shutdown or ctx is cancelled.
func (s *Server) RunWorker(ctx context.Context) {
	s.wg.Add(1)
	defer s.wg.Done()
	s.runWorker(ctx)
}

func (s *Server) runWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case job := <-s.queue:
			s.depth.Add(-1)
			s.process(ctx, job)
		}
	}
}

// Shutdown stops the worker.
func (s *Server) Shutdown(ctx context.Context) error {
	s.stopOnce.Do(func() { close(s.stop) })
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) process(ctx context.Context, job Job) {
	res := JobResult{Status: http.StatusOK}
	switch job.Kind {
	case JobRead:
		eps, err := s.applier.ReadState()
		res.Endpoints = eps
		res.Err = err
		if err != nil {
			res.Status = http.StatusInternalServerError
		}
	case JobWrite:
		filtered := &webhook.Changes{
			Create:    validate.FilterEndpoints(job.Changes.Create, s.cfg.AllowDomains),
			UpdateOld: validate.FilterEndpoints(job.Changes.UpdateOld, s.cfg.AllowDomains),
			UpdateNew: validate.FilterEndpoints(job.Changes.UpdateNew, s.cfg.AllowDomains),
			Delete:    validate.FilterEndpoints(job.Changes.Delete, s.cfg.AllowDomains),
		}
		_, err := s.applier.Apply(ctx, filtered)
		res.Err = err
		if err != nil {
			res.Status = http.StatusInternalServerError
		} else {
			res.Status = http.StatusNoContent
		}
	}
	select {
	case job.ResultCh <- res:
	default:
	}
}

func (s *Server) enqueue(job Job) bool {
	select {
	case s.queue <- job:
		s.depth.Add(1)
		return true
	default:
		return false
	}
}

func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	resultCh := make(chan JobResult, 1)
	job := Job{ResultCh: resultCh}

	switch r.Method {
	case http.MethodGet:
		job.Kind = JobRead
	case http.MethodPost:
		job.Kind = JobWrite
		var changes webhook.Changes
		if err := json.NewDecoder(r.Body).Decode(&changes); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		job.Changes = &changes
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.enqueue(job) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "queue full", http.StatusServiceUnavailable)
		return
	}

	select {
	case res := <-resultCh:
		if res.Err != nil && res.Status >= 500 {
			http.Error(w, res.Err.Error(), res.Status)
			return
		}
		if job.Kind == JobRead {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(res.Endpoints)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case <-r.Context().Done():
		http.Error(w, "cancelled", http.StatusRequestTimeout)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if err := s.cfg.Access(s.cfg.DnsmasqDir); err != nil {
		http.Error(w, fmt.Sprintf("dnsmasq dir not writable: %v", err), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "ok",
		"queueDepth": s.QueueDepth(),
		"queueCap":   s.cfg.QueueSize,
	})
}
