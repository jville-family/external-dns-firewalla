package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jville-family/external-dns-firewalla/internal/config"
	"github.com/jville-family/external-dns-firewalla/internal/listener"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "listener: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := envOr("CONFIG_ENV", "/home/pi/.firewalla/k8s-external-dns/config.env")
	if err := config.LoadEnvFile(cfgPath); err != nil {
		return err
	}
	cfg, err := config.LoadListener()
	if err != nil {
		return err
	}
	level, err := config.ParseLogLevel(cfg.LogLevel)
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	srv := listener.NewServer(listener.ServerConfig{
		Config: listener.Config{
			StateDir:   cfg.StateDir,
			DnsmasqDir: cfg.DnsmasqDir,
			ConfName:   cfg.ConfName,
		},
		Secret:       []byte(cfg.HMACSecret),
		AllowDomains: cfg.AllowDomains,
		QueueSize:    cfg.QueueSize,
		Reloader:     listener.SystemctlReloader{Mode: cfg.ReloadMode},
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	srv.StartWorker(ctx)

	addr := fmt.Sprintf("%s:%s", cfg.ListenAddr, cfg.ListenPort)
	httpSrv := &http.Server{Addr: addr, Handler: srv.Handler()}
	errCh := make(chan error, 1)
	go func() {
		slog.Warn("listener listening", "addr", addr, "state", filepath.Join(cfg.StateDir, "state.json"))
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
