package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jville-family/external-dns-firewalla/internal/config"
	"github.com/jville-family/external-dns-firewalla/internal/proxy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "proxy: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadProxy()
	if err != nil {
		return err
	}
	level, err := config.ParseLogLevel(cfg.LogLevel)
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	srv := proxy.New(proxy.Config{
		ListenerURL:  cfg.ListenerURL,
		Secret:       []byte(cfg.HMACSecret),
		AllowDomains: cfg.AllowDomains,
	})

	webhookSrv := &http.Server{Addr: cfg.WebhookAddr, Handler: srv.WebhookHandler()}
	healthSrv := &http.Server{Addr: cfg.HealthAddr, Handler: srv.HealthHandler()}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)
	go func() {
		slog.Warn("webhook listening", "addr", cfg.WebhookAddr)
		errCh <- webhookSrv.ListenAndServe()
	}()
	go func() {
		slog.Warn("health listening", "addr", cfg.HealthAddr)
		errCh <- healthSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = webhookSrv.Shutdown(shutdownCtx)
		_ = healthSrv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
