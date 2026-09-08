package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jville-family/external-dns-firewalla/internal/config"
)

func TestLoadEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.env")
	content := `
# comment
export HMAC_SECRET=abc123
ALLOWED_DOMAINS="app.lan,k8s.local"
LISTEN_ADDR=0.0.0.0
LISTEN_PORT=10053
LOG_LEVEL=debug
PATH_WITH_EQ=a=b=c
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.LoadEnvFile(path); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("HMAC_SECRET") != "abc123" {
		t.Fatalf("HMAC_SECRET=%q", os.Getenv("HMAC_SECRET"))
	}
	if os.Getenv("ALLOWED_DOMAINS") != "app.lan,k8s.local" {
		t.Fatalf("ALLOWED_DOMAINS=%q", os.Getenv("ALLOWED_DOMAINS"))
	}
	if os.Getenv("PATH_WITH_EQ") != "a=b=c" {
		t.Fatalf("PATH_WITH_EQ=%q", os.Getenv("PATH_WITH_EQ"))
	}
	if os.Getenv("LOG_LEVEL") != "debug" {
		t.Fatalf("LOG_LEVEL=%q", os.Getenv("LOG_LEVEL"))
	}
}

func TestListenerConfigDefaults(t *testing.T) {
	t.Setenv("HMAC_SECRET", "s")
	t.Setenv("ALLOWED_DOMAINS", "app.lan")
	t.Setenv("LISTEN_ADDR", "")
	t.Setenv("LISTEN_PORT", "")
	t.Setenv("LOG_LEVEL", "")
	cfg, err := config.LoadListener()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "127.0.0.1" || cfg.ListenPort != "10053" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.LogLevel != "warn" {
		t.Fatalf("log=%q", cfg.LogLevel)
	}
}

func TestListenerMissingSecret(t *testing.T) {
	t.Setenv("HMAC_SECRET", "")
	t.Setenv("ALLOWED_DOMAINS", "app.lan")
	if _, err := config.LoadListener(); err == nil {
		t.Fatal("expected error")
	}
}

func TestProxyConfig(t *testing.T) {
	t.Setenv("HMAC_SECRET", "s")
	t.Setenv("ALLOWED_DOMAINS", "app.lan,k8s.local")
	t.Setenv("LISTENER_URL", "http://192.168.1.1:10053")
	t.Setenv("WEBHOOK_ADDR", "")
	t.Setenv("HEALTH_ADDR", "")
	cfg, err := config.LoadProxy()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenerURL != "http://192.168.1.1:10053" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.WebhookAddr != ":8888" || cfg.HealthAddr != ":8080" {
		t.Fatalf("%+v", cfg)
	}
	if len(cfg.AllowDomains) != 2 {
		t.Fatalf("%v", cfg.AllowDomains)
	}
}

func TestParseLogLevel(t *testing.T) {
	cases := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true, "bogus": false,
	}
	for lvl, ok := range cases {
		_, err := config.ParseLogLevel(lvl)
		if ok && err != nil {
			t.Fatalf("%s: %v", lvl, err)
		}
		if !ok && err == nil {
			t.Fatalf("%s: expected error", lvl)
		}
	}
}
