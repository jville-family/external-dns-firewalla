package config

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// ListenerConfig holds Firewalla listener settings.
type ListenerConfig struct {
	HMACSecret   string
	AllowDomains []string
	ListenAddr   string
	ListenPort   string
	LogLevel     string
	StateDir     string
	DnsmasqDir   string
	ConfName     string
	QueueSize    int
	ReloadMode   string
}

// ProxyConfig holds Kubernetes webhook proxy settings.
type ProxyConfig struct {
	HMACSecret   string
	AllowDomains []string
	ListenerURL  string
	WebhookAddr  string
	HealthAddr   string
	LogLevel     string
}

// LoadEnvFile loads KEY=VALUE pairs into the process environment.
// Existing env vars are not overwritten. Supports comments, export prefix, and quotes.
func LoadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if os.Getenv(key) == "" {
			if err := os.Setenv(key, val); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

// LoadListener reads listener config from the environment.
func LoadListener() (ListenerConfig, error) {
	secret := os.Getenv("HMAC_SECRET")
	if secret == "" {
		return ListenerConfig{}, fmt.Errorf("HMAC_SECRET is required")
	}
	domains := splitCSV(os.Getenv("ALLOWED_DOMAINS"))
	if len(domains) == 0 {
		return ListenerConfig{}, fmt.Errorf("ALLOWED_DOMAINS is required")
	}
	cfg := ListenerConfig{
		HMACSecret:   secret,
		AllowDomains: domains,
		ListenAddr:   envOr("LISTEN_ADDR", "127.0.0.1"),
		ListenPort:   envOr("LISTEN_PORT", "10053"),
		LogLevel:     envOr("LOG_LEVEL", "warn"),
		StateDir:     envOr("STATE_DIR", "/home/pi/.firewalla/k8s-external-dns"),
		DnsmasqDir:   envOr("DNSMASQ_DIR", "/home/pi/.firewalla/config/dnsmasq_local"),
		ConfName:     envOr("CONF_NAME", "k8s-external-dns.conf"),
		QueueSize:    8,
		ReloadMode:   envOr("RELOAD_MODE", "restart"),
	}
	return cfg, nil
}

// LoadProxy reads proxy config from the environment.
func LoadProxy() (ProxyConfig, error) {
	secret := os.Getenv("HMAC_SECRET")
	if secret == "" {
		return ProxyConfig{}, fmt.Errorf("HMAC_SECRET is required")
	}
	domains := splitCSV(os.Getenv("ALLOWED_DOMAINS"))
	if len(domains) == 0 {
		return ProxyConfig{}, fmt.Errorf("ALLOWED_DOMAINS is required")
	}
	url := os.Getenv("LISTENER_URL")
	if url == "" {
		return ProxyConfig{}, fmt.Errorf("LISTENER_URL is required")
	}
	return ProxyConfig{
		HMACSecret:   secret,
		AllowDomains: domains,
		ListenerURL:  url,
		WebhookAddr:  envOr("WEBHOOK_ADDR", ":8888"),
		HealthAddr:   envOr("HEALTH_ADDR", ":8080"),
		LogLevel:     envOr("LOG_LEVEL", "warn"),
	}, nil
}

// ParseLogLevel maps a string to slog.Level.
func ParseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid LOG_LEVEL %q", s)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
