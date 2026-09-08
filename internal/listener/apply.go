package listener

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/jville-family/external-dns-firewalla/internal/dnsmasq"
	"github.com/jville-family/external-dns-firewalla/internal/webhook"
)

// Config holds filesystem paths for the listener.
type Config struct {
	StateDir   string
	DnsmasqDir string
	ConfName   string
}

// Reloader restarts or reloads the DNS service.
type Reloader interface {
	Reload(ctx context.Context) error
}

// SystemctlReloader runs systemctl against firerouter_dns via sudo.
// The listener runs as user pi; a sudoers drop-in grants NOPASSWD for these
// exact commands only.
type SystemctlReloader struct {
	Mode string // "restart" or "stop-start"

	// Optional overrides for tests. Empty means look up on PATH / well-known paths.
	SudoPath      string
	SystemctlPath string
}

const firerouterDNS = "firerouter_dns"

// Reload implements Reloader.
func (s SystemctlReloader) Reload(ctx context.Context) error {
	mode := s.Mode
	if mode == "" {
		mode = "restart"
	}
	sudo := s.sudoBin()
	systemctl := s.systemctlBin()

	run := func(args ...string) error {
		cmd := exec.CommandContext(ctx, sudo, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %w (%s)", args, err, bytes.TrimSpace(out))
		}
		return nil
	}

	if mode == "stop-start" {
		if err := run(systemctl, "stop", firerouterDNS); err != nil {
			return err
		}
		if err := run(systemctl, "start", firerouterDNS); err != nil {
			return err
		}
		return nil
	}
	return run(systemctl, "restart", firerouterDNS)
}

func (s SystemctlReloader) sudoBin() string {
	if s.SudoPath != "" {
		return s.SudoPath
	}
	if p, err := exec.LookPath("sudo"); err == nil {
		return p
	}
	return "/usr/bin/sudo"
}

func (s SystemctlReloader) systemctlBin() string {
	if s.SystemctlPath != "" {
		return s.SystemctlPath
	}
	for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("systemctl"); err == nil {
		return p
	}
	return "/usr/bin/systemctl"
}

// Applier applies DNS change sets transactionally.
type Applier struct {
	cfg      Config
	store    *Store
	reloader Reloader
}

// NewApplier constructs an Applier.
func NewApplier(cfg Config, r Reloader) *Applier {
	if cfg.ConfName == "" {
		cfg.ConfName = "k8s-external-dns.conf"
	}
	return &Applier{
		cfg:      cfg,
		store:    NewStore(filepath.Join(cfg.StateDir, "state.json")),
		reloader: r,
	}
}

// Apply loads state, applies changes, and on real change writes state+conf and reloads.
// Returns (changed, err). On reload failure, state and conf are already persisted.
func (a *Applier) Apply(ctx context.Context, changes *webhook.Changes) (bool, error) {
	current, err := a.store.Load()
	if err != nil {
		return false, err
	}
	next := ApplyDiff(current, changes)
	if Equal(current, next) {
		return false, nil
	}

	rendered, err := dnsmasq.Render(next.Endpoints())
	if err != nil {
		return false, err
	}

	confPath := filepath.Join(a.cfg.DnsmasqDir, a.cfg.ConfName)
	existing, _ := os.ReadFile(confPath)
	if Equal(current, next) && bytes.Equal(existing, rendered) {
		return false, nil
	}

	if err := os.MkdirAll(a.cfg.StateDir, 0o755); err != nil {
		return false, err
	}
	if err := os.MkdirAll(a.cfg.DnsmasqDir, 0o755); err != nil {
		return false, err
	}
	if err := a.store.Save(next); err != nil {
		return false, err
	}
	if err := atomicWrite(confPath, rendered, 0o644); err != nil {
		return false, err
	}
	if err := a.reloader.Reload(ctx); err != nil {
		return true, err
	}
	return true, nil
}

// ReadState returns the current managed endpoints.
func (a *Applier) ReadState() ([]*webhook.Endpoint, error) {
	st, err := a.store.Load()
	if err != nil {
		return nil, err
	}
	return st.Endpoints(), nil
}
