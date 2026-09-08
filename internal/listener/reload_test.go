package listener_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jville-family/external-dns-firewalla/internal/listener"
)

func TestSystemctlReloaderUsesSudo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scripts")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "cmds.log")
	sudo := filepath.Join(dir, "sudo")
	systemctl := "/usr/bin/systemctl"

	script := "#!/bin/sh\necho \"$@\" >> \"$LOG\"\n"
	if err := os.WriteFile(sudo, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// Rewrite with LOG baked in — avoid env dependency in shebang body
	script = "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + logPath + "'\n"
	if err := os.WriteFile(sudo, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	r := listener.SystemctlReloader{
		Mode:          "restart",
		SudoPath:      sudo,
		SystemctlPath: systemctl,
	}
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	want := systemctl + " restart firerouter_dns\n"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSystemctlReloaderStopStart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scripts")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "cmds.log")
	sudo := filepath.Join(dir, "sudo")
	systemctl := "/bin/systemctl"
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + logPath + "'\n"
	if err := os.WriteFile(sudo, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	r := listener.SystemctlReloader{
		Mode:          "stop-start",
		SudoPath:      sudo,
		SystemctlPath: systemctl,
	}
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(got)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines=%v", lines)
	}
	if lines[0] != systemctl+" stop firerouter_dns" {
		t.Fatalf("line0=%q", lines[0])
	}
	if lines[1] != systemctl+" start firerouter_dns" {
		t.Fatalf("line1=%q", lines[1])
	}
}

func TestSystemctlReloaderPropagatesFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scripts")
	}
	dir := t.TempDir()
	sudo := filepath.Join(dir, "sudo")
	if err := os.WriteFile(sudo, []byte("#!/bin/sh\necho nope >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := listener.SystemctlReloader{SudoPath: sudo, SystemctlPath: "/usr/bin/systemctl"}
	if err := r.Reload(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}
