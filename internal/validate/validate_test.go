package validate_test

import (
	"strings"
	"testing"

	"github.com/jville-family/external-dns-firewalla/internal/validate"
	"github.com/jville-family/external-dns-firewalla/internal/webhook"
)

func TestDomainAllowed(t *testing.T) {
	allow := []string{"app.lan", "k8s.local"}

	cases := []struct {
		name string
		ok   bool
	}{
		{"app.lan", true},
		{"plex.app.lan", true},
		{"a.b.c.app.lan", true},
		{"APP.LAN", true},
		{"plex.app.lan.", true},
		{"svc.k8s.local", true},
		{"badapp.lan", false},
		{"xapp.lan", false},
		{"app.lan.evil.com", false},
		{"lan", false},
		{"", false},
		{"notallowed.example", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validate.DomainAllowed(tc.name, allow)
			if got != tc.ok {
				t.Fatalf("DomainAllowed(%q) = %v, want %v", tc.name, got, tc.ok)
			}
		})
	}
}

func TestDomainAllowedEmptyFailClosed(t *testing.T) {
	if validate.DomainAllowed("app.lan", nil) {
		t.Fatal("empty allowlist must reject everything")
	}
	if validate.DomainAllowed("app.lan", []string{}) {
		t.Fatal("empty allowlist must reject everything")
	}
}

func TestRecordTypeAllowed(t *testing.T) {
	ok := []string{"A", "AAAA", "CNAME", "TXT", "SRV", "a", "aaaa", "cname", "txt", "srv"}
	bad := []string{"NS", "MX", "PTR", "SOA", "CAA", "", "AFSDB"}

	for _, rt := range ok {
		if !validate.RecordTypeAllowed(rt) {
			t.Fatalf("RecordTypeAllowed(%q) = false, want true", rt)
		}
	}
	for _, rt := range bad {
		if validate.RecordTypeAllowed(rt) {
			t.Fatalf("RecordTypeAllowed(%q) = true, want false", rt)
		}
	}
}

func TestHostnameValid(t *testing.T) {
	ok := []string{
		"app.lan",
		"plex.app.lan",
		"_http._tcp.app.lan",
		"a-plex.app.lan",
		"cname-plex.app.lan",
		"txt-plex.app.lan",
	}
	bad := []string{
		"*.app.lan",
		"a..b",
		"-leading.app.lan",
		"trailing-.app.lan",
		strings.Repeat("a", 64) + ".lan",
		strings.Repeat("a.", 130) + "com", // >253
		"",
		"host with space",
	}

	for _, h := range ok {
		if err := validate.Hostname(h); err != nil {
			t.Fatalf("Hostname(%q) unexpected error: %v", h, err)
		}
	}
	for _, h := range bad {
		if err := validate.Hostname(h); err == nil {
			t.Fatalf("Hostname(%q) expected error", h)
		}
	}
}

func TestRejectMetacharacters(t *testing.T) {
	metas := []string{"\n", "\r", ";", "&", "|", "$", "`", "(", ")", "<", ">", "\\"}
	for _, m := range metas {
		val := "safe" + m + "value"
		if err := validate.NoInjection(val); err == nil {
			t.Fatalf("NoInjection(%q) expected error", val)
		}
	}
	if err := validate.NoInjection("safe-value"); err != nil {
		t.Fatalf("NoInjection(safe) unexpected: %v", err)
	}
}

func TestTargetFamily(t *testing.T) {
	cases := []struct {
		rt, target string
		ok         bool
	}{
		{"A", "10.0.0.5", true},
		{"A", "fd00::1", false},
		{"A", "10.0.0.256", false},
		{"A", "not-an-ip", false},
		{"AAAA", "fd00::1", true},
		{"AAAA", "10.0.0.5", false},
		{"CNAME", "target.app.lan", true},
		{"CNAME", "bad;target", false},
		{"TXT", `heritage=external-dns,external-dns/owner=default`, true},
		{"TXT", "bad\nvalue", false},
		{"SRV", "0 5 5060 sip.app.lan", true},
	}

	for _, tc := range cases {
		t.Run(tc.rt+"/"+tc.target, func(t *testing.T) {
			err := validate.Target(tc.rt, tc.target)
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestFilterEndpoints(t *testing.T) {
	allow := []string{"app.lan"}
	in := []*webhook.Endpoint{
		{DNSName: "plex.app.lan", RecordType: "A", Targets: []string{"10.0.0.5"}},
		{DNSName: "evil.com", RecordType: "A", Targets: []string{"1.2.3.4"}},
		{DNSName: "bad.app.lan", RecordType: "NS", Targets: []string{"ns1.example"}},
		{DNSName: "broken.app.lan", RecordType: "A", Targets: []string{"fd00::1"}},
		{DNSName: "ok.app.lan", RecordType: "AAAA", Targets: []string{"fd00::5"}},
		{DNSName: "partial.app.lan", RecordType: "A", Targets: []string{"10.0.0.1", "not-an-ip"}},
	}

	out := validate.FilterEndpoints(in, allow)
	if len(out) != 3 {
		t.Fatalf("got %d endpoints, want 3: %+v", len(out), names(out))
	}
	if out[0].DNSName != "plex.app.lan" || out[1].DNSName != "ok.app.lan" || out[2].DNSName != "partial.app.lan" {
		t.Fatalf("unexpected: %v", names(out))
	}
	if len(out[2].Targets) != 1 || out[2].Targets[0] != "10.0.0.1" {
		t.Fatalf("partial targets = %v, want [10.0.0.1]", out[2].Targets)
	}
}

func names(eps []*webhook.Endpoint) []string {
	out := make([]string, len(eps))
	for i, e := range eps {
		out[i] = e.DNSName
	}
	return out
}

func TestFilterEndpointsDropsAllFailedTargets(t *testing.T) {
	allow := []string{"app.lan"}
	in := []*webhook.Endpoint{
		{DNSName: "x.app.lan", RecordType: "A", Targets: []string{"not-ip", "also-bad"}},
	}
	out := validate.FilterEndpoints(in, allow)
	if len(out) != 0 {
		t.Fatalf("expected empty, got %+v", out)
	}
}

func TestNormalizeRecordType(t *testing.T) {
	if got := validate.NormalizeRecordType("a"); got != "A" {
		t.Fatalf("got %q", got)
	}
}
