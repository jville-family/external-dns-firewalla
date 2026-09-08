package dnsmasq_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jville-family/external-dns-firewalla/internal/dnsmasq"
	"github.com/jville-family/external-dns-firewalla/internal/webhook"
)

func TestRenderHeader(t *testing.T) {
	out, err := dnsmasq.Render(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), "# managed by external-dns-firewalla") {
		t.Fatalf("missing header: %q", out)
	}
}

func TestRenderHostRecordMerge(t *testing.T) {
	eps := []*webhook.Endpoint{
		{DNSName: "plex.app.lan", RecordType: "A", Targets: []string{"10.0.0.5"}},
		{DNSName: "plex.app.lan", RecordType: "AAAA", Targets: []string{"fd00::5"}},
	}
	out, err := dnsmasq.Render(eps)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "host-record=plex.app.lan,10.0.0.5,fd00::5") {
		t.Fatalf("expected merged host-record, got:\n%s", out)
	}
}

func TestRenderTwoIPv4(t *testing.T) {
	eps := []*webhook.Endpoint{
		{DNSName: "web.app.lan", RecordType: "A", Targets: []string{"10.0.0.1", "10.0.0.2"}},
	}
	out, err := dnsmasq.Render(eps)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "host-record=web.app.lan,10.0.0.1") {
		t.Fatalf("missing first: %s", s)
	}
	if !strings.Contains(s, "host-record=web.app.lan,10.0.0.2") {
		t.Fatalf("missing second: %s", s)
	}
}

func TestRenderCNAME(t *testing.T) {
	eps := []*webhook.Endpoint{
		{DNSName: "alias.app.lan", RecordType: "CNAME", Targets: []string{"target.app.lan"}, RecordTTL: 300},
	}
	out, err := dnsmasq.Render(eps)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "cname=alias.app.lan,target.app.lan,300") {
		t.Fatalf("got:\n%s", out)
	}
}

func TestRenderCNAMENoTTL(t *testing.T) {
	eps := []*webhook.Endpoint{
		{DNSName: "alias.app.lan", RecordType: "CNAME", Targets: []string{"target.app.lan"}},
	}
	out, err := dnsmasq.Render(eps)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "cname=alias.app.lan,target.app.lan\n") &&
		!strings.HasSuffix(strings.TrimSpace(string(out)), "cname=alias.app.lan,target.app.lan") {
		t.Fatalf("got:\n%s", out)
	}
}

func TestRenderTXTQuoted(t *testing.T) {
	eps := []*webhook.Endpoint{
		{
			DNSName:    "a-plex.app.lan",
			RecordType: "TXT",
			Targets:    []string{`heritage=external-dns,external-dns/owner=default`},
		},
	}
	out, err := dnsmasq.Render(eps)
	if err != nil {
		t.Fatal(err)
	}
	want := `txt-record=a-plex.app.lan,"heritage=external-dns,external-dns/owner=default"`
	if !strings.Contains(string(out), want) {
		t.Fatalf("got:\n%s", out)
	}
}

func TestRenderTXTEscapeQuote(t *testing.T) {
	eps := []*webhook.Endpoint{
		{DNSName: "t.app.lan", RecordType: "TXT", Targets: []string{`say "hi"`}},
	}
	out, err := dnsmasq.Render(eps)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `txt-record=t.app.lan,"say \"hi\""`) {
		t.Fatalf("got:\n%s", out)
	}
}

func TestRenderTXTChunk255(t *testing.T) {
	val := strings.Repeat("a", 600)
	eps := []*webhook.Endpoint{
		{DNSName: "big.app.lan", RecordType: "TXT", Targets: []string{val}},
	}
	out, err := dnsmasq.Render(eps)
	if err != nil {
		t.Fatal(err)
	}
	line := ""
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "txt-record=") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("no txt-record line")
	}
	// Expect three quoted chunks: 255, 255, 90
	if strings.Count(line, `"`) < 6 {
		t.Fatalf("expected chunked quotes, got: %s", line)
	}
	if !strings.Contains(line, `,"`+strings.Repeat("a", 255)+`"`) &&
		!strings.Contains(line, `"`+strings.Repeat("a", 255)+`"`) {
		t.Fatalf("missing 255-char chunk: %s", line)
	}
}

func TestRenderSRV(t *testing.T) {
	eps := []*webhook.Endpoint{
		{DNSName: "_http._tcp.app.lan", RecordType: "SRV", Targets: []string{"10 5 8080 target.app.lan"}},
	}
	out, err := dnsmasq.Render(eps)
	if err != nil {
		t.Fatal(err)
	}
	want := "srv-host=_http._tcp.app.lan,target.app.lan,8080,10,5"
	if !strings.Contains(string(out), want) {
		t.Fatalf("got:\n%s\nwant substring %s", out, want)
	}
}

func TestRenderMalformedSRV(t *testing.T) {
	eps := []*webhook.Endpoint{
		{DNSName: "_http._tcp.app.lan", RecordType: "SRV", Targets: []string{"bad"}},
	}
	_, err := dnsmasq.Render(eps)
	if err == nil {
		t.Fatal("expected error for malformed SRV")
	}
}

func TestRenderGolden(t *testing.T) {
	eps := []*webhook.Endpoint{
		{DNSName: "plex.app.lan", RecordType: "A", Targets: []string{"10.0.0.5"}},
		{DNSName: "plex.app.lan", RecordType: "AAAA", Targets: []string{"fd00::5"}},
		{DNSName: "alias.app.lan", RecordType: "CNAME", Targets: []string{"plex.app.lan"}},
		{DNSName: "a-plex.app.lan", RecordType: "TXT", Targets: []string{`heritage=external-dns,external-dns/owner=default`}},
		{DNSName: "_http._tcp.app.lan", RecordType: "SRV", Targets: []string{"10 5 8080 target.app.lan"}},
	}
	got, err := dnsmasq.Render(eps)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "full.conf")
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("golden mismatch\nGOT:\n%s\nWANT:\n%s", got, want)
	}
}

func TestRenderDeterministic(t *testing.T) {
	makeState := func() []*webhook.Endpoint {
		return []*webhook.Endpoint{
			{DNSName: "b.app.lan", RecordType: "A", Targets: []string{"10.0.0.2"}},
			{DNSName: "a.app.lan", RecordType: "A", Targets: []string{"10.0.0.1"}},
			{DNSName: "c.app.lan", RecordType: "TXT", Targets: []string{"v"}},
			{DNSName: "a.app.lan", RecordType: "AAAA", Targets: []string{"fd00::1"}},
		}
	}
	first, err := dnsmasq.Render(makeState())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		got, err := dnsmasq.Render(makeState())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, first) {
			t.Fatalf("iteration %d not deterministic", i)
		}
	}
}
