package validate

import (
	"fmt"
	"net"
	"strings"
	"unicode"

	"github.com/jville-family/external-dns-firewalla/internal/webhook"
)

var allowedRecordTypes = map[string]struct{}{
	"A":     {},
	"AAAA":  {},
	"CNAME": {},
	"TXT":   {},
	"SRV":   {},
}

const injectionChars = ";&|$`()<>\\\n\r"

// NormalizeRecordType uppercases a DNS record type.
func NormalizeRecordType(rt string) string {
	return strings.ToUpper(strings.TrimSpace(rt))
}

// RecordTypeAllowed reports whether rt is one of A, AAAA, CNAME, TXT, SRV.
func RecordTypeAllowed(rt string) bool {
	_, ok := allowedRecordTypes[NormalizeRecordType(rt)]
	return ok
}

// DomainAllowed reports whether name is equal to or a subdomain of any entry
// in allow, using strict suffix matching with a leading-dot boundary.
// An empty allowlist rejects everything (fail closed).
func DomainAllowed(name string, allow []string) bool {
	if len(allow) == 0 {
		return false
	}
	n := normalizeDNSName(name)
	if n == "" {
		return false
	}
	for _, d := range allow {
		dom := normalizeDNSName(d)
		if dom == "" {
			continue
		}
		if n == dom || strings.HasSuffix(n, "."+dom) {
			return true
		}
	}
	return false
}

func normalizeDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// NoInjection rejects strings containing shell metacharacters or newlines.
func NoInjection(s string) error {
	if strings.ContainsAny(s, injectionChars) {
		return fmt.Errorf("value contains forbidden characters")
	}
	return nil
}

// Hostname validates a DNS name for use in dnsmasq config.
// Labels may start with underscore (SRV / external-dns registry names).
func Hostname(name string) error {
	n := normalizeDNSName(name)
	if n == "" {
		return fmt.Errorf("empty hostname")
	}
	if len(n) > 253 {
		return fmt.Errorf("hostname longer than 253 characters")
	}
	if strings.Contains(n, "*") {
		return fmt.Errorf("wildcards are not allowed")
	}
	if err := NoInjection(n); err != nil {
		return err
	}
	labels := strings.Split(n, ".")
	for _, label := range labels {
		if err := validateLabel(label); err != nil {
			return err
		}
	}
	return nil
}

func validateLabel(label string) error {
	if label == "" {
		return fmt.Errorf("empty label")
	}
	if len(label) > 63 {
		return fmt.Errorf("label longer than 63 characters")
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("label must not start or end with hyphen")
	}
	for _, r := range label {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			continue
		}
		return fmt.Errorf("invalid character %q in label", r)
	}
	return nil
}

// Target validates a record target for the given record type.
func Target(recordType, target string) error {
	rt := NormalizeRecordType(recordType)
	if err := NoInjection(target); err != nil {
		return err
	}
	switch rt {
	case "A":
		ip := net.ParseIP(target)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid IPv4 address %q", target)
		}
	case "AAAA":
		ip := net.ParseIP(target)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("invalid IPv6 address %q", target)
		}
	case "CNAME":
		return Hostname(target)
	case "TXT":
		if target == "" {
			return fmt.Errorf("empty TXT value")
		}
		return nil
	case "SRV":
		// SRV targets in external-dns are typically "priority weight port hostname"
		// or just a hostname depending on source; accept space-separated or hostname.
		parts := strings.Fields(target)
		if len(parts) == 1 {
			return Hostname(parts[0])
		}
		if len(parts) == 4 {
			return Hostname(parts[3])
		}
		return fmt.Errorf("invalid SRV target %q", target)
	default:
		return fmt.Errorf("unsupported record type %q", rt)
	}
	return nil
}

// FilterEndpoints returns a copy of endpoints that pass domain, type, hostname,
// and target validation. Endpoints whose targets all fail are dropped.
func FilterEndpoints(endpoints []*webhook.Endpoint, allow []string) []*webhook.Endpoint {
	out := make([]*webhook.Endpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		if ep == nil {
			continue
		}
		rt := NormalizeRecordType(ep.RecordType)
		if !RecordTypeAllowed(rt) {
			continue
		}
		if !DomainAllowed(ep.DNSName, allow) {
			continue
		}
		if err := Hostname(ep.DNSName); err != nil {
			continue
		}
		validTargets := make([]string, 0, len(ep.Targets))
		for _, tgt := range ep.Targets {
			if err := Target(rt, tgt); err != nil {
				continue
			}
			validTargets = append(validTargets, tgt)
		}
		if len(validTargets) == 0 {
			continue
		}
		cp := *ep
		cp.RecordType = rt
		cp.Targets = validTargets
		out = append(out, &cp)
	}
	return out
}
