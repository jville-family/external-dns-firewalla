package dnsmasq

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/jville-family/external-dns-firewalla/internal/webhook"
)

const header = "# managed by external-dns-firewalla — DO NOT EDIT\n"

// Render compiles endpoints into a deterministic dnsmasq config file.
func Render(endpoints []*webhook.Endpoint) ([]byte, error) {
	var lines []string

	// Group A/AAAA by DNS name for host-record merging.
	type addrs struct {
		v4 []string
		v6 []string
	}
	hosts := map[string]*addrs{}
	var hostNames []string

	for _, ep := range endpoints {
		if ep == nil {
			continue
		}
		rt := strings.ToUpper(ep.RecordType)
		name := strings.ToLower(strings.TrimSuffix(ep.DNSName, "."))

		switch rt {
		case "A", "AAAA":
			h, ok := hosts[name]
			if !ok {
				h = &addrs{}
				hosts[name] = h
				hostNames = append(hostNames, name)
			}
			for _, t := range ep.Targets {
				ip := net.ParseIP(t)
				if ip == nil {
					return nil, fmt.Errorf("invalid IP %q for %s", t, name)
				}
				if rt == "A" {
					if ip.To4() == nil {
						return nil, fmt.Errorf("not IPv4: %q", t)
					}
					h.v4 = append(h.v4, t)
				} else {
					if ip.To4() != nil {
						return nil, fmt.Errorf("not IPv6: %q", t)
					}
					h.v6 = append(h.v6, t)
				}
			}
		case "CNAME":
			for _, tgt := range ep.Targets {
				tgt = strings.ToLower(strings.TrimSuffix(tgt, "."))
				line := fmt.Sprintf("cname=%s,%s", name, tgt)
				if ep.RecordTTL > 0 {
					line += fmt.Sprintf(",%d", ep.RecordTTL)
				}
				lines = append(lines, line)
			}
		case "TXT":
			for _, tgt := range ep.Targets {
				lines = append(lines, renderTXT(name, tgt))
			}
		case "SRV":
			for _, tgt := range ep.Targets {
				line, err := renderSRV(name, tgt)
				if err != nil {
					return nil, err
				}
				lines = append(lines, line)
			}
		default:
			return nil, fmt.Errorf("unsupported record type %q", rt)
		}
	}

	sort.Strings(hostNames)
	for _, name := range hostNames {
		h := hosts[name]
		sort.Strings(h.v4)
		sort.Strings(h.v6)
		switch {
		case len(h.v4) > 0 && len(h.v6) > 0:
			// Pair first of each when both present; remaining as separate lines.
			n := len(h.v4)
			if len(h.v6) > n {
				n = len(h.v6)
			}
			for i := 0; i < n; i++ {
				parts := []string{name}
				if i < len(h.v4) {
					parts = append(parts, h.v4[i])
				}
				if i < len(h.v6) {
					parts = append(parts, h.v6[i])
				}
				lines = append(lines, "host-record="+strings.Join(parts, ","))
			}
		case len(h.v4) > 0:
			for _, v4 := range h.v4 {
				lines = append(lines, fmt.Sprintf("host-record=%s,%s", name, v4))
			}
		case len(h.v6) > 0:
			for _, v6 := range h.v6 {
				lines = append(lines, fmt.Sprintf("host-record=%s,%s", name, v6))
			}
		}
	}

	sort.Strings(lines)
	var b strings.Builder
	b.WriteString(header)
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

func renderTXT(name, value string) string {
	chunks := chunkTXT(value, 255)
	parts := make([]string, 0, len(chunks))
	for _, c := range chunks {
		parts = append(parts, `"`+escapeTXT(c)+`"`)
	}
	return fmt.Sprintf("txt-record=%s,%s", name, strings.Join(parts, ","))
}

func escapeTXT(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func chunkTXT(s string, size int) []string {
	if len(s) == 0 {
		return []string{""}
	}
	var out []string
	for len(s) > size {
		out = append(out, s[:size])
		s = s[size:]
	}
	out = append(out, s)
	return out
}

func renderSRV(name, target string) (string, error) {
	parts := strings.Fields(target)
	if len(parts) != 4 {
		return "", fmt.Errorf("malformed SRV target %q; want priority weight port hostname", target)
	}
	priority, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid SRV priority: %w", err)
	}
	weight, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid SRV weight: %w", err)
	}
	port, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", fmt.Errorf("invalid SRV port: %w", err)
	}
	host := strings.ToLower(strings.TrimSuffix(parts[3], "."))
	// dnsmasq: srv-host=name,target,port,priority,weight
	return fmt.Sprintf("srv-host=%s,%s,%d,%d,%d", name, host, port, priority, weight), nil
}
