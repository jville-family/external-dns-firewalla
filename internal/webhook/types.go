package webhook

// MediaType is the content type used for external-dns webhook negotiation.
const MediaType = "application/external.dns.webhook+json;version=1"

// Endpoint is the wire representation of an external-dns DNS endpoint.
type Endpoint struct {
	DNSName          string             `json:"dnsName"`
	Targets          []string           `json:"targets"`
	RecordType       string             `json:"recordType"`
	SetIdentifier    string             `json:"setIdentifier,omitempty"`
	RecordTTL        int64              `json:"recordTTL,omitempty"`
	Labels           map[string]string  `json:"labels,omitempty"`
	ProviderSpecific ProviderSpecific   `json:"providerSpecific,omitempty"`
}

// ProviderSpecific is a list of provider-specific key/value pairs.
type ProviderSpecific []ProviderSpecificProperty

// ProviderSpecificProperty is a single provider-specific key/value.
type ProviderSpecificProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Changes is the wire representation of plan.Changes from external-dns.
type Changes struct {
	Create    []*Endpoint `json:"Create"`
	UpdateOld []*Endpoint `json:"UpdateOld"`
	UpdateNew []*Endpoint `json:"UpdateNew"`
	Delete    []*Endpoint `json:"Delete"`
}

// DomainFilter is returned during webhook negotiation.
type DomainFilter struct {
	Filters []string `json:"filters"`
	Exclude []string `json:"exclude,omitempty"`
}
