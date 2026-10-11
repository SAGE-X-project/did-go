package did

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// DID parameter names (DID Core 1.0 §3.2.1, DID Resolution v1.0 §3).
const (
	ParamService     = "service"
	ParamServiceType = "serviceType"
	ParamRelativeRef = "relativeRef"
	ParamVersionID   = "versionId"
	ParamVersionTime = "versionTime"
	// ParamHL is the DID Core 1.0 hashlink parameter, removed in DID
	// Resolution v1.0.
	ParamHL = "hl"
)

// ParameterError reports a query that cannot be read as DID parameters.
type ParameterError struct {
	// Name is the parameter name, or "" when the name itself is malformed.
	Name string
	// Msg says what is wrong.
	Msg string
}

// Error describes the failure.
func (e *ParameterError) Error() string {
	if e.Name == "" {
		return "did: invalid DID parameter: " + e.Msg
	}
	return fmt.Sprintf("did: invalid DID parameter %q: %s", e.Name, e.Msg)
}

// DIDParameters are the DID parameters of a DID URL query as parsed values.
// Values are percent-decoded once; delimiters encoded in a value (for
// example %2F in relativeRef) therefore appear decoded. Support for any
// parameter is optional for a dereferencer (DID Core 1.0 §3.2.1).
type DIDParameters struct {
	// Service is the service parameter.
	Service string
	// ServiceType is the serviceType parameter (DID Resolution only).
	ServiceType string
	// RelativeRef is the relativeRef parameter.
	RelativeRef string
	// VersionID is the versionId parameter.
	VersionID string
	// VersionTime is the versionTime parameter, or the zero time when absent.
	VersionTime time.Time
	// HL is the DID Core 1.0 hl parameter.
	HL     string
	params []param
}

type param struct{ name, value string }

// Get returns the decoded value of any parameter, including extension
// parameters, and whether it is present.
func (p DIDParameters) Get(name string) (string, bool) {
	for _, x := range p.params {
		if x.name == name {
			return x.value, true
		}
	}
	return "", false
}

// Names returns the parameter names in query order, in a fresh slice.
func (p DIDParameters) Names() []string {
	out := make([]string, len(p.params))
	for i, x := range p.params {
		out[i] = x.name
	}
	return out
}

// Parameters parses the query of u as DID parameters: name=value pairs
// separated by "&". A pair without "=", an empty name, a repeated name or a
// versionTime that is not a UTC datetime without sub-second precision (DID
// Resolution v1.0 §3, §3.1) is an error. Extension parameters are kept.
func (u DIDURL) Parameters() (DIDParameters, error) {
	var p DIDParameters
	if u.query == "" {
		return p, nil
	}
	for _, pair := range strings.Split(u.query, "&") {
		name, raw, ok := strings.Cut(pair, "=")
		if !ok || name == "" {
			return DIDParameters{}, &ParameterError{Name: name, Msg: `a DID parameter is name "=" value`}
		}
		if slices.ContainsFunc(p.params, func(x param) bool { return x.name == name }) {
			return DIDParameters{}, &ParameterError{Name: name, Msg: "repeated parameter"}
		}
		value, err := url.PathUnescape(raw)
		if err != nil {
			return DIDParameters{}, &ParameterError{Name: name, Msg: err.Error()}
		}
		if err := p.set(name, value); err != nil {
			return DIDParameters{}, err
		}
		p.params = append(p.params, param{name, value})
	}
	return p, nil
}

func (p *DIDParameters) set(name, value string) error {
	switch name {
	case ParamService:
		p.Service = value
	case ParamServiceType:
		p.ServiceType = value
	case ParamRelativeRef:
		p.RelativeRef = value
	case ParamVersionID:
		p.VersionID = value
	case ParamHL:
		p.HL = value
	case ParamVersionTime:
		t, ok := parseTimestamp(value)
		if !ok {
			return &ParameterError{Name: name, Msg: "must be a UTC datetime without sub-second precision, such as 2020-12-20T19:17:47Z"}
		}
		p.VersionTime = t
	}
	return nil
}

// parseTimestamp parses the datetime format of DID Resolution v1.0 §3.1. It
// matches spec.ParseTimestamp, which this package does not import so that
// parsing DIDs needs no other package (docs/14 §1).
func parseTimestamp(s string) (time.Time, bool) {
	const layout = "2006-01-02T15:04:05Z"
	if len(s) != len(layout) || s[len(s)-1] != 'Z' {
		return time.Time{}, false
	}
	t, err := time.Parse(layout, s)
	return t, err == nil
}
