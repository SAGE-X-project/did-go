package document

import (
	"fmt"
	"strings"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/internal/multiformats"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// Severity says whether a finding makes a document non-conforming.
type Severity int

// Severities.
const (
	// SeverityError marks a violated MUST: the document does not conform to
	// the version.
	SeverityError Severity = iota + 1
	// SeverityWarning marks a SHOULD or RECOMMENDED that is not followed, or
	// a value that consumers of the version may not understand.
	SeverityWarning
)

// String returns "error" or "warning".
func (s Severity) String() string {
	if s == SeverityError {
		return "error"
	}
	return "warning"
}

// Finding is one result of Validate.
type Finding struct {
	Severity Severity
	// Statement is the requirement id the finding is about; "" for a did-go
	// policy warning without a statement.
	Statement string
	// Property locates the value, for example "service[0].id".
	Property string
	// Message says what was found.
	Message string
}

// String formats the finding.
func (f Finding) String() string {
	s := fmt.Sprintf("%s: %s: %s", f.Severity, f.Property, f.Message)
	if f.Statement != "" {
		s += " (" + f.Statement + ")"
	}
	return s
}

// HasErrors reports whether any finding has SeverityError.
func HasErrors(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}

// Validate checks d against the rules of version v that Build does not
// check because they differ between versions, and against the SHOULD and
// RECOMMENDED statements of both. VUnknown is validated as spec.Latest.
// A nil document yields one error.
func Validate(d *Document, v spec.Version) []Finding {
	if v == spec.VUnknown {
		v = spec.Latest
	}
	p, err := spec.ProfileOf(v)
	if d == nil || err != nil {
		return []Finding{{SeverityError, "", "document", "no document or unsupported version"}}
	}
	var fs []Finding
	fs = append(fs, validateServices(d, p)...)
	fs = append(fs, validateMethods(d, p)...)
	return fs
}

func validateServices(d *Document, p spec.Profile) []Finding {
	var fs []Finding
	for i, s := range d.services {
		where := fmt.Sprintf("service[%d]", i)
		switch {
		case s.ID == "" && p.ServiceIDRequired:
			fs = append(fs, Finding{SeverityError, "core10#services.3", where + ".id", "DID Core 1.0 requires id in every service map"})
		case s.ID == "":
			fs = append(fs, Finding{SeverityWarning, "cid10#services.3", where + ".id",
				"the CID 1.0 parent sentence requires id; the property definition makes it optional"})
		case p.ServiceIDMustBeURI && !vm.IsURI(s.ID):
			fs = append(fs, Finding{SeverityError, "core10#services.5", where + ".id", "a DID Core 1.0 service id is an RFC 3986 URI"})
		}
		if !p.ServiceIDMustBeURI {
			continue
		}
		for j, e := range s.ServiceEndpoint {
			if e.Map == nil && !vm.IsNormalizedURI(e.URL) {
				fs = append(fs, Finding{SeverityError, "core10#services.11", fmt.Sprintf("%s.serviceEndpoint[%d]", where, j),
					"a DID Core 1.0 endpoint string is an RFC 3986 URI in normal form"})
			}
		}
	}
	return fs
}

// allMethods returns every verificationMethod entry and embedded method with
// the property path that locates it.
func allMethods(d *Document) ([]vm.Method, []string) {
	var ms []vm.Method
	var where []string
	for i, m := range d.methods {
		ms, where = append(ms, m), append(where, fmt.Sprintf("verificationMethod[%d]", i))
	}
	for _, p := range vm.Purposes() {
		for i, r := range d.relationships[p] {
			if m, ok := r.Method(); ok {
				ms, where = append(ms, m), append(where, fmt.Sprintf("%s[%d]", p, i))
			}
		}
	}
	return ms, where
}

func validateMethods(d *Document, p spec.Profile) []Finding {
	var fs []Finding
	ms, where := allMethods(d)
	for i, m := range ms {
		if m.ID.IsRelative() && !p.RelativeMethodIDs {
			fs = append(fs, Finding{SeverityError, "core10#verification-methods.6", where[i] + ".id",
				"a DID Core 1.0 verification method id is an absolute DID URL"})
		}
		if !p.DefinesTerm("expires") && (m.Expires != nil || m.Revoked != nil || m.SecretKeyJwk != nil || m.SecretKeyMultibase != "") {
			fs = append(fs, Finding{SeverityWarning, "", where[i],
				"expires, revoked and secret key properties are not defined by DID Core 1.0; its consumers treat them as extensions"})
		}
		if (m.Type == vm.TypeMultikey || m.Type == vm.TypeJsonWebKey) && !p.DefinesTerm(m.Type) {
			fs = append(fs, Finding{SeverityWarning, "", where[i] + ".type",
				"type " + m.Type + " is not defined by the DID Core 1.0 context; its consumers treat it as an extension"})
		}
		if h := m.PublicKeyMultibase; h != "" && h[0] != multiformats.HeaderBase58BTC && h[0] != multiformats.HeaderBase64URL {
			fs = append(fs, Finding{SeverityWarning, "", where[i] + ".publicKeyMultibase",
				"the Multibase header is not one CID 1.0 defines; the key cannot be decoded by did-go"})
		}
		if m.PublicKeyJwk != nil {
			fs = append(fs, jwkAdvice(d.id, m, where[i], p.Version)...)
		}
	}
	return fs
}

// jwkAdvice reports the RECOMMENDED and SHOULD statements about JWK kid and
// alg (DID Core 1.0 §5.2.1, CID 1.0 §2.2.3).
func jwkAdvice(subject did.DID, m vm.Method, where string, v spec.Version) []Finding {
	fragStmt, thumbStmt := "cid10#JsonWebKey.5", "cid10#JsonWebKey.6"
	if v == spec.V10 {
		fragStmt, thumbStmt = "core10#verification-material.4", "core10#verification-material.5"
	}
	var fs []Finding
	kid, hasKid := m.PublicKeyJwk["kid"].(string)
	id := m.ID
	if abs, err := m.ID.Resolve(subject.URL()); err == nil {
		id = abs
	}
	switch {
	case !hasKid:
		fs = append(fs, Finding{SeverityWarning, fragStmt, where + ".publicKeyJwk", "no kid to use as the fragment identifier"})
	case kid != id.Fragment():
		fs = append(fs, Finding{SeverityWarning, fragStmt, where + ".id", "the fragment is not the JWK kid"})
	}
	if hasKid && v != spec.V10 && !strings.Contains(id.String(), kid) {
		fs = append(fs, Finding{SeverityWarning, "cid10#JsonWebKey.9", where + ".publicKeyJwk.kid", "kid is not part of the method id"})
	}
	if thumb, err := vm.JWKThumbprint(m.PublicKeyJwk); err == nil && hasKid && kid != thumb {
		fs = append(fs, Finding{SeverityWarning, thumbStmt, where + ".publicKeyJwk.kid", "kid is not the RFC 7638 SHA-256 thumbprint"})
	}
	if _, ok := m.PublicKeyJwk["alg"].(string); !ok && v != spec.V10 {
		fs = append(fs, Finding{SeverityWarning, "cid10#JsonWebKey.7", where + ".publicKeyJwk.alg", "alg is not included"})
	}
	return fs
}
