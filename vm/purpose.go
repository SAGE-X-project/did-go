package vm

import (
	"fmt"

	"github.com/sage-x-project/did-go/did"
)

// Purpose is a verification relationship (CID 1.0 §2.3, DID Core 1.0 §5.3).
// The zero value is not a purpose.
type Purpose int

// The five verification relationships.
const (
	Authentication Purpose = iota + 1
	AssertionMethod
	KeyAgreement
	CapabilityInvocation
	CapabilityDelegation
)

// String returns the property name, for example "assertionMethod".
func (p Purpose) String() string {
	switch p {
	case Authentication:
		return "authentication"
	case AssertionMethod:
		return "assertionMethod"
	case KeyAgreement:
		return "keyAgreement"
	case CapabilityInvocation:
		return "capabilityInvocation"
	case CapabilityDelegation:
		return "capabilityDelegation"
	}
	return fmt.Sprintf("Purpose(%d)", int(p))
}

// Valid reports whether p is one of the five relationships.
func (p Purpose) Valid() bool { return p >= Authentication && p <= CapabilityDelegation }

// ParsePurpose returns the relationship with the given property name.
func ParsePurpose(s string) (Purpose, error) {
	for _, p := range Purposes() {
		if p.String() == s {
			return p, nil
		}
	}
	return 0, fmt.Errorf("vm: unknown verification relationship %q", s)
}

// Purposes returns the five relationships in specification order, in a fresh
// slice.
func Purposes() []Purpose {
	return []Purpose{Authentication, AssertionMethod, KeyAgreement, CapabilityInvocation, CapabilityDelegation}
}

// Relationship is one element of a verification relationship: either a
// reference to a verification method (a DID URL, possibly relative) or an
// embedded verification method (CID 1.0 §2.3: "Each verification method MAY
// be embedded or referenced"). The zero value is empty.
type Relationship struct {
	ref    did.DIDURL
	method *Method
}

// Ref returns a relationship element that references a verification method.
func Ref(u did.DIDURL) Relationship { return Relationship{ref: u} }

// Embed returns a relationship element that embeds a copy of m.
func Embed(m Method) Relationship {
	c := m.Clone()
	return Relationship{method: &c}
}

// Reference returns the referenced DID URL and true, or false for an
// embedded method.
func (r Relationship) Reference() (did.DIDURL, bool) {
	return r.ref, r.method == nil && !r.ref.IsZero()
}

// Method returns a copy of the embedded method and true, or false for a
// reference.
func (r Relationship) Method() (Method, bool) {
	if r.method == nil {
		return Method{}, false
	}
	return r.method.Clone(), true
}

// IsEmbedded reports whether r embeds a verification method.
func (r Relationship) IsEmbedded() bool { return r.method != nil }

// ID returns the referenced DID URL or the id of the embedded method.
func (r Relationship) ID() did.DIDURL {
	if r.method != nil {
		return r.method.ID
	}
	return r.ref
}

// Validate checks that r is a reference or a valid embedded method.
func (r Relationship) Validate() error {
	if r.method != nil {
		return r.method.Validate()
	}
	if r.ref.IsZero() {
		return errorf("relationship", "cid10#authentication.3", "an element is a DID URL reference or an embedded verification method")
	}
	return nil
}
