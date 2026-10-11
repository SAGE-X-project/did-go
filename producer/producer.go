// Package producer is the conforming producer of did-go (DID Core 1.0 §1.4,
// §6; DID 1.1 §6; docs/14 §5). It implements representation.Producer for
// every profile in package spec:
//
//	Version  JSONLD  @context[0]                       media type
//	V11      true    https://www.w3.org/ns/did/v1.1    application/did
//	V11      false   (no @context)                     application/did
//	V10      true    https://www.w3.org/ns/did/v1      application/did+ld+json
//	V10      false   (no @context)                     application/did+json
//
// (docs/09 §5). Output is deterministic (docs/00 NFR-1): the root members are
// @context, the core properties in specification order, the other
// representation-specific entries and the extensions in their map order;
// verification method and service members follow the order of the
// internal/wire tables and then the additional properties sorted by name.
//
// The producer never writes a non-conforming document: before writing it
// applies document.Validate for the target version and refuses any error
// finding, which makes service.id required for DID Core 1.0 output. Secret
// key material is left out unless ProduceOptions.IncludeSecret is set.
//
// Undefined terms. A producer "MUST serialize all entries in the DID
// document data model ... and return the serialization after the production
// process completes" (production-and-consumption.10), and "A conforming
// producer that generates a JSON-LD representation SHOULD NOT produce a DID
// document that contains terms not defined via the @context" (DID Core 1.0
// §6.3.1 production-0.5, DID 1.1 §6.2.3 json-ld-processors.6). A document
// with undefined terms is still conforming, so refusing it would fail the
// MUST; by default the producer writes every entry. RejectUndefinedTerms
// follows the recommendation instead and refuses, rather than drops, a
// JSON-LD document that holds a term its @context does not define. The
// check is made only when every context is known locally (the DID base
// contexts and inline maps, jsonld.Context.Terms); a context URL that is
// not known leaves the question undecided and the document is written. JSON
// production is not checked.
package producer

import (
	"fmt"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/wire"
	"github.com/sage-x-project/did-go/jsonld"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
)

// Producer serializes DID documents. It has no mutable state and is safe for
// concurrent use.
type Producer struct {
	rejectUndefined bool
}

var _ representation.Producer = (*Producer)(nil)

// Option configures a Producer.
type Option func(*Producer)

// RejectUndefinedTerms makes JSON-LD production refuse a document that
// holds a term its @context does not define, with an *Error whose Statement
// is did11-cr20260305#json-ld-processors.6 (DID 1.1) or core10#production-0.5
// (DID Core 1.0), following "A conforming producer that generates a JSON-LD
// representation SHOULD NOT produce a DID document that contains terms not
// defined via the @context". A refused document is not written, so no entry
// is dropped, but refusing a conforming document deviates from
// production-and-consumption.10 ("MUST serialize all entries"), which the
// default follows.
func RejectUndefinedTerms() Option {
	return func(p *Producer) { p.rejectUndefined = true }
}

// New returns a Producer. Without options it writes every entry, also
// terms the @context does not define (see RejectUndefinedTerms).
func New(opts ...Option) *Producer {
	p := &Producer{}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Error reports a document that the producer refuses to serialize.
type Error struct {
	// Property locates the value, for example "service[0]".
	Property string
	// Statement is the requirement id that refusing follows, if one applies.
	Statement string
	// Reason says what is wrong.
	Reason string
}

// Error describes the refusal.
func (e *Error) Error() string {
	s := fmt.Sprintf("producer: %s: %s", e.Property, e.Reason)
	if e.Statement != "" {
		s += " (" + e.Statement + ")"
	}
	return s
}

func errorf(property, statement, format string, args ...any) *Error {
	return &Error{Property: property, Statement: statement, Reason: fmt.Sprintf(format, args...)}
}

// Produce serializes d as the representation opts select and returns the
// bytes with their media type (production-and-consumption.11). A version of
// spec.VUnknown means spec.Latest.
func (p *Producer) Produce(d *document.Document, opts representation.ProduceOptions) ([]byte, string, error) {
	if d == nil {
		return nil, "", errorf("document", "", "no document")
	}
	v := opts.Version
	if v == spec.VUnknown {
		v = spec.Latest
	}
	if !v.IsSupported() {
		return nil, "", errorf("version", "", "unsupported DID version %d", int(v))
	}
	if err := conforms(d, v); err != nil {
		return nil, "", err
	}
	w := writer{includeSecret: opts.IncludeSecret}
	root, ctx, err := w.document(d, v, opts.JSONLD)
	if err != nil {
		return nil, "", err
	}
	if opts.JSONLD && p.rejectUndefined {
		if err := checkTerms(root, ctx, v); err != nil {
			return nil, "", err
		}
	}
	return wire.Encode(root), representation.MediaTypeFor(v, opts.JSONLD), nil
}

// conforms refuses a document with an error finding for version v
// (production-and-consumption.12: "MUST NOT produce non-conforming DIDs or
// DID documents").
func conforms(d *document.Document, v spec.Version) error {
	for _, f := range document.Validate(d, v) {
		if f.Severity == document.SeverityError {
			return &document.ConformanceError{
				Code: document.CodeInvalidControlledIdentifierDocument, Property: f.Property,
				Statement: f.Statement, Reason: f.Message,
			}
		}
	}
	return nil
}

// checkTerms reports the first term of root, a verification method or a
// service that ctx, the @context written, does not define.
func checkTerms(root wire.Node, ctx document.Value, v spec.Version) error {
	c, _ := jsonld.ParseContext(ctx) // ProductionContext returned a valid form
	terms, known := c.Terms()
	if !known {
		return nil
	}
	statement := "did11-cr20260305#json-ld-processors.6"
	if v == spec.V10 {
		statement = "core10#production-0.5"
	}
	return walkTerms(root, "", terms, statement)
}

// walkTerms checks the member names of a document, method or service node
// and descends into the properties that hold methods and services.
func walkTerms(n wire.Node, where string, terms jsonld.Terms, statement string) error {
	for _, m := range n.Members {
		path := m.Name
		if where != "" {
			path = where + "." + m.Name
		}
		if !terms.Defines(m.Name) {
			return errorf(path, statement, "term %q is not defined by the @context", m.Name)
		}
		if where != "" || !holdsNodes(m.Name) {
			continue
		}
		for i, item := range m.Value.Items {
			if item.Kind != wire.Object {
				continue
			}
			if err := walkTerms(item, fmt.Sprintf("%s[%d]", m.Name, i), terms, statement); err != nil {
				return err
			}
		}
	}
	return nil
}

// holdsNodes reports whether a root property holds verification method or
// service maps.
func holdsNodes(name string) bool {
	switch name {
	case wire.PropVerificationMethod, wire.PropService, wire.PropAuthentication, wire.PropAssertionMethod,
		wire.PropKeyAgreement, wire.PropCapabilityInvocation, wire.PropCapabilityDelegation:
		return true
	}
	return false
}
