// Package consumer is the conforming consumer of did-go (DID Core 1.0 §1.4,
// §6; DID 1.1 §6; docs/14 §5). It implements representation.Consumer.
//
// Consumption takes the bytes and their media type (production-and-
// consumption.13), parses them as strict JSON within input limits (docs/12
// §6.3), requires the root to be a JSON object, decides the representation
// and version with representation.Detect (docs/09 §4 as revised by docs/12
// §6.1), and reads every entry into one core document (docs/09 ADR-11):
//
//   - @context, the only known representation-specific entry, goes to the
//     representation-specific entries map under every media type (consumer
//     rule 3, production-and-consumption.16);
//   - the core properties are decoded into the typed model, recording
//     whether controller, service type and serviceEndpoint were a single
//     value or a set;
//   - every other entry becomes an extension of the data model (consumer
//     rule 4, production-and-consumption.17; docs/00 FR-D7), except that in
//     a JSON-LD representation whose contexts are all known locally, terms
//     the @context does not define are dropped ("Conforming consumers that
//     process a JSON-LD representation SHOULD drop all terms from a DID
//     document that are not defined via the @context"). KeepUndefinedTerms
//     turns the drop off.
//
// The document is then built and validated for the detected version (for
// spec.VUnknown, spec.Latest), and any violation is an error
// (production-and-consumption.18).
package consumer

import (
	"fmt"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/wire"
	"github.com/sage-x-project/did-go/jsonld"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
)

// Default input limits; see WithLimits.
const (
	DefaultMaxBytes = wire.DefaultMaxBytes
	DefaultMaxDepth = wire.DefaultMaxDepth
)

// Consumer parses DID document representations. It has no mutable state and
// is safe for concurrent use.
type Consumer struct {
	limits        wire.Limits
	keepUndefined bool
}

var _ representation.Consumer = (*Consumer)(nil)

// Option configures a Consumer.
type Option func(*Consumer)

// WithLimits sets the largest accepted input in bytes and the deepest
// accepted nesting of arrays and objects. A value of zero or less keeps the
// default (DefaultMaxBytes, DefaultMaxDepth).
func WithLimits(maxBytes, maxDepth int) Option {
	return func(c *Consumer) { c.limits = wire.Limits{MaxBytes: maxBytes, MaxDepth: maxDepth} }
}

// KeepUndefinedTerms keeps terms that the @context of a JSON-LD
// representation does not define as extensions instead of dropping them.
func KeepUndefinedTerms() Option {
	return func(c *Consumer) { c.keepUndefined = true }
}

// New returns a Consumer.
func New(opts ...Option) *Consumer {
	c := &Consumer{}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Error reports input that is not a conforming representation of a DID
// document: malformed JSON, input beyond the limits, a root that is not an
// object, or a property whose JSON type the data model does not allow.
// Detection failures are *representation.DetectError and data model
// violations are *document.ConformanceError.
type Error struct {
	// Property locates the value, for example "service[0].type".
	Property string
	// Statement is the requirement id that was violated, if one applies.
	Statement string
	// Reason says what is wrong. It never contains the input.
	Reason string
}

// Error describes the failure.
func (e *Error) Error() string {
	s := fmt.Sprintf("consumer: %s: %s", e.Property, e.Reason)
	if e.Statement != "" {
		s += " (" + e.Statement + ")"
	}
	return s
}

func errorf(property, statement, format string, args ...any) *Error {
	return &Error{Property: property, Statement: statement, Reason: fmt.Sprintf(format, args...)}
}

// Consume parses data, received with mediaType, into a document.
func (c *Consumer) Consume(data []byte, mediaType string, opts representation.ConsumeOptions) (*document.Document, representation.ConsumeInfo, error) {
	var none representation.ConsumeInfo
	if err := knownMediaType(mediaType, opts); err != nil {
		return nil, none, err
	}
	root, err := wire.Parse(data, c.limits)
	if err != nil {
		return nil, none, errorf("document", "", "%v", err)
	}
	if root.Kind != wire.Object {
		return nil, none, errorf("document", rootStatement(mediaType),
			"the root element is a JSON %s, not a JSON Object", root.Kind)
	}
	info, err := representation.Detect(mediaType, detectContext(root), opts)
	if err != nil {
		return nil, none, err
	}
	r := reader{}
	if info.IsJSONLD {
		if err := r.context(root, info.DetectedVersion, c.keepUndefined); err != nil {
			return nil, none, err
		}
	}
	d, err := r.document(root)
	if err != nil {
		return nil, none, err
	}
	if err := conforms(d, info.DetectedVersion); err != nil {
		return nil, none, err
	}
	return d, info, nil
}

// knownMediaType rejects a missing or unknown media type before the payload
// is read: a consumer takes a media type as input and determines the
// representation with it (production-and-consumption.13 and .15).
func knownMediaType(mediaType string, opts representation.ConsumeOptions) error {
	if mt, err := representation.NormalizeMediaType(mediaType); err == nil &&
		(representation.IsDIDMediaType(mt) || representation.IsLowPrecision(mt)) {
		return nil
	}
	_, err := representation.Detect(mediaType, representation.Context{}, opts)
	return err
}

// rootStatement names the consumption rule that requires a root object.
func rootStatement(mediaType string) string {
	mt, _ := representation.NormalizeMediaType(mediaType)
	if v, ok := representation.VersionOf(mt); ok && v == spec.V10 {
		return "core10#consumption.3"
	}
	return "did11-cr20260305#consumption.3"
}

// detectContext describes the @context entry of root for detection.
func detectContext(root wire.Node) representation.Context {
	n, ok := root.Get(jsonld.ContextEntry)
	if !ok {
		return representation.Context{}
	}
	if n.Kind == wire.Array && len(n.Items) > 0 {
		n = n.Items[0]
	}
	if n.Kind == wire.String {
		return representation.Context{Present: true, First: n.Text}
	}
	return representation.Context{Present: true}
}

// conforms refuses a document with an error finding for version v.
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
