package representation

import (
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/spec"
)

// ProduceOptions select the representation a Producer writes.
type ProduceOptions struct {
	// Version is the target version; VUnknown means spec.Latest.
	Version spec.Version
	// JSONLD writes the representation for JSON-LD processing, with the
	// version's base context first in @context.
	JSONLD bool
	// IncludeSecret writes secret key material. It is false by default, and
	// secret material is then never written.
	IncludeSecret bool
}

// Producer serializes a document. It must not produce a non-conforming
// representation; it returns the bytes and their media type.
type Producer interface {
	Produce(d *document.Document, opts ProduceOptions) (data []byte, mediaType string, err error)
}

// ConsumeOptions control how a Consumer detects and accepts input.
type ConsumeOptions struct {
	// Expected is the version to assume for low-precision input without
	// @context; VUnknown means none.
	Expected spec.Version
	// Require rejects input whose detected version is not Require; VUnknown
	// accepts every version.
	Require spec.Version
	// Strict turns the payload decision for low-precision input, an assumed
	// version and an unexpected @context under application/did+json into
	// errors.
	Strict bool
}

// LowPrecision records how input received under a low-precision media type
// was decided from its payload.
type LowPrecision struct {
	// Declared is the low-precision media type received.
	Declared string
	// Detected is the DID media type of the representation in the payload.
	Detected string
}

// ConsumeInfo is what a Consumer detected.
type ConsumeInfo struct {
	// DetectedVersion is the version of the representation.
	DetectedVersion spec.Version
	// IsJSONLD is true for a JSON-LD representation.
	IsJSONLD bool
	// LowPrecision is set when a low-precision media type was received.
	LowPrecision *LowPrecision
	// Assumed is true when the version was decided without @context.
	Assumed bool
	// UnexpectedContext is, for application/did+json input, the first
	// @context value when it is not the DID Core 1.0 context.
	UnexpectedContext string
	// DroppedTerms locates, in input order, the entries a consumer dropped
	// from a JSON-LD representation because its @context does not define
	// their term (DID Core 1.0 §6.3.2, DID 1.1 §6.2.3: consumers "SHOULD drop
	// all terms from a DID document that are not defined via the
	// @context"), for example "foo" or "service[0].bar". It is nil when
	// nothing was dropped.
	DroppedTerms []string
}

// Consumer parses a representation with its declared media type into a
// document. It must produce an error for non-conforming input.
type Consumer interface {
	Consume(data []byte, mediaType string, opts ConsumeOptions) (*document.Document, ConsumeInfo, error)
}
