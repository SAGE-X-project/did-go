package resolution

import (
	"context"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/representation"
)

// Resolver resolves a DID: resolve(did, resolutionOptions) returns
// «didResolutionMetadata, didDocument, didDocumentMetadata» (DID Resolution
// v1.0 §4). Failures are reported in Result.ResolutionMetadata.Error, never
// as a Go error.
type Resolver interface {
	Resolve(ctx context.Context, d did.DID, opts ResolutionOptions) Result
}

// Dereferencer dereferences a DID URL: dereference(didUrl,
// dereferenceOptions) returns «dereferencingMetadata, contentStream,
// contentMetadata» (DID Resolution v1.0 §5).
type Dereferencer interface {
	Dereference(ctx context.Context, u did.DIDURL, opts DereferenceOptions) DereferenceResult
}

// SourceBytes are the bytes a method driver returned and their media type.
type SourceBytes struct {
	Data        []byte
	ContentType string
}

// Result is the resolution result, with the returned bytes, what the
// consumer detected and, after transcoding, the driver's original bytes
// (docs/12 §6.2).
type Result struct {
	// Document is the didDocument, or nil on failure or deactivation.
	Document *document.Document
	// Raw are the bytes returned to the caller, in the representation named
	// by ResolutionMetadata.ContentType.
	Raw []byte
	// Info is the detection result of consuming the driver's bytes.
	Info representation.ConsumeInfo
	// Source holds the driver's original bytes when the resolver transcoded.
	Source *SourceBytes
	// ResolutionMetadata is didResolutionMetadata.
	ResolutionMetadata ResolutionMetadata
	// DocumentMetadata is didDocumentMetadata; deactivated lives here.
	DocumentMetadata DocumentMetadata
}

// ErrorResult returns the result of a failed resolution: no document, empty
// document metadata and e in the resolution metadata.
func ErrorResult(e *Error) Result {
	return Result{ResolutionMetadata: ResolutionMetadata{Error: e}}
}

// DereferenceResult is the dereferencing result.
type DereferenceResult struct {
	// ContentStream is the dereferenced resource: a *document.Document, a
	// vm.Method, a vm.Service, a []string of URLs or bytes; nil on failure.
	ContentStream any
	// DereferencingMetadata is dereferencingMetadata.
	DereferencingMetadata DereferencingMetadata
	// ContentMetadata is contentMetadata (didDocumentMetadata when the
	// content is a DID document).
	ContentMetadata DocumentMetadata
}

// ErrorDereferenceResult returns the result of a failed dereference: no
// content, empty content metadata and e in the dereferencing metadata.
func ErrorDereferenceResult(e *Error) DereferenceResult {
	return DereferenceResult{DereferencingMetadata: DereferencingMetadata{Error: e}}
}
