// Package method holds the contract between DID method drivers and the
// players that use them (docs/05 §5, docs/14 §4): the Method interface, the
// options and results of its operations, the Signer callback through which
// a controller signs without handing over a key, the errors a driver
// returns, and an immutable Registry. It contains no driver.
package method

import (
	"context"
	"time"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
)

// Error is the type of the constant errors of this package. Drivers wrap
// them with fmt.Errorf("...: %w", err) and callers test with errors.Is.
type Error string

// Error returns the message.
func (e Error) Error() string { return string(e) }

// Errors a driver returns.
const (
	// ErrNotSupported: the operation or an option (for example versionId or
	// versionTime) is not supported. Resolvers report FEATURE_NOT_SUPPORTED.
	ErrNotSupported Error = "method: operation not supported"
	// ErrNotFound: the DID does not exist. Resolvers report NOT_FOUND.
	ErrNotFound Error = "method: DID not found"
	// ErrUnauthorized: the proof of authorization was missing or invalid.
	ErrUnauthorized Error = "method: authorization failed"
	// ErrInvalidInput: a DID or document the operation cannot accept.
	// Resolvers report INVALID_DID.
	ErrInvalidInput Error = "method: invalid input"
	// ErrInvalidDocument: the driver obtained a DID document from the
	// verifiable data registry that does not conform, or whose id is not the
	// DID being resolved (res10-crd20261001#resolving.7: "The value of id in
	// the resolved DID document MUST be string equal to the DID that was
	// resolved"). The DID itself was acceptable. Resolvers report
	// INVALID_DID_DOCUMENT.
	ErrInvalidDocument Error = "method: invalid DID document"
)

// Signer signs on behalf of a DID controller. The library never holds the
// private key (docs/12 §6.3); KeyID names the verification method whose key
// signs.
type Signer interface {
	Sign(ctx context.Context, msg []byte) ([]byte, error)
	KeyID() did.DIDURL
}

// Method implements the operations of one DID method (DID Core 1.0 §8.2).
// A driver that does not support Update or Deactivate returns
// ErrNotSupported.
type Method interface {
	// Name returns the method name, for example "key".
	Name() string
	// Produces returns the media types Read can label its bytes with, in a
	// fresh slice.
	Produces() []string
	// Create creates a DID and its document.
	Create(ctx context.Context, input *document.Document, opts CreateOptions) (*CreateResult, error)
	// Read retrieves the document of d as bytes, verifying its authenticity
	// as the method specification requires.
	Read(ctx context.Context, d did.DID, opts ReadOptions) (*ReadResult, error)
	// Update replaces the document of d.
	Update(ctx context.Context, d did.DID, next *document.Document, opts UpdateOptions) (*UpdateResult, error)
	// Deactivate deactivates d.
	Deactivate(ctx context.Context, d did.DID, opts DeactivateOptions) (*DeactivateResult, error)
}

// ReadOptions are the inputs of Read that a resolver passes on.
type ReadOptions struct {
	// VersionID selects a version; "" means the latest.
	VersionID string
	// VersionTime selects the latest version before this time, or nil.
	VersionTime *time.Time
	// MediaType is the representation the resolver picked from Produces;
	// "" means the driver's default.
	MediaType string
	// NoCache asks the driver to bypass any cache it keeps.
	NoCache bool
}

// ReadResult is what Read returns: the document bytes, the media type they
// are labelled with, and didDocumentMetadata. The resolver consumes Data
// with ContentType as the declared media type.
type ReadResult struct {
	Data        []byte
	ContentType string
	Metadata    document.Metadata
}

// CreateOptions are the inputs of Create.
type CreateOptions struct {
	// Signer proves authorization where the method requires it.
	Signer Signer
	// Extra holds method-specific options.
	Extra map[string]any
}

// CreateResult is what Create returns.
type CreateResult struct {
	DID      did.DID
	Document *document.Document
	Metadata document.Metadata
}

// UpdateOptions are the inputs of Update.
type UpdateOptions struct {
	Signer Signer
	Extra  map[string]any
}

// UpdateResult is what Update returns.
type UpdateResult struct {
	Document *document.Document
	Metadata document.Metadata
}

// DeactivateOptions are the inputs of Deactivate.
type DeactivateOptions struct {
	Signer Signer
	Extra  map[string]any
}

// DeactivateResult is what Deactivate returns; Metadata.Deactivated is true.
type DeactivateResult struct {
	Metadata document.Metadata
}
