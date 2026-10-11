// Package resolution holds the shared contract of DID resolution and DID URL
// dereferencing (DID Resolution v1.0 CRD 2026-10-01, docs/07): the Resolver
// and Dereferencer interfaces, their options, metadata and results, and RFC
// 9457 error objects with their type URLs and HTTP status mapping. It
// contains no resolver logic and performs no I/O.
package resolution

import (
	"fmt"
	"strings"

	"github.com/sage-x-project/did-go/document"
)

// Type URL prefixes of DID Resolution v1.0 §11 and CID 1.0 §3.5.
const (
	NamespaceDID      = "https://www.w3.org/ns/did#"
	NamespaceSecurity = "https://w3id.org/security#"
)

// Code names an error type: one of the constants below, an extension name
// (which gets the NamespaceDID prefix) or a full type URL.
type Code string

// DID Resolution v1.0 §11 error codes.
const (
	CodeInvalidDID                 Code = "INVALID_DID"
	CodeInvalidDIDURL              Code = "INVALID_DID_URL"
	CodeInvalidOptions             Code = "INVALID_OPTIONS"
	CodeNotFound                   Code = "NOT_FOUND"
	CodeRepresentationNotSupported Code = "REPRESENTATION_NOT_SUPPORTED"
	CodeInvalidDIDDocument         Code = "INVALID_DID_DOCUMENT"
	CodeMethodNotSupported         Code = "METHOD_NOT_SUPPORTED"
	CodeFeatureNotSupported        Code = "FEATURE_NOT_SUPPORTED"
	CodeInternalError              Code = "INTERNAL_ERROR"
)

// CID 1.0 §3.5 error codes, whose type URLs start with NamespaceSecurity.
const (
	CodeInvalidVerificationMethodURL             = Code(document.CodeInvalidVerificationMethodURL)
	CodeInvalidControlledIdentifierDocument      = Code(document.CodeInvalidControlledIdentifierDocument)
	CodeInvalidControlledIdentifierDocumentID    = Code(document.CodeInvalidControlledIdentifierDocumentID)
	CodeInvalidVerificationMethod                = Code(document.CodeInvalidVerificationMethod)
	CodeInvalidRelationshipForVerificationMethod = Code(document.CodeInvalidRelationshipForVerificationMethod)
)

// codeInfo returns the title, the binding status and whether c is a CID
// code.
func codeInfo(c Code) (title string, status int, cid bool) {
	switch c {
	case CodeInvalidDID:
		return "Invalid DID", 400, false
	case CodeInvalidDIDURL:
		return "Invalid DID URL", 400, false
	case CodeInvalidOptions:
		return "Invalid options", 400, false
	case CodeNotFound:
		return "Not found", 404, false
	case CodeRepresentationNotSupported:
		return "Representation not supported", 406, false
	case CodeInvalidDIDDocument:
		return "Invalid DID document", 500, false
	case CodeMethodNotSupported:
		return "Method not supported", 501, false
	case CodeFeatureNotSupported:
		return "Feature not supported", 501, false
	case CodeInternalError:
		return "Internal error", 500, false
	case CodeInvalidVerificationMethodURL:
		return "Invalid verification method URL", 0, true
	case CodeInvalidControlledIdentifierDocument:
		return "Invalid controlled identifier document", 0, true
	case CodeInvalidControlledIdentifierDocumentID:
		return "Invalid controlled identifier document id", 0, true
	case CodeInvalidVerificationMethod:
		return "Invalid verification method", 0, true
	case CodeInvalidRelationshipForVerificationMethod:
		return "Invalid relationship for verification method", 0, true
	}
	return string(c), 0, false
}

// isURL reports whether a code is already a type URL.
func isURL(c Code) bool {
	s := string(c)
	return strings.Contains(s, "://") || strings.HasPrefix(s, "urn:")
}

// TypeURL returns the RFC 9457 type of c: c itself when it is a URL,
// NamespaceSecurity + c for a CID code, and NamespaceDID + c otherwise
// (DID Resolution v1.0 §11, CID 1.0 §3.5).
func (c Code) TypeURL() string {
	if isURL(c) {
		return string(c)
	}
	if _, _, cid := codeInfo(c); cid {
		return NamespaceSecurity + string(c)
	}
	return NamespaceDID + string(c)
}

// bindingStatus is the status code table of the HTTPS binding (DID
// Resolution v1.0 §12.1), keyed by type URL.
func bindingStatus(typeURL string) (int, bool) {
	code, ok := strings.CutPrefix(typeURL, NamespaceDID)
	if !ok {
		return 0, false
	}
	_, status, cid := codeInfo(Code(code))
	return status, status != 0 && !cid
}

// Error is an RFC 9457 problem details object.
type Error struct {
	// Type is the error type URL.
	Type string `json:"type"`
	// Title is a short human-readable summary.
	Title string `json:"title,omitempty"`
	// Status is an HTTP status for a type outside the binding table.
	Status int `json:"status,omitempty"`
	// Detail is a longer human-readable explanation.
	Detail string `json:"detail,omitempty"`
	// Instance identifies this occurrence.
	Instance string `json:"instance,omitempty"`
	// Refines is the type URL of a DID Resolution v1.0 §11 error this type
	// refines (§11: a specification "MAY declare that it refines one of the
	// error types defined in this section"); "" for a type of that table.
	Refines string `json:"-"`
	accept  bool
}

// NewError returns a new error of type code with the given detail. The
// title, and the status of a binding table type, are filled in. A CID 1.0
// error refines INVALID_DID_URL, so the HTTPS binding conveys it with 400
// (did-go policy, docs/07 §4). A FEATURE_NOT_SUPPORTED error without detail
// gets one that says a requested feature is not supported.
func NewError(code Code, detail string) *Error {
	title, status, cid := codeInfo(code)
	e := &Error{Type: code.TypeURL(), Title: title, Status: status, Detail: detail}
	if cid {
		e.Refines = CodeInvalidDIDURL.TypeURL()
	}
	if code == CodeFeatureNotSupported && detail == "" {
		e.Detail = "the resolver does not support a feature the request needs"
	}
	return e
}

// NewAcceptNotSupported returns the FEATURE_NOT_SUPPORTED error of a
// resolver that cannot produce a representation acceptable to accept
// (docs/12 §6.2 step 4). IsAcceptNotSupported recognizes it, so that the
// DID Core 1.0 adapter can report representationNotSupported.
func NewAcceptNotSupported(accept string) *Error {
	e := NewError(CodeFeatureNotSupported, fmt.Sprintf("no representation acceptable to %q can be produced", accept))
	e.accept = true
	return e
}

// IsAcceptNotSupported reports whether e came from NewAcceptNotSupported.
func (e *Error) IsAcceptNotSupported() bool { return e != nil && e.accept }

// Error describes the problem.
func (e *Error) Error() string {
	if e.Detail == "" {
		return "resolution: " + e.Type
	}
	return "resolution: " + e.Type + ": " + e.Detail
}

// Is reports whether target is an *Error of the same type, so that
// errors.Is(err, NewError(CodeNotFound, "")) matches any NOT_FOUND error.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && e != nil && t != nil && t.Type == e.Type
}

// Code returns the code of e's type: the name after a known namespace, or
// the type URL itself.
func (e *Error) Code() Code {
	if c, ok := strings.CutPrefix(e.Type, NamespaceDID); ok {
		return Code(c)
	}
	if c, ok := strings.CutPrefix(e.Type, NamespaceSecurity); ok {
		return Code(c)
	}
	return Code(e.Type)
}

// HTTPStatus returns the status code the HTTPS binding uses for e: the
// binding table status of Type; otherwise the table status of Refines;
// otherwise Status; otherwise 500. The steps after the table are did-go
// policy for types whose status "is determined by the implementation".
func (e *Error) HTTPStatus() int {
	if e == nil {
		return 500
	}
	if s, ok := bindingStatus(e.Type); ok {
		return s
	}
	if s, ok := bindingStatus(e.Refines); ok {
		return s
	}
	if e.Status != 0 {
		return e.Status
	}
	return 500
}
