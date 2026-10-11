// Package document holds the DID document data model: the immutable
// Document with copy-returning accessors, the Builder that validates and
// creates it, INFRA values for extensions and representation-specific
// entries, didDocumentMetadata, per-version validation that reports findings
// with statement ids, and the pure verification method selector of CID 1.0
// §3.3 (docs/14 §4).
//
// Documents are representation-independent: serialization is the job of the
// producer and consumer players.
package document

import "fmt"

// Code is an error type name of CID 1.0 §3.5 Processing Errors. The type URL
// of each is https://w3id.org/security# followed by the code; package
// resolution writes those URLs.
type Code string

// CID 1.0 §3.5 error codes.
const (
	CodeInvalidVerificationMethodURL             Code = "INVALID_VERIFICATION_METHOD_URL"
	CodeInvalidControlledIdentifierDocument      Code = "INVALID_CONTROLLED_IDENTIFIER_DOCUMENT"
	CodeInvalidControlledIdentifierDocumentID    Code = "INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID"
	CodeInvalidVerificationMethod                Code = "INVALID_VERIFICATION_METHOD"
	CodeInvalidRelationshipForVerificationMethod Code = "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD"
)

// ConformanceError reports a document, or a selection from it, that does not
// conform. Code is the CID 1.0 §3.5 error type; Statement is the requirement
// id that was violated, when one applies.
type ConformanceError struct {
	Code      Code
	Property  string
	Statement string
	Reason    string
}

// Error describes the violation.
func (e *ConformanceError) Error() string {
	s := fmt.Sprintf("document: %s: %s: %s", e.Code, e.Property, e.Reason)
	if e.Statement != "" {
		s += " (" + e.Statement + ")"
	}
	return s
}

func invalidDoc(property, statement, format string, args ...any) *ConformanceError {
	return &ConformanceError{
		Code: CodeInvalidControlledIdentifierDocument, Property: property,
		Statement: statement, Reason: fmt.Sprintf(format, args...),
	}
}
