package web

import (
	"fmt"

	"github.com/sage-x-project/did-go/method"
)

// Error codes of the did:web driver. The specification defines no error
// names, so these are did-go names.
const (
	// CodeInvalidDid: the DID is not a did:web DID this driver can turn into
	// an HTTPS URL. It unwraps to method.ErrInvalidInput.
	CodeInvalidDid = "invalidDid"
	// CodeInvalidURL: a URL given to DIDFromURL cannot name a did:web DID
	// document. It unwraps to method.ErrInvalidInput.
	CodeInvalidURL = "invalidUrl"
	// CodeNotFound: the web server answered 404. It unwraps to
	// method.ErrNotFound.
	CodeNotFound = "notFound"
	// CodeInvalidDidDocument: the fetched bytes are not a JSON object whose
	// id is the resolved DID, or they contain a relative DID URL. It unwraps
	// to method.ErrInvalidDocument, which a resolver reports as
	// INVALID_DID_DOCUMENT: the DID was acceptable, the document the web
	// server returned is not.
	CodeInvalidDidDocument = "invalidDidDocument"
	// CodeFetchFailed: the HTTPS request failed, was refused by a security
	// rule of the driver, or exceeded a limit. It unwraps to the cause only,
	// so a resolver reports it as an internal error.
	CodeFetchFailed = "fetchFailed"
)

// Error is an error the did:web driver returns. Unwrap yields the method
// error class of the code (method.ErrInvalidInput, method.ErrInvalidDocument,
// method.ErrNotFound) and the underlying cause, so errors.Is works with both.
type Error struct {
	// Code is one of the Code constants.
	Code string
	// Statement is the requirement id of the rule that failed, or the
	// specification section when the rule has no requirement id.
	Statement string
	// Reason says what is wrong. It never contains document content.
	Reason string
	// Err is the underlying cause, if any.
	Err error
}

// Error describes the failure.
func (e *Error) Error() string {
	msg := fmt.Sprintf("web: %s: %s (%s)", e.Code, e.Reason, e.Statement)
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the method error class of the code and the cause.
func (e *Error) Unwrap() []error {
	var out []error
	switch e.Code {
	case CodeInvalidDid, CodeInvalidURL:
		out = append(out, method.ErrInvalidInput)
	case CodeInvalidDidDocument:
		out = append(out, method.ErrInvalidDocument)
	case CodeNotFound:
		out = append(out, method.ErrNotFound)
	}
	if e.Err != nil {
		out = append(out, e.Err)
	}
	return out
}

func raise(code, statement, format string, args ...any) *Error {
	return &Error{Code: code, Statement: statement, Reason: fmt.Sprintf(format, args...)}
}

func wrap(code, statement string, err error, format string, args ...any) *Error {
	e := raise(code, statement, format, args...)
	e.Err = err
	return e
}
