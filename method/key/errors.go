package key

import (
	"fmt"

	"github.com/sage-x-project/did-go/method"
)

// Error codes the did:key specification raises (didkey-2cc490c §3.1).
const (
	CodeInvalidDid               = "invalidDid"
	CodeInvalidDidURL            = "invalidDidUrl"
	CodeInvalidPublicKey         = "invalidPublicKey"
	CodeInvalidPublicKeyLength   = "invalidPublicKeyLength"
	CodeInvalidPublicKeyType     = "invalidPublicKeyType"
	CodeUnsupportedPublicKeyType = "unsupportedPublicKeyType"
)

// Error is an error the did:key algorithms raise. It unwraps to
// method.ErrNotSupported for CodeUnsupportedPublicKeyType and to
// method.ErrInvalidInput for every other code, so a resolver can map it
// without knowing did:key.
type Error struct {
	// Code is one of the Code constants.
	Code string
	// Statement is the requirement id of the step that raised the error.
	Statement string
	// Reason says what is wrong.
	Reason string
}

// Error describes the failure.
func (e *Error) Error() string {
	return fmt.Sprintf("key: %s: %s (%s)", e.Code, e.Reason, e.Statement)
}

// Unwrap returns the method error class of the code.
func (e *Error) Unwrap() error {
	if e.Code == CodeUnsupportedPublicKeyType {
		return method.ErrNotSupported
	}
	return method.ErrInvalidInput
}

func raise(code, statement, format string, args ...any) *Error {
	return &Error{Code: code, Statement: statement, Reason: fmt.Sprintf(format, args...)}
}
