// Package vm holds the verification method, verification relationship and
// service types of a DID document and their value-level checks (Controlled
// Identifiers v1.0 §2.1.4, §2.2, §2.3; DID Core 1.0 §5.2 to §5.4; docs/06).
//
// The checks here are the same in DID Core 1.0 and DID 1.1. Rules that
// differ between versions are applied by document.Validate.
package vm

import "fmt"

// Error reports a value that violates a specification statement.
type Error struct {
	// Property is the offending property, for example "publicKeyJwk".
	Property string
	// Statement is the requirement id the value violates.
	Statement string
	// Reason says what is wrong.
	Reason string
}

// Error describes the violation.
func (e *Error) Error() string {
	return fmt.Sprintf("vm: %s: %s (%s)", e.Property, e.Reason, e.Statement)
}

func errorf(property, statement, format string, args ...any) *Error {
	return &Error{Property: property, Statement: statement, Reason: fmt.Sprintf(format, args...)}
}
