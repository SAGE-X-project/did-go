// Package did parses and represents DIDs and DID URLs following the ABNF of
// DID Core 1.0 §3.1 and §3.2, which DID 1.1 keeps unchanged (docs/10 §1). It
// also resolves relative DID URLs with RFC 3986 §5 and parses DID parameters.
//
// Values are immutable and comparable with ==. The package has no I/O and no
// mutable global state.
package did

import (
	"errors"
	"fmt"
	"strings"
)

// MaxLength bounds the length of any DID or DID URL input, in bytes
// (docs/12 §6.3). Longer input is rejected before parsing.
const MaxLength = 16 * 1024

// Error is the type of the constant errors of this package.
type Error string

// Error returns the message.
func (e Error) Error() string { return string(e) }

// ErrIdentifierRestriction reports a DID URL with a path, query or fragment
// where a plain DID is required, such as the subject or a controller.
const ErrIdentifierRestriction Error = "did: a plain DID must not contain a path, query or fragment"

// SyntaxError reports input that does not match the DID or DID URL ABNF.
type SyntaxError struct {
	// Input is the rejected input.
	Input string
	// Pos is the byte offset of the first offending character.
	Pos int
	// Msg says which rule failed.
	Msg string
	// Err is an underlying cause such as ErrIdentifierRestriction, or nil.
	Err error
}

// Error describes the failure with its position.
func (e *SyntaxError) Error() string {
	return fmt.Sprintf("did: invalid syntax at position %d: %s", e.Pos, e.Msg)
}

// Unwrap returns the underlying cause.
func (e *SyntaxError) Unwrap() error { return e.Err }

func syntaxErr(input string, pos int, msg string) *SyntaxError {
	return &SyntaxError{Input: input, Pos: pos, Msg: msg}
}

// DID is a parsed DID: "did:" method-name ":" method-specific-id. The zero
// value is not a valid DID; IsZero reports it.
type DID struct {
	method string
	msid   string
}

// Method returns the method name.
func (d DID) Method() string { return d.method }

// MSID returns the method-specific identifier.
func (d DID) MSID() string { return d.msid }

// String returns the DID, or "" for the zero value.
func (d DID) String() string {
	if d.IsZero() {
		return ""
	}
	return "did:" + d.method + ":" + d.msid
}

// IsZero reports whether d is the zero value.
func (d DID) IsZero() bool { return d.method == "" }

// URL returns d as a DID URL without path, query or fragment.
func (d DID) URL() DIDURL { return DIDURL{did: d} }

// Parse parses a DID. The scheme "did:" is accepted in any case and the
// result is written in lowercase; the method name is lowercase only. A valid DID URL that carries a path, query or fragment
// is rejected with an error that wraps ErrIdentifierRestriction.
func Parse(s string) (DID, error) {
	if len(s) > MaxLength {
		return DID{}, syntaxErr("", MaxLength, "input longer than MaxLength")
	}
	d, end, err := parseDID(s)
	if err != nil {
		return DID{}, err
	}
	if end == len(s) {
		return d, nil
	}
	if _, err := ParseURL(s); err != nil {
		return DID{}, err
	}
	e := syntaxErr(s, end, "a plain DID must end after the method-specific-id")
	e.Err = ErrIdentifierRestriction
	return DID{}, e
}

// hasScheme reports whether s starts with "did:" in any case: an ABNF
// string literal is case-insensitive (RFC 5234 §2.3). String writes the
// scheme in lowercase (RFC 3986 §3.1).
func hasScheme(s string) bool {
	return len(s) >= 4 && strings.EqualFold(s[:4], "did:")
}

// IsMethodName reports whether s matches method-name = 1*method-char, where
// method-char = %x61-7A / DIGIT.
func IsMethodName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isMethodChar(s[i]) {
			return false
		}
	}
	return true
}

// parseDID parses the did production at the start of s and returns the
// offset where it ends.
func parseDID(s string) (DID, int, error) {
	if !hasScheme(s) {
		return DID{}, 0, syntaxErr(s, 0, `a DID starts with "did:"`)
	}
	i := len("did:")
	start := i
	for i < len(s) && isMethodChar(s[i]) {
		i++
	}
	if i == start {
		return DID{}, 0, syntaxErr(s, i, "method-name needs at least one lowercase letter or digit")
	}
	if i == len(s) || s[i] != ':' {
		return DID{}, 0, syntaxErr(s, i, `method-name must be followed by ":"`)
	}
	method := s[start:i]
	i++
	msStart := i
	last := byte(0)
	for i < len(s) {
		w, err := idcharWidth(s, i)
		if err != nil {
			return DID{}, 0, err
		}
		if w == 0 {
			break
		}
		last = s[i]
		i += w
	}
	if i == msStart {
		return DID{}, 0, syntaxErr(s, i, "method-specific-id must not be empty")
	}
	if last == ':' {
		return DID{}, 0, syntaxErr(s, i-1, "method-specific-id must end with an idchar")
	}
	return DID{method: method, msid: s[msStart:i]}, i, nil
}

// idcharWidth returns the width of an idchar or ":" at s[i], 0 when s[i]
// starts neither, or an error for a malformed pct-encoded triplet.
func idcharWidth(s string, i int) (int, error) {
	c := s[i]
	switch {
	case isAlpha(c) || isDigit(c) || c == '.' || c == '-' || c == '_' || c == ':':
		return 1, nil
	case c == '%':
		if err := checkPct(s, i); err != nil {
			return 0, err
		}
		return 3, nil
	}
	return 0, nil
}

func checkPct(s string, i int) error {
	if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
		return syntaxErr(s, i, `"%" must be followed by two hexadecimal digits`)
	}
	return nil
}

func isMethodChar(c byte) bool { return (c >= 'a' && c <= 'z') || isDigit(c) }
func isAlpha(c byte) bool      { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool      { return c >= '0' && c <= '9' }
func isHex(c byte) bool        { return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') }

// isUnreserved reports RFC 3986 unreserved.
func isUnreserved(c byte) bool {
	return isAlpha(c) || isDigit(c) || c == '-' || c == '.' || c == '_' || c == '~'
}

// isSubDelim reports RFC 3986 sub-delims.
func isSubDelim(c byte) bool {
	return strings.IndexByte("!$&'()*+,;=", c) >= 0
}

// isPchar reports RFC 3986 pchar characters other than pct-encoded.
func isPchar(c byte) bool {
	return isUnreserved(c) || isSubDelim(c) || c == ':' || c == '@'
}

// errNotDIDURL is the cause of a resolved reference that is not a DID URL.
var errNotDIDURL = errors.New("did: the resolved reference is not a DID URL")
