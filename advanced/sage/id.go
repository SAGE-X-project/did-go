package sage

import (
	"regexp"
	"strings"
)

// Identifier bounds of chapter 06 ID-01.
const (
	maxDIDLen    = 256
	maxDIDURLLen = 289
	didPrefix    = "did:" + MethodName + ":"
)

var (
	kindPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	segmentPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// checkID applies chapter 06 ID-01 to a did:sage identifier or DID URL
// before any record is observed (RESOLVE-02 step 1): the exact lowercase
// prefix, a lowercase kind, at least one locator segment and an agent id of
// 1 to 64 permitted characters each, no percent-encoding, no path or query,
// and at most one fragment that is a key-id. A DID longer than 256 bytes, or
// a DID URL longer than 289 bytes, is size.exceeded. How many segments the
// locator has depends on the kind, which only the Source knows; it reports
// id.unknown-kind or id.malformed for that.
func checkID(s string) *Error {
	if len(s) > maxDIDURLLen {
		return NewError(CodeSizeExceeded, "a did:sage DID URL is at most 289 bytes")
	}
	base, fragment, hasFragment := strings.Cut(s, "#")
	if len(base) > maxDIDLen {
		return NewError(CodeSizeExceeded, "a did:sage DID is at most 256 bytes")
	}
	rest, ok := strings.CutPrefix(base, didPrefix)
	if !ok {
		return NewError(CodeIDMalformed, "the identifier does not start with did:sage:")
	}
	parts := strings.Split(rest, ":")
	if len(parts) < 3 || !kindPattern.MatchString(parts[0]) {
		return NewError(CodeIDMalformed, "a did:sage identifier is did:sage:kind:locator:agent-id")
	}
	for _, seg := range parts[1:] {
		if !segmentPattern.MatchString(seg) {
			return NewError(CodeIDMalformed, "a did:sage segment is 1 to 64 letters, digits, dots, hyphens or underscores")
		}
	}
	if hasFragment && !keyName.MatchString(fragment) {
		return NewError(CodeIDMalformed, "a did:sage fragment is a single key-id")
	}
	return nil
}

// malformed applies checkID to a string that names the sage method in any
// letter case; any other string is left to the standard resolver.
func malformed(s string) *Error {
	if len(s) < len(didPrefix) || !strings.EqualFold(s[:len(didPrefix)], didPrefix) {
		return nil
	}
	return checkID(s)
}
