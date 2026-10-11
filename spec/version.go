// Package spec is layer 0 of did-go (docs/14 §3): the only place where
// version-specific facts live. It holds the DID specification versions, the
// per-version profile table (context URL, media types, production rules,
// base-context terms), the media type strings, the datetime format and the
// specification keys of requirement ids. It imports only the standard library
// and has no mutable state.
package spec

import "fmt"

// Version is a DID specification version. It is a property of
// representations and contracts, never of a document (docs/09 §3).
type Version int

const (
	// VUnknown means "not determined". Each player states which profile it
	// applies to it; consumers apply Latest (docs/09 §4).
	VUnknown Version = iota
	// V10 is Decentralized Identifiers (DIDs) v1.0, W3C Recommendation
	// 2022-07-19.
	V10
	// V11 is Decentralized Identifiers (DIDs) v1.1, W3C Candidate
	// Recommendation Snapshot 2026-03-05.
	V11
)

// Latest is the newest supported version.
const Latest = V11

// String returns "1.0", "1.1" or "unknown".
func (v Version) String() string {
	switch v {
	case V10:
		return "1.0"
	case V11:
		return "1.1"
	}
	return "unknown"
}

// ParseVersion parses "1.0" or "1.1".
func ParseVersion(s string) (Version, error) {
	switch s {
	case "1.0":
		return V10, nil
	case "1.1":
		return V11, nil
	}
	return VUnknown, fmt.Errorf("spec: unsupported DID version %q", s)
}

// Supported returns the supported versions, oldest first, in a fresh slice.
func Supported() []Version {
	return []Version{V10, V11}
}

// IsSupported reports whether v is one of Supported.
func (v Version) IsSupported() bool {
	return v == V10 || v == V11
}
