package spec

import (
	"fmt"
	"slices"
)

// Media type strings (DID Core 1.0 §6.2, §6.3, appendix E; DID 1.1 §6.3,
// appendix E.1; DID Resolution v1.0 §12).
const (
	// MediaTypeDID is the DID 1.1 representation (JSON, JSON-LD compatible).
	MediaTypeDID = "application/did"
	// MediaTypeDIDJSON is the DID Core 1.0 JSON representation.
	MediaTypeDIDJSON = "application/did+json"
	// MediaTypeDIDLDJSON is the DID Core 1.0 JSON-LD representation.
	MediaTypeDIDLDJSON = "application/did+ld+json"
	// MediaTypeJSON is a low-precision media type (DID 1.1 §6.3.1).
	MediaTypeJSON = "application/json"
	// MediaTypeLDJSON is a low-precision media type (DID 1.1 §6.3.1).
	MediaTypeLDJSON = "application/ld+json"
	// MediaTypeDIDResolution is the DID resolution result media type.
	MediaTypeDIDResolution = "application/did-resolution"
	// MediaTypeDIDURLDereferencing is the DID URL dereferencing result media
	// type.
	MediaTypeDIDURLDereferencing = "application/did-url-dereferencing"
	// MediaTypeURIList is the media type of a list of service endpoint URLs.
	MediaTypeURIList = "text/uri-list"
)

// Base context URLs.
const (
	ContextURLV10 = "https://www.w3.org/ns/did/v1"
	ContextURLV11 = "https://www.w3.org/ns/did/v1.1"
)

// Profile holds the facts that differ between DID versions.
type Profile struct {
	// Version is the version the profile describes.
	Version Version
	// ContextURL is the first @context value of a JSON-LD representation.
	ContextURL string
	// JSONMediaType is the media type of the representation produced without
	// JSON-LD.
	JSONMediaType string
	// JSONLDMediaType is the media type of the representation produced for
	// JSON-LD processing.
	JSONLDMediaType string
	// ServiceIDRequired is true when every service map must contain id
	// (DID Core 1.0 §5.4); CID 1.0 §2.1.4 makes it optional.
	ServiceIDRequired bool
	// ServiceIDMustBeURI is true when a service id must be an RFC 3986 URI
	// and endpoint strings must be normalized URIs (DID Core 1.0 §5.4).
	ServiceIDMustBeURI bool
	// RelativeMethodIDs is true when a verification method id may be a
	// relative DID URL (DID 1.1 §5.2).
	RelativeMethodIDs bool
	// MetadataNumbers is true when metadata values may be numbers (DID
	// Resolution v1.0 §metadata-structure); DID Core 1.0 §7.3 does not allow
	// them.
	MetadataNumbers bool
	terms           []string
}

// Produces returns the media types a producer of this version emits, in a
// fresh slice.
func (p Profile) Produces() []string {
	if p.JSONMediaType == p.JSONLDMediaType {
		return []string{p.JSONMediaType}
	}
	return []string{p.JSONMediaType, p.JSONLDMediaType}
}

// Accepts returns the DID media types a consumer maps to this version, in a
// fresh slice.
func (p Profile) Accepts() []string {
	return p.Produces()
}

// Terms returns the terms defined by this version's base context, sorted, in
// a fresh slice.
func (p Profile) Terms() []string {
	return slices.Clone(p.terms)
}

// DefinesTerm reports whether the base context of this version defines term.
func (p Profile) DefinesTerm(term string) bool {
	_, found := slices.BinarySearch(p.terms, term)
	return found
}

// termsV10 are the terms of https://www.w3.org/ns/did/v1 (SHA-256
// 4f3eae5568c9c5f036a082088f9e192019ee06faa78973c87ff91d5421b88dad).
func termsV10() []string {
	return []string{
		"alsoKnownAs", "assertionMethod", "authentication", "capabilityDelegation",
		"capabilityInvocation", "controller", "id", "keyAgreement", "service",
		"serviceEndpoint", "type", "verificationMethod",
	}
}

// termsV11 are the terms of https://www.w3.org/ns/did/v1.1 (SHA-256
// ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85).
func termsV11() []string {
	return []string{
		"JsonWebKey", "Multikey", "alsoKnownAs", "assertionMethod", "authentication",
		"capabilityDelegation", "capabilityInvocation", "controller", "expires", "id",
		"keyAgreement", "publicKeyJwk", "publicKeyMultibase", "revoked",
		"secretKeyJwk", "secretKeyMultibase", "service", "serviceEndpoint", "type",
		"verificationMethod",
	}
}

// ProfileOf returns the profile of a supported version. VUnknown has no
// profile: the caller decides which version it stands for.
func ProfileOf(v Version) (Profile, error) {
	switch v {
	case V10:
		return Profile{
			Version: V10, ContextURL: ContextURLV10,
			JSONMediaType: MediaTypeDIDJSON, JSONLDMediaType: MediaTypeDIDLDJSON,
			ServiceIDRequired: true, ServiceIDMustBeURI: true,
			terms: termsV10(),
		}, nil
	case V11:
		return Profile{
			Version: V11, ContextURL: ContextURLV11,
			JSONMediaType: MediaTypeDID, JSONLDMediaType: MediaTypeDID,
			RelativeMethodIDs: true, MetadataNumbers: true,
			terms: termsV11(),
		}, nil
	}
	return Profile{}, fmt.Errorf("spec: no profile for version %s", v)
}

// LowPrecisionMediaTypes returns the media types whose payload decides the
// representation (DID 1.1 §6.3.1), in a fresh slice.
func LowPrecisionMediaTypes() []string {
	return []string{MediaTypeJSON, MediaTypeLDJSON}
}
