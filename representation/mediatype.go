// Package representation holds the contracts between the DID document data
// model and its serializations: the Producer and Consumer interfaces their
// players implement, their options and results, media type helpers that read
// package spec, and the consumer's version detection rule as a pure function
// (docs/09 §4, docs/12 §6.1). It contains no serialization code.
package representation

import (
	"fmt"
	"mime"
	"slices"

	"github.com/sage-x-project/did-go/spec"
)

// NormalizeMediaType returns the lowercase type/subtype of mt without
// parameters, for example "application/did" for "Application/DID;
// charset=utf-8".
func NormalizeMediaType(mt string) (string, error) {
	t, _, err := mime.ParseMediaType(mt)
	if err != nil {
		return "", fmt.Errorf("representation: invalid media type %q: %w", mt, err)
	}
	return t, nil
}

// IsDIDMediaType reports whether mt (normalized) is a DID representation
// media type of a supported version.
func IsDIDMediaType(mt string) bool {
	_, ok := VersionOf(mt)
	return ok
}

// IsLowPrecision reports whether mt (normalized) is a low-precision media
// type whose payload decides the representation (DID 1.1 §6.3.1).
func IsLowPrecision(mt string) bool {
	return slices.Contains(spec.LowPrecisionMediaTypes(), mt)
}

// VersionOf returns the version a DID media type (normalized) declares.
func VersionOf(mt string) (spec.Version, bool) {
	for _, v := range spec.Supported() {
		p, _ := spec.ProfileOf(v)
		if slices.Contains(p.Accepts(), mt) {
			return v, true
		}
	}
	return spec.VUnknown, false
}

// MediaTypeFor returns the media type a producer of version v emits, with or
// without JSON-LD. VUnknown is treated as spec.Latest.
func MediaTypeFor(v spec.Version, jsonld bool) string {
	p, err := spec.ProfileOf(v)
	if err != nil {
		p, _ = spec.ProfileOf(spec.Latest)
	}
	if jsonld {
		return p.JSONLDMediaType
	}
	return p.JSONMediaType
}

// MediaTypeOf returns the DID media type of the representation a consumer
// detected (docs/12 §6.2): V10 without JSON-LD is application/did+json, V10
// with JSON-LD is application/did+ld+json, and V11 or VUnknown is
// application/did.
func MediaTypeOf(info ConsumeInfo) string {
	return MediaTypeFor(info.DetectedVersion, info.IsJSONLD)
}

// CoreMediaTypes returns the media types a producer can produce from any
// valid document, in a fresh slice.
func CoreMediaTypes() []string {
	return []string{spec.MediaTypeDID, spec.MediaTypeDIDLDJSON, spec.MediaTypeDIDJSON}
}

// OptionsFor returns the production options for a target DID media type
// (docs/09 §5): application/did is V11 with JSON-LD context,
// application/did+ld+json is V10 with context and application/did+json is
// V10 without.
func OptionsFor(mediaType string) (ProduceOptions, error) {
	mt, err := NormalizeMediaType(mediaType)
	if err != nil {
		return ProduceOptions{}, err
	}
	v, ok := VersionOf(mt)
	if !ok {
		return ProduceOptions{}, fmt.Errorf("representation: %q is not a DID media type", mediaType)
	}
	p, _ := spec.ProfileOf(v)
	return ProduceOptions{Version: v, JSONLD: mt == p.JSONLDMediaType}, nil
}

// isContextOf reports whether s is the base context URL of v.
func isContextOf(s string, v spec.Version) bool {
	p, err := spec.ProfileOf(v)
	return err == nil && s == p.ContextURL
}
