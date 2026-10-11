// Package compat is the DID Core 1.0 adapter of did-go (docs/09 §6, docs/14
// §5). It offers the abstract functions of DID Core 1.0 §7 (W3C
// Recommendation 2022-07-19), resolve, resolveRepresentation and
// dereference, with their single-keyword string errors, on top of any
// resolver and dereferencer of the DID Resolution v1.0 CRD 2026-10-01
// contract. The adapter only wraps: accept negotiation and transcoding to a
// DID Core 1.0 representation are done by the inner resolver (docs/12 §6.2).
//
// Rules of the DID Core 1.0 path:
//
//   - resolve: the accept option "MUST NOT be used with the resolve
//     function" (§7.1.1), so it is removed, with a warning; contentType
//     "MUST NOT be present if the resolve function was called" (§7.1.2).
//   - resolveRepresentation: contentType "is REQUIRED if resolution is
//     successful" and names the representation of the returned byte stream.
//     The stream must be "in one of the conformant representations" of DID
//     Core 1.0, so an empty accept is replaced by the two DID Core 1.0 media
//     types. An accept that cannot be satisfied is representationNotSupported
//     (§7.1.2), not featureNotSupported.
//   - Errors are single keyword ASCII strings: the codes DID Core 1.0
//     defines are mapped exactly and the others are converted from
//     SCREAMING_SNAKE to camelCase, the convention of the DID Specification
//     Registries (docs/09 §6.1).
//   - Metadata values are strings, maps, lists, booleans or null (§7.3): every
//     number in Extra and Proof is converted to its decimal string.
//   - A failed resolution or dereference returns no document or content and
//     empty document or content metadata (§7.1, §7.2).
//   - A deactivated DID returns no document, deactivated true and, from
//     resolveRepresentation, no stream and no contentType: deliberate
//     deviation DEV-V10-1 (docs/09 §6.1), because the inner resolver returns
//     no document for a deactivated DID.
//   - DID parameters: hl (DID Core 1.0 only) is accepted and not forwarded,
//     because DID Resolution v1.0 no longer defines it; serviceType (DID
//     Resolution v1.0 only) is featureNotSupported (docs/09 §6.2).
package compat

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
)

// DID Core 1.0 error strings (§7.1.2, §7.2.2) and the conversions of the
// other DID Resolution v1.0 codes (docs/09 §6.1).
const (
	ErrInvalidDID                 = "invalidDid"
	ErrNotFound                   = "notFound"
	ErrRepresentationNotSupported = "representationNotSupported"
	ErrInvalidDIDURL              = "invalidDidUrl"
	ErrMethodNotSupported         = "methodNotSupported"
	ErrInvalidDIDDocument         = "invalidDidDocument"
	ErrInvalidOptions             = "invalidOptions"
	ErrFeatureNotSupported        = "featureNotSupported"
	ErrInternalError              = "internalError"
)

// WarningAcceptIgnored is the warning when an accept option given to Resolve
// is removed.
const WarningAcceptIgnored = "the accept option must not be used with resolve (DID Core 1.0 §7.1.1) and was ignored"

// WarningHLIgnored is the warning when an hl DID parameter is removed.
const WarningHLIgnored = "the hl DID parameter is not verified and was not forwarded"

// V10ResolutionMetadata is the DID resolution metadata of DID Core 1.0
// §7.1.2.
type V10ResolutionMetadata struct {
	// ContentType is the media type of the stream returned by a successful
	// ResolveRepresentation, and empty otherwise.
	ContentType string
	// Error is a single keyword ASCII string, or "" on success.
	Error string
	// Warnings lists inputs the adapter ignored. It is not part of the
	// metadata structure and is never serialized.
	Warnings []string
}

// MarshalJSON writes the metadata structure: contentType and error when
// present.
func (m V10ResolutionMetadata) MarshalJSON() ([]byte, error) {
	out := map[string]string{}
	if m.ContentType != "" {
		out["contentType"] = m.ContentType
	}
	if m.Error != "" {
		out["error"] = m.Error
	}
	return json.Marshal(out)
}

// V10DereferencingMetadata is the DID URL dereferencing metadata of DID Core
// 1.0 §7.2.2.
type V10DereferencingMetadata = V10ResolutionMetadata

// ErrorString returns the DID Core 1.0 error string of e (docs/09 §6.1):
// invalidDid, notFound, representationNotSupported and invalidDidUrl for the
// codes DID Core 1.0 defines, the camelCase form of any other
// SCREAMING_SNAKE code (for example invalidDidDocument, or
// invalidVerificationMethod for a CID 1.0 code), and internalError for a type
// that is not such a code. The error of resolution.NewAcceptNotSupported is
// representationNotSupported (§7.1.2). A nil e is "".
func ErrorString(e *resolution.Error) string {
	if e == nil {
		return ""
	}
	if e.IsAcceptNotSupported() {
		return ErrRepresentationNotSupported
	}
	code := string(e.Code())
	if i := strings.LastIndexAny(code, "#/"); i >= 0 {
		code = code[i+1:]
	}
	if s := camel(code); s != "" {
		return s
	}
	return ErrInternalError
}

// camel converts SCREAMING_SNAKE to camelCase, mapping the segments DID and
// URL as DID Core 1.0 writes them (invalidDid, invalidDidUrl); it returns ""
// when s is not SCREAMING_SNAKE.
func camel(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for i, part := range strings.Split(s, "_") {
		if part == "" {
			return ""
		}
		for _, c := range part {
			if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				return ""
			}
		}
		lower := strings.ToLower(part)
		if i > 0 {
			lower = strings.ToUpper(lower[:1]) + lower[1:]
		}
		b.WriteString(lower)
	}
	return b.String()
}

// V10Metadata returns md for the DID Core 1.0 path: a deep copy in which
// every number in Extra and Proof, nested values included, is a decimal
// string, since DID Core 1.0 §7.3 allows no numbers. Datetimes keep their
// value; document.Metadata writes them in UTC without sub-second precision.
func V10Metadata(md document.Metadata) document.Metadata {
	c := md.Clone()
	if c.Extra != nil {
		c.Extra = stringify(c.Extra).(map[string]any)
	}
	for i, p := range c.Proof {
		if p != nil {
			c.Proof[i] = stringify(p).(map[string]any)
		}
	}
	return c
}

func stringify(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = stringify(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = stringify(x)
		}
		return out
	case json.Number:
		return t.String()
	case int, int8, int16, int32, int64:
		return strconv.FormatInt(reflect.ValueOf(t).Int(), 10)
	case uint, uint8, uint16, uint32, uint64:
		return strconv.FormatUint(reflect.ValueOf(t).Uint(), 10)
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return v
}

// V10Resolver offers resolve and resolveRepresentation of DID Core 1.0 §7.1
// over a DID Resolution v1.0 resolver.
type V10Resolver struct {
	// Inner is the resolver that does the work.
	Inner resolution.Resolver
}

// v10Accept is the accept value used for resolveRepresentation when the
// caller gives none: the DID Core 1.0 representations.
const v10Accept = spec.MediaTypeDIDLDJSON + ", " + spec.MediaTypeDIDJSON

// options removes the hl extension option, which DID Resolution v1.0 does
// not define (docs/09 §6.2).
func options(opts resolution.ResolutionOptions, md *V10ResolutionMetadata) resolution.ResolutionOptions {
	if _, ok := opts.Extra[did.ParamHL]; ok {
		extra := make(map[string]any, len(opts.Extra))
		for k, v := range opts.Extra {
			if k != did.ParamHL {
				extra[k] = v
			}
		}
		opts.Extra = extra
		md.Warnings = append(md.Warnings, WarningHLIgnored)
	}
	return opts
}

// Resolve is resolve(did, resolutionOptions) of DID Core 1.0 §7.1: it returns
// the DID resolution metadata without contentType, the document as data
// model and the document metadata.
func (r *V10Resolver) Resolve(ctx context.Context, d did.DID, opts resolution.ResolutionOptions) (V10ResolutionMetadata, *document.Document, resolution.DocumentMetadata) {
	var md V10ResolutionMetadata
	if opts.Accept != "" {
		opts.Accept = ""
		md.Warnings = append(md.Warnings, WarningAcceptIgnored)
	}
	res := r.Inner.Resolve(ctx, d, options(opts, &md))
	if e := res.ResolutionMetadata.Error; e != nil {
		md.Error = ErrorString(e)
		return md, nil, resolution.DocumentMetadata{}
	}
	return md, res.Document, V10Metadata(res.DocumentMetadata)
}

// ResolveRepresentation is resolveRepresentation(did, resolutionOptions) of
// DID Core 1.0 §7.1: it returns the DID resolution metadata with the
// contentType of the stream, the document as a byte stream and the document
// metadata.
func (r *V10Resolver) ResolveRepresentation(ctx context.Context, d did.DID, opts resolution.ResolutionOptions) (V10ResolutionMetadata, []byte, resolution.DocumentMetadata) {
	var md V10ResolutionMetadata
	if opts.Accept == "" {
		opts.Accept = v10Accept
	}
	res := r.Inner.Resolve(ctx, d, options(opts, &md))
	if e := res.ResolutionMetadata.Error; e != nil {
		md.Error = ErrorString(e)
		return md, nil, resolution.DocumentMetadata{}
	}
	if res.Document == nil {
		return md, nil, V10Metadata(res.DocumentMetadata) // DEV-V10-1
	}
	md.ContentType = res.ResolutionMetadata.ContentType
	return md, res.Raw, V10Metadata(res.DocumentMetadata)
}

// V10Dereferencer offers dereference of DID Core 1.0 §7.2 over a DID
// Resolution v1.0 dereferencer.
type V10Dereferencer struct {
	// Inner is the dereferencer that does the work.
	Inner resolution.Dereferencer
}

// Dereference is dereference(didUrl, dereferenceOptions) of DID Core 1.0
// §7.2. The content type of the content comes from the inner
// dereferencingMetadata, or else from its contentMetadata (docs/07 caveat
// 8).
func (r *V10Dereferencer) Dereference(ctx context.Context, u did.DIDURL, opts resolution.DereferenceOptions) (V10DereferencingMetadata, any, resolution.DocumentMetadata) {
	var md V10DereferencingMetadata
	params, err := u.Parameters()
	if err != nil {
		md.Error = ErrInvalidDIDURL
		return md, nil, resolution.DocumentMetadata{}
	}
	if _, ok := params.Get(did.ParamServiceType); ok {
		md.Error = ErrFeatureNotSupported
		return md, nil, resolution.DocumentMetadata{}
	}
	if _, ok := params.Get(did.ParamHL); ok {
		u = withoutParameter(u, did.ParamHL)
		md.Warnings = append(md.Warnings, WarningHLIgnored)
	}
	res := r.Inner.Dereference(ctx, u, opts)
	if e := res.DereferencingMetadata.Error; e != nil {
		md.Error = ErrorString(e)
		return md, nil, resolution.DocumentMetadata{}
	}
	md.ContentType = res.DereferencingMetadata.ContentType
	if md.ContentType == "" {
		md.ContentType, _ = res.ContentMetadata.Extra["contentType"].(string)
	}
	return md, res.ContentStream, V10Metadata(res.ContentMetadata)
}

// withoutParameter returns u without the DID parameter name. Removing a
// name=value pair from a valid query leaves a valid DID URL.
func withoutParameter(u did.DIDURL, name string) did.DIDURL {
	var kept []string
	for _, pair := range strings.Split(u.Query(), "&") {
		if n, _, _ := strings.Cut(pair, "="); n != name {
			kept = append(kept, pair)
		}
	}
	s := u.DID().String() + u.Path()
	if len(kept) > 0 {
		s += "?" + strings.Join(kept, "&")
	}
	if u.HasFragment() {
		s += "#" + u.Fragment()
	}
	out, err := did.ParseURL(s)
	if err != nil {
		return u
	}
	return out
}
