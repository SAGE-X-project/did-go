// Package dereferencer is the DID URL dereferencer player of did-go (DID
// Resolution v1.0 CRD 2026-10-01 §5, docs/07 §2, docs/14 §5). Dereferencer
// implements resolution.Dereferencer over any resolution.Resolver.
//
// The algorithm follows DID Resolution §5.4:
//
//   - Dereferencing the resource (§5.4.1): a DID URL that does not conform to
//     the did-url rule, or whose query cannot be read as DID parameters, is
//     INVALID_DID_URL. The DID is resolved with the dereferencing options and
//     every DID parameter passed as resolution options; NOT_FOUND and every
//     other resolution error is returned as the dereferencing error. A DID
//     URL without path and query dereferences to the resolved DID document
//     and its metadata. With the service or serviceType parameter the
//     matching services are selected, relativeRef is resolved against each
//     selected service endpoint URL with RFC 3986 §5, and the result is the
//     document reduced to the selected services, or the list of selected
//     service endpoint URLs for accept text/uri-list, or
//     REPRESENTATION_NOT_SUPPORTED. A path or another query is dereferenced
//     by the first ResourceHandler that handles it, and is NOT_FOUND
//     otherwise.
//   - Dereferencing the fragment (§5.4.2): with the verificationRelationship
//     option the fragment must select a conforming verification method of
//     the document that the relationship authorizes (document.SelectMethod,
//     INVALID_VERIFICATION_METHOD and
//     INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD). Without it the fragment
//     is resolved in the document with the Fragment Resolution algorithm of
//     CID 1.0 §3.4, which DID 1.1 names for application/did; no match is
//     NOT_FOUND. Selected service endpoint URLs inherit the fragment, and an
//     endpoint URL that already has one is an error.
//
// Choices where the specification leaves room are documented on the
// functions that make them; the main ones are:
//
//   - every accept preference is passed unchanged to the resolver. A resolver
//     used to retrieve intermediate documents can be constructed separately
//     with resolver.ForDereferencing; the direct resolver remains strict;
//   - a query made only of versionId and versionTime dereferences to the
//     resolved (versioned) document, because those parameters are resolution
//     options;
//   - a service parameter matches a service id after RFC 3986 §5 resolution
//     against the DID, and also as a fragment of the DID, as in DID
//     Resolution Example 13 (service=messages selects #messages);
//   - text/uri-list results carry contentType in both dereferencingMetadata
//     and contentMetadata (docs/07 caveat 8).
//
// Content types: a DID document is a *document.Document whose
// representation is dereferencingMetadata.contentType (checked with the
// producer); a fragment is a vm.Method, a vm.Service, a document.Map or a
// fresh map[string]any when numeric fidelity requires it, whose
// contentType is application/ld+json for a JSON-LD based representation and
// application/json for application/did+json; a URI list is a []string with
// contentType text/uri-list.
package dereferencer

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
)

// MediaTypeURIList is the media type of a list of service endpoint URLs.
const MediaTypeURIList = "text/uri-list"

// ResourceHandler dereferences a DID URL with a path or a query that DID
// Resolution §5.4.1 leaves to the DID method, an extension or the client
// ("The applicable DID method MAY specify how to dereference the DID path
// and/or DID query"). It receives the full DID URL, fragment included, and
// the resolution result of its DID, and reports whether it handled the URL.
type ResourceHandler func(ctx context.Context, u did.DIDURL, resolved resolution.Result, opts resolution.DereferenceOptions) (resolution.DereferenceResult, bool)

// Dereferencer dereferences DID URLs. It has no mutable state and is safe
// for concurrent use when its resolver and producer are.
type Dereferencer struct {
	resolver resolution.Resolver
	producer representation.Producer
	handlers []ResourceHandler
}

var _ resolution.Dereferencer = (*Dereferencer)(nil)

// Option configures a Dereferencer.
type Option func(*Dereferencer)

// WithResourceHandler adds a handler for DID URLs with a path or a query.
// Handlers are tried in the order they were added.
func WithResourceHandler(h ResourceHandler) Option {
	return func(d *Dereferencer) { d.handlers = append(d.handlers, h) }
}

// New returns a dereferencer that resolves DIDs with r and checks document
// representations with p. A nil resolver or producer is an error. All options,
// including accept for final content, reach r unchanged. For service URI lists,
// construct a dedicated resolver with resolver.ForDereferencing; New does not
// reconfigure r or retry a failed resolution with different options.
func New(r resolution.Resolver, p representation.Producer, opts ...Option) (*Dereferencer, error) {
	if r == nil || p == nil {
		return nil, errors.New("dereferencer: a resolver and a producer are required")
	}
	d := &Dereferencer{resolver: r, producer: p}
	for _, o := range opts {
		if o != nil {
			o(d)
		}
	}
	return d, nil
}

func failed(code resolution.Code, detail string) resolution.DereferenceResult {
	return resolution.ErrorDereferenceResult(resolution.NewError(code, detail))
}

// DereferenceString parses s as a DID URL and dereferences it; a string that
// does not conform to the did-url rule is INVALID_DID_URL (DID Resolution
// §5.4.1 step 1).
func (d *Dereferencer) DereferenceString(ctx context.Context, s string, opts resolution.DereferenceOptions) resolution.DereferenceResult {
	u, err := did.ParseURL(s)
	if err != nil {
		return failed(resolution.CodeInvalidDIDURL, err.Error())
	}
	return d.Dereference(ctx, u, opts)
}

// Dereference runs the DID URL dereferencing algorithm of DID Resolution
// §5.4 on u, which must include its fragment, if any (§5: "To dereference a
// DID fragment, the complete DID URL including the DID fragment MUST be
// used").
func (d *Dereferencer) Dereference(ctx context.Context, u did.DIDURL, opts resolution.DereferenceOptions) resolution.DereferenceResult {
	if u.IsZero() || u.IsRelative() {
		return failed(resolution.CodeInvalidDIDURL, "a DID URL to dereference is absolute")
	}
	params, err := u.Parameters()
	if err != nil {
		return failed(resolution.CodeInvalidDIDURL, err.Error())
	}
	if e := opts.Validate(); e != nil {
		return resolution.ErrorDereferenceResult(e)
	}
	res := d.resolver.Resolve(ctx, u.DID(), resolutionOptions(params, opts))
	if e := res.ResolutionMetadata.Error; e != nil {
		if e.IsAcceptNotSupported() {
			// REPRESENTATION_NOT_SUPPORTED is the dereferencing error for an
			// accept value that cannot be satisfied (§5.4.1); the resolver
			// reports the same condition as FEATURE_NOT_SUPPORTED.
			return failed(resolution.CodeRepresentationNotSupported, e.Detail)
		}
		return resolution.ErrorDereferenceResult(e)
	}
	if res.Document == nil {
		// A deactivated DID resolves to no document (DID Resolution §4.4);
		// its metadata, with deactivated true, is the content metadata.
		return resolution.DereferenceResult{ContentMetadata: res.DocumentMetadata.Clone()}
	}
	out, handled := d.resource(ctx, u, params, res, opts)
	if handled || out.DereferencingMetadata.Error != nil {
		return out
	}
	return d.fragment(u, out, opts)
}

// resolutionOptions maps the DID parameters and dereferencing options to
// resolution options (DID Resolution §5.4.1: "All dereferencing options and
// all DID parameters of the input DID URL MUST be passed as resolution
// options"). versionId and versionTime become the options of the same name;
// every other parameter, verificationRelationship and the extension options
// go to Extra under their names. accept is always passed unchanged, including
// a preference for content that is not a DID document representation.
func resolutionOptions(params did.DIDParameters, opts resolution.DereferenceOptions) resolution.ResolutionOptions {
	ro := resolution.ResolutionOptions{VersionID: params.VersionID, Accept: opts.Accept}
	if _, ok := params.Get(did.ParamVersionTime); ok {
		t := params.VersionTime
		ro.VersionTime = &t
	}
	extra := maps.Clone(opts.Extra)
	add := func(k string, v any) {
		if extra == nil {
			extra = map[string]any{}
		}
		extra[k] = v
	}
	for _, name := range params.Names() {
		if name != did.ParamVersionID && name != did.ParamVersionTime {
			v, _ := params.Get(name)
			add(name, v)
		}
	}
	if opts.VerificationRelationship != "" {
		add("verificationRelationship", opts.VerificationRelationship)
	}
	ro.Extra = extra
	return ro
}

// resource is DID Resolution §5.4.1 after resolution. It reports handled
// when a ResourceHandler produced the result, which then is final.
func (d *Dereferencer) resource(ctx context.Context, u did.DIDURL, params did.DIDParameters, res resolution.Result,
	opts resolution.DereferenceOptions) (resolution.DereferenceResult, bool) {
	_, hasService := params.Get(did.ParamService)
	_, hasType := params.Get(did.ParamServiceType)
	switch {
	case hasService || hasType:
		return d.services(params, res, opts, u.HasFragment()), false
	case u.Path() == "" && onlyResolutionParameters(params):
		return d.documentResult(res.Document, res, opts, u.HasFragment()), false
	}
	for _, h := range d.handlers {
		if out, ok := h(ctx, u, res, opts); ok {
			return out, true
		}
	}
	return failed(resolution.CodeNotFound, "no dereferencing is defined for the path or query of "+u.String()), false
}

// onlyResolutionParameters reports whether every DID parameter is one that
// selects the resolved document version. DID Resolution §5.4.1 returns the
// resolved document for a DID URL with "no DID path and no DID query"; a
// query made only of versionId and versionTime is treated the same way,
// because those parameters were passed to resolution and the resolved
// document is the version they select (did-go interpretation).
func onlyResolutionParameters(params did.DIDParameters) bool {
	for _, n := range params.Names() {
		if n != did.ParamVersionID && n != did.ParamVersionTime {
			return false
		}
	}
	return true
}

// documentResult returns doc as the content with the resolved document
// metadata. Its contentType is the representation accept selects among those
// the producer can write, the resolver's first; without accept it is the
// resolver's contentType. When withFragment is set a fragment follows and
// accept is not applied: the content will be the fragment, whose single
// representation is given by the media type of the document (DID Resolution
// §5.4.2), so accept stays a preference that cannot fail.
func (d *Dereferencer) documentResult(doc *document.Document, res resolution.Result, opts resolution.DereferenceOptions,
	withFragment bool) resolution.DereferenceResult {
	ct := res.ResolutionMetadata.ContentType
	if opts.Accept != "" && !withFragment {
		offers := append([]string{ct}, representation.CoreMediaTypes()...)
		target, ok := resolution.Negotiate(opts.Accept, offers)
		if !ok {
			return failed(resolution.CodeRepresentationNotSupported, "no DID document representation is acceptable to "+opts.Accept)
		}
		ct = target
	}
	if !d.producible(doc, ct) {
		return failed(resolution.CodeRepresentationNotSupported, "the document cannot be represented as "+ct)
	}
	return resolution.DereferenceResult{
		ContentStream:         doc,
		DereferencingMetadata: resolution.DereferencingMetadata{ContentType: ct},
		ContentMetadata:       res.DocumentMetadata.Clone(),
	}
}

// producible reports whether the producer can write doc as mediaType.
func (d *Dereferencer) producible(doc *document.Document, mediaType string) bool {
	popts, err := representation.OptionsFor(mediaType)
	if err != nil {
		return false
	}
	_, _, err = d.producer.Produce(doc, popts)
	return err == nil
}

// isDIDMediaType reports whether mt is the media type of a DID document
// representation.
func isDIDMediaType(mt string) bool {
	return slices.Contains(representation.CoreMediaTypes(), mt)
}
