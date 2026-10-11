// Package resolver is the DID resolver player of did-go (DID Resolution v1.0
// CRD 2026-10-01 §4, docs/07 §1, docs/12 §6.2, docs/14 §5). DefaultResolver
// implements resolution.Resolver over the method drivers of a
// method.Registry, consuming every driver output with a
// representation.Consumer and transcoding with a representation.Producer.
//
// The resolve algorithm follows DID Resolution §4.4 step by step:
//
//  1. a DID that does not conform to the did rule is INVALID_DID;
//  2. a method without a driver is METHOD_NOT_SUPPORTED;
//  3. an option the resolver does not support is FEATURE_NOT_SUPPORTED: an
//     extension option it does not know, or an accept value no
//     representation it can produce satisfies;
//  4. an invalid option is INVALID_OPTIONS (resolution.ResolutionOptions
//     Validate);
//  5. the driver's Read runs: method.ErrNotFound is NOT_FOUND,
//     method.ErrNotSupported (for example versionId on a method without
//     versions) is FEATURE_NOT_SUPPORTED, method.ErrInvalidDocument (the
//     driver obtained a document that does not conform or whose id is not
//     the DID) is INVALID_DID_DOCUMENT, method.ErrInvalidInput is
//     INVALID_DID, and any other failure is INTERNAL_ERROR. The document
//     metadata the driver supplied is validated, before the deactivated
//     check, and a violation is INVALID_DID_DOCUMENT (docs/12 §6.2). A
//     deactivated DID is not an error: the result has no document and
//     didDocumentMetadata with deactivated true. Otherwise the driver bytes
//     are consumed with the media type the driver labelled them with; bytes
//     that do not conform, and a document whose id is not the resolved DID,
//     are INVALID_DID_DOCUMENT;
//  6. with expandRelativeUrls, relative DID URLs in ids and verification
//     relationships are made absolute;
//  7. the result carries the bytes returned to the caller in Raw and their
//     media type in didResolutionMetadata.contentType (docs/07 caveat 4).
//
// Every error result has a nil document, empty document metadata and the
// error in the resolution metadata (resolution.ErrorResult).
//
// Representation selection follows docs/12 §6.2: without accept the driver
// bytes are returned unchanged; with accept they are returned when their
// representation is acceptable, and otherwise the validated document is
// transcoded with the producer, the driver original kept in Result.Source.
// With expandRelativeUrls the bytes no longer match the document, so they
// are always produced again. When no acceptable representation can be
// produced the result is FEATURE_NOT_SUPPORTED, created by
// resolution.NewAcceptNotSupported so that the DID Core 1.0 adapter can
// report representationNotSupported.
//
// DefaultResolver keeps no cache, so it honours the noCache option (DID
// Resolution §13.2) trivially; it passes the option to the driver in
// method.ReadOptions.NoCache so that a driver cache is bypassed as well.
// Package resolution/cache adds a cache in front of any resolver.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
)

// DefaultResolver resolves DIDs with the drivers of a registry. It has no
// mutable state and is safe for concurrent use when its registry, consumer
// and producer are.
type DefaultResolver struct {
	registry *method.Registry
	consumer representation.Consumer
	producer representation.Producer
	accepted []string
}

var _ resolution.Resolver = (*DefaultResolver)(nil)

// Option configures a DefaultResolver.
type Option func(*DefaultResolver)

// AcceptOptions names extension resolution options (keys of
// ResolutionOptions.Extra) that the resolver accepts and ignores, in
// addition to those accepted by default. Any other extension option is
// FEATURE_NOT_SUPPORTED (DID Resolution §4.4 step 3).
func AcceptOptions(names ...string) Option {
	return func(r *DefaultResolver) { r.accepted = append(r.accepted, names...) }
}

// DefaultAcceptedOptions returns the extension options a DefaultResolver
// accepts and ignores without configuration, in a fresh slice: the DID
// parameters service, serviceType and relativeRef and the dereferencing
// option verificationRelationship. A DID URL dereferencer passes all of them
// as resolution options (DID Resolution §5.4.1: "All dereferencing options
// and all DID parameters of the input DID URL MUST be passed as resolution
// options"), and none of them changes which DID document is resolved.
func DefaultAcceptedOptions() []string {
	return []string{did.ParamService, did.ParamServiceType, did.ParamRelativeRef, "verificationRelationship"}
}

// New returns a resolver over the drivers in registry. Driver output is
// consumed with consumer, and producer writes a representation the driver
// did not produce. A nil argument is an error.
func New(registry *method.Registry, consumer representation.Consumer, producer representation.Producer, opts ...Option) (*DefaultResolver, error) {
	if registry == nil || consumer == nil || producer == nil {
		return nil, errors.New("resolver: a registry, a consumer and a producer are required")
	}
	r := &DefaultResolver{registry: registry, consumer: consumer, producer: producer, accepted: DefaultAcceptedOptions()}
	for _, o := range opts {
		o(r)
	}
	return r, nil
}

// ResolveString parses s as a DID and resolves it; a string that does not
// conform to the did rule is INVALID_DID (DID Resolution §4.4 step 1).
func (r *DefaultResolver) ResolveString(ctx context.Context, s string, opts resolution.ResolutionOptions) resolution.Result {
	d, err := did.Parse(s)
	if err != nil {
		return resolution.ErrorResult(resolution.NewError(resolution.CodeInvalidDID, err.Error()))
	}
	return r.Resolve(ctx, d, opts)
}

// Resolve runs the DID resolution algorithm of DID Resolution §4.4.
func (r *DefaultResolver) Resolve(ctx context.Context, d did.DID, opts resolution.ResolutionOptions) resolution.Result {
	if d.IsZero() {
		return failed(resolution.CodeInvalidDID, "the DID is empty")
	}
	m, ok := r.registry.Lookup(d.Method())
	if !ok {
		return failed(resolution.CodeMethodNotSupported, fmt.Sprintf("no driver for DID method %q", d.Method()))
	}
	if e := r.supported(opts); e != nil {
		return resolution.ErrorResult(e)
	}
	if e := opts.Validate(); e != nil {
		return resolution.ErrorResult(e)
	}
	rr, e := read(ctx, m, d, opts)
	if e != nil {
		return resolution.ErrorResult(e)
	}
	if err := rr.Metadata.Check(d, spec.V11); err != nil {
		return failed(resolution.CodeInvalidDIDDocument, "document metadata from the driver: "+err.Error())
	}
	if rr.Metadata.Deactivated {
		return resolution.Result{DocumentMetadata: rr.Metadata.Clone()}
	}
	return r.output(d, rr, opts)
}

// supported is step 3: every extension option must be one the resolver
// accepts, and a present accept value must accept a representation the
// producer can write.
func (r *DefaultResolver) supported(opts resolution.ResolutionOptions) *resolution.Error {
	for name := range opts.Extra {
		if !slices.Contains(r.accepted, name) && !slices.Contains(modeledOptions(), name) {
			return resolution.NewError(resolution.CodeFeatureNotSupported, fmt.Sprintf("the resolution option %q is not supported", name))
		}
	}
	if opts.Accept != "" {
		if _, err := resolution.ParseAccept(opts.Accept); err == nil {
			if _, ok := resolution.Negotiate(opts.Accept, representation.CoreMediaTypes()); !ok {
				return resolution.NewAcceptNotSupported(opts.Accept)
			}
		}
	}
	return nil
}

// modeledOptions are the option names ResolutionOptions models; Validate
// reports them as INVALID_OPTIONS when they appear in Extra.
func modeledOptions() []string {
	return []string{"accept", "expandRelativeUrls", "versionId", "versionTime", "noCache"}
}

// read is step 5: the driver's Read, with its errors mapped.
func read(ctx context.Context, m method.Method, d did.DID, opts resolution.ResolutionOptions) (*method.ReadResult, *resolution.Error) {
	want := ""
	if opts.Accept != "" {
		want, _ = resolution.Negotiate(opts.Accept, m.Produces())
	}
	rr, err := m.Read(ctx, d, method.ReadOptions{
		VersionID: opts.VersionID, VersionTime: opts.VersionTime, MediaType: want, NoCache: opts.NoCache,
	})
	switch {
	case errors.Is(err, method.ErrNotFound):
		return nil, resolution.NewError(resolution.CodeNotFound, fmt.Sprintf("%s does not exist", d))
	case errors.Is(err, method.ErrNotSupported):
		return nil, resolution.NewError(resolution.CodeFeatureNotSupported, "the DID method does not support the request: "+err.Error())
	case errors.Is(err, method.ErrInvalidDocument):
		return nil, resolution.NewError(resolution.CodeInvalidDIDDocument, "the DID method driver obtained an invalid DID document: "+err.Error())
	case errors.Is(err, method.ErrInvalidInput):
		return nil, resolution.NewError(resolution.CodeInvalidDID, "the DID does not conform to its method: "+err.Error())
	case err != nil:
		return nil, resolution.NewError(resolution.CodeInternalError, "the DID method driver failed")
	case rr == nil:
		return nil, resolution.NewError(resolution.CodeInternalError, "the DID method driver returned no result")
	}
	return rr, nil
}

// output consumes and validates the driver bytes (docs/12 §6.2 step 1),
// expands relative DID URLs (DID Resolution §4.4 step 6) and selects the
// returned representation (docs/12 §6.2 steps 2 to 4).
func (r *DefaultResolver) output(d did.DID, rr *method.ReadResult, opts resolution.ResolutionOptions) resolution.Result {
	doc, info, err := r.consumer.Consume(rr.Data, rr.ContentType, representation.ConsumeOptions{})
	if err != nil {
		return failed(resolution.CodeInvalidDIDDocument, err.Error())
	}
	if doc.ID().String() != d.String() {
		return failed(resolution.CodeInvalidDIDDocument, fmt.Sprintf("the document id %s is not the resolved DID %s", doc.ID(), d))
	}
	detected := representation.MediaTypeOf(info)
	if opts.ExpandRelativeURLs {
		if doc, err = expand(doc); err != nil {
			return failed(resolution.CodeInternalError, "expanding relative DID URLs: "+err.Error())
		}
	}
	res := resolution.Result{Document: doc, Info: info, DocumentMetadata: rr.Metadata.Clone()}
	if !opts.ExpandRelativeURLs && (opts.Accept == "" || resolution.Acceptable(opts.Accept, detected)) {
		res.Raw = slices.Clone(rr.Data)
		res.ResolutionMetadata.ContentType = detected
		return res
	}
	offers := []string{detected}
	if opts.Accept != "" {
		offers = append(offers, representation.CoreMediaTypes()...)
	}
	target, ok := resolution.Negotiate(opts.Accept, offers)
	if !ok {
		return resolution.ErrorResult(resolution.NewAcceptNotSupported(opts.Accept))
	}
	popts, _ := representation.OptionsFor(target)
	data, mt, err := r.producer.Produce(doc, popts)
	if err != nil {
		if opts.Accept == "" {
			return failed(resolution.CodeInternalError, "producing the expanded document: "+err.Error())
		}
		return resolution.ErrorResult(resolution.NewAcceptNotSupported(opts.Accept))
	}
	res.Raw = data
	res.Source = &resolution.SourceBytes{Data: slices.Clone(rr.Data), ContentType: rr.ContentType}
	res.ResolutionMetadata.ContentType = mt
	return res
}

func failed(code resolution.Code, detail string) resolution.Result {
	return resolution.ErrorResult(resolution.NewError(code, detail))
}
