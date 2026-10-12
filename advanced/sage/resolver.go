package sage

import (
	"context"
	"errors"

	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolver"
)

// Resolver presents SAGE resolution through the DID Resolution interface
// (chapter 10 DIDP-05). It runs a standard did-go resolver whose registry
// holds a did:sage Driver and any other drivers, so that the standard
// resolve algorithm, validation, accept matching and transcoding apply
// unchanged (DIDP-02 binds only the SAGE interface). When the record source
// fails, Resolver replaces the standard resolver's fixed driver-error code
// with the DID Resolution error DIDP-05 maps the SAGE code to, and reports
// the SAGE code beside the result.
type Resolver struct {
	resolver *resolver.DefaultResolver
	deref    *dereferencer.Dereferencer
}

var (
	_ resolution.Resolver     = (*Resolver)(nil)
	_ resolution.Dereferencer = (*Resolver)(nil)
)

// NewResolver returns a resolver for did:sage identifiers, observed through
// source, and for the methods of others. Driver output is consumed with
// consumer, and producer writes projections and transcoded representations.
func NewResolver(source Source, consumer representation.Consumer, producer representation.Producer, others ...method.Method) (*Resolver, error) {
	drv, err := NewDriver(source, producer)
	if err != nil {
		return nil, err
	}
	reg, err := method.NewRegistry(append([]method.Method{drv}, others...)...)
	if err != nil {
		return nil, err
	}
	r, err := resolver.New(reg, consumer, producer)
	if err != nil {
		return nil, err
	}
	d, err := dereferencer.New(r, producer)
	if err != nil {
		return nil, err
	}
	return &Resolver{resolver: r, deref: d}, nil
}

// Resolve resolves d (resolution.Resolver).
func (r *Resolver) Resolve(ctx context.Context, d did.DID, opts resolution.ResolutionOptions) resolution.Result {
	res, _ := r.ResolveWithCode(ctx, d, opts)
	return res
}

// ResolveWithCode resolves d and returns the SAGE code of a failed did:sage
// resolution, or "".
func (r *Resolver) ResolveWithCode(ctx context.Context, d did.DID, opts resolution.ResolutionOptions) (resolution.Result, Code) {
	if e := preset(ctx); e != nil {
		return resolution.ErrorResult(e.ResolutionError()), report(ctx, e)
	}
	ctx, rec := withRecorder(ctx, d.String())
	res := r.resolver.Resolve(ctx, d, opts)
	if e := rec.get(); e != nil {
		return resolution.ErrorResult(e.ResolutionError()), report(ctx, e)
	}
	return res, ""
}

// ResolveString parses s and resolves it. A string that names the sage
// method in any letter case but breaks chapter 06 ID-01 is INVALID_DID with
// sageCode id.malformed (or size.exceeded) and is never observed.
func (r *Resolver) ResolveString(ctx context.Context, s string, opts resolution.ResolutionOptions) (resolution.Result, Code) {
	if e := malformed(s); e != nil {
		return resolution.ErrorResult(e.ResolutionError()), report(ctx, e)
	}
	d, err := did.Parse(s)
	if err != nil {
		return resolution.ErrorResult(resolution.NewError(resolution.CodeInvalidDID, err.Error())), ""
	}
	return r.ResolveWithCode(ctx, d, opts)
}

// Dereference dereferences u (resolution.Dereferencer).
func (r *Resolver) Dereference(ctx context.Context, u did.DIDURL, opts resolution.DereferenceOptions) resolution.DereferenceResult {
	res, _ := r.DereferenceWithCode(ctx, u, opts)
	return res
}

// DereferenceWithCode dereferences u with the standard dereferencer and
// returns the SAGE code of a failure, or "". A did:sage DID URL with a path,
// a query or a fragment that is not a key-id breaks chapter 06 ID-01 and is
// id.malformed. A did:sage resolution failure is mapped as in
// ResolveWithCode. A fragment that names nothing in a resolved did:sage
// document is NOT_FOUND with sageCode key.not-in-record (DIDP-05).
func (r *Resolver) DereferenceWithCode(ctx context.Context, u did.DIDURL, opts resolution.DereferenceOptions) (resolution.DereferenceResult, Code) {
	e := preset(ctx)
	if e == nil && u.DID().Method() == MethodName {
		e = checkID(u.String())
	}
	if e != nil {
		return resolution.ErrorDereferenceResult(e.ResolutionError()), report(ctx, e)
	}
	ctx, rec := withRecorder(ctx, u.DID().String())
	res := r.deref.Dereference(ctx, u, opts)
	if e := rec.get(); e != nil {
		return resolution.ErrorDereferenceResult(e.ResolutionError()), report(ctx, e)
	}
	de := res.DereferencingMetadata.Error
	if de != nil && u.DID().Method() == MethodName && u.HasFragment() && u.Path() == "" && !u.HasQuery() &&
		errors.Is(de, resolution.NewError(resolution.CodeNotFound, "")) {
		return res, report(ctx, NewError(CodeKeyNotInRecord, ""))
	}
	return res, ""
}
