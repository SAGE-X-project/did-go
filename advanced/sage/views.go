package sage

import (
	"bytes"
	"context"
	"slices"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/representation"
)

// ProjectionView owns a document's bytes, media type and observation metadata.
// It grants no authority to authenticate a protected operation.
type ProjectionView struct {
	Data        []byte
	ContentType string
	Metadata    document.Metadata
}

// Views contains the two DIDP-01 projections of one observation (chapter 10
// DIDP-03). Both views own their bytes and metadata independently.
type Views struct {
	Core10 ProjectionView
	DID11  ProjectionView
}

// ObserveViews observes d exactly once through the explicitly configured source
// and produces both DID projections from that record. A subsequent call makes a
// new observation. Source still supplies proof, freshness and history validation;
// this operation does not select or establish a deployment's trust policy.
//
// A failure returns no pair, including when producing the second view fails.
// This is an output guarantee, not rollback: observing may already have advanced
// the Source's durable journal. Cancellation is checked between synchronous
// calls; an uncooperative producer cannot be interrupted while Produce runs.
//
// Each document retains Produce's existing size/media bounds. This local API
// introduces no HTTP envelope, aggregate wire format or resolution policy.
// Created/deactivated records remain inspectable without authorizing operations;
// Driver's standard deactivated-null behavior is unchanged. Nil interfaces or a
// nil context are rejected; configured implementations must honor their contracts.
func ObserveViews(ctx context.Context, source Source, d did.DID, producer representation.Producer) (*Views, *Error) {
	if ctx == nil || source == nil || producer == nil {
		return nil, NewError(CodeRecordInvalid, "a context, source and producer are required")
	}
	if e := checkID(d.String()); e != nil {
		return nil, e
	}
	if err := ctx.Err(); err != nil {
		return nil, codeOf(err)
	}
	rec, err := source.Observe(ctx, d)
	if err != nil {
		return nil, codeOf(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, codeOf(err)
	}
	if rec.DID != d {
		return nil, NewError(CodeRecordInvalid, "the observed record is not the requested identifier")
	}
	if e := rec.check(); e != nil {
		return nil, e
	}
	rec = snapshotRecord(rec)
	core, e := Produce(rec, Core10, producer)
	if e != nil {
		return nil, e
	}
	// A conforming producer may reuse its scratch buffer on the next call.
	core = bytes.Clone(core)
	if err := ctx.Err(); err != nil {
		return nil, codeOf(err)
	}
	modern, e := Produce(rec, DID11, producer)
	if e != nil {
		return nil, e
	}
	modern = bytes.Clone(modern)
	if err := ctx.Err(); err != nil {
		return nil, codeOf(err)
	}
	md := Metadata(rec)
	return &Views{
		Core10: ProjectionView{Data: core, ContentType: MediaTypeCore10, Metadata: md.Clone()},
		DID11:  ProjectionView{Data: modern, ContentType: MediaTypeDID11, Metadata: md.Clone()},
	}, nil
}

// snapshotRecord owns mutable record members. Source must not concurrently
// mutate a returned record; copying is not synchronization for a violating Source.
func snapshotRecord(r Record) Record {
	r.Keys = slices.Clone(r.Keys)
	for i := range r.Keys {
		r.Keys[i].Material = bytes.Clone(r.Keys[i].Material)
		if r.Keys[i].Expires != nil {
			expires := *r.Keys[i].Expires
			r.Keys[i].Expires = &expires
		}
	}
	r.Services = slices.Clone(r.Services)
	if r.Observation.Issued != nil {
		issued := *r.Observation.Issued
		r.Observation.Issued = &issued
	}
	return r
}
