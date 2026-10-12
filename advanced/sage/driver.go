package sage

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/representation"
)

// MethodName is the DID method name of SAGE identifiers.
const MethodName = "sage"

// Driver is the did:sage method driver for the DID Resolution interface.
// Each Read observes the record once through the Source and writes the
// DIDP-01 projection for the media type the resolver picked: the DID 1.1
// projection for application/did and the DID Core 1.0 projection otherwise,
// which is also the default (OPEN-2 of the adopted proposal). Both
// projections are built from the record, never one from the other (DG-5).
//
// Plugged into a standard resolver on its own, a Driver reports
// record.not-found as NOT_FOUND, id.malformed and size.exceeded as
// INVALID_DID and every other failure as INTERNAL_ERROR, because the
// standard resolver maps driver errors to fixed codes. Resolver stands in
// front of the standard resolver and reports every DIDP-05 code and the
// sageCode member.
type Driver struct {
	source   Source
	producer representation.Producer
}

var _ method.Method = (*Driver)(nil)

// NewDriver returns a driver that observes records through source and
// writes projections with producer.
func NewDriver(source Source, producer representation.Producer) (*Driver, error) {
	if source == nil || producer == nil {
		return nil, errors.New("sage: a source and a producer are required")
	}
	return &Driver{source: source, producer: producer}, nil
}

// Name returns "sage".
func (*Driver) Name() string { return MethodName }

// Produces returns the projection media types, DID Core 1.0 first.
func (*Driver) Produces() []string { return []string{MediaTypeCore10, MediaTypeDID11} }

// Read observes the record of d and returns the selected projection. A
// deactivated record returns no bytes and metadata with deactivated true,
// which a DID Resolution resolver reports with a null document (DIDP-05).
// Historical resolution is not offered (RESOLVE-02), so versionId and
// versionTime are not supported.
func (dr *Driver) Read(ctx context.Context, d did.DID, opts method.ReadOptions) (*method.ReadResult, error) {
	if opts.VersionID != "" || opts.VersionTime != nil {
		return nil, fmt.Errorf("%w: did:sage resolves the current record only", method.ErrNotSupported)
	}
	rr, e := dr.read(ctx, d, opts.MediaType)
	if e != nil {
		record(ctx, d.String(), e)
		return nil, &driverError{sage: e}
	}
	return rr, nil
}

func (dr *Driver) read(ctx context.Context, d did.DID, mediaType string) (*method.ReadResult, *Error) {
	if e := checkID(d.String()); e != nil {
		return nil, e
	}
	rec, err := dr.source.Observe(ctx, d)
	if err != nil {
		return nil, codeOf(err)
	}
	if rec.DID != d {
		return nil, NewError(CodeRecordInvalid, "the observed record is not the requested identifier")
	}
	p, ok := projectionOf(mediaType)
	if !ok {
		p = Core10
	}
	data, e := Produce(rec, p, dr.producer)
	if e != nil {
		return nil, e
	}
	md := Metadata(rec)
	if md.Deactivated {
		return &method.ReadResult{Metadata: md}, nil
	}
	return &method.ReadResult{Data: data, ContentType: p.MediaType(), Metadata: md}, nil
}

// Create is not supported: records are written through a SAGE registry.
func (*Driver) Create(context.Context, *document.Document, method.CreateOptions) (*method.CreateResult, error) {
	return nil, writeNotSupported()
}

// Update is not supported: records are written through a SAGE registry.
func (*Driver) Update(context.Context, did.DID, *document.Document, method.UpdateOptions) (*method.UpdateResult, error) {
	return nil, writeNotSupported()
}

// Deactivate is not supported: records are written through a SAGE registry.
func (*Driver) Deactivate(context.Context, did.DID, method.DeactivateOptions) (*method.DeactivateResult, error) {
	return nil, writeNotSupported()
}

func writeNotSupported() error {
	return fmt.Errorf("%w: did:sage records are written through a SAGE registry", method.ErrNotSupported)
}

// driverError carries a SAGE error to a standard resolver as the method
// error it maps to a DID Resolution code.
type driverError struct{ sage *Error }

func (e *driverError) Error() string { return e.sage.Error() }

func (e *driverError) Unwrap() []error {
	switch e.sage.Code {
	case CodeRecordNotFound:
		return []error{e.sage, method.ErrNotFound}
	case CodeIDMalformed, CodeSizeExceeded:
		return []error{e.sage, method.ErrInvalidInput}
	}
	return []error{e.sage}
}

// recorder receives the SAGE error of one resolution that Resolver or
// Handler runs. It belongs to one target DID, so that a driver resolving
// another DID on the same context, for example to look up a controller,
// cannot replace the outer result. The first error wins.
type recorder struct {
	target string
	err    atomic.Pointer[Error]
}

func (r *recorder) get() *Error { return r.err.Load() }

func (r *recorder) set(e *Error) { r.err.CompareAndSwap(nil, e) }

type recorderKey struct{}

// withRecorder returns ctx carrying a new recorder for target.
func withRecorder(ctx context.Context, target string) (context.Context, *recorder) {
	rec := &recorder{target: target}
	return context.WithValue(ctx, recorderKey{}, rec), rec
}

// sink receives the SAGE error of the request Handler serves, and preset is
// an error Handler found before the standard handler ran.
type (
	sinkKey   struct{}
	presetKey struct{}
)

// preset returns the error Handler preset on ctx, or nil.
func preset(ctx context.Context) *Error {
	e, _ := ctx.Value(presetKey{}).(*Error)
	return e
}

// report passes e to the sink of ctx, if any, and returns its code.
func report(ctx context.Context, e *Error) Code {
	if s, ok := ctx.Value(sinkKey{}).(*recorder); ok {
		s.set(e)
	}
	return e.Code
}

// record stores e in the recorder of ctx when it belongs to target.
func record(ctx context.Context, target string, e *Error) {
	if rec, ok := ctx.Value(recorderKey{}).(*recorder); ok && rec.target == target {
		rec.set(e)
	}
}
