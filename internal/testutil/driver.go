// Package testutil holds test fixtures shared by the tests of several
// players. It is imported only by tests.
package testutil

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
)

// ReadFunc answers a Read call.
type ReadFunc func(ctx context.Context, d did.DID, opts method.ReadOptions) (*method.ReadResult, error)

// Driver is a fixture method driver: Read calls Func and records every call.
// Create, Update and Deactivate return method.ErrNotSupported. It is safe
// for concurrent use.
type Driver struct {
	// Method is the method name.
	Method string
	// Media are the media types Produces returns.
	Media []string
	// Func answers Read.
	Func ReadFunc

	mu    sync.Mutex
	calls []method.ReadOptions
}

var _ method.Method = (*Driver)(nil)

// Name returns the method name.
func (d *Driver) Name() string { return d.Method }

// Produces returns a copy of Media.
func (d *Driver) Produces() []string { return slices.Clone(d.Media) }

// Read records opts and calls Func.
func (d *Driver) Read(ctx context.Context, id did.DID, opts method.ReadOptions) (*method.ReadResult, error) {
	d.mu.Lock()
	d.calls = append(d.calls, opts)
	d.mu.Unlock()
	return d.Func(ctx, id, opts)
}

// Calls returns the options of every Read call so far.
func (d *Driver) Calls() []method.ReadOptions {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.calls)
}

// Create is not supported.
func (d *Driver) Create(context.Context, *document.Document, method.CreateOptions) (*method.CreateResult, error) {
	return nil, fmt.Errorf("%w: fixture", method.ErrNotSupported)
}

// Update is not supported.
func (d *Driver) Update(context.Context, did.DID, *document.Document, method.UpdateOptions) (*method.UpdateResult, error) {
	return nil, fmt.Errorf("%w: fixture", method.ErrNotSupported)
}

// Deactivate is not supported.
func (d *Driver) Deactivate(context.Context, did.DID, method.DeactivateOptions) (*method.DeactivateResult, error) {
	return nil, fmt.Errorf("%w: fixture", method.ErrNotSupported)
}

// Static returns a ReadFunc that returns data labelled with contentType and
// metadata md for every DID.
func Static(data, contentType string, md document.Metadata) ReadFunc {
	return func(context.Context, did.DID, method.ReadOptions) (*method.ReadResult, error) {
		return &method.ReadResult{Data: []byte(data), ContentType: contentType, Metadata: md.Clone()}, nil
	}
}

// Fail returns a ReadFunc that returns err.
func Fail(err error) ReadFunc {
	return func(context.Context, did.DID, method.ReadOptions) (*method.ReadResult, error) {
		return nil, err
	}
}

// MustDID parses s and panics on error.
func MustDID(s string) did.DID {
	d, err := did.Parse(s)
	if err != nil {
		panic(err)
	}
	return d
}

// MustURL parses s as a DID URL and panics on error.
func MustURL(s string) did.DIDURL {
	u, err := did.ParseURL(s)
	if err != nil {
		panic(err)
	}
	return u
}
