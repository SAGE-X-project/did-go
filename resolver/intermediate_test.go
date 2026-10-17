package resolver_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/testutil"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/cache"
	"github.com/sage-x-project/did-go/resolver"
	"github.com/sage-x-project/did-go/spec"
)

func intermediate(t *testing.T, drv method.Method, p representation.Producer) *resolver.DefaultResolver {
	t.Helper()
	reg, err := method.NewRegistry(drv)
	if err != nil {
		t.Fatal(err)
	}
	r, err := resolver.New(reg, consumer.New(), p, resolver.ForDereferencing())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// This fixture is conforming in both versions; relative IDs must not turn a
// representation preference control into a document-validation failure.
const absoluteDocument = `{"id":"did:example:123","service":[{"id":"did:example:123#files","type":"FileService","serviceEndpoint":"https://files.example/a"}]}`

func absoluteDriver() *testutil.Driver {
	return fixture(testutil.Static(absoluteDocument, spec.MediaTypeDID, document.Metadata{VersionID: "1"}))
}

func TestIntermediateDocumentResolution(t *testing.T) {
	for _, accept := range []string{"", "text/uri-list", "image/png", "application/did+json", "application/did;q=0", "*/*", "text/uri-list;q=1, application/did;q=0.5"} {
		t.Run(accept, func(t *testing.T) {
			drv := absoluteDriver()
			direct := newResolver(t, drv)
			retrieval := intermediate(t, drv, producer.New())
			id := testutil.MustDID(testutil.ExampleDID)
			opts := resolution.ResolutionOptions{Accept: accept, VersionID: "1", Extra: map[string]any{"service": "files"}}
			before := resolution.ResolutionOptions{Accept: accept, VersionID: "1", Extra: map[string]any{"service": "files"}}
			res := retrieval.Resolve(t.Context(), id, opts)
			wantSuccess(t, res)
			mt := spec.MediaTypeDID
			if accept == "application/did+json" {
				mt = spec.MediaTypeDIDJSON
			}
			if res.ResolutionMetadata.ContentType != mt {
				t.Fatalf("actual document type: %s", res.ResolutionMetadata.ContentType)
			}
			if mt == spec.MediaTypeDID && (!bytes.Equal(res.Raw, []byte(absoluteDocument)) || res.Source != nil || res.DocumentMetadata.VersionID != "1") {
				t.Fatal("fallback changed the actual document bytes or metadata")
			}
			calls := drv.Calls()
			if len(calls) != 1 || calls[0].VersionID != "1" {
				t.Fatalf("driver calls: %+v", calls)
			}
			if accept == "text/uri-list" || accept == "image/png" || accept == "application/did;q=0" {
				if calls[0].MediaType != "" {
					t.Fatal("content preference presented as a DID media type")
				}
				wantError(t, direct.Resolve(t.Context(), id, opts), resolution.CodeFeatureNotSupported)
				if len(drv.Calls()) != 1 {
					t.Fatal("strict unsupported preference reached driver")
				}
			} else {
				wantSuccess(t, direct.Resolve(t.Context(), id, opts))
			}
			if !reflect.DeepEqual(opts, before) {
				t.Fatal("caller options mutated")
			}
		})
	}
	for _, tc := range []struct {
		name string
		opts resolution.ResolutionOptions
		code resolution.Code
	}{
		{"invalid accept", resolution.ResolutionOptions{Accept: "text/uri-list;q=2"}, resolution.CodeInvalidOptions},
		{"unknown option", resolution.ResolutionOptions{Accept: "text/uri-list", Extra: map[string]any{"unknown": true}}, resolution.CodeFeatureNotSupported},
		{"modeled shadow", resolution.ResolutionOptions{Accept: "text/uri-list", Extra: map[string]any{"accept": "application/did"}}, resolution.CodeInvalidOptions},
		{"invalid version", resolution.ResolutionOptions{Accept: "text/uri-list", VersionID: "é"}, resolution.CodeInvalidOptions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			drv := absoluteDriver()
			r := intermediate(t, drv, producer.New())
			wantError(t, r.Resolve(t.Context(), testutil.MustDID(testutil.ExampleDID), tc.opts), tc.code)
			if len(drv.Calls()) != 0 {
				t.Fatal("invalid input reached driver")
			}
		})
	}
}

func TestIntermediateDocumentFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		read testutil.ReadFunc
		code resolution.Code
	}{
		{"missing", testutil.Fail(method.ErrNotFound), resolution.CodeNotFound},
		{"unsupported driver", testutil.Fail(method.ErrNotSupported), resolution.CodeFeatureNotSupported},
		{"invalid driver", testutil.Fail(method.ErrInvalidDocument), resolution.CodeInvalidDIDDocument},
		{"driver failure", testutil.Fail(errors.New("failure")), resolution.CodeInternalError},
		{"invalid bytes", testutil.Static(`{"id":false}`, spec.MediaTypeDID, document.Metadata{}), resolution.CodeInvalidDIDDocument},
		{"wrong document", testutil.Static(`{"id":"did:example:other"}`, spec.MediaTypeDID, document.Metadata{}), resolution.CodeInvalidDIDDocument},
		{"invalid metadata", testutil.Static(testutil.ExampleDoc, spec.MediaTypeDID, document.Metadata{VersionID: "é"}), resolution.CodeInvalidDIDDocument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := intermediate(t, fixture(tc.read), producer.New())
			wantError(t, r.ResolveString(t.Context(), testutil.ExampleDID, resolution.ResolutionOptions{Accept: "text/uri-list"}), tc.code)
		})
	}
	t.Run("deactivated", func(t *testing.T) {
		r := intermediate(t, fixture(testutil.Static("", spec.MediaTypeDID, document.Metadata{Deactivated: true})), producer.New())
		res := r.ResolveString(t.Context(), testutil.ExampleDID, resolution.ResolutionOptions{Accept: "text/uri-list"})
		if res.ResolutionMetadata.Error != nil || res.Document != nil || !res.DocumentMetadata.Deactivated {
			t.Fatalf("deactivated result: %+v", res)
		}
	})
	t.Run("producer failure remains an error", func(t *testing.T) {
		r := intermediate(t, absoluteDriver(), failingProducer{})
		wantError(t, r.ResolveString(t.Context(), testutil.ExampleDID, resolution.ResolutionOptions{Accept: "application/did+json"}), resolution.CodeFeatureNotSupported)
		wantError(t, r.ResolveString(t.Context(), testutil.ExampleDID, resolution.ResolutionOptions{Accept: "text/uri-list", ExpandRelativeURLs: true}), resolution.CodeInternalError)
	})
}

func TestIntermediateResolverIsolation(t *testing.T) {
	drv := absoluteDriver()
	direct := newResolver(t, drv)
	retrieval := intermediate(t, drv, producer.New())
	a, err := cache.New(direct, cache.WithTTL(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	b, err := cache.New(retrieval, cache.WithTTL(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	id := testutil.MustDID(testutil.ExampleDID)
	opts := resolution.ResolutionOptions{Accept: "text/uri-list", Extra: map[string]any{"service": "files"}}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			success := b.Resolve(context.Background(), id, opts)
			if success.ResolutionMetadata.Error != nil || success.Document == nil {
				t.Error("dedicated cached resolver failed")
			}
			failure := a.Resolve(context.Background(), id, opts)
			if failure.ResolutionMetadata.Error == nil || failure.ResolutionMetadata.Error.Type != resolution.CodeFeatureNotSupported.TypeURL() || failure.Document != nil || len(failure.Raw) != 0 {
				t.Error("strict cached resolver accepted the content preference")
			}
		}()
	}
	wg.Wait()
	wantError(t, direct.Resolve(t.Context(), id, opts), resolution.CodeFeatureNotSupported)
	wantSuccess(t, retrieval.Resolve(t.Context(), id, opts))
}

func TestStrictDereferencerIsNotReconfigured(t *testing.T) {
	drv := absoluteDriver()
	strict := newResolver(t, drv)
	d, err := dereferencer.New(strict, producer.New())
	if err != nil {
		t.Fatal(err)
	}
	out := d.DereferenceString(t.Context(), testutil.ExampleDID+"?service=files", resolution.DereferenceOptions{Accept: "text/uri-list"})
	if out.DereferencingMetadata.Error == nil || out.DereferencingMetadata.Error.Type != resolution.CodeRepresentationNotSupported.TypeURL() || out.ContentStream != nil || !out.ContentMetadata.IsEmpty() || len(drv.Calls()) != 0 {
		t.Fatalf("strict resolver was changed: %+v", out)
	}
	wantError(t, strict.ResolveString(t.Context(), testutil.ExampleDID, resolution.ResolutionOptions{Accept: "text/uri-list"}), resolution.CodeFeatureNotSupported)
}
