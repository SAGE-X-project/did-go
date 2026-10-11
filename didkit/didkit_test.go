package didkit_test

import (
	"context"
	"testing"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/didkit"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/testutil"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/method/key"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/cache"
	"github.com/sage-x-project/did-go/resolver"
	"github.com/sage-x-project/did-go/spec"
)

// extensionDoc is a DID 1.1 document with a term no base context defines.
const extensionDoc = `{"@context":["https://www.w3.org/ns/did/v1.1"],"id":"did:example:123","undefinedTerm":"x"}`

func exampleDriver() *testutil.Driver {
	return &testutil.Driver{Method: "example", Media: []string{spec.MediaTypeDID},
		Func: testutil.Static(extensionDoc, spec.MediaTypeDID, document.Metadata{})}
}

func resolve(t *testing.T, r resolution.Resolver, s string, opts resolution.ResolutionOptions) resolution.Result {
	t.Helper()
	return r.Resolve(t.Context(), testutil.MustDID(s), opts)
}

func wantCode(t *testing.T, res resolution.Result, code resolution.Code) {
	t.Helper()
	e := res.ResolutionMetadata.Error
	if code == "" {
		if e != nil {
			t.Fatalf("unexpected error %s: %s", e.Type, e.Detail)
		}
		return
	}
	if e == nil || e.Type != code.TypeURL() {
		t.Fatalf("got %v, want %s", e, code)
	}
}

func TestNewResolverWiresTheDefaultResolver(t *testing.T) {
	r, err := didkit.NewResolver(key.New(producer.New()))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(*resolver.DefaultResolver); !ok {
		t.Fatalf("without WithCache the resolver is a *resolver.DefaultResolver, got %T", r)
	}
	t.Run("res10-crd20261001#resolving.1 the wired resolver returns a DID document for did:key", func(t *testing.T) {
		res := resolve(t, r, exampleKeyDID, resolution.ResolutionOptions{})
		wantCode(t, res, "")
		if res.Document == nil || res.Document.ID().String() != exampleKeyDID {
			t.Fatal("no document")
		}
	})
	t.Run("a method without a driver is METHOD_NOT_SUPPORTED", func(t *testing.T) {
		wantCode(t, resolve(t, r, "did:example:123", resolution.ResolutionOptions{}), resolution.CodeMethodNotSupported)
	})
	t.Run("no drivers is a resolver that supports no method", func(t *testing.T) {
		empty, err := didkit.NewResolver()
		if err != nil {
			t.Fatal(err)
		}
		wantCode(t, resolve(t, empty, exampleKeyDID, resolution.ResolutionOptions{}), resolution.CodeMethodNotSupported)
	})
}

func TestNewResolverRejectsBadDrivers(t *testing.T) {
	p := producer.New()
	for name, ms := range map[string][]method.Method{
		"nil driver":     {nil},
		"duplicate name": {key.New(p), key.New(p)},
		"bad name":       {&testutil.Driver{Method: "Key"}},
	} {
		if r, err := didkit.NewResolver(ms...); err == nil || r != nil {
			t.Errorf("%s: accepted", name)
		}
		if r, err := didkit.New(didkit.WithCache()).NewResolver(ms...); err == nil || r != nil {
			t.Errorf("%s: accepted with a cache", name)
		}
	}
}

func TestNewDereferencer(t *testing.T) {
	if d, err := didkit.NewDereferencer(nil); err == nil || d != nil {
		t.Fatal("a nil resolver is an error")
	}
	r, err := didkit.NewResolver(exampleDriver())
	if err != nil {
		t.Fatal(err)
	}
	d, err := didkit.NewDereferencer(r)
	if err != nil {
		t.Fatal(err)
	}
	res := d.DereferenceString(t.Context(), "did:example:123", resolution.DereferenceOptions{})
	if res.DereferencingMetadata.Error != nil {
		t.Fatal(res.DereferencingMetadata.Error)
	}
	if doc, ok := res.ContentStream.(*document.Document); !ok || doc.ID().String() != "did:example:123" {
		t.Fatalf("content %T", res.ContentStream)
	}
}

func TestProducerOptions(t *testing.T) {
	jsonld := resolution.ResolutionOptions{Accept: spec.MediaTypeDIDLDJSON}
	t.Run("did11-cr20260305#production-and-consumption.10 the default producer writes every entry", func(t *testing.T) {
		// The consumer keeps the undefined term so that the producer sees it.
		kit := didkit.New(didkit.WithConsumerOptions(consumer.KeepUndefinedTerms()))
		r, err := kit.NewResolver(exampleDriver())
		if err != nil {
			t.Fatal(err)
		}
		wantCode(t, resolve(t, r, "did:example:123", jsonld), "")
		if first, second := kit.Producer(), kit.Producer(); first == nil || first != second {
			t.Fatal("the Kit has one producer")
		}
	})
	t.Run("core10#production-0.5 producer options reach the resolver's producer", func(t *testing.T) {
		kit := didkit.New(didkit.WithConsumerOptions(consumer.KeepUndefinedTerms()),
			didkit.WithProducerOptions(producer.RejectUndefinedTerms()))
		r, err := kit.NewResolver(exampleDriver())
		if err != nil {
			t.Fatal(err)
		}
		wantCode(t, resolve(t, r, "did:example:123", jsonld), resolution.CodeFeatureNotSupported)
	})
}

func TestConsumerOptions(t *testing.T) {
	kit := didkit.New(didkit.WithConsumerOptions(consumer.WithLimits(16, 0)))
	r, err := kit.NewResolver(exampleDriver())
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, resolve(t, r, "did:example:123", resolution.ResolutionOptions{}), resolution.CodeInvalidDIDDocument)
}

func TestResolverOptions(t *testing.T) {
	opts := resolution.ResolutionOptions{Extra: map[string]any{"example-option": true}}
	r, err := didkit.NewResolver(exampleDriver())
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, resolve(t, r, "did:example:123", opts), resolution.CodeFeatureNotSupported)
	r, err = didkit.New(didkit.WithResolverOptions(resolver.AcceptOptions("example-option"))).NewResolver(exampleDriver())
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, resolve(t, r, "did:example:123", opts), "")
}

func TestDereferencerOptions(t *testing.T) {
	handled := func(_ context.Context, u did.DIDURL, _ resolution.Result, _ resolution.DereferenceOptions) (resolution.DereferenceResult, bool) {
		return resolution.DereferenceResult{ContentStream: []byte(u.Path())}, true
	}
	kit := didkit.New(didkit.WithDereferencerOptions(dereferencer.WithResourceHandler(handled)))
	r, err := kit.NewResolver(exampleDriver())
	if err != nil {
		t.Fatal(err)
	}
	d, err := kit.NewDereferencer(r)
	if err != nil {
		t.Fatal(err)
	}
	res := d.DereferenceString(t.Context(), "did:example:123/files/a", resolution.DereferenceOptions{})
	if b, ok := res.ContentStream.([]byte); !ok || string(b) != "/files/a" {
		t.Fatalf("handler not wired: %#v", res)
	}
}

func TestCache(t *testing.T) {
	drv := exampleDriver()
	kit := didkit.New(nil, didkit.WithCache(cache.WithMaxEntries(4)))
	r, err := kit.NewResolver(drv)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := r.(*cache.Resolver)
	if !ok {
		t.Fatalf("WithCache wraps the resolver, got %T", r)
	}
	for range 3 {
		wantCode(t, resolve(t, r, "did:example:123", resolution.ResolutionOptions{}), "")
	}
	if n := len(drv.Calls()); n != 1 || c.Len() != 1 {
		t.Fatalf("driver read %d times, %d cached", n, c.Len())
	}
	t.Run("noCache bypasses the cache wired by didkit", func(t *testing.T) {
		wantCode(t, resolve(t, r, "did:example:123", resolution.ResolutionOptions{NoCache: true}), "")
		if n := len(drv.Calls()); n != 2 {
			t.Fatalf("driver read %d times", n)
		}
	})
}
