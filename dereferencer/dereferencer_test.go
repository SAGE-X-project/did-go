package dereferencer_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/testutil"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/method/key"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolver"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

const keyDID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

// spy records the options of every resolution and delegates to inner.
type spy struct {
	inner resolution.Resolver
	calls []resolution.ResolutionOptions
}

func (s *spy) Resolve(ctx context.Context, d did.DID, opts resolution.ResolutionOptions) resolution.Result {
	s.calls = append(s.calls, opts)
	return s.inner.Resolve(ctx, d, opts)
}

func newResolver(t *testing.T, ropts []resolver.Option, ms ...method.Method) *resolver.DefaultResolver {
	t.Helper()
	reg, err := method.NewRegistry(ms...)
	if err != nil {
		t.Fatal(err)
	}
	ropts = append(ropts, resolver.ForDereferencing())
	r, err := resolver.New(reg, consumer.New(), producer.New(), ropts...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func fixture(data, mt string, md document.Metadata) *testutil.Driver {
	return &testutil.Driver{Method: "example", Media: []string{mt}, Func: testutil.Static(data, mt, md)}
}

type env struct {
	spy *spy
	drv *testutil.Driver
	d   *dereferencer.Dereferencer
}

func newEnv(t *testing.T, opts ...dereferencer.Option) env {
	t.Helper()
	drv := fixture(testutil.ExampleDoc, spec.MediaTypeDID, document.Metadata{VersionID: "1"})
	s := &spy{inner: newResolver(t, nil, drv, key.New(producer.New()))}
	d, err := dereferencer.New(s, producer.New(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return env{spy: s, drv: drv, d: d}
}

func (e env) deref(t *testing.T, u string, opts resolution.DereferenceOptions) resolution.DereferenceResult {
	t.Helper()
	return e.d.DereferenceString(t.Context(), u, opts)
}

// wantError checks the shape of every failed dereference.
func wantError(t *testing.T, res resolution.DereferenceResult, code resolution.Code) {
	t.Helper()
	e := res.DereferencingMetadata.Error
	if e == nil {
		t.Fatalf("no error, want %s", code)
	}
	if e.Type != code.TypeURL() {
		t.Fatalf("error %s, want %s (%s)", e.Type, code.TypeURL(), e.Detail)
	}
	if res.ContentStream != nil || !res.ContentMetadata.IsEmpty() || res.DereferencingMetadata.ContentType != "" {
		t.Fatal("a failed dereference has empty content and content metadata")
	}
}

func wantSuccess(t *testing.T, res resolution.DereferenceResult) {
	t.Helper()
	if e := res.DereferencingMetadata.Error; e != nil {
		t.Fatalf("unexpected error %v", e)
	}
	if res.ContentStream == nil || res.DereferencingMetadata.ContentType == "" {
		t.Fatal("a successful dereference has content and a contentType")
	}
}

func TestNew(t *testing.T) {
	if _, err := dereferencer.New(nil, producer.New()); err == nil {
		t.Fatal("nil resolver")
	}
	if _, err := dereferencer.New(&spy{}, nil); err == nil {
		t.Fatal("nil producer")
	}
	if _, err := dereferencer.New(&spy{}, producer.New(), nil); err != nil {
		t.Fatal("a nil option is ignored")
	}
}

func TestDereferenceResource(t *testing.T) {
	e := newEnv(t)
	t.Run("res10-crd20261001#dereferencing.1 a did:key DID URL dereferences", func(t *testing.T) {
		res := e.deref(t, keyDID, resolution.DereferenceOptions{})
		wantSuccess(t, res)
		if res.ContentStream.(*document.Document).ID().String() != keyDID {
			t.Fatal("content is the did:key document")
		}
	})
	t.Run(covers("res10-crd20261001#dereferencing.4", "res10-crd20261001#dereferencing.5", "the DID URL is required and the options may be empty"), func(t *testing.T) {
		wantSuccess(t, e.deref(t, testutil.ExampleDID, resolution.DereferenceOptions{}))
		wantError(t, e.d.Dereference(t.Context(), did.DIDURL{}, resolution.DereferenceOptions{}), resolution.CodeInvalidDIDURL)
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-resource.1", "res10-crd20261001#dereferencing-algorithm-resource.2", "res10-crd20261001#dereferencing-algorithm-resource.3", "res10-crd20261001#dereferencing-algorithm-resource.4", "res10-crd20261001#dereferencing-algorithm-resource.5", "a non-conforming DID URL is INVALID_DID_URL"), func(t *testing.T) {
		for _, s := range []string{"", "example:123", "did:example", "did:example:123#a#b", "did:example:123?service", "did:example:123?a=1&a=2", "did:example:123?versionTime=2021"} {
			wantError(t, e.deref(t, s, resolution.DereferenceOptions{}), resolution.CodeInvalidDIDURL)
		}
		rel, _ := did.ParseReference("#key-1")
		wantError(t, e.d.Dereference(t.Context(), rel, resolution.DereferenceOptions{}), resolution.CodeInvalidDIDURL)
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-resource.6", "res10-crd20261001#dereferencing-algorithm-resource.7", "res10-crd20261001#dereferencing-algorithm-resource.8", "dereferencing options and DID parameters are resolution options"), func(t *testing.T) {
		drv := fixture(testutil.ExampleDoc, spec.MediaTypeDID, document.Metadata{VersionID: "1"})
		e := env{spy: &spy{inner: newResolver(t, []resolver.Option{resolver.AcceptOptions("ext")}, drv)}, drv: drv}
		e.d, _ = dereferencer.New(e.spy, producer.New())
		res := e.deref(t, testutil.ExampleDID+"?service=files&versionId=1&versionTime=2021-05-01T00:00:00Z&relativeRef=%2Fx",
			resolution.DereferenceOptions{VerificationRelationship: "authentication", Extra: map[string]any{"ext": true}})
		if res.DereferencingMetadata.Error == nil || res.DereferencingMetadata.Error.Type != resolution.CodeInvalidVerificationMethod.TypeURL() {
			t.Fatalf("a service result is not a verification method: %v", res.DereferencingMetadata.Error)
		}
		got := e.spy.calls[0]
		if got.VersionID != "1" || got.VersionTime == nil || !got.VersionTime.Equal(time.Date(2021, 5, 1, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("versionId and versionTime: %+v", got)
		}
		want := map[string]any{"service": "files", "relativeRef": "/x", "verificationRelationship": "authentication", "ext": true}
		if !reflect.DeepEqual(got.Extra, want) {
			t.Fatalf("Extra %v", got.Extra)
		}
		if c := e.drv.Calls(); c[0].VersionID != "1" {
			t.Fatal("the driver reads the requested version")
		}
	})
	t.Run("every accept value reaches the nested resolution unchanged", func(t *testing.T) {
		e := newEnv(t)
		e.deref(t, testutil.ExampleDID, resolution.DereferenceOptions{Accept: "application/did+json"})
		e.deref(t, testutil.ExampleDID+"?service=files", resolution.DereferenceOptions{Accept: dereferencer.MediaTypeURIList})
		if e.spy.calls[0].Accept != "application/did+json" || e.spy.calls[1].Accept != dereferencer.MediaTypeURIList {
			t.Fatalf("accept passed: %q %q", e.spy.calls[0].Accept, e.spy.calls[1].Accept)
		}
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-resource.9", "res10-crd20261001#dereferencing-algorithm-resource.10", "res10-crd20261001#dereferencing-algorithm-resource.11", "res10-crd20261001#dereferencing-algorithm-resource.12", "a DID that does not exist is NOT_FOUND"), func(t *testing.T) {
		drv := &testutil.Driver{Method: "example", Func: testutil.Fail(method.ErrNotFound)}
		d, _ := dereferencer.New(newResolver(t, nil, drv), producer.New())
		wantError(t, d.DereferenceString(t.Context(), testutil.ExampleDID+"#key-1", resolution.DereferenceOptions{}), resolution.CodeNotFound)
	})
	t.Run("other resolution errors are returned", func(t *testing.T) {
		wantError(t, e.deref(t, "did:web:example.com", resolution.DereferenceOptions{}), resolution.CodeMethodNotSupported)
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-resource.13", "res10-crd20261001#dereferencing-algorithm-resource.15", "res10-crd20261001#dereferencing-algorithm-resource.16", "res10-crd20261001#dereferencing-algorithm-resource.17", "res10-crd20261001#dereferencing-algorithm-resource.18", "res10-crd20261001#dereferencing.8", "res10-crd20261001#dereferencing.12", "a DID URL without path and query is the resolved document with its metadata"), func(t *testing.T) {
		res := e.deref(t, testutil.ExampleDID, resolution.DereferenceOptions{})
		wantSuccess(t, res)
		doc := res.ContentStream.(*document.Document)
		if doc.ID().String() != testutil.ExampleDID || len(doc.Services()) != 3 {
			t.Fatal("the resolved document")
		}
		if res.ContentMetadata.VersionID != "1" || res.DereferencingMetadata.ContentType != spec.MediaTypeDID {
			t.Fatal("the resolved document metadata and its contentType")
		}
	})
	t.Run("a versionId or versionTime query selects the resolved version", func(t *testing.T) {
		wantSuccess(t, e.deref(t, testutil.ExampleDID+"?versionId=1", resolution.DereferenceOptions{}))
	})
	t.Run(covers("res10-crd20261001#did-url-dereferencing-options.3", "core10#did-url-dereferencing-options.3", "accept determines the contentType"), func(t *testing.T) {
		for _, mt := range representation.CoreMediaTypes() {
			res := e.deref(t, testutil.MustDID(keyDID).String(), resolution.DereferenceOptions{Accept: mt})
			wantSuccess(t, res)
			if res.DereferencingMetadata.ContentType != mt {
				t.Errorf("accept %s: contentType %s", mt, res.DereferencingMetadata.ContentType)
			}
		}
	})
	t.Run("an unsatisfiable accept is REPRESENTATION_NOT_SUPPORTED", func(t *testing.T) {
		wantError(t, e.deref(t, testutil.ExampleDID, resolution.DereferenceOptions{Accept: "image/png"}), resolution.CodeRepresentationNotSupported)
		noServiceID := fixture(`{"id":"did:example:123","service":[{"type":"A","serviceEndpoint":"https://a.example/"}]}`, spec.MediaTypeDID, document.Metadata{})
		d, _ := dereferencer.New(newResolver(t, nil, noServiceID), producer.New())
		res := d.DereferenceString(t.Context(), testutil.ExampleDID, resolution.DereferenceOptions{Accept: spec.MediaTypeDIDJSON})
		wantError(t, res, resolution.CodeRepresentationNotSupported)
	})
	t.Run(covers("res10-crd20261001#dereferencing.6", "res10-crd20261001#dereferencing.7", "res10-crd20261001#dereferencing.10", "res10-crd20261001#dereferencing.13", "res10-crd20261001#did-url-dereferencing-metadata.4", "an error result has an error, no content and empty content metadata"), func(t *testing.T) {
		res := e.deref(t, testutil.ExampleDID+"/nowhere", resolution.DereferenceOptions{})
		wantError(t, res, resolution.CodeNotFound)
		if res.DereferencingMetadata.Error.Title == "" {
			t.Fatal("the error object is not empty")
		}
	})
	t.Run("invalid options are INVALID_OPTIONS", func(t *testing.T) {
		wantError(t, e.deref(t, testutil.ExampleDID, resolution.DereferenceOptions{VerificationRelationship: "é"}), resolution.CodeInvalidOptions)
	})
	t.Run("a deactivated DID has no content and deactivated content metadata", func(t *testing.T) {
		drv := fixture(testutil.ExampleDoc, spec.MediaTypeDID, document.Metadata{Deactivated: true})
		d, _ := dereferencer.New(newResolver(t, nil, drv), producer.New())
		res := d.DereferenceString(t.Context(), testutil.ExampleDID+"#key-1", resolution.DereferenceOptions{})
		if res.DereferencingMetadata.Error != nil || res.ContentStream != nil || !res.ContentMetadata.Deactivated {
			t.Fatal("deactivated")
		}
	})
}

func TestDIDParameters(t *testing.T) {
	e := newEnv(t)
	t.Run(covers("core10#did-parameters.1", "res10-crd20261001#did-parameters.2", "support for a DID parameter is optional: an unsupported one is FEATURE_NOT_SUPPORTED"), func(t *testing.T) {
		wantError(t, e.deref(t, testutil.ExampleDID+"?hl=zQm", resolution.DereferenceOptions{}), resolution.CodeFeatureNotSupported)
	})
	t.Run(covers("core10#did-parameters.2", "core10#did-parameters.3", "core10#did-parameters.4", "res10-crd20261001#did-parameters.1", "parameter values are ASCII, percent-encoded where needed"), func(t *testing.T) {
		for _, s := range []string{"?service=fïles", "?relativeRef=/a b", "?versionId=ü", "?relativeRef=%zz"} {
			wantError(t, e.deref(t, testutil.ExampleDID+s, resolution.DereferenceOptions{}), resolution.CodeInvalidDIDURL)
		}
		res := e.deref(t, testutil.ExampleDID+"?service=files&relativeRef=%2Fres%20ume.pdf", resolution.DereferenceOptions{Accept: dereferencer.MediaTypeURIList})
		wantSuccess(t, res)
		if res.ContentStream.([]string)[0] != "https://files.example/res%20ume.pdf" {
			t.Fatal(res.ContentStream)
		}
	})
	t.Run(covers("core10#did-parameters.5", "core10#did-parameters.6", "res10-crd20261001#did-parameters.3", "versionTime is a UTC datetime without sub-second precision"), func(t *testing.T) {
		wantSuccess(t, e.deref(t, testutil.ExampleDID+"?versionTime=2021-05-01T00:00:00Z", resolution.DereferenceOptions{}))
		for _, v := range []string{"2021-05-01T00:00:00.5Z", "2021-05-01T01:00:00%2B01:00", "2021-05-01"} {
			wantError(t, e.deref(t, testutil.ExampleDID+"?versionTime="+v, resolution.DereferenceOptions{}), resolution.CodeInvalidDIDURL)
		}
	})
}

func TestServices(t *testing.T) {
	e := newEnv(t)
	uriList := resolution.DereferenceOptions{Accept: dereferencer.MediaTypeURIList}
	ids := func(res resolution.DereferenceResult) []string {
		var out []string
		for _, s := range res.ContentStream.(*document.Document).Services() {
			out = append(out, s.ID)
		}
		return out
	}
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-resource.19", "res10-crd20261001#dereferencing-algorithm-resource.20", "res10-crd20261001#dereferencing-algorithm-resource.21", "the service parameter selects by id"), func(t *testing.T) {
		res := e.deref(t, testutil.ExampleDID+"?service=messages", resolution.DereferenceOptions{})
		wantSuccess(t, res)
		if got := ids(res); !reflect.DeepEqual(got, []string{"#messages"}) {
			t.Fatal(got)
		}
		wantError(t, e.deref(t, testutil.ExampleDID+"?service=nothing", resolution.DereferenceOptions{}), resolution.CodeNotFound)
	})
	t.Run("res10-crd20261001#dereferencing-algorithm-resource.22 relative and absolute ids are compared after RFC 3986 reference resolution", func(t *testing.T) {
		for _, q := range []string{"?service=%23files", "?service=did:example:123%23files", "?service=files", "?service=%23messages"} {
			res := e.deref(t, testutil.ExampleDID+q, resolution.DereferenceOptions{})
			wantSuccess(t, res)
			if len(ids(res)) != 1 {
				t.Errorf("%s selects %v", q, ids(res))
			}
		}
		res := e.deref(t, testutil.ExampleDID+"?service=did:example:123%23messages", resolution.DereferenceOptions{})
		if got := ids(res); !reflect.DeepEqual(got, []string{"#messages"}) {
			t.Fatalf("an absolute parameter matches a relative id: %v", got)
		}
	})
	t.Run("res10-crd20261001#dereferencing-algorithm-resource.23 the serviceType parameter selects by type", func(t *testing.T) {
		res := e.deref(t, testutil.ExampleDID+"?serviceType=Storage", resolution.DereferenceOptions{})
		if got := ids(res); !reflect.DeepEqual(got, []string{"did:example:123#files"}) {
			t.Fatal(got)
		}
		wantError(t, e.deref(t, testutil.ExampleDID+"?service=messages&serviceType=Storage", resolution.DereferenceOptions{}), resolution.CodeNotFound)
		res = e.deref(t, testutil.ExampleDID+"?service=files&serviceType=FileService", resolution.DereferenceOptions{})
		if got := ids(res); len(got) != 1 {
			t.Fatal("both parameters must match")
		}
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-resource.24", "res10-crd20261001#dereferencing-algorithm-resource.25", "res10-crd20261001#dereferencing-algorithm-resource.26", "res10-crd20261001#dereferencing-algorithm-resource.27", "res10-crd20261001#dereferencing-algorithm-resource.28", "endpoint URLs: map endpoints are skipped, strings and string set items are added"), func(t *testing.T) {
		res := e.deref(t, testutil.ExampleDID+"?service=files&relativeRef=x", uriList)
		want := []string{"https://files.example/a/x", "https://files.example/x"}
		if !reflect.DeepEqual(res.ContentStream, want) {
			t.Fatalf("got %v", res.ContentStream)
		}
		wantError(t, e.deref(t, testutil.ExampleDID+"?service=map&relativeRef=x", uriList), resolution.CodeNotFound)
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-resource.29", "res10-crd20261001#dereferencing-algorithm-resource.30", "res10-crd20261001#dereferencing-algorithm-resource.31", "res10-crd20261001#dereferencing-algorithm-resource.32", "relativeRef is resolved against each endpoint URL with RFC 3986 §5"), func(t *testing.T) {
		res := e.deref(t, testutil.ExampleDID+"?service=messages&relativeRef=%2Fsome%2Fpath%3Fquery", uriList)
		if !reflect.DeepEqual(res.ContentStream, []string{"https://example.com/some/path?query"}) {
			t.Fatalf("an absolute-path reference replaces the base path (docs/07 caveat 6): %v", res.ContentStream)
		}
		res = e.deref(t, testutil.ExampleDID+"?service=messages&relativeRef=..%2Fup%3Fq", uriList)
		if !reflect.DeepEqual(res.ContentStream, []string{"https://example.com/up?q"}) {
			t.Fatalf("dot segments: %v", res.ContentStream)
		}
		wantError(t, e.deref(t, testutil.ExampleDID+"?service=messages&relativeRef=%3A%2F%2F", uriList), resolution.CodeInvalidDIDURL)
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-resource.33", "res10-crd20261001#dereferencing-algorithm-resource.34", "res10-crd20261001#dereferencing-algorithm-resource.35", "res10-crd20261001#dereferencing-algorithm-resource.36", "res10-crd20261001#dereferencing-algorithm-resource.37", "res10-crd20261001#dereferencing-algorithm-resource.38", "without accept, or with a DID document type, the document keeps only the selected services"), func(t *testing.T) {
		for _, accept := range []string{"", spec.MediaTypeDID, "*/*"} {
			res := e.deref(t, testutil.ExampleDID+"?serviceType=FileService", resolution.DereferenceOptions{Accept: accept})
			wantSuccess(t, res)
			doc := res.ContentStream.(*document.Document)
			if len(doc.Services()) != 1 || len(doc.VerificationMethods()) != 2 || len(doc.Relationship(vm.Authentication)) != 2 {
				t.Fatalf("accept %q: reduced document", accept)
			}
			if _, ok := doc.Extensions().Get("linkedResource"); !ok {
				t.Fatal("extensions are kept")
			}
			if res.ContentMetadata.VersionID != "1" {
				t.Fatal("content metadata is the resolved document metadata")
			}
		}
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-resource.39", "res10-crd20261001#dereferencing-algorithm-resource.40", "res10-crd20261001#dereferencing-algorithm-resource.41", "res10-crd20261001#dereferencing-algorithm-resource.42", "res10-crd20261001#dereferencing-algorithm-resource.43", "accept text/uri-list returns the endpoint URLs"), func(t *testing.T) {
		res := e.deref(t, testutil.ExampleDID+"?service=messages", uriList)
		wantSuccess(t, res)
		if !reflect.DeepEqual(res.ContentStream, []string{"https://example.com/messages/8377464"}) {
			t.Fatal(res.ContentStream)
		}
		if res.DereferencingMetadata.ContentType != dereferencer.MediaTypeURIList || res.ContentMetadata.Extra["contentType"] != dereferencer.MediaTypeURIList {
			t.Fatal("contentType in both places (docs/07 caveat 8)")
		}
		res = e.deref(t, testutil.ExampleDID+"?service=files", uriList)
		if !reflect.DeepEqual(res.ContentStream, []string{"https://files.example/a/b", "https://files.example/c#top"}) {
			t.Fatal(res.ContentStream)
		}
		wantError(t, e.deref(t, testutil.ExampleDID+"?service=map", uriList), resolution.CodeNotFound)
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-resource.44", "res10-crd20261001#dereferencing-algorithm-resource.45", "res10-crd20261001#dereferencing-algorithm-resource.46", "res10-crd20261001#dereferencing-algorithm-resource.47", "any other accept is REPRESENTATION_NOT_SUPPORTED"), func(t *testing.T) {
		wantError(t, e.deref(t, testutil.ExampleDID+"?service=files", resolution.DereferenceOptions{Accept: "image/png"}), resolution.CodeRepresentationNotSupported)
	})
}

func TestPathAndQuery(t *testing.T) {
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-resource.48", "res10-crd20261001#dereferencing-algorithm-resource.56", "res10-crd20261001#dereferencing-algorithm-resource.57", "res10-crd20261001#dereferencing-algorithm-resource.58", "res10-crd20261001#dereferencing-algorithm-resource.59", "a path nobody dereferences is NOT_FOUND"), func(t *testing.T) {
		wantError(t, newEnv(t).deref(t, testutil.ExampleDID+"/custom/path", resolution.DereferenceOptions{}), resolution.CodeNotFound)
	})
	whois := func(_ context.Context, u did.DIDURL, res resolution.Result, _ resolution.DereferenceOptions) (resolution.DereferenceResult, bool) {
		if u.Path() != "/whois" && u.Query() != "transformKey=JsonWebKey" {
			return resolution.DereferenceResult{}, false
		}
		return resolution.DereferenceResult{ContentStream: []byte(res.Document.ID().String()),
			DereferencingMetadata: resolution.DereferencingMetadata{ContentType: "text/plain"}}, true
	}
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-resource.49", "res10-crd20261001#dereferencing-algorithm-resource.51", "res10-crd20261001#dereferencing-algorithm-resource.55", "a method, an extension or the client may dereference a path"), func(t *testing.T) {
		e := newEnv(t, dereferencer.WithResourceHandler(whois))
		res := e.deref(t, testutil.ExampleDID+"/whois", resolution.DereferenceOptions{})
		wantSuccess(t, res)
		if string(res.ContentStream.([]byte)) != testutil.ExampleDID {
			t.Fatal("handler content")
		}
		wantError(t, e.deref(t, testutil.ExampleDID+"/other", resolution.DereferenceOptions{}), resolution.CodeNotFound)
	})
	t.Run("res10-crd20261001#dereferencing-algorithm-resource.53 an extension may dereference a query", func(t *testing.T) {
		drv := fixture(testutil.ExampleDoc, spec.MediaTypeDID, document.Metadata{})
		r := newResolver(t, []resolver.Option{resolver.AcceptOptions("transformKey")}, drv)
		d, _ := dereferencer.New(r, producer.New(), dereferencer.WithResourceHandler(whois))
		wantSuccess(t, d.DereferenceString(t.Context(), testutil.ExampleDID+"?transformKey=JsonWebKey", resolution.DereferenceOptions{}))
	})
}

func TestFragment(t *testing.T) {
	e := newEnv(t)
	auth := resolution.DereferenceOptions{VerificationRelationship: "authentication"}
	t.Run(covers("res10-crd20261001#dereferencing.3", "res10-crd20261001#dereferencing.9", "the complete DID URL with its fragment dereferences to a verification method"), func(t *testing.T) {
		res := e.deref(t, testutil.ExampleDID+"#key-2", resolution.DereferenceOptions{})
		wantSuccess(t, res)
		if m := res.ContentStream.(vm.Method); m.ID.String() != "did:example:123#key-2" {
			t.Fatal(m.ID)
		}
		if _, isDoc := e.deref(t, testutil.ExampleDID, resolution.DereferenceOptions{}).ContentStream.(*document.Document); !isDoc {
			t.Fatal("without the fragment the content is the document")
		}
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-fragment.1", "res10-crd20261001#dereferencing-algorithm-fragment.2", "res10-crd20261001#dereferencing-algorithm-fragment.3", "res10-crd20261001#dereferencing-algorithm-fragment.6", "an authorized verification method is returned"), func(t *testing.T) {
		for _, frag := range []string{"#key-1", "#key-3"} {
			res := e.deref(t, testutil.ExampleDID+frag, auth)
			wantSuccess(t, res)
			if m := res.ContentStream.(vm.Method); m.ID.String() != "did:example:123"+frag && m.ID.String() != frag {
				t.Fatal(m.ID)
			}
			if res.DereferencingMetadata.ContentType != "application/ld+json" {
				t.Fatal(res.DereferencingMetadata.ContentType)
			}
		}
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-fragment.4", "res10-crd20261001#did-url-dereferencing-options.5", "a fragment that is not a conforming verification method is INVALID_VERIFICATION_METHOD"), func(t *testing.T) {
		for _, u := range []string{testutil.ExampleDID + "#missing", testutil.ExampleDID + "#messages", testutil.ExampleDID} {
			wantError(t, e.deref(t, u, auth), resolution.CodeInvalidVerificationMethod)
		}
		wantError(t, e.deref(t, testutil.ExampleDID+"?service=messages#x", resolution.DereferenceOptions{VerificationRelationship: "authentication", Accept: dereferencer.MediaTypeURIList}),
			resolution.CodeInvalidVerificationMethod)
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-fragment.5", "res10-crd20261001#did-url-dereferencing-options.5", "a method the relationship does not authorize is INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD"), func(t *testing.T) {
		wantError(t, e.deref(t, testutil.ExampleDID+"#key-1", resolution.DereferenceOptions{VerificationRelationship: "assertionMethod"}),
			resolution.CodeInvalidRelationshipForVerificationMethod)
		wantError(t, e.deref(t, testutil.ExampleDID+"#key-1", resolution.DereferenceOptions{VerificationRelationship: "noSuchRelationship"}),
			resolution.CodeInvalidRelationshipForVerificationMethod)
		res := e.deref(t, testutil.ExampleDID+"#key-2", resolution.DereferenceOptions{VerificationRelationship: "assertionMethod"})
		wantSuccess(t, res)
	})
	t.Run("an empty fragment is not a verification method URL", func(t *testing.T) {
		wantError(t, e.deref(t, testutil.ExampleDID+"#", auth), resolution.CodeInvalidVerificationMethodURL)
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-fragment.7", "res10-crd20261001#dereferencing-algorithm-fragment.9", "res10-crd20261001#dereferencing-algorithm-fragment.10", "res10-crd20261001#dereferencing-algorithm-fragment.11", "a service endpoint URL inherits the fragment"), func(t *testing.T) {
		res := e.deref(t, testutil.ExampleDID+"?service=messages&relativeRef=%2Fsome%2Fpath%3Fquery#frag", resolution.DereferenceOptions{Accept: dereferencer.MediaTypeURIList})
		wantSuccess(t, res)
		if !reflect.DeepEqual(res.ContentStream, []string{"https://example.com/some/path?query#frag"}) {
			t.Fatal(res.ContentStream)
		}
	})
	t.Run("res10-crd20261001#dereferencing-algorithm-fragment.8 an endpoint URL that has a fragment raises an error", func(t *testing.T) {
		wantError(t, e.deref(t, testutil.ExampleDID+"?service=files#frag", resolution.DereferenceOptions{Accept: dereferencer.MediaTypeURIList}), resolution.CodeInvalidDIDURL)
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-fragment.12", "res10-crd20261001#dereferencing-algorithm-fragment.13", "cid10#fragment-resolution.1", "cid10#fragment-resolution.2", "cid10#fragment-resolution.3", "cid10#fragment-resolution.4", "cid10#fragment-resolution.5", "cid10#fragment-resolution.6", "other fragments are resolved in the document by CID Fragment Resolution"), func(t *testing.T) {
		cases := map[string]func(any) bool{
			"#key-1":    func(c any) bool { m, ok := c.(vm.Method); return ok && m.ID.String() == "#key-1" },
			"#key-2":    func(c any) bool { m, ok := c.(vm.Method); return ok && m.ID.String() == "did:example:123#key-2" },
			"#key-3":    func(c any) bool { m, ok := c.(vm.Method); return ok && m.ID.String() == "#key-3" },
			"#files":    func(c any) bool { s, ok := c.(vm.Service); return ok && s.ID == "did:example:123#files" },
			"#messages": func(c any) bool { s, ok := c.(vm.Service); return ok && s.ID == "#messages" },
			"#res-1":    func(c any) bool { m, ok := c.(document.Map); return ok && m.Len() == 2 },
			"#res-2": func(c any) bool {
				m, ok := c.(document.Map)
				v, _ := m.Get("name")
				return ok && v == document.String("two")
			},
		}
		for frag, check := range cases {
			res := e.deref(t, testutil.ExampleDID+frag, resolution.DereferenceOptions{})
			wantSuccess(t, res)
			if !check(res.ContentStream) || res.DereferencingMetadata.ContentType != "application/ld+json" {
				t.Errorf("%s: %#v", frag, res.ContentStream)
			}
			if !res.ContentMetadata.IsEmpty() {
				t.Errorf("%s: a fragment has its own (empty) content metadata", frag)
			}
		}
		for _, frag := range []string{"#missing", "#plain"} {
			wantError(t, e.deref(t, testutil.ExampleDID+frag, resolution.DereferenceOptions{}), resolution.CodeNotFound)
		}
	})
	t.Run(covers("res10-crd20261001#dereferencing-algorithm-resource.14", "the fragment is separated and dereferenced in the reduced document"), func(t *testing.T) {
		wantSuccess(t, e.deref(t, testutil.ExampleDID+"?service=files#files", resolution.DereferenceOptions{}))
		wantError(t, e.deref(t, testutil.ExampleDID+"?service=files#messages", resolution.DereferenceOptions{}), resolution.CodeNotFound)
	})
	t.Run("a fragment of application/did+json is application/json", func(t *testing.T) {
		drv := fixture(`{"id":"did:example:123","verificationMethod":[{"id":"did:example:123#k","type":"Multikey","controller":"did:example:123"}]}`,
			spec.MediaTypeDIDJSON, document.Metadata{})
		d, _ := dereferencer.New(newResolver(t, nil, drv), producer.New())
		res := d.DereferenceString(t.Context(), testutil.ExampleDID+"#k", resolution.DereferenceOptions{})
		wantSuccess(t, res)
		if res.DereferencingMetadata.ContentType != "application/json" {
			t.Fatal(res.DereferencingMetadata.ContentType)
		}
	})
}

func TestSerializable(t *testing.T) {
	e := newEnv(t)
	t.Run(covers("res10-crd20261001#dereferencing.2", "res10-crd20261001#dereferencing.11", "res10-crd20261001#did-url-dereferencing-metadata.2", "inputs and outputs other than contentStream serialize to JSON"), func(t *testing.T) {
		opts := resolution.DereferenceOptions{Accept: dereferencer.MediaTypeURIList, VerificationRelationship: "authentication", Extra: map[string]any{"x": "y"}}
		if _, err := json.Marshal(opts); err != nil {
			t.Fatal(err)
		}
		for _, u := range []string{testutil.ExampleDID, testutil.ExampleDID + "#key-1", testutil.ExampleDID + "?service=files", testutil.ExampleDID + "/x"} {
			for _, o := range []resolution.DereferenceOptions{{}, {Accept: dereferencer.MediaTypeURIList}} {
				res := e.deref(t, u, o)
				if res.DereferencingMetadata.Error == nil && res.DereferencingMetadata.ContentType == "" {
					t.Errorf("%s: a successful dereference expresses contentType", u)
				}
				if _, err := json.Marshal(res.DereferencingMetadata); err != nil {
					t.Error(err)
				}
				if _, err := json.Marshal(res.ContentMetadata); err != nil {
					t.Error(err)
				}
			}
		}
	})
}

// covers joins the statement ids a subtest checks and its description into
// the subtest name. Each id is its own string literal, which is how the
// coverage check (conformance/coverage_test.go) finds it.
func covers(parts ...string) string { return strings.Join(parts, " ") }
