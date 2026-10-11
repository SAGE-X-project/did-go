package compat_test

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"regexp"
	"strings"
	"testing"

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
	"github.com/sage-x-project/did-go/resolution/compat"
	"github.com/sage-x-project/did-go/resolver"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

const keyDID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

var keyword = regexp.MustCompile(`^[a-z][A-Za-z0-9]*$`)

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

type spyResolver struct {
	inner resolution.Resolver
	last  resolution.ResolutionOptions
}

func (s *spyResolver) Resolve(ctx context.Context, d did.DID, opts resolution.ResolutionOptions) resolution.Result {
	s.last = opts
	return s.inner.Resolve(ctx, d, opts)
}

type stubDereferencer struct {
	res  resolution.DereferenceResult
	last did.DIDURL
}

func (s *stubDereferencer) Dereference(_ context.Context, u did.DIDURL, _ resolution.DereferenceOptions) resolution.DereferenceResult {
	s.last = u
	return s.res
}

func core(t *testing.T, ms ...method.Method) *resolver.DefaultResolver {
	t.Helper()
	reg, err := method.NewRegistry(ms...)
	if err != nil {
		t.Fatal(err)
	}
	r, err := resolver.New(reg, consumer.New(), producer.New())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func exampleDriver(md document.Metadata) *testutil.Driver {
	return &testutil.Driver{Method: "example", Media: []string{spec.MediaTypeDID},
		Func: testutil.Static(testutil.ExampleDocV10, spec.MediaTypeDIDLDJSON, md)}
}

func numbers() document.Metadata {
	return document.Metadata{VersionID: "1", Extra: map[string]any{
		"height": json.Number("12"), "nested": map[string]any{"n": 1.5, "list": []any{int64(-3), uint8(4), "s", true, nil}},
		"f32": float32(0.25), "big": uint64(math.MaxUint64), "i": 7,
	}, Proof: []map[string]any{{"nonce": 42}}}
}

func TestResolve(t *testing.T) {
	ctx := t.Context()
	spy := &spyResolver{inner: core(t, key.New(producer.New()), exampleDriver(numbers()))}
	r := &compat.V10Resolver{Inner: spy}
	t.Run(covers("core10#did-resolution.2", "core10#did-resolution.6", "core10#did-resolution.7", "core10#did-resolution.11", "resolve returns the data model whose id is the DID and a metadata structure"), func(t *testing.T) {
		md, doc, dm := r.Resolve(ctx, testutil.MustDID(keyDID), resolution.ResolutionOptions{})
		if md.Error != "" || doc == nil || doc.ID().String() != keyDID {
			t.Fatalf("%+v", md)
		}
		if _, err := json.Marshal(dm); err != nil {
			t.Fatal(err)
		}
	})
	t.Run(covers("core10#did-resolution-metadata.2", "core10#did-resolution-options.3", "resolve has no contentType and does not pass accept"), func(t *testing.T) {
		md, doc, _ := r.Resolve(ctx, testutil.MustDID(keyDID), resolution.ResolutionOptions{Accept: spec.MediaTypeDIDJSON})
		if doc == nil || md.ContentType != "" || spy.last.Accept != "" {
			t.Fatal("accept must not be used with resolve")
		}
		if len(md.Warnings) != 1 || md.Warnings[0] != compat.WarningAcceptIgnored {
			t.Fatal("ignoring accept is warned")
		}
		if b, _ := json.Marshal(md); string(b) != "{}" {
			t.Fatalf("metadata %s", b)
		}
	})
	t.Run(covers("core10#did-resolution.1", "core10#did-resolution.3", "core10#did-resolution.5", "core10#did-resolution.8", "core10#did-resolution.12", "core10#did-resolution-metadata.5", "core10#did-resolution-metadata.6", "an error is a keyword, the document is empty and the metadata empty"), func(t *testing.T) {
		for _, c := range []struct {
			d    did.DID
			want string
		}{{did.DID{}, compat.ErrInvalidDID}, {testutil.MustDID("did:web:x.example"), compat.ErrMethodNotSupported}, {testutil.MustDID("did:key:abc"), compat.ErrInvalidDID}} {
			md, doc, dm := r.Resolve(ctx, c.d, resolution.ResolutionOptions{})
			if md.Error != c.want || doc != nil || !dm.IsEmpty() || !keyword.MatchString(md.Error) {
				t.Errorf("%v: %+v", c.d, md)
			}
			if b, _ := json.Marshal(md); string(b) != `{"error":"`+c.want+`"}` {
				t.Errorf("non-empty metadata with error: %s", b)
			}
		}
	})
	t.Run("numbers in metadata become strings for DID Core 1.0", func(t *testing.T) {
		_, _, dm := r.Resolve(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{})
		if err := dm.Check(testutil.MustDID(testutil.ExampleDID), spec.V10); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"height": "12", "nested": map[string]any{"n": "1.5", "list": []any{"-3", "4", "s", true, nil}},
			"f32": "0.25", "big": "18446744073709551615", "i": "7"}
		if !reflect.DeepEqual(dm.Extra, want) || dm.Proof[0]["nonce"] != "42" {
			t.Fatalf("%#v %#v", dm.Extra, dm.Proof)
		}
	})
	t.Run("hl is accepted and not forwarded", func(t *testing.T) {
		md, doc, _ := r.Resolve(ctx, testutil.MustDID(keyDID), resolution.ResolutionOptions{Extra: map[string]any{"hl": "zQm", "service": "x"}})
		if doc == nil || md.Error != "" || len(md.Warnings) != 1 {
			t.Fatalf("%+v", md)
		}
		if _, ok := spy.last.Extra["hl"]; ok || spy.last.Extra["service"] != "x" {
			t.Fatal("hl forwarded")
		}
	})
}

func TestResolveRepresentation(t *testing.T) {
	ctx := t.Context()
	r := &compat.V10Resolver{Inner: core(t, key.New(producer.New()), exampleDriver(document.Metadata{}))}
	t.Run(covers("core10#did-resolution.4", "core10#did-resolution.9", "core10#did-resolution-metadata.1", "core10#did-resolution-metadata.3", "core10#did-resolution-metadata.4", "a successful resolveRepresentation returns a DID Core 1.0 stream and its contentType"), func(t *testing.T) {
		md, stream, _ := r.ResolveRepresentation(ctx, testutil.MustDID(keyDID), resolution.ResolutionOptions{})
		if md.Error != "" || md.ContentType != spec.MediaTypeDIDLDJSON {
			t.Fatalf("%+v", md)
		}
		d, _, err := consumer.New().Consume(stream, md.ContentType, representation.ConsumeOptions{Require: spec.V10})
		if err != nil || d.ID().String() != keyDID {
			t.Fatalf("the stream parses with contentType as DID Core 1.0: %v", err)
		}
		if b, _ := json.Marshal(md); string(b) != `{"contentType":"application/did+ld+json"}` {
			t.Fatal(string(b))
		}
	})
	t.Run("core10#did-resolution-options.3 accept is used by resolveRepresentation", func(t *testing.T) {
		md, stream, _ := r.ResolveRepresentation(ctx, testutil.MustDID(keyDID), resolution.ResolutionOptions{Accept: spec.MediaTypeDIDJSON})
		if md.ContentType != spec.MediaTypeDIDJSON || len(stream) == 0 {
			t.Fatal(md)
		}
		md, _, _ = r.ResolveRepresentation(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{Accept: spec.MediaTypeDIDJSON})
		if md.ContentType != spec.MediaTypeDIDJSON {
			t.Fatal("the core transcodes to the accepted representation")
		}
	})
	t.Run(covers("core10#did-resolution.10", "core10#did-resolution.12", "an unsatisfiable accept is representationNotSupported with an empty stream"), func(t *testing.T) {
		md, stream, dm := r.ResolveRepresentation(ctx, testutil.MustDID(keyDID), resolution.ResolutionOptions{Accept: "text/html"})
		if md.Error != compat.ErrRepresentationNotSupported || stream != nil || !dm.IsEmpty() || md.ContentType != "" {
			t.Fatalf("%+v", md)
		}
		md, _, _ = r.ResolveRepresentation(ctx, testutil.MustDID(keyDID), resolution.ResolutionOptions{VersionID: "1"})
		if md.Error != compat.ErrFeatureNotSupported {
			t.Fatal("other FEATURE_NOT_SUPPORTED errors stay featureNotSupported")
		}
	})
	t.Run("DEV-V10-1 a deactivated DID returns no stream and no contentType", func(t *testing.T) {
		r := &compat.V10Resolver{Inner: core(t, exampleDriver(document.Metadata{Deactivated: true}))}
		md, stream, dm := r.ResolveRepresentation(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{})
		if md.Error != "" || md.ContentType != "" || stream != nil || !dm.Deactivated {
			t.Fatalf("%+v", md)
		}
		_, doc, dm := r.Resolve(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{})
		if doc != nil || !dm.Deactivated {
			t.Fatal("deactivated passes through resolve")
		}
	})
}

func TestErrorString(t *testing.T) {
	t.Run(covers("core10#did-resolution-metadata.6", "core10#did-resolution-metadata.7", "core10#did-url-dereferencing-metadata.4", "core10#did-url-dereferencing-metadata.5", "errors map to the DID Core 1.0 keywords and the registries convention"), func(t *testing.T) {
		want := map[resolution.Code]string{
			resolution.CodeInvalidDID:                 "invalidDid",
			resolution.CodeNotFound:                   "notFound",
			resolution.CodeRepresentationNotSupported: "representationNotSupported",
			resolution.CodeInvalidDIDURL:              "invalidDidUrl",
			resolution.CodeMethodNotSupported:         "methodNotSupported",
			resolution.CodeInvalidDIDDocument:         "invalidDidDocument",
			resolution.CodeInvalidOptions:             "invalidOptions",
			resolution.CodeFeatureNotSupported:        "featureNotSupported",
			resolution.CodeInternalError:              "internalError",
			resolution.CodeInvalidVerificationMethod:  "invalidVerificationMethod",
			"https://e.example/errors#RATE_LIMITED":   "rateLimited",
			"https://e.example/errors/not-a-code":     "internalError",
			"https://e.example/errors#BAD__CODE":      "internalError",
			"https://e.example/errors#":               "internalError",
		}
		for code, s := range want {
			got := compat.ErrorString(resolution.NewError(code, ""))
			if got != s || !keyword.MatchString(got) {
				t.Errorf("%s: %s, want %s", code, got, s)
			}
		}
		if compat.ErrorString(nil) != "" || compat.ErrorString(resolution.NewAcceptNotSupported("x/y")) != compat.ErrRepresentationNotSupported {
			t.Fatal("nil and accept")
		}
	})
}

func TestDereference(t *testing.T) {
	ctx := t.Context()
	inner, err := dereferencer.New(core(t, key.New(producer.New()), exampleDriver(document.Metadata{VersionID: "4"})), producer.New())
	if err != nil {
		t.Fatal(err)
	}
	d := &compat.V10Dereferencer{Inner: inner}
	t.Run(covers("core10#did-url-dereferencing.1", "core10#did-url-dereferencing.2", "core10#did-url-dereferencing.3", "core10#did-url-dereferencing.6", "core10#did-url-dereferencing.7", "core10#did-url-dereferencing.9", "a DID URL with its fragment dereferences to a verification method"), func(t *testing.T) {
		md, content, cm := d.Dereference(ctx, testutil.MustURL(testutil.ExampleDID+"#key-1"), resolution.DereferenceOptions{})
		m, ok := content.(vm.Method)
		if md.Error != "" || !ok || m.ID.String() != "did:example:123#key-1" {
			t.Fatalf("%+v %T", md, content)
		}
		if _, err := json.Marshal(cm); err != nil {
			t.Fatal(err)
		}
	})
	t.Run(covers("core10#did-url-dereferencing.10", "core10#did-url-dereferencing-metadata.1", "core10#did-url-dereferencing-metadata.2", "a DID document comes with its didDocumentMetadata and contentType"), func(t *testing.T) {
		md, content, cm := d.Dereference(ctx, testutil.MustURL(testutil.ExampleDID), resolution.DereferenceOptions{})
		if _, ok := content.(*document.Document); !ok || cm.VersionID != "4" || md.ContentType != spec.MediaTypeDIDLDJSON || !isASCII(md.ContentType) {
			t.Fatalf("%+v", md)
		}
	})
	t.Run(covers("core10#did-url-dereferencing.4", "core10#did-url-dereferencing.5", "core10#did-url-dereferencing.8", "core10#did-url-dereferencing.11", "core10#did-url-dereferencing-metadata.3", "a failure has an error keyword, no content and empty metadata"), func(t *testing.T) {
		for u, want := range map[string]string{
			testutil.ExampleDID + "#missing":       compat.ErrNotFound,
			testutil.ExampleDID + "?service":       compat.ErrInvalidDIDURL,
			testutil.ExampleDID + "?serviceType=X": compat.ErrFeatureNotSupported,
			"did:web:x.example":                    compat.ErrMethodNotSupported,
		} {
			md, content, cm := d.Dereference(ctx, testutil.MustURL(u), resolution.DereferenceOptions{})
			if md.Error != want || content != nil || !cm.IsEmpty() {
				t.Errorf("%s: %+v", u, md)
			}
		}
	})
	t.Run(covers("core10#did-url-dereferencing-options.3", "accept is passed on and determines the contentType"), func(t *testing.T) {
		md, content, _ := d.Dereference(ctx, testutil.MustURL(testutil.ExampleDID), resolution.DereferenceOptions{Accept: spec.MediaTypeDIDJSON})
		if _, ok := content.(*document.Document); !ok || md.ContentType != spec.MediaTypeDIDJSON {
			t.Fatalf("%+v", md)
		}
	})
	t.Run("hl is accepted and not forwarded", func(t *testing.T) {
		stub := &stubDereferencer{res: resolution.DereferenceResult{ContentStream: []string{"https://a.example/"},
			ContentMetadata: resolution.DocumentMetadata{Extra: map[string]any{"contentType": "text/uri-list", "n": 1}}}}
		d := &compat.V10Dereferencer{Inner: stub}
		md, _, cm := d.Dereference(ctx, testutil.MustURL(testutil.ExampleDID+"/p?hl=zQm&service=files#f"), resolution.DereferenceOptions{})
		if stub.last.String() != testutil.ExampleDID+"/p?service=files#f" || len(md.Warnings) != 1 {
			t.Fatalf("forwarded %s", stub.last)
		}
		if md.ContentType != "text/uri-list" || cm.Extra["n"] != "1" {
			t.Fatal("contentType is read from contentMetadata as well (docs/07 caveat 8)")
		}
		d.Dereference(ctx, testutil.MustURL(testutil.ExampleDID+"?hl=zQm"), resolution.DereferenceOptions{})
		if stub.last.String() != testutil.ExampleDID {
			t.Fatalf("forwarded %s", stub.last)
		}
	})
}

// covers joins the statement ids a subtest checks and its description into
// the subtest name. Each id is its own string literal, which is how the
// coverage check (conformance/coverage_test.go) finds it.
func covers(parts ...string) string { return strings.Join(parts, " ") }
