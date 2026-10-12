package resolver_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/consumer"
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

func newResolver(t *testing.T, ms ...method.Method) *resolver.DefaultResolver {
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

func fixture(f testutil.ReadFunc, media ...string) *testutil.Driver {
	if media == nil {
		media = []string{spec.MediaTypeDID}
	}
	return &testutil.Driver{Method: "example", Media: media, Func: f}
}

func exampleDriver() *testutil.Driver {
	return fixture(testutil.Static(testutil.ExampleDoc, spec.MediaTypeDID, document.Metadata{VersionID: "1"}))
}

// wantError checks the shape every failed resolution must have: an error of
// the given code, no document, no bytes and empty document metadata.
func wantError(t *testing.T, res resolution.Result, code resolution.Code) {
	t.Helper()
	e := res.ResolutionMetadata.Error
	if e == nil {
		t.Fatalf("no error, want %s", code)
	}
	if e.Type != code.TypeURL() {
		t.Fatalf("error type %s, want %s (%s)", e.Type, code.TypeURL(), e.Detail)
	}
	if res.Document != nil || res.Raw != nil || res.Source != nil {
		t.Fatal("a failed resolution has no document")
	}
	if !res.DocumentMetadata.IsEmpty() {
		t.Fatal("a failed resolution has empty document metadata")
	}
	if res.ResolutionMetadata.ContentType != "" {
		t.Fatal("a failed resolution has no contentType")
	}
}

func wantSuccess(t *testing.T, res resolution.Result) {
	t.Helper()
	if e := res.ResolutionMetadata.Error; e != nil {
		t.Fatalf("unexpected error %v", e)
	}
	if res.Document == nil || len(res.Raw) == 0 || res.ResolutionMetadata.ContentType == "" {
		t.Fatal("a successful resolution has a document, bytes and a contentType")
	}
}

func TestNew(t *testing.T) {
	reg, _ := method.NewRegistry()
	if _, err := resolver.New(nil, consumer.New(), producer.New()); err == nil {
		t.Fatal("nil registry")
	}
	if _, err := resolver.New(reg, nil, producer.New()); err == nil {
		t.Fatal("nil consumer")
	}
	if _, err := resolver.New(reg, consumer.New(), nil); err == nil {
		t.Fatal("nil producer")
	}
}

func TestResolveDIDKey(t *testing.T) {
	r := newResolver(t, key.New(producer.New()))
	t.Run(covers("res10-crd20261001#resolving.1", "core10#resolution.1", "a did:key DID resolves to a DID document"), func(t *testing.T) {
		res := r.Resolve(t.Context(), testutil.MustDID(keyDID), resolution.ResolutionOptions{})
		wantSuccess(t, res)
		if res.ResolutionMetadata.ContentType != spec.MediaTypeDID || res.Source != nil {
			t.Fatalf("driver bytes are returned as labelled: %s", res.ResolutionMetadata.ContentType)
		}
	})
	t.Run("res10-crd20261001#resolving.3 resolution options may be empty", func(t *testing.T) {
		wantSuccess(t, r.Resolve(t.Context(), testutil.MustDID(keyDID), resolution.ResolutionOptions{}))
	})
	t.Run(covers("res10-crd20261001#resolving.6", "res10-crd20261001#resolving-algorithm.31", "the document is in a conformant representation"), func(t *testing.T) {
		res := r.Resolve(t.Context(), testutil.MustDID(keyDID), resolution.ResolutionOptions{})
		d, _, err := consumer.New().Consume(res.Raw, res.ResolutionMetadata.ContentType, representation.ConsumeOptions{})
		if err != nil || d.ID().String() != keyDID {
			t.Fatalf("Raw does not parse with contentType: %v", err)
		}
	})
	t.Run(covers("res10-crd20261001#did-resolution-options.3", "core10#did-resolution-options.2", "accept selects the driver's representation"), func(t *testing.T) {
		for _, mt := range representation.CoreMediaTypes() {
			res := r.Resolve(t.Context(), testutil.MustDID(keyDID), resolution.ResolutionOptions{Accept: mt})
			wantSuccess(t, res)
			if res.ResolutionMetadata.ContentType != mt || res.Source != nil {
				t.Errorf("accept %s: got %s, transcoded %v", mt, res.ResolutionMetadata.ContentType, res.Source != nil)
			}
		}
	})
	t.Run("did:key has no versions: FEATURE_NOT_SUPPORTED", func(t *testing.T) {
		wantError(t, r.Resolve(t.Context(), testutil.MustDID(keyDID), resolution.ResolutionOptions{VersionID: "1"}), resolution.CodeFeatureNotSupported)
	})
	t.Run("a DID the method rejects is INVALID_DID", func(t *testing.T) {
		wantError(t, r.Resolve(t.Context(), testutil.MustDID("did:key:abc"), resolution.ResolutionOptions{}), resolution.CodeInvalidDID)
	})
}

func TestResolutionAlgorithmErrors(t *testing.T) {
	r := newResolver(t, exampleDriver())
	ctx := t.Context()
	t.Run(covers("res10-crd20261001#resolving-algorithm.1", "res10-crd20261001#resolving-algorithm.2", "res10-crd20261001#resolving-algorithm.3", "res10-crd20261001#resolving-algorithm.4", "res10-crd20261001#resolving-algorithm.5", "res10-crd20261001#resolving.2", "a non-conforming DID is INVALID_DID"), func(t *testing.T) {
		for _, s := range []string{"", "did:example", "did:example:123#frag", "did:example:1 2", "did:Example:1"} {
			wantError(t, r.ResolveString(ctx, s, resolution.ResolutionOptions{}), resolution.CodeInvalidDID)
		}
		wantError(t, r.Resolve(ctx, did.DID{}, resolution.ResolutionOptions{}), resolution.CodeInvalidDID)
		wantSuccess(t, r.ResolveString(ctx, testutil.ExampleDID, resolution.ResolutionOptions{}))
	})
	t.Run(covers("res10-crd20261001#resolving-algorithm.6", "res10-crd20261001#resolving-algorithm.7", "res10-crd20261001#resolving-algorithm.8", "res10-crd20261001#resolving-algorithm.9", "res10-crd20261001#resolving-algorithm.10", "an unsupported method is METHOD_NOT_SUPPORTED"), func(t *testing.T) {
		wantError(t, r.Resolve(ctx, testutil.MustDID("did:web:example.com"), resolution.ResolutionOptions{}), resolution.CodeMethodNotSupported)
	})
	t.Run(covers("res10-crd20261001#resolving-algorithm.11", "res10-crd20261001#resolving-algorithm.12", "res10-crd20261001#resolving-algorithm.13", "res10-crd20261001#resolving-algorithm.14", "res10-crd20261001#resolving-algorithm.15", "an unsupported option is FEATURE_NOT_SUPPORTED"), func(t *testing.T) {
		res := r.Resolve(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{Extra: map[string]any{"transformKey": "JsonWebKey"}})
		wantError(t, res, resolution.CodeFeatureNotSupported)
		if !strings.Contains(res.ResolutionMetadata.Error.Detail, "transformKey") {
			t.Fatal("the detail names the unsupported option")
		}
		res = r.Resolve(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{Accept: "text/html, image/*"})
		wantError(t, res, resolution.CodeFeatureNotSupported)
		if !res.ResolutionMetadata.Error.IsAcceptNotSupported() {
			t.Fatal("an unsatisfiable accept is NewAcceptNotSupported")
		}
	})
	t.Run(covers("res10-crd20261001#resolving-algorithm.16", "res10-crd20261001#resolving-algorithm.17", "res10-crd20261001#resolving-algorithm.18", "res10-crd20261001#resolving-algorithm.19", "res10-crd20261001#resolving-algorithm.20", "an invalid option is INVALID_OPTIONS"), func(t *testing.T) {
		sub := time.Date(2020, 1, 1, 0, 0, 0, 5, time.UTC)
		drv := exampleDriver()
		r := newResolver(t, drv)
		for _, o := range []resolution.ResolutionOptions{
			{Accept: "application/did;q=2"},
			{VersionID: "é"},
			{VersionTime: &sub},
			{Extra: map[string]any{"accept": "application/did"}},
		} {
			wantError(t, r.Resolve(ctx, testutil.MustDID(testutil.ExampleDID), o), resolution.CodeInvalidOptions)
		}
		if len(drv.Calls()) != 0 {
			t.Fatal("options are checked before Read")
		}
	})
	t.Run(covers("res10-crd20261001#resolving-algorithm.21", "res10-crd20261001#resolving-algorithm.22", "res10-crd20261001#resolving-algorithm.23", "res10-crd20261001#resolving-algorithm.24", "res10-crd20261001#resolving-algorithm.25", "a DID that does not exist is NOT_FOUND"), func(t *testing.T) {
		nf := newResolver(t, fixture(testutil.Fail(method.ErrNotFound)))
		wantError(t, nf.Resolve(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{}), resolution.CodeNotFound)
	})
	t.Run(covers("res10-crd20261001#resolving-algorithm.41", "res10-crd20261001#resolving-algorithm.42", "res10-crd20261001#resolving-algorithm.43", "res10-crd20261001#resolving-algorithm.44", "an unexpected driver error is INTERNAL_ERROR"), func(t *testing.T) {
		for _, f := range []testutil.ReadFunc{
			testutil.Fail(errors.New("registry unreachable")),
			testutil.Fail(context.Canceled),
			func(context.Context, did.DID, method.ReadOptions) (*method.ReadResult, error) { return nil, nil },
		} {
			res := newResolver(t, fixture(f)).Resolve(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{})
			wantError(t, res, resolution.CodeInternalError)
			if strings.Contains(res.ResolutionMetadata.Error.Detail, "unreachable") {
				t.Fatal("an internal error does not leak driver detail")
			}
		}
	})
	t.Run(covers("res10-crd20261001#resolving.4", "res10-crd20261001#resolving.5", "res10-crd20261001#resolving.8", "res10-crd20261001#resolving.10", "every error result has an error, no document and empty metadata"), func(t *testing.T) {
		res := newResolver(t, fixture(testutil.Fail(method.ErrNotFound))).Resolve(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{})
		wantError(t, res, resolution.CodeNotFound)
		if res.ResolutionMetadata.Error.Title == "" {
			t.Fatal("the error object is not empty")
		}
	})
	t.Run(covers("res10-crd20261001#resolving.7", "a document the driver rejects as invalid is INVALID_DID_DOCUMENT"), func(t *testing.T) {
		for _, err := range []error{
			method.ErrInvalidDocument,
			fmt.Errorf("fetched document id differs: %w", method.ErrInvalidDocument),
			// A document error is more specific than an input error.
			fmt.Errorf("%w: %w", method.ErrInvalidInput, method.ErrInvalidDocument),
		} {
			wantError(t, newResolver(t, fixture(testutil.Fail(err))).Resolve(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{}), resolution.CodeInvalidDIDDocument)
		}
	})
	t.Run("a DID the driver rejects as input stays INVALID_DID", func(t *testing.T) {
		res := newResolver(t, fixture(testutil.Fail(method.ErrInvalidInput))).Resolve(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{})
		wantError(t, res, resolution.CodeInvalidDID)
	})
	t.Run("a method that does not support an option is FEATURE_NOT_SUPPORTED", func(t *testing.T) {
		ns := newResolver(t, fixture(testutil.Fail(method.ErrNotSupported)))
		res := ns.Resolve(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{VersionTime: ptr(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))})
		wantError(t, res, resolution.CodeFeatureNotSupported)
	})
}

func ptr[T any](v T) *T { return &v }

func TestDeactivated(t *testing.T) {
	ctx := t.Context()
	t.Run(covers("res10-crd20261001#resolving-algorithm.26", "res10-crd20261001#resolving-algorithm.27", "res10-crd20261001#resolving-algorithm.28", "res10-crd20261001#resolving-algorithm.29", "a deactivated DID has no document and deactivated metadata"), func(t *testing.T) {
		r := newResolver(t, fixture(testutil.Static(testutil.ExampleDoc, spec.MediaTypeDID, document.Metadata{Deactivated: true, VersionID: "9"})))
		res := r.Resolve(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{})
		if res.ResolutionMetadata.Error != nil || res.Document != nil || res.Raw != nil {
			t.Fatal("deactivation is not an error and returns no document")
		}
		if !res.DocumentMetadata.Deactivated || res.DocumentMetadata.VersionID != "9" {
			t.Fatal("didDocumentMetadata carries deactivated true")
		}
	})
	t.Run("the metadata of a deactivated DID is validated first", func(t *testing.T) {
		r := newResolver(t, fixture(testutil.Static("not json", spec.MediaTypeDID, document.Metadata{Deactivated: true, CanonicalID: "did:other:1"})))
		wantError(t, r.Resolve(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{}), resolution.CodeInvalidDIDDocument)
	})
}

func TestDriverOutputValidation(t *testing.T) {
	ctx := t.Context()
	resolve := func(data, mt string, md document.Metadata) resolution.Result {
		return newResolver(t, fixture(testutil.Static(data, mt, md))).Resolve(ctx, testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{})
	}
	t.Run(covers("res10-crd20261001#resolving.7", "cid10#subjects.4", "cid10#subjects.5", "a document whose id is not the resolved DID is rejected"), func(t *testing.T) {
		other := strings.ReplaceAll(testutil.ExampleDoc, "did:example:123", "did:example:456")
		wantError(t, resolve(other, spec.MediaTypeDID, document.Metadata{}), resolution.CodeInvalidDIDDocument)
	})
	t.Run(covers("cid10#subjects.3", "res10-crd20261001#resolving-algorithm.30", "the output DID document is the document the method reads"), func(t *testing.T) {
		res := resolve(testutil.ExampleDoc, spec.MediaTypeDID, document.Metadata{})
		wantSuccess(t, res)
		if string(res.Raw) != testutil.ExampleDoc {
			t.Fatal("the driver bytes are returned unchanged")
		}
	})
	t.Run("bytes that do not conform to the declared DID media type are INVALID_DID_DOCUMENT", func(t *testing.T) {
		wantError(t, resolve(testutil.ExampleDocV10, spec.MediaTypeDID, document.Metadata{}), resolution.CodeInvalidDIDDocument)
		wantError(t, resolve(testutil.ExampleDoc, spec.MediaTypeDIDLDJSON, document.Metadata{}), resolution.CodeInvalidDIDDocument)
		wantError(t, resolve(testutil.ExampleDoc, "text/plain", document.Metadata{}), resolution.CodeInvalidDIDDocument)
		wantError(t, resolve(testutil.ExampleDoc, "", document.Metadata{}), resolution.CodeInvalidDIDDocument)
	})
	t.Run("malformed bytes are INVALID_DID_DOCUMENT", func(t *testing.T) {
		for _, data := range []string{"", "{", "[]", `{"id":"did:example:123","id":"did:example:123"}`, `{"id":"did:example:123","service":{}}`} {
			wantError(t, resolve(data, spec.MediaTypeDID, document.Metadata{}), resolution.CodeInvalidDIDDocument)
		}
	})
	t.Run("a low-precision label is decided by the payload", func(t *testing.T) {
		res := resolve(testutil.ExampleDoc, "application/json", document.Metadata{})
		wantSuccess(t, res)
		if res.ResolutionMetadata.ContentType != spec.MediaTypeDID || res.Info.LowPrecision == nil || res.Info.LowPrecision.Declared != "application/json" {
			t.Fatalf("contentType %s", res.ResolutionMetadata.ContentType)
		}
		res = resolve(testutil.ExampleDocV10, "application/ld+json", document.Metadata{})
		if res.ResolutionMetadata.ContentType != spec.MediaTypeDIDLDJSON {
			t.Fatalf("V10 with @context is application/did+ld+json, got %s", res.ResolutionMetadata.ContentType)
		}
	})
	t.Run("res10-crd20261001#resolving.9 driver metadata is returned as a metadata structure", func(t *testing.T) {
		created := time.Date(2020, 12, 20, 19, 17, 47, 0, time.UTC)
		md := document.Metadata{Created: &created, VersionID: "3", EquivalentID: []string{"did:example:ABC"},
			CanonicalID: "did:example:abc", Proof: []map[string]any{{"type": "X"}}, Extra: map[string]any{"blockHeight": 7}}
		res := resolve(testutil.ExampleDoc, spec.MediaTypeDID, md)
		wantSuccess(t, res)
		if res.DocumentMetadata.VersionID != "3" || res.DocumentMetadata.Extra["blockHeight"] != 7 {
			t.Fatal("metadata passes through")
		}
		if err := res.DocumentMetadata.Check(testutil.MustDID(testutil.ExampleDID), spec.V11); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("driver metadata that violates DID Resolution §4.3 is INVALID_DID_DOCUMENT", func(t *testing.T) {
		sub := time.Date(2020, 1, 1, 0, 0, 0, 1, time.UTC)
		for name, md := range map[string]document.Metadata{
			"equivalentId of another method": {EquivalentID: []string{"did:other:1"}},
			"equivalentId not a DID":         {EquivalentID: []string{"nope"}},
			"canonicalId of another method":  {CanonicalID: "did:other:1"},
			"sub-second created":             {Created: &sub},
			"sub-second updated":             {Updated: &sub},
			"sub-second nextUpdate":          {NextUpdate: &sub},
			"deactivated in Extra":           {Extra: map[string]any{"deactivated": "yes"}},
			"Extra value of another type":    {Extra: map[string]any{"x": struct{}{}}},
			"proof that is not a map":        {Proof: []map[string]any{nil}},
		} {
			if res := resolve(testutil.ExampleDoc, spec.MediaTypeDID, md); res.ResolutionMetadata.Error == nil ||
				res.ResolutionMetadata.Error.Type != resolution.CodeInvalidDIDDocument.TypeURL() {
				t.Errorf("%s: accepted", name)
			}
		}
	})
}

func TestAcceptAndTranscoding(t *testing.T) {
	ctx := t.Context()
	r := newResolver(t, exampleDriver())
	d := testutil.MustDID(testutil.ExampleDID)
	t.Run("res10-crd20261001#did-resolution-options.3 an acceptable driver representation is returned as is", func(t *testing.T) {
		for _, accept := range []string{"*/*", "application/*", "application/did+json;q=0.9, application/did;q=0.1"} {
			res := r.Resolve(ctx, d, resolution.ResolutionOptions{Accept: accept})
			wantSuccess(t, res)
			if res.Source != nil || res.ResolutionMetadata.ContentType != spec.MediaTypeDID || string(res.Raw) != testutil.ExampleDoc {
				t.Errorf("%s: transcoded", accept)
			}
		}
	})
	t.Run(covers("res10-crd20261001#resolving-algorithm.37", "res10-crd20261001#resolving-algorithm.38", "res10-crd20261001#resolving-algorithm.39", "res10-crd20261001#resolving-algorithm.40", "core10#did-resolution-options.2", "another representation is transcoded and contentType names it"), func(t *testing.T) {
		v10 := newResolver(t, fixture(testutil.Static(testutil.ExampleDocV10, spec.MediaTypeDIDLDJSON, document.Metadata{})))
		for _, want := range []string{spec.MediaTypeDIDJSON, spec.MediaTypeDID} {
			res := v10.Resolve(ctx, d, resolution.ResolutionOptions{Accept: want})
			wantSuccess(t, res)
			if res.ResolutionMetadata.ContentType != want || res.Source == nil || res.Source.ContentType != spec.MediaTypeDIDLDJSON ||
				string(res.Source.Data) != testutil.ExampleDocV10 {
				t.Fatalf("accept %s: contentType %s", want, res.ResolutionMetadata.ContentType)
			}
			back, _, err := consumer.New().Consume(res.Raw, res.ResolutionMetadata.ContentType, representation.ConsumeOptions{})
			if err != nil || back.ID() != d {
				t.Fatalf("produced bytes do not parse with contentType: %v", err)
			}
			if res.Info.DetectedVersion != spec.V10 {
				t.Fatal("Info describes the driver bytes")
			}
		}
	})
	t.Run("a representation that cannot be produced is FEATURE_NOT_SUPPORTED from NewAcceptNotSupported", func(t *testing.T) {
		noServiceID := `{"id":"did:example:123","service":[{"type":"A","serviceEndpoint":"https://a.example/"}]}`
		r := newResolver(t, fixture(testutil.Static(noServiceID, spec.MediaTypeDID, document.Metadata{})))
		res := r.Resolve(ctx, d, resolution.ResolutionOptions{Accept: spec.MediaTypeDIDJSON})
		wantError(t, res, resolution.CodeFeatureNotSupported)
		if !res.ResolutionMetadata.Error.IsAcceptNotSupported() {
			t.Fatal("NewAcceptNotSupported")
		}
	})
	t.Run("the driver is asked for the accepted representation it produces", func(t *testing.T) {
		drv := exampleDriver()
		drv.Media = []string{spec.MediaTypeDID, spec.MediaTypeDIDJSON}
		newResolver(t, drv).Resolve(ctx, d, resolution.ResolutionOptions{Accept: "application/did+json"})
		newResolver(t, drv).Resolve(ctx, d, resolution.ResolutionOptions{Accept: "application/did+ld+json"})
		calls := drv.Calls()
		if calls[0].MediaType != spec.MediaTypeDIDJSON || calls[1].MediaType != "" {
			t.Fatalf("ReadOptions.MediaType %q %q", calls[0].MediaType, calls[1].MediaType)
		}
	})
}

func TestExpandRelativeURLs(t *testing.T) {
	ctx := t.Context()
	r := newResolver(t, exampleDriver())
	d := testutil.MustDID(testutil.ExampleDID)
	t.Run(covers("res10-crd20261001#resolving-algorithm.32", "res10-crd20261001#resolving-algorithm.33", "res10-crd20261001#resolving-algorithm.34", "res10-crd20261001#resolving-algorithm.35", "res10-crd20261001#resolving-algorithm.36", "relative DID URLs become absolute"), func(t *testing.T) {
		res := r.Resolve(ctx, d, resolution.ResolutionOptions{ExpandRelativeURLs: true})
		wantSuccess(t, res)
		doc := res.Document
		if id := doc.VerificationMethods()[0].ID.String(); id != "did:example:123#key-1" {
			t.Fatalf("verification method id %s", id)
		}
		auth := doc.Relationship(vm.Authentication)
		if ref, _ := auth[0].Reference(); ref.String() != "did:example:123#key-1" {
			t.Fatalf("relationship reference %s", ref)
		}
		if m, _ := auth[1].Method(); m.ID.String() != "did:example:123#key-3" {
			t.Fatalf("embedded method id %s", m.ID)
		}
		if s := doc.Services()[0].ID; s != "did:example:123#messages" {
			t.Fatalf("service id %s", s)
		}
		ext, _ := doc.Extensions().Get("linkedResource")
		m := ext.(document.Map)
		if id, _ := m.Get("id"); id != document.String("did:example:123#res-1") {
			t.Fatalf("extension id %v", id)
		}
		items, _ := m.Get("items")
		if id, _ := items.(document.List).At(0).(document.Map).Get("id"); id != document.String("did:example:123#res-2") {
			t.Fatalf("nested extension id %v", id)
		}
		if items.(document.List).At(1) != document.String("#plain") {
			t.Fatal("only ids are replaced")
		}
		if res.Source == nil || res.ResolutionMetadata.ContentType != spec.MediaTypeDID || !strings.Contains(string(res.Raw), `"did:example:123#key-1"`) {
			t.Fatal("expanded bytes are produced again in the detected representation")
		}
	})
	t.Run("without the option relative DID URLs stay relative", func(t *testing.T) {
		res := r.Resolve(ctx, d, resolution.ResolutionOptions{})
		if id := res.Document.VerificationMethods()[0].ID.String(); id != "#key-1" {
			t.Fatal(id)
		}
	})
	t.Run("expanded with accept is produced in the accepted representation", func(t *testing.T) {
		res := r.Resolve(ctx, d, resolution.ResolutionOptions{ExpandRelativeURLs: true, Accept: "application/did+ld+json"})
		wantSuccess(t, res)
		if res.ResolutionMetadata.ContentType != spec.MediaTypeDIDLDJSON {
			t.Fatal(res.ResolutionMetadata.ContentType)
		}
	})
}

func TestOptionsForwarding(t *testing.T) {
	ctx := t.Context()
	d := testutil.MustDID(testutil.ExampleDID)
	t.Run("versionId and versionTime reach the driver, which selects the version", func(t *testing.T) {
		vt := time.Date(2021, 5, 1, 0, 0, 0, 0, time.UTC)
		drv := fixture(func(_ context.Context, _ did.DID, o method.ReadOptions) (*method.ReadResult, error) {
			if o.VersionID == "2" || (o.VersionTime != nil && o.VersionTime.Equal(vt)) {
				return &method.ReadResult{Data: []byte(testutil.ExampleDoc), ContentType: spec.MediaTypeDID,
					Metadata: document.Metadata{VersionID: "2", NextVersionID: "3"}}, nil
			}
			return nil, method.ErrNotFound
		})
		r := newResolver(t, drv)
		for _, o := range []resolution.ResolutionOptions{{VersionID: "2"}, {VersionTime: &vt}} {
			res := r.Resolve(ctx, d, o)
			wantSuccess(t, res)
			if res.DocumentMetadata.NextVersionID != "3" {
				t.Fatal("versioned metadata")
			}
		}
		wantError(t, r.Resolve(ctx, d, resolution.ResolutionOptions{VersionID: "7"}), resolution.CodeNotFound)
	})
	t.Run("noCache reaches the driver", func(t *testing.T) {
		drv := exampleDriver()
		newResolver(t, drv).Resolve(ctx, d, resolution.ResolutionOptions{NoCache: true})
		if !drv.Calls()[0].NoCache {
			t.Fatal("NoCache not forwarded")
		}
	})
	t.Run("DID parameters and dereferencing options are accepted; AcceptOptions adds names", func(t *testing.T) {
		r := newResolver(t, exampleDriver())
		extra := map[string]any{"service": "files", "serviceType": "X", "relativeRef": "/a", "verificationRelationship": "authentication"}
		wantSuccess(t, r.Resolve(ctx, d, resolution.ResolutionOptions{Extra: extra}))
		reg, _ := method.NewRegistry(exampleDriver())
		custom, _ := resolver.New(reg, consumer.New(), producer.New(), resolver.AcceptOptions("transformKey"))
		wantSuccess(t, custom.Resolve(ctx, d, resolution.ResolutionOptions{Extra: map[string]any{"transformKey": "JsonWebKey"}}))
		if len(resolver.DefaultAcceptedOptions()) != 4 {
			t.Fatal("DefaultAcceptedOptions")
		}
	})
}

type failingProducer struct{}

func (failingProducer) Produce(*document.Document, representation.ProduceOptions) ([]byte, string, error) {
	return nil, "", errors.New("no")
}

func TestProducerFailure(t *testing.T) {
	reg, _ := method.NewRegistry(exampleDriver())
	r, _ := resolver.New(reg, consumer.New(), failingProducer{})
	res := r.Resolve(t.Context(), testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{ExpandRelativeURLs: true})
	wantError(t, res, resolution.CodeInternalError)
}

// covers joins the statement ids a subtest checks and its description into
// the subtest name. Each id is its own string literal, which is how the
// coverage check (conformance/coverage_test.go) finds it.
func covers(parts ...string) string { return strings.Join(parts, " ") }

// expandRelativeUrls returns a new document; an empty verificationMethod or
// service set stays present in it (core10#verification-methods.2,
// core10#services.2: the values are sets, which may be empty).
func TestExpandKeepsEmptySets(t *testing.T) {
	doc := `{"id":"did:example:123","verificationMethod":[],"service":[]}`
	r := newResolver(t, fixture(testutil.Static(doc, spec.MediaTypeDID, document.Metadata{})))
	res := r.Resolve(t.Context(), testutil.MustDID(testutil.ExampleDID), resolution.ResolutionOptions{ExpandRelativeURLs: true})
	if res.ResolutionMetadata.Error != nil {
		t.Fatal(res.ResolutionMetadata.Error)
	}
	if !strings.Contains(string(res.Raw), `"verificationMethod":[],"service":[]`) {
		t.Errorf("expanded document %s lost an empty set", res.Raw)
	}
}
