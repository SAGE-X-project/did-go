package sage

import (
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/method/key"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

func newResolver(t *testing.T, src Source, others ...method.Method) *Resolver {
	t.Helper()
	r, err := NewResolver(src, consumer.New(), producer.New(), others...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func wantCode(t *testing.T, res resolution.Result, sage Code, got Code, mapped resolution.Code) {
	t.Helper()
	e := res.ResolutionMetadata.Error
	if e == nil || e.Type != mapped.TypeURL() || got != sage || res.Document != nil || res.Raw != nil {
		t.Errorf("want %s with sageCode %q, got %+v code %q", mapped, sage, e, got)
	}
}

// DIDP-05 through the DID Resolution interface: the planned cases
// didp-05-malformed, -not-found, -stale-not-absent and -unknown-kind, and
// version.unsupported as INVALID_OPTIONS.
func TestResolveErrors(t *testing.T) {
	src := newSource()
	r := newResolver(t, src)
	res, code := r.ResolveString(t.Context(), "did:Sage:web:registry.example:agent-1", resolution.ResolutionOptions{})
	wantCode(t, res, CodeIDMalformed, code, resolution.CodeInvalidDID)
	res, code = r.ResolveString(t.Context(), "DID:sage:web:registry.example:agent-1", resolution.ResolutionOptions{})
	wantCode(t, res, CodeIDMalformed, code, resolution.CodeInvalidDID)
	if src.count() != 0 {
		t.Error("a malformed identifier was observed")
	}
	cases := []struct {
		sage   Code
		mapped resolution.Code
	}{
		{CodeRecordNotFound, resolution.CodeNotFound},
		{CodeRecordStale, resolution.CodeInternalError},
		{CodeRecordUnreachable, resolution.CodeInternalError},
		{CodeRecordInvalid, resolution.CodeInternalError},
		{CodeIDUnknownKind, resolution.CodeMethodNotSupported},
		{CodeVersionUnsupported, resolution.CodeInvalidOptions},
		{CodeIDMalformed, resolution.CodeInvalidDID},
	}
	d := mustDID(t, testDID)
	for _, c := range cases {
		src.errs[testDID] = NewError(c.sage, "")
		res, code := r.ResolveWithCode(t.Context(), d, resolution.ResolutionOptions{})
		wantCode(t, res, c.sage, code, c.mapped)
	}
	if res := r.Resolve(t.Context(), d, resolution.ResolutionOptions{}); res.ResolutionMetadata.Error == nil {
		t.Error("Resolve hid the error")
	}
}

// DIDP-05: a deactivated record is reported with a null document and
// deactivated true (didp-05-deactivated).
func TestResolveDeactivated(t *testing.T) {
	rec := activeRecord(t)
	rec.State = StateDeactivated
	res, code := newResolver(t, newSource(rec)).ResolveWithCode(t.Context(), rec.DID, resolution.ResolutionOptions{})
	if code != "" || res.ResolutionMetadata.Error != nil || res.Document != nil || !res.DocumentMetadata.Deactivated {
		t.Errorf("deactivated: %+v", res)
	}
}

// DIDP-02 binds only the SAGE interface: through the DID Resolution
// interface accept is matched with q-values and the document can be
// transcoded, and every returned document is a DIDP-01 projection
// (didp-02-did-resolution-interface).
func TestResolveAcceptFollowsDIDResolution(t *testing.T) {
	rec := activeRecord(t)
	r := newResolver(t, newSource(rec))
	for accept, want := range map[string]string{
		"":                MediaTypeCore10,
		"application/did": MediaTypeDID11,
		"application/did;q=0.9, application/did+json": MediaTypeCore10,
		"application/did+ld+json":                     spec.MediaTypeDIDLDJSON,
	} {
		res, code := r.ResolveWithCode(t.Context(), rec.DID, resolution.ResolutionOptions{Accept: accept})
		if code != "" || res.ResolutionMetadata.Error != nil || res.ResolutionMetadata.ContentType != want {
			t.Fatalf("accept %q: %+v", accept, res.ResolutionMetadata)
		}
		if p, ok := projectionOf(want); ok && string(res.Raw) != produce(t, rec, p) {
			t.Errorf("accept %q: %s", accept, res.Raw)
		}
	}
	res, code := r.ResolveWithCode(t.Context(), rec.DID, resolution.ResolutionOptions{Accept: "text/html"})
	if code != "" || res.ResolutionMetadata.Error == nil || res.ResolutionMetadata.Error.Type != resolution.CodeFeatureNotSupported.TypeURL() {
		t.Errorf("text/html (didp-05-unsupported-accept): %+v %q", res.ResolutionMetadata, code)
	}
}

// Other DID methods resolve through the drivers passed in.
func TestResolveOtherMethods(t *testing.T) {
	r := newResolver(t, newSource(), key.New(producer.New()))
	res, code := r.ResolveString(t.Context(), "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", resolution.ResolutionOptions{})
	if code != "" || res.ResolutionMetadata.Error != nil {
		t.Errorf("did:key: %+v", res.ResolutionMetadata)
	}
	res, code = r.ResolveString(t.Context(), "not a did", resolution.ResolutionOptions{})
	if code != "" || res.ResolutionMetadata.Error == nil || res.ResolutionMetadata.Error.Type != resolution.CodeInvalidDID.TypeURL() {
		t.Errorf("not a DID: %+v", res.ResolutionMetadata)
	}
	if _, err := NewResolver(nil, consumer.New(), producer.New()); err == nil {
		t.Error("nil source accepted")
	}
	if _, err := NewResolver(newSource(), nil, producer.New()); err == nil {
		t.Error("nil consumer accepted")
	}
	if _, err := NewResolver(newSource(), consumer.New(), producer.New(), &Driver{}); err == nil {
		t.Error("a second sage driver accepted")
	}
}

// DIDP-05: dereferencing a key of the record returns it; a fragment naming
// no key is NOT_FOUND with sageCode key.not-in-record; a resolution failure
// keeps its SAGE code.
func TestDereference(t *testing.T) {
	rec := activeRecord(t)
	src := newSource(rec)
	r := newResolver(t, src)
	u, _ := did.ParseURL(testDID + "#sign")
	res, code := r.DereferenceWithCode(t.Context(), u, resolution.DereferenceOptions{})
	if code != "" || res.DereferencingMetadata.Error != nil {
		t.Fatalf("key: %+v", res.DereferencingMetadata)
	}
	if m, ok := res.ContentStream.(vm.Method); !ok || m.ID.Fragment() != "sign" {
		t.Errorf("content %T %+v", res.ContentStream, res.ContentStream)
	}
	u, _ = did.ParseURL(testDID + "#absent")
	res, code = r.DereferenceWithCode(t.Context(), u, resolution.DereferenceOptions{})
	if code != CodeKeyNotInRecord || res.DereferencingMetadata.Error == nil ||
		res.DereferencingMetadata.Error.Type != resolution.CodeNotFound.TypeURL() {
		t.Errorf("absent key: %+v %q", res.DereferencingMetadata, code)
	}
	src.errs[testDID] = NewError(CodeRecordStale, "")
	res, code = r.DereferenceWithCode(t.Context(), u, resolution.DereferenceOptions{})
	if code != CodeRecordStale || res.DereferencingMetadata.Error.Type != resolution.CodeInternalError.TypeURL() {
		t.Errorf("stale: %+v %q", res.DereferencingMetadata, code)
	}
	if res := r.Dereference(t.Context(), u, resolution.DereferenceOptions{}); res.DereferencingMetadata.Error == nil {
		t.Error("Dereference hid the error")
	}
	other := newResolver(t, newSource(), key.New(producer.New()))
	ku, _ := did.ParseURL("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#absent")
	if _, code := other.DereferenceWithCode(t.Context(), ku, resolution.DereferenceOptions{}); code != "" {
		t.Errorf("a did:key fragment got sageCode %q", code)
	}
}

func TestMalformed(t *testing.T) {
	for s, want := range map[string]bool{
		"did:sage:web:x:a":   false,
		"did:key:z6Mk":       false,
		"did:sa":             false,
		"DID:SAGE:web:x:a":   true,
		"did:sage:web:x:%zz": true,
	} {
		if got := malformed(s) != nil; got != want {
			t.Errorf("malformed(%q) = %v", s, got)
		}
	}
	if !strings.HasPrefix(testDID, "did:"+MethodName+":") {
		t.Error("test DID")
	}
}
