package sage

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
)

// RESOLVE-05: a Source's internal diagnostics never reach public problem
// details; they stay in the cause for local logs.
func TestSourceDetailIsNotPublic(t *testing.T) {
	secret := "internal rpc https://key@rpc.internal failed"
	src := newSource()
	src.errs[testDID] = NewError(CodeRecordNotFound, secret)
	other := "did:sage:web:registry.example:agent-2"
	src.errs[other] = errors.New(secret)
	r := newResolver(t, src)
	for _, d := range []string{testDID, other} {
		res, _ := r.ResolveWithCode(t.Context(), mustDID(t, d), resolution.ResolutionOptions{})
		if e := res.ResolutionMetadata.Error; e == nil || strings.Contains(e.Detail, "rpc") {
			t.Errorf("%s: %+v", d, e)
		}
	}
	resp, obj := serve(t, plainHandler(t, src), prefix+"/"+testDID, "application/did")
	if resp.StatusCode != 404 || strings.Contains(obj["detail"].(string), "rpc") {
		t.Errorf("handler leaked: %v", obj)
	}
	e := codeOf(errors.New(secret))
	if !strings.Contains(e.Error(), "rpc") || errors.Unwrap(e) == nil || strings.Contains(e.Problem().Detail, "rpc") {
		t.Errorf("cause handling: %v %+v", e, e.Problem())
	}
}

// otherMethod is a driver of another method that resolves a did:sage
// identifier on the same context while reading its own document.
type otherMethod struct {
	r    *Resolver
	sage did.DID
}

func (o *otherMethod) Name() string       { return "example" }
func (o *otherMethod) Produces() []string { return []string{spec.MediaTypeDID} }
func (o *otherMethod) Read(ctx context.Context, d did.DID, _ method.ReadOptions) (*method.ReadResult, error) {
	o.r.resolver.Resolve(ctx, o.sage, resolution.ResolutionOptions{}) // fails: no such record
	return &method.ReadResult{Data: []byte(`{"id":"` + d.String() + `"}`), ContentType: spec.MediaTypeDID, Metadata: document.Metadata{}}, nil
}
func (o *otherMethod) Create(context.Context, *document.Document, method.CreateOptions) (*method.CreateResult, error) {
	return nil, method.ErrNotSupported
}
func (o *otherMethod) Update(context.Context, did.DID, *document.Document, method.UpdateOptions) (*method.UpdateResult, error) {
	return nil, method.ErrNotSupported
}
func (o *otherMethod) Deactivate(context.Context, did.DID, method.DeactivateOptions) (*method.DeactivateResult, error) {
	return nil, method.ErrNotSupported
}

// A nested did:sage resolution for another DID cannot replace the outer
// result, because a recorder belongs to one target DID.
func TestRecorderIsScopedToItsDID(t *testing.T) {
	o := &otherMethod{sage: mustDID(t, "did:sage:web:registry.example:none")}
	r := newResolver(t, newSource(), o)
	o.r = r
	res, code := r.ResolveWithCode(t.Context(), mustDID(t, "did:example:123"), resolution.ResolutionOptions{})
	if code != "" || res.ResolutionMetadata.Error != nil {
		t.Errorf("outer result replaced: %+v %q", res.ResolutionMetadata, code)
	}
}

// One Resolver serves concurrent resolutions on one context; each reports
// its own code (run with -race).
func TestConcurrentResolutions(t *testing.T) {
	rec := activeRecord(t)
	src := newSource(rec)
	src.errs["did:sage:web:registry.example:stale"] = NewError(CodeRecordStale, "")
	r := newResolver(t, src)
	ctx := t.Context()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, code := r.ResolveWithCode(ctx, rec.DID, resolution.ResolutionOptions{}); code != "" {
				t.Errorf("good record got %q", code)
			}
		}()
		go func() {
			defer wg.Done()
			if _, code := r.ResolveWithCode(ctx, mustDID(t, "did:sage:web:registry.example:stale"), resolution.ResolutionOptions{}); code != CodeRecordStale {
				t.Errorf("stale record got %q", code)
			}
		}()
	}
	wg.Wait()
}

// Chapter 06 ID-01 forbids paths and queries in a did:sage DID URL.
func TestDereferencePathOrQuery(t *testing.T) {
	src := newSource(activeRecord(t))
	r := newResolver(t, src)
	for _, s := range []string{testDID + "/path", testDID + "?service=a2a"} {
		u, err := did.ParseURL(s)
		if err != nil {
			t.Fatal(err)
		}
		res, code := r.DereferenceWithCode(t.Context(), u, resolution.DereferenceOptions{})
		if code != CodeIDMalformed || res.DereferencingMetadata.Error == nil {
			t.Errorf("%s: %+v %q", s, res.DereferencingMetadata, code)
		}
	}
	if src.count() != 0 {
		t.Error("a malformed DID URL was observed")
	}
}

// The standard handler reports INVALID_DID_URL for a malformed DID URL; the
// SAGE code is still added. Requests for other methods pass through.
func TestHandlerMalformedURLAndOtherMethods(t *testing.T) {
	h := plainHandler(t, newSource(activeRecord(t)))
	resp, obj := serve(t, h, prefix+"/did:SAGE:web:x:a/p", "application/did")
	if resp.StatusCode != 400 || obj[SageCodeMember] != "id.malformed" {
		t.Errorf("malformed URL: %d %v", resp.StatusCode, obj)
	}
	resp, obj = serve(t, h, prefix+"/"+testDID+"?service=a2a", "application/did")
	if resp.StatusCode != 400 || obj[SageCodeMember] != "id.malformed" {
		t.Errorf("query: %d %v", resp.StatusCode, obj)
	}
	resp, obj = serve(t, h, prefix+"/did:example:123", "application/did")
	if resp.StatusCode != 501 || obj[SageCodeMember] != nil {
		t.Errorf("other method: %d %v", resp.StatusCode, obj)
	}
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/elsewhere", nil))
	if r.Code == 0 || strings.Contains(r.Body.String(), SageCodeMember) {
		t.Errorf("outside the prefix: %d %s", r.Code, r.Body.String())
	}
}
