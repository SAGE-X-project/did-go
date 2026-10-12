package sage

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/universal"
)

const prefix = "/1.0/identifiers"

func serve(t *testing.T, h http.Handler, path, accept string) (*http.Response, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	var obj map[string]any
	_ = json.Unmarshal(body, &obj)
	return resp, obj
}

func plainHandler(t *testing.T, src Source) *Handler {
	return NewHandler(newResolver(t, src), prefix, universal.WithPlaintext(true))
}

// DIDP-05 over the HTTP(S) binding: the problem type is the DID Resolution
// URL, the status follows DID Resolution §12.1 and sageCode carries the SAGE
// code.
func TestHandlerProblem(t *testing.T) {
	src := newSource()
	src.errs[testDID] = NewError(CodeRecordStale, "")
	h := plainHandler(t, src)
	resp, obj := serve(t, h, prefix+"/"+testDID, "application/did")
	if resp.StatusCode != 500 || resp.Header.Get("Content-Type") != MediaTypeProblemJSON ||
		obj["type"] != resolution.CodeInternalError.TypeURL() || obj[SageCodeMember] != "record.stale" {
		t.Errorf("stale: %d %v", resp.StatusCode, obj)
	}
	resp, obj = serve(t, h, prefix+"/did:sage:web:registry.example:none", "application/did")
	if resp.StatusCode != 404 || obj[SageCodeMember] != "record.not-found" {
		t.Errorf("not found: %d %v", resp.StatusCode, obj)
	}
}

// A complete result carries sageCode inside didResolutionMetadata.error.
func TestHandlerCompleteResult(t *testing.T) {
	src := newSource()
	src.errs[testDID] = NewError(CodeIDUnknownKind, "")
	resp, obj := serve(t, plainHandler(t, src), prefix+"/"+testDID, "application/did-resolution")
	md, _ := obj["didResolutionMetadata"].(map[string]any)
	e, _ := md["error"].(map[string]any)
	if resp.StatusCode != 501 || e["type"] != resolution.CodeMethodNotSupported.TypeURL() || e[SageCodeMember] != "id.unknown-kind" {
		t.Errorf("complete result: %d %v", resp.StatusCode, obj)
	}
}

// A did:sage identifier whose prefix is not exactly lowercase is
// INVALID_DID with sageCode id.malformed and is never observed; a method
// name in another letter case is not a DID at all and gets the same code.
func TestHandlerMalformed(t *testing.T) {
	src := newSource(activeRecord(t))
	h := plainHandler(t, src)
	for _, id := range []string{"DID:sage:web:registry.example:agent-1", "did:SAGE:web:registry.example:agent-1"} {
		resp, obj := serve(t, h, prefix+"/"+id, "application/did")
		if resp.StatusCode != 400 || obj["type"] != resolution.CodeInvalidDID.TypeURL() || obj[SageCodeMember] != "id.malformed" {
			t.Errorf("%s: %d %v", id, resp.StatusCode, obj)
		}
	}
	resp, obj := serve(t, h, prefix+"/"+strings.ReplaceAll("did:SAGE:web:x:a", ":", "%3A"), "application/did")
	if resp.StatusCode != 400 || obj[SageCodeMember] != "id.malformed" {
		t.Errorf("encoded: %d %v", resp.StatusCode, obj)
	}
	if src.count() != 0 {
		t.Errorf("a malformed identifier was observed %d times", src.count())
	}
}

// Successful responses and the standard handler's own refusals pass through
// unchanged: no sageCode, no observation for a request that is refused.
func TestHandlerPassThrough(t *testing.T) {
	rec := activeRecord(t)
	src := newSource(rec)
	resp, _ := serve(t, plainHandler(t, src), prefix+"/"+testDID, "application/did")
	body := produce(t, rec, DID11)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != MediaTypeDID11 {
		t.Errorf("success: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	r := httptest.NewRecorder()
	plainHandler(t, src).ServeHTTP(r, httptest.NewRequest(http.MethodGet, prefix+"/"+testDID, nil))
	if !strings.Contains(r.Body.String(), `"didDocument"`) || strings.Contains(r.Body.String(), SageCodeMember) {
		t.Errorf("complete result without Accept: %s", r.Body.String())
	}
	tlsOnly := NewHandler(newResolver(t, src), prefix+"/")
	before := src.count()
	resp, obj := serve(t, tlsOnly, prefix+"/DID:sage:web:registry.example:agent-1", "application/did")
	if resp.StatusCode != http.StatusForbidden || obj[SageCodeMember] != nil || src.count() != before {
		t.Errorf("plaintext refusal: %d %v", resp.StatusCode, obj)
	}
	_ = body
}

// Dereferencing an absent key over the binding is 404 with sageCode
// key.not-in-record.
func TestHandlerDereference(t *testing.T) {
	encoded := strings.ReplaceAll(testDID, ":", "%3A") + "%23absent"
	resp, obj := serve(t, plainHandler(t, newSource(activeRecord(t))), prefix+"/"+encoded, "application/did")
	if resp.StatusCode != 404 || obj[SageCodeMember] != "key.not-in-record" {
		t.Errorf("absent key: %d %v", resp.StatusCode, obj)
	}
}

func TestAddSageCode(t *testing.T) {
	cases := []struct{ body, ct, want string }{
		{`not json`, MediaTypeProblemJSON, `not json`},
		{`{"a":1}`, "text/plain", `{"a":1}`},
		{`{"didResolutionMetadata":{}}`, "application/did-resolution", `{"didResolutionMetadata":{}}`},
		{`{"didResolutionMetadata":{"error":1}}`, "application/did-resolution", `{"didResolutionMetadata":{"error":1}}`},
		{`{"type":"x"}`, MediaTypeProblemJSON, `{"type":"x"}`},
		{`{"dereferencingMetadata":{"error":{"type":"x"}}}`, "application/did-url-dereferencing",
			`{"dereferencingMetadata":{"error":{"type":"x"}}}`},
		{`{"dereferencingMetadata":{"error":{"type":"https://www.w3.org/ns/did#NOT_FOUND"}}}`, "application/did-url-dereferencing",
			`{"dereferencingMetadata":{"error":{"sageCode":"key.not-in-record","type":"https://www.w3.org/ns/did#NOT_FOUND"}}}`},
	}
	for _, c := range cases {
		if got := string(addSageCode([]byte(c.body), c.ct, NewError(CodeKeyNotInRecord, ""))); got != c.want {
			t.Errorf("addSageCode(%s, %s) = %s", c.body, c.ct, got)
		}
	}
	if got := marshalOr(func() {}, []byte("x")); string(got) != "x" {
		t.Error("marshalOr fallback")
	}
	w := &bufferedWriter{header: http.Header{}}
	if w.statusCode() != 200 {
		t.Error("default status")
	}
	_, _ = w.Write([]byte("a"))
	w.WriteHeader(500)
	if w.statusCode() != 200 {
		t.Error("a status after the body was written")
	}
	if (&Handler{prefix: "/x/"}).identifier(httptest.NewRequest(http.MethodGet, "/other", nil)) != "" {
		t.Error("identifier outside the prefix")
	}
}
