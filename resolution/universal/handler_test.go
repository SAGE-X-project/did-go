package universal

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
)

// get sends a request to the handler server and returns the response with
// its body.
func get(t *testing.T, srv *httptest.Server, method, path, accept, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	hc := srv.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp, string(data)
}

func TestHandlerMethods(t *testing.T) {
	r := &fakeResolver{result: okResult()}
	srv := tlsServer(t, NewHandler(r, nil))
	t.Run("res10-crd20261001#bindings-https.1 GET is implemented and POST may be", func(t *testing.T) {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			resp, body := get(t, srv, m, DefaultPathPrefix+testDID, "application/did", "")
			if resp.StatusCode != 200 || body != docV11 {
				t.Errorf("%s: %d %s", m, resp.StatusCode, body)
			}
		}
		resp, _ := get(t, srv, http.MethodPut, DefaultPathPrefix+testDID, "", "")
		if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "GET, POST" {
			t.Fatal(resp.StatusCode, resp.Header)
		}
		noPost := tlsServer(t, NewHandler(r, nil, WithoutPOST()))
		resp, _ = get(t, noPost, http.MethodPost, DefaultPathPrefix+testDID, "", "")
		if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "GET" {
			t.Fatal(resp.StatusCode)
		}
	})
	t.Run("res10-crd20261001#bindings-https.2 requests without TLS are refused", func(t *testing.T) {
		plain := httptest.NewServer(NewHandler(r, nil))
		defer plain.Close()
		resp, err := plain.Client().Get(plain.URL + DefaultPathPrefix + testDID)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || resp.Header.Get("Content-Type") != MediaTypeProblem {
			t.Fatal(resp.StatusCode)
		}
		proxied := httptest.NewServer(NewHandler(r, nil, WithPlaintext(true)))
		defer proxied.Close()
		resp, err = proxied.Client().Get(proxied.URL + DefaultPathPrefix + testDID)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}
	})
}

func TestHandlerRequestParsing(t *testing.T) {
	r := &fakeResolver{result: okResult()}
	d := &fakeDereferencer{result: resolution.DereferenceResult{
		ContentStream:         []byte("hello"),
		DereferencingMetadata: resolution.DereferencingMetadata{ContentType: "text/plain"},
	}}
	srv := tlsServer(t, NewHandler(r, d, WithPathPrefix("/r"), WithRequestLimit(64)))
	// Raw DID with a percent-encoded octet: taken as written.
	get(t, srv, "GET", "/r/did:example:12%3A34", "application/did", "")
	if id, _ := r.last(t); id != "did:example:12%3A34" {
		t.Fatal(id)
	}
	// Encoded DID with options.
	get(t, srv, "GET", "/r/did%3Aexample%3A12%253A34?versionId=7&noCache=true&expandRelativeUrls=false&x=1", "application/did", "")
	id, opts := r.last(t)
	if id != "did:example:12%3A34" || opts.VersionID != "7" || !opts.NoCache || opts.ExpandRelativeURLs || opts.Extra["x"] != "1" || opts.Accept != "application/did" {
		t.Fatal(id, opts)
	}
	// Raw DID URL with a query (Example 25) is dereferenced.
	get(t, srv, "GET", "/r/did:example:123?service=files&relativeRef=/resume.pdf", "text/plain", "")
	if u, o := d.last(t); u != "did:example:123?service=files&relativeRef=/resume.pdf" || o.Accept != "text/plain" {
		t.Fatal(u, o)
	}
	// Encoded DID URL with a fragment and options.
	get(t, srv, "GET", "/r/did%3Aexample%3A123%23k?verificationRelationship=authentication", "", "")
	if u, o := d.last(t); u != "did:example:123#k" || o.VerificationRelationship != "authentication" || o.Accept != "" {
		t.Fatal(u, o)
	}
	// A plain DID with Accept application/did-url-dereferencing is
	// dereferenced.
	get(t, srv, "GET", "/r/did:example:123", spec.MediaTypeDIDURLDereferencing, "")
	if u, _ := d.last(t); u != testDID {
		t.Fatal(u)
	}
	// POST body options.
	get(t, srv, "POST", "/r/did:example:123?service=x", "text/plain", `{"verificationRelationship":"assertionMethod"}`)
	if u, o := d.last(t); u != "did:example:123?service=x" || o.VerificationRelationship != "assertionMethod" {
		t.Fatal(u, o)
	}
	bad := []struct {
		method, path, accept, body string
		status                     int
		code                       resolution.Code
	}{
		{"GET", "/other/did:example:123", "", "", 404, ""},
		{"GET", "/r/", "", "", 404, ""},
		{"GET", "/r/notadid", "", "", 400, resolution.CodeInvalidDID},
		{"GET", "/r/did:example:/p", "", "", 400, resolution.CodeInvalidDIDURL},
		{"GET", "/r/did%3Aexample%3A%25zz", "", "", 400, resolution.CodeInvalidDID},
		{"GET", "/r/did:example:123", "bad accept;", "", 400, resolution.CodeInvalidOptions},
		{"GET", "/r/did%3Aexample%3A123?noCache=yes", "", "", 400, resolution.CodeInvalidOptions},
		{"GET", "/r/did%3Aexample%3A123?versionId=1&versionId=2", "", "", 400, resolution.CodeInvalidOptions},
		{"GET", "/r/did%3Aexample%3A123?accept=application/did", "", "", 400, resolution.CodeInvalidOptions},
		{"GET", "/r/did%3Aexample%3A123?a=%zz", "", "", 400, resolution.CodeInvalidOptions},
		{"GET", "/r/did%3Aexample%3A123?versionTime=yesterday", "", "", 400, resolution.CodeInvalidOptions},
		{"GET", "/r/did%3Aexample%3A123%23k?verificationRelationship=%C3%A9", "", "", 400, resolution.CodeInvalidOptions},
		{"GET", "/r/did:example:123", "application/did;q=2", "", 400, resolution.CodeInvalidOptions},
		{"POST", "/r/did:example:123", "", "[1]", 400, resolution.CodeInvalidOptions},
		{"POST", "/r/did:example:123", "", "{", 400, resolution.CodeInvalidOptions},
		{"POST", "/r/did:example:123", "", `{"pad":"` + strings.Repeat("x", 100) + `"}`, 400, resolution.CodeInvalidOptions},
		{"POST", "/r/did%3Aexample%3A123?versionId=1", "", "", 400, resolution.CodeInvalidOptions},
		{"POST", "/r/did:example:123", "", `{"versionId":5}`, 400, resolution.CodeInvalidOptions},
		{"POST", "/r/did%3Aexample%3A123%23k", "", `{"verificationRelationship":5}`, 400, resolution.CodeInvalidOptions},
	}
	for _, b := range bad {
		resp, body := get(t, srv, b.method, b.path, b.accept, b.body)
		var e resolution.Error
		_ = json.Unmarshal([]byte(body), &e)
		if resp.StatusCode != b.status || resp.Header.Get("Content-Type") != MediaTypeProblem || (b.code != "" && e.Code() != b.code) || e.Status != b.status {
			t.Errorf("%s %s: %d %s", b.method, b.path, resp.StatusCode, body)
		}
	}
	// The encoded DID URL form is needed for a fragment, which HTTP never
	// sends: a raw "#" ends the request path.
	resp, _ := get(t, srv, "POST", "/r/did:example:123", "", "")
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
}

func TestHandlerStatusTable(t *testing.T) {
	codes := map[resolution.Code]int{
		resolution.CodeInvalidDID: 400, resolution.CodeInvalidDIDURL: 400, resolution.CodeInvalidOptions: 400,
		resolution.CodeNotFound: 404, resolution.CodeRepresentationNotSupported: 406,
		resolution.CodeInvalidDIDDocument: 500, resolution.CodeMethodNotSupported: 501,
		resolution.CodeFeatureNotSupported: 501, resolution.CodeInternalError: 500,
		resolution.CodeInvalidVerificationMethod: 400, resolution.Code("https://ext.example/E"): 500,
	}
	t.Run("res10-crd20261001#bindings-https.31 the status code corresponds to the error type", func(t *testing.T) {
		for code, status := range codes {
			e := resolution.NewError(code, "detail")
			r := &fakeResolver{result: resolution.ErrorResult(e)}
			d := &fakeDereferencer{result: resolution.ErrorDereferenceResult(e)}
			c, _, srv := pair(t, r, d, nil)
			for _, accept := range []string{"application/did", ""} {
				resp, _ := get(t, srv, "GET", DefaultPathPrefix+testDID, accept, "")
				if resp.StatusCode != status {
					t.Errorf("%s accept %q: %d want %d", code, accept, resp.StatusCode, status)
				}
				resp, _ = get(t, srv, "GET", DefaultPathPrefix+"did:example:123/p", accept, "")
				if resp.StatusCode != status {
					t.Errorf("deref %s accept %q: %d want %d", code, accept, resp.StatusCode, status)
				}
			}
			// The client gets the same error type back from both forms.
			for _, accept := range []string{"application/did", ""} {
				res := c.Resolve(t.Context(), mustDID(t, testDID), resolution.ResolutionOptions{Accept: accept})
				if !errors.Is(res.ResolutionMetadata.Error, e) || res.ResolutionMetadata.Error.Detail != "detail" {
					t.Errorf("client %s accept %q: %v", code, accept, res.ResolutionMetadata.Error)
				}
				dr := c.Dereference(t.Context(), mustURL(t, "did:example:123/p"), resolution.DereferenceOptions{Accept: accept})
				if !errors.Is(dr.DereferencingMetadata.Error, e) {
					t.Errorf("client deref %s accept %q: %v", code, accept, dr.DereferencingMetadata.Error)
				}
			}
		}
	})
	t.Run("cid10#processing-errors.1 errors over HTTP are RFC 9457 objects", func(t *testing.T) {
		r := &fakeResolver{result: resolution.ErrorResult(resolution.NewError(resolution.CodeNotFound, "no such DID"))}
		srv := tlsServer(t, NewHandler(r, nil))
		resp, body := get(t, srv, "GET", DefaultPathPrefix+testDID, "application/did", "")
		var obj map[string]any
		if err := json.Unmarshal([]byte(body), &obj); err != nil {
			t.Fatal(err)
		}
		if resp.Header.Get("Content-Type") != MediaTypeProblem || obj["type"] != "https://www.w3.org/ns/did#NOT_FOUND" ||
			obj["title"] != "Not found" || obj["status"] != float64(404) || obj["detail"] != "no such DID" {
			t.Fatal(resp.Header, body)
		}
	})
}

func TestHandlerResolutionResponses(t *testing.T) {
	proof := map[string]any{"type": "DataIntegrityProof", "proofValue": "z1"}
	full := okResult()
	full.ResolutionMetadata.Proof = []map[string]any{proof}
	full.DocumentMetadata = document.Metadata{VersionID: "3", Extra: map[string]any{"method": map[string]any{"x": "y"}}}
	r := &fakeResolver{result: full}
	c, _, srv := pair(t, r, nil, nil)
	for _, id := range []string{
		"res10-crd20261001#bindings-https.34 the DID resolution function",
		"res10-crd20261001#bindings-https.35 Content-Type application/did-resolution",
		"res10-crd20261001#bindings-https.36 the body contains a DID resolution result",
		"res10-crd20261001#bindings-https.37 the result is that of the DID resolution function",
	} {
		t.Run(id, func(t *testing.T) {
			resp, body := get(t, srv, "GET", DefaultPathPrefix+testDID, spec.MediaTypeDIDResolution, "")
			if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != spec.MediaTypeDIDResolution {
				t.Fatal(resp.StatusCode, resp.Header)
			}
			var rr map[string]json.RawMessage
			if err := json.Unmarshal([]byte(body), &rr); err != nil {
				t.Fatal(err)
			}
			if string(rr["didDocument"]) != docV11 || !strings.Contains(string(rr["didResolutionMetadata"]), `"contentType":"application/did"`) ||
				!strings.Contains(string(rr["didDocumentMetadata"]), `"versionId":"3"`) {
				t.Fatal(body)
			}
		})
	}
	for _, id := range []string{
		"res10-crd20261001#bindings-https.38 a successful resolve returning a didDocument",
		"res10-crd20261001#bindings-https.39 the status code is 200",
		"res10-crd20261001#bindings-https.40 the response contains a Content-Type header",
		"res10-crd20261001#bindings-https.41 Content-Type is the contentType of didResolutionMetadata",
		"res10-crd20261001#bindings-https.42 the body is the didDocument in that representation",
	} {
		t.Run(id, func(t *testing.T) {
			resp, body := get(t, srv, "GET", DefaultPathPrefix+testDID, "application/did", "")
			if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != spec.MediaTypeDID || body != docV11 {
				t.Fatal(resp.StatusCode, resp.Header, body)
			}
			if _, o := r.last(t); o.Accept != "application/did" {
				t.Fatal(o)
			}
		})
	}
	t.Run("res10-crd20261001#resolver-architectures.3 proofs in didResolutionMetadata reach the client", func(t *testing.T) {
		res := c.Resolve(t.Context(), mustDID(t, testDID), resolution.ResolutionOptions{})
		if len(res.ResolutionMetadata.Proof) != 1 || res.ResolutionMetadata.Proof[0]["proofValue"] != "z1" {
			t.Fatal(res.ResolutionMetadata)
		}
	})
	t.Run("wildcard Accept asks for the complete result", func(t *testing.T) {
		for _, a := range []string{"*/*", "application/*", "application/did;q=0.5, */*"} {
			resp, _ := get(t, srv, "GET", DefaultPathPrefix+testDID, a, "")
			if resp.Header.Get("Content-Type") != spec.MediaTypeDIDResolution {
				t.Errorf("%s: %s", a, resp.Header.Get("Content-Type"))
			}
		}
	})
}

func TestHandlerDeactivated(t *testing.T) {
	deact := resolution.Result{DocumentMetadata: document.Metadata{Deactivated: true}}
	r := &fakeResolver{result: deact}
	d := &fakeDereferencer{result: resolution.DereferenceResult{ContentMetadata: document.Metadata{Deactivated: true}}}
	c, _, srv := pair(t, r, d, nil)
	for _, id := range []string{
		"res10-crd20261001#bindings-https.32 deactivated true in didDocumentMetadata or contentMetadata",
		"res10-crd20261001#bindings-https.33 the status code is 410",
	} {
		t.Run(id, func(t *testing.T) {
			for _, path := range []string{DefaultPathPrefix + testDID, DefaultPathPrefix + "did:example:123/p"} {
				for _, accept := range []string{"", "application/did"} {
					resp, body := get(t, srv, "GET", path, accept, "")
					if resp.StatusCode != http.StatusGone || !strings.Contains(body, `"deactivated":true`) {
						t.Errorf("%s %q: %d %s", path, accept, resp.StatusCode, body)
					}
				}
			}
			for _, accept := range []string{"", "application/did"} {
				res := c.Resolve(t.Context(), mustDID(t, testDID), resolution.ResolutionOptions{Accept: accept})
				if !res.DocumentMetadata.Deactivated || res.Document != nil || res.ResolutionMetadata.Error != nil {
					t.Errorf("client %q: %+v", accept, res)
				}
				dr := c.Dereference(t.Context(), mustURL(t, "did:example:123/p"), resolution.DereferenceOptions{Accept: accept})
				if !dr.ContentMetadata.Deactivated || dr.ContentStream != nil {
					t.Errorf("client deref %q: %+v", accept, dr)
				}
			}
		})
	}
}

func TestHandlerDereferenceResponses(t *testing.T) {
	d := &fakeDereferencer{result: resolution.DereferenceResult{
		ContentStream:         []byte(docV11),
		DereferencingMetadata: resolution.DereferencingMetadata{ContentType: spec.MediaTypeDID},
		ContentMetadata:       document.Metadata{VersionID: "2"},
	}}
	c, _, srv := pair(t, nil, d, nil)
	for _, id := range []string{
		"res10-crd20261001#bindings-https.43 the DID URL dereferencing function",
		"res10-crd20261001#bindings-https.44 Content-Type application/did-url-dereferencing",
		"res10-crd20261001#bindings-https.45 the body contains a DID URL dereferencing result",
		"res10-crd20261001#bindings-https.46 the result is that of the DID URL dereferencing function",
	} {
		t.Run(id, func(t *testing.T) {
			resp, body := get(t, srv, "GET", DefaultPathPrefix+"did%3Aexample%3A123?versionId=2", spec.MediaTypeDIDURLDereferencing, "")
			want := `{"content":` + docV11 + `,"dereferencingMetadata":{"contentType":"application/did"},"contentMetadata":{"versionId":"2"}}`
			if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != spec.MediaTypeDIDURLDereferencing || body != want {
				t.Fatal(resp.StatusCode, body)
			}
			dr := c.Dereference(t.Context(), mustURL(t, "did:example:123?versionId=2"), resolution.DereferenceOptions{})
			if doc, ok := dr.ContentStream.(*document.Document); !ok || doc.ID().String() != testDID || dr.ContentMetadata.VersionID != "2" {
				t.Fatal(dr)
			}
		})
	}
	for _, id := range []string{
		"res10-crd20261001#bindings-https.52 a successful dereference with any other contentType",
		"res10-crd20261001#bindings-https.53 the status code is 200",
		"res10-crd20261001#bindings-https.54 the response contains a Content-Type header",
		"res10-crd20261001#bindings-https.55 Content-Type is the contentType of dereferencingMetadata",
		"res10-crd20261001#bindings-https.56 the body is the contentStream in that representation",
	} {
		t.Run(id, func(t *testing.T) {
			resp, body := get(t, srv, "GET", DefaultPathPrefix+"did:example:123?versionId=2", spec.MediaTypeDID, "")
			if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != spec.MediaTypeDID || body != docV11 {
				t.Fatal(resp.StatusCode, body)
			}
		})
	}
	uris := &fakeDereferencer{result: resolution.DereferenceResult{
		ContentStream:         []string{"https://files.example/resume.pdf"},
		DereferencingMetadata: resolution.DereferencingMetadata{ContentType: spec.MediaTypeURIList},
	}}
	uc, _, usrv := pair(t, nil, uris, nil)
	for _, id := range []string{
		"res10-crd20261001#bindings-https.47 a successful dereference returning text/uri-list",
		"res10-crd20261001#bindings-https.48 the status code is 303",
		"res10-crd20261001#bindings-https.49 the response contains a Location header",
		"res10-crd20261001#bindings-https.50 Location is the selected service endpoint URL",
		"res10-crd20261001#bindings-https.51 the body is empty",
	} {
		t.Run(id, func(t *testing.T) {
			resp, body := get(t, usrv, "GET", DefaultPathPrefix+"did:example:123?service=files&relativeRef=/resume.pdf", spec.MediaTypeURIList, "")
			if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "https://files.example/resume.pdf" || body != "" || resp.Header.Get("Content-Type") != "" {
				t.Fatal(resp.StatusCode, resp.Header, body)
			}
			dr := uc.Dereference(t.Context(), mustURL(t, "did:example:123?service=files&relativeRef=/resume.pdf"), resolution.DereferenceOptions{Accept: spec.MediaTypeURIList})
			list, ok := dr.ContentStream.([]string)
			if !ok || len(list) != 1 || list[0] != "https://files.example/resume.pdf" || dr.DereferencingMetadata.ContentType != spec.MediaTypeURIList ||
				dr.ContentMetadata.Extra["contentType"] != spec.MediaTypeURIList {
				t.Fatal(dr)
			}
		})
	}
	// The complete result of a URL list is a 200 JSON result.
	resp, body := get(t, usrv, "GET", DefaultPathPrefix+"did:example:123?service=files", "", "")
	if resp.StatusCode != 200 || !strings.Contains(body, `"content":["https://files.example/resume.pdf"]`) {
		t.Fatal(resp.StatusCode, body)
	}
	dr := uc.Dereference(t.Context(), mustURL(t, "did:example:123?service=files"), resolution.DereferenceOptions{})
	if l, ok := dr.ContentStream.([]string); !ok || len(l) != 1 {
		t.Fatal(dr)
	}
}

func TestHandlerContentForms(t *testing.T) {
	doc, _ := document.NewBuilder(mustDID(t, testDID)).Build()
	type want struct {
		status int
		body   string
	}
	cases := []struct {
		name        string
		content     any
		ct          string
		producer    bool
		alone, full want
	}{
		{"string", "hi", "text/plain", false, want{200, "hi"}, want{200, `"hi"`}},
		{"bytes not JSON", []byte("hi"), "text/plain", false, want{200, "hi"}, want{200, `"hi"`}},
		{"raw JSON", json.RawMessage(`{"a":1}`), "application/json", false, want{200, `{"a":1}`}, want{200, `{"a":1}`}},
		{"map", map[string]any{"a": "b"}, "application/json", false, want{200, `{"a":"b"}`}, want{200, `{"a":"b"}`}},
		{"list", []any{"a"}, "application/json", false, want{200, `["a"]`}, want{200, `["a"]`}},
		{"document", doc, spec.MediaTypeDIDJSON, true, want{200, `{"id":"did:example:123"}`}, want{200, `{"id":"did:example:123"}`}},
		{"document without producer", doc, spec.MediaTypeDIDJSON, false, want{500, ""}, want{500, ""}},
		{"document with other type", doc, "text/plain", true, want{500, ""}, want{500, ""}},
		{"url list as text", []string{"https://a.example/"}, "text/plain", false, want{200, "https://a.example/\r\n"}, want{200, `["https://a.example/"]`}},
		{"unsupported", 42, "text/plain", false, want{500, ""}, want{500, ""}},
		{"no content type", []byte("x"), "", false, want{500, ""}, want{200, `"x"`}},
		{"no content", nil, "text/plain", false, want{500, ""}, want{200, `null`}},
		{"binary bytes", []byte{0xff}, "application/octet-stream", false, want{200, "\xff"}, want{500, ""}},
	}
	for _, tc := range cases {
		d := &fakeDereferencer{result: resolution.DereferenceResult{
			ContentStream:         tc.content,
			DereferencingMetadata: resolution.DereferencingMetadata{ContentType: tc.ct},
		}}
		var opts []HandlerOption
		if tc.producer {
			opts = append(opts, WithProducer(stubProducer{}))
		}
		srv := tlsServer(t, NewHandler(nil, d, opts...))
		accept := tc.ct
		if accept == "" {
			accept = "text/plain"
		}
		resp, body := get(t, srv, "GET", DefaultPathPrefix+"did:example:123/p", accept, "")
		if resp.StatusCode != tc.alone.status || (tc.alone.status == 200 && body != tc.alone.body) {
			t.Errorf("%s alone: %d %q", tc.name, resp.StatusCode, body)
		}
		resp, body = get(t, srv, "GET", DefaultPathPrefix+"did:example:123/p", "", "")
		if resp.StatusCode != tc.full.status {
			t.Errorf("%s full: %d %q", tc.name, resp.StatusCode, body)
			continue
		}
		if tc.full.status == 200 {
			var dr map[string]json.RawMessage
			_ = json.Unmarshal([]byte(body), &dr)
			if string(dr["content"]) != tc.full.body {
				t.Errorf("%s full: %s", tc.name, body)
			}
		}
	}
	// 303 needs an absolute URL in the content.
	for _, content := range []any{[]string{}, "relative/x", []byte("https://a.example/\n"), 5} {
		d := &fakeDereferencer{result: resolution.DereferenceResult{
			ContentStream:         content,
			DereferencingMetadata: resolution.DereferencingMetadata{ContentType: spec.MediaTypeURIList},
		}}
		srv := tlsServer(t, NewHandler(nil, d))
		resp, _ := get(t, srv, "GET", DefaultPathPrefix+"did:example:123?service=x", spec.MediaTypeURIList, "")
		wantStatus := 500
		if b, ok := content.([]byte); ok && len(b) > 0 {
			wantStatus = 303
		}
		if resp.StatusCode != wantStatus {
			t.Errorf("%v: %d", content, resp.StatusCode)
		}
	}
}

func TestHandlerDocumentForms(t *testing.T) {
	doc, _ := document.NewBuilder(mustDID(t, testDID)).Build()
	cases := []struct {
		name   string
		res    resolution.Result
		opts   []HandlerOption
		alone  int
		full   int
		inBody string
	}{
		{"produced", resolution.Result{Document: doc, ResolutionMetadata: resolution.ResolutionMetadata{ContentType: spec.MediaTypeDIDJSON}},
			[]HandlerOption{WithProducer(stubProducer{})}, 200, 200, `{"id":"did:example:123"}`},
		{"producer fails", resolution.Result{Document: doc, ResolutionMetadata: resolution.ResolutionMetadata{ContentType: spec.MediaTypeDIDJSON}},
			[]HandlerOption{WithProducer(stubProducer{err: errors.New("boom")})}, 500, 500, ""},
		{"no producer", resolution.Result{Document: doc, ResolutionMetadata: resolution.ResolutionMetadata{ContentType: spec.MediaTypeDIDJSON}},
			nil, 500, 500, ""},
		{"no contentType", resolution.Result{Raw: []byte(docV11)}, nil, 500, 500, ""},
		{"no document", resolution.Result{ResolutionMetadata: resolution.ResolutionMetadata{ContentType: spec.MediaTypeDID}}, nil, 500, 200, "null"},
		{"not JSON", resolution.Result{Raw: []byte{0xa1}, ResolutionMetadata: resolution.ResolutionMetadata{ContentType: "application/did+cbor"}}, nil, 200, 500, ""},
		{"unwritable metadata", resolution.Result{Raw: []byte(docV11), ResolutionMetadata: resolution.ResolutionMetadata{ContentType: spec.MediaTypeDID,
			Extra: map[string]any{"bad": make(chan int)}}}, nil, 200, 500, ""},
	}
	for _, tc := range cases {
		r := &fakeResolver{result: tc.res}
		srv := tlsServer(t, NewHandler(r, nil, tc.opts...))
		resp, _ := get(t, srv, "GET", DefaultPathPrefix+testDID, "application/did+json", "")
		if resp.StatusCode != tc.alone {
			t.Errorf("%s alone: %d", tc.name, resp.StatusCode)
		}
		resp, body := get(t, srv, "GET", DefaultPathPrefix+testDID, "", "")
		if resp.StatusCode != tc.full || (tc.full == 200 && !strings.Contains(body, `"didDocument":`+tc.inBody)) {
			t.Errorf("%s full: %d %s", tc.name, resp.StatusCode, body)
		}
	}
	// Unwritable dereferencing metadata.
	d := &fakeDereferencer{result: resolution.DereferenceResult{ContentStream: []byte("x"),
		DereferencingMetadata: resolution.DereferencingMetadata{ContentType: "text/plain", Extra: map[string]any{"bad": make(chan int)}}}}
	srv := tlsServer(t, NewHandler(nil, d))
	if resp, _ := get(t, srv, "GET", DefaultPathPrefix+"did:example:123/p", "", ""); resp.StatusCode != 500 {
		t.Fatal(resp.StatusCode)
	}
	// Missing functions.
	none := tlsServer(t, NewHandler(nil, nil))
	for _, p := range []string{testDID, "did:example:123/p"} {
		resp, body := get(t, none, "GET", DefaultPathPrefix+p, "", "")
		if resp.StatusCode != 501 || !strings.Contains(body, "FEATURE_NOT_SUPPORTED") {
			t.Errorf("%s: %d %s", p, resp.StatusCode, body)
		}
	}
	// A type outside the binding table keeps its own status.
	rec := httptest.NewRecorder()
	writeProblem(rec, &resolution.Error{Type: "about:blank", Status: 418, Detail: string([]byte{0xff})})
	if rec.Code != 418 {
		t.Fatal(rec.Code)
	}
}
