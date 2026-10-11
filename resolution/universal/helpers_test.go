package universal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
)

const (
	testDID = "did:example:123"
	docV11  = `{"@context":["https://www.w3.org/ns/did/v1.1"],"id":"did:example:123"}`
)

// stubConsumer stands in for the consumer player: it accepts a JSON object
// with an id under a DID or low-precision media type and records the media
// types it was called with.
type stubConsumer struct {
	mu    *sync.Mutex
	types *[]string
}

func newConsumer() stubConsumer { return stubConsumer{mu: &sync.Mutex{}, types: &[]string{}} }

func (c stubConsumer) Consume(data []byte, mediaType string, _ representation.ConsumeOptions) (*document.Document, representation.ConsumeInfo, error) {
	c.mu.Lock()
	*c.types = append(*c.types, mediaType)
	c.mu.Unlock()
	mt, err := representation.NormalizeMediaType(mediaType)
	if err != nil {
		return nil, representation.ConsumeInfo{}, err
	}
	info := representation.ConsumeInfo{DetectedVersion: spec.V11}
	switch {
	case mt == spec.MediaTypeDIDJSON:
		info.DetectedVersion = spec.V10
	case mt == spec.MediaTypeDIDLDJSON:
		info = representation.ConsumeInfo{DetectedVersion: spec.V10, IsJSONLD: true}
	case mt == spec.MediaTypeDID, representation.IsLowPrecision(mt):
	default:
		return nil, info, errors.New("stub: unsupported media type " + mt)
	}
	var obj struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, info, err
	}
	d, err := did.Parse(obj.ID)
	if err != nil {
		return nil, info, err
	}
	doc, err := document.NewBuilder(d).Build()
	return doc, info, err
}

func (c stubConsumer) seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), *c.types...)
}

// stubProducer writes {"id": ...} with the media type of the options.
type stubProducer struct{ err error }

func (p stubProducer) Produce(d *document.Document, opts representation.ProduceOptions) ([]byte, string, error) {
	if p.err != nil {
		return nil, "", p.err
	}
	data, _ := json.Marshal(map[string]string{"id": d.ID().String()})
	return data, representation.MediaTypeFor(opts.Version, opts.JSONLD), nil
}

// fakeResolver returns a fixed result and records its calls.
type fakeResolver struct {
	mu     sync.Mutex
	result resolution.Result
	calls  []resolution.ResolutionOptions
	dids   []string
}

func (f *fakeResolver) Resolve(_ context.Context, d did.DID, opts resolution.ResolutionOptions) resolution.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, opts)
	f.dids = append(f.dids, d.String())
	return f.result
}

func (f *fakeResolver) last(t *testing.T) (string, resolution.ResolutionOptions) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("resolver not called")
	}
	return f.dids[len(f.dids)-1], f.calls[len(f.calls)-1]
}

// fakeDereferencer returns a fixed result and records its calls.
type fakeDereferencer struct {
	mu     sync.Mutex
	result resolution.DereferenceResult
	calls  []resolution.DereferenceOptions
	urls   []string
}

func (f *fakeDereferencer) Dereference(_ context.Context, u did.DIDURL, opts resolution.DereferenceOptions) resolution.DereferenceResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, opts)
	f.urls = append(f.urls, u.String())
	return f.result
}

func (f *fakeDereferencer) last(t *testing.T) (string, resolution.DereferenceOptions) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("dereferencer not called")
	}
	return f.urls[len(f.urls)-1], f.calls[len(f.calls)-1]
}

func tlsServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// pair starts a TLS server with a Handler over r and d and returns a client
// of it.
func pair(t *testing.T, r resolution.Resolver, d resolution.Dereferencer, copts []ClientOption, hopts ...HandlerOption) (*Client, stubConsumer, *httptest.Server) {
	t.Helper()
	srv := tlsServer(t, NewHandler(r, d, hopts...))
	cons := newConsumer()
	c, err := NewClient(srv.URL+DefaultPathPrefix, srv.Client(), cons, copts...)
	if err != nil {
		t.Fatal(err)
	}
	return c, cons, srv
}

// recorded is one request seen by a recording server.
type recorded struct {
	method, path, rawPath, query, accept, contentType string
	body                                              []byte
	tls                                               bool
}

// recorder starts a TLS server that records each request and answers with
// respond.
func recorder(t *testing.T, respond http.HandlerFunc) (*httptest.Server, func() recorded) {
	t.Helper()
	var (
		mu   sync.Mutex
		last recorded
	)
	srv := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		last = recorded{method: r.Method, path: r.URL.Path, rawPath: r.URL.EscapedPath(), query: r.URL.RawQuery,
			accept: r.Header.Get("Accept"), contentType: r.Header.Get("Content-Type"), body: body, tls: r.TLS != nil}
		mu.Unlock()
		respond(w, r)
	}))
	return srv, func() recorded {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

func mustDID(t *testing.T, s string) did.DID {
	t.Helper()
	d, err := did.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustURL(t *testing.T, s string) did.DIDURL {
	t.Helper()
	u, err := did.ParseURL(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func respondJSON(status int, contentType, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func newClient(t *testing.T, srv *httptest.Server, opts ...ClientOption) (*Client, stubConsumer) {
	t.Helper()
	cons := newConsumer()
	c, err := NewClient(srv.URL+DefaultPathPrefix, srv.Client(), cons, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c, cons
}

func okResult() resolution.Result {
	return resolution.Result{
		Raw:                []byte(docV11),
		ResolutionMetadata: resolution.ResolutionMetadata{ContentType: spec.MediaTypeDID},
	}
}
