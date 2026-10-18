package universal_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/testutil"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/universal"
	"github.com/sage-x-project/did-go/resolver"
	"github.com/sage-x-project/did-go/spec"
)

type primaryURLTrace struct {
	inner                          resolution.Dereferencer
	mu                             sync.Mutex
	input, primary, methods, outer []string
	tls                            []bool
}

func (s *primaryURLTrace) Dereference(ctx context.Context, u did.DIDURL, o resolution.DereferenceOptions) resolution.DereferenceResult {
	s.mu.Lock()
	s.input = append(s.input, u.String())
	s.mu.Unlock()
	return s.inner.Dereference(ctx, u, o)
}

func TestPrimaryResourceTLS(t *testing.T) {
	for _, post := range []bool{false, true} {
		mode := "GET"
		if post {
			mode = "POST"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tc := range []struct{ name, input, primary string }{
				{"absent", "did:example:resources/resource", "did:example:resources/resource"},
				{"empty fragment", "did:example:resources/resource#", "did:example:resources/resource"},
				{"encoded delimiters", "did:example:resources/res%23x?relativeRef=next%23part#tail%2Fone", "did:example:resources/res%23x?relativeRef=next%23part"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					drv := &testutil.Driver{Method: "example", Media: []string{spec.MediaTypeDID}, Func: testutil.Static(`{"id":"did:example:resources"}`, spec.MediaTypeDID, document.Metadata{})}
					reg, err := method.NewRegistry(drv)
					if err != nil {
						t.Fatal(err)
					}
					p := producer.New()
					r, err := resolver.New(reg, consumer.New(), p, resolver.ForDereferencing())
					if err != nil {
						t.Fatal(err)
					}
					trace := &primaryURLTrace{}
					h := func(_ context.Context, u did.DIDURL, _ resolution.Result, _ resolution.DereferenceOptions) (resolution.DereferenceResult, bool) {
						trace.mu.Lock()
						trace.primary = append(trace.primary, u.String())
						trace.mu.Unlock()
						return resolution.DereferenceResult{ContentStream: []byte("primary:" + u.String()), DereferencingMetadata: resolution.DereferencingMetadata{ContentType: "text/plain"}}, true
					}
					d, err := dereferencer.New(r, p, dereferencer.WithResourceHandler(h))
					if err != nil {
						t.Fatal(err)
					}
					trace.inner = d
					handler := universal.NewHandler(r, trace, universal.WithProducer(p))
					srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
						trace.mu.Lock()
						trace.methods = append(trace.methods, q.Method)
						trace.outer = append(trace.outer, q.URL.Fragment)
						trace.tls = append(trace.tls, q.TLS != nil)
						trace.mu.Unlock()
						handler.ServeHTTP(w, q)
					}))
					t.Cleanup(srv.Close)
					client, err := universal.NewClient(srv.URL+universal.DefaultPathPrefix, srv.Client(), consumer.New(), universal.WithPOST(post))
					if err != nil {
						t.Fatal(err)
					}
					u := testutil.MustURL(tc.input)
					original := u
					got := client.Dereference(t.Context(), u, resolution.DereferenceOptions{Accept: "text/plain"})
					if got.DereferencingMetadata.Error != nil || got.DereferencingMetadata.ContentType != "text/plain" || string(got.ContentStream.([]byte)) != "primary:"+tc.primary {
						t.Fatalf("client result: %+v", got)
					}
					// Encode the entire DID URL, including its logical fragment, inside the
					// HTTP identifier path. An HTTP URL fragment itself is never transmitted.
					response, body := request(t, srv, url.QueryEscape(tc.input), "text/plain")
					if response.StatusCode != 200 || body != "primary:"+tc.primary {
						t.Fatalf("wire: %d %s", response.StatusCode, body)
					}
					trace.mu.Lock()
					defer trace.mu.Unlock()
					if !reflect.DeepEqual(trace.input, []string{tc.input, tc.input}) || !reflect.DeepEqual(trace.primary, []string{tc.primary, tc.primary}) || !reflect.DeepEqual(trace.methods, []string{mode, "GET"}) || !reflect.DeepEqual(trace.outer, []string{"", ""}) || !reflect.DeepEqual(trace.tls, []bool{true, true}) || u != original {
						t.Fatal("TLS same-call input/primary/method binding changed")
					}
					if strings.Contains(trace.primary[0], "#") {
						t.Fatal("fragment reached primary handler")
					}
				})
			}
		})
	}
}
