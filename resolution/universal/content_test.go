package universal_test

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/testutil"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/universal"
	"github.com/sage-x-project/did-go/resolver"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// relationships is a DID 1.1 JSON-LD document with a verification method, a
// service and a map inside an extension that its inline context defines.
const relationships = `{"@context":["https://www.w3.org/ns/did/v1.1",{"fooExtension":"https://e.example/foo","value":"https://e.example/value"}],` +
	`"id":"did:example:relationships",` +
	`"verificationMethod":[{"id":"did:example:relationships#key-1","type":"Multikey","controller":"did:example:relationships",` +
	`"publicKeyMultibase":"z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}],` +
	`"authentication":["did:example:relationships#key-1"],` +
	`"service":[{"id":"did:example:relationships#files","type":"LinkedDomains","serviceEndpoint":"https://files.example/"}],` +
	`"fooExtension":{"id":"did:example:relationships#m","value":1}}`

const (
	methodJSON = `{"id":"did:example:relationships#key-1","type":"Multikey","controller":"did:example:relationships",` +
		`"publicKeyMultibase":"z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}`
	serviceJSON = `{"id":"did:example:relationships#files","type":"LinkedDomains","serviceEndpoint":"https://files.example/"}`
	mapJSON     = `{"id":"did:example:relationships#m","value":1}`
)

// server serves the real dereferencer over a resolver of the relationships
// document through Handler, over TLS, and returns a Client of it.
func server(t *testing.T) (*httptest.Server, *universal.Client) {
	t.Helper()
	drv := &testutil.Driver{Method: "example", Media: []string{spec.MediaTypeDID},
		Func: testutil.Static(relationships, spec.MediaTypeDID, document.Metadata{})}
	reg, err := method.NewRegistry(drv)
	if err != nil {
		t.Fatal(err)
	}
	p := producer.New()
	r, err := resolver.New(reg, consumer.New(), p)
	if err != nil {
		t.Fatal(err)
	}
	documentResolver, err := resolver.New(reg, consumer.New(), p, resolver.ForDereferencing())
	if err != nil {
		t.Fatal(err)
	}
	d, err := dereferencer.New(documentResolver, p)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(universal.NewHandler(r, d, universal.WithProducer(p)))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	c, err := universal.NewClient(srv.URL+universal.DefaultPathPrefix, srv.Client(), consumer.New())
	if err != nil {
		t.Fatal(err)
	}
	return srv, c
}

func request(t *testing.T, srv *httptest.Server, identifier, accept string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+universal.DefaultPathPrefix+identifier, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", accept)
	hc := srv.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// TestFragmentContent dereferences DID URLs with a fragment through Handler:
// the dereferencer returns a vm.Method, a vm.Service or a document.Map, and
// the handler writes each as its JSON object under the contentType the
// dereferencer chose (application/ld+json for a fragment of application/did).
func TestFragmentContent(t *testing.T) {
	srv, client := server(t)
	cases := []struct {
		name, fragment, body string
		check                func(t *testing.T, content any)
	}{
		{"a verification method", "key-1", methodJSON, func(t *testing.T, content any) {
			m, ok := content.(vm.Method)
			if !ok || m.ID.String() != "did:example:relationships#key-1" || m.Type != "Multikey" || m.PublicKeyMultibase == "" {
				t.Fatalf("%T %+v", content, content)
			}
		}},
		{"a service", "files", serviceJSON, func(t *testing.T, content any) {
			s, ok := content.(vm.Service)
			if !ok || s.ID != "did:example:relationships#files" || len(s.ServiceEndpoint) != 1 || s.ServiceEndpoint[0].URL != "https://files.example/" {
				t.Fatalf("%T %+v", content, content)
			}
		}},
		{"a map", "m", mapJSON, func(t *testing.T, content any) {
			m, ok := content.(document.Map)
			if !ok {
				t.Fatalf("%T %+v", content, content)
			}
			if v, _ := m.Get("value"); v != document.Integer(1) {
				t.Fatalf("%+v", m)
			}
		}},
	}
	for _, tc := range cases {
		identifier := "did%3Aexample%3Arelationships%23" + tc.fragment
		didURL := testutil.MustURL("did:example:relationships#" + tc.fragment)
		t.Run("res10-crd20261001#bindings-https.11 res10-crd20261001#bindings-https.17 res10-crd20261001#bindings-https.52 "+
			"res10-crd20261001#bindings-https.39 res10-crd20261001#bindings-https.40 res10-crd20261001#bindings-https.42 "+
			tc.name+" is written alone for Accept application/did", func(t *testing.T) {
			resp, body := request(t, srv, identifier, spec.MediaTypeDID)
			if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != spec.MediaTypeLDJSON || body != tc.body {
				t.Fatalf("%d %s %s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
			}
			dr := client.Dereference(t.Context(), didURL, resolution.DereferenceOptions{Accept: spec.MediaTypeDID})
			if dr.DereferencingMetadata.Error != nil || dr.DereferencingMetadata.ContentType != spec.MediaTypeLDJSON {
				t.Fatalf("%+v", dr.DereferencingMetadata)
			}
			tc.check(t, dr.ContentStream)
		})
		t.Run("res10-crd20261001#bindings-https.34 res10-crd20261001#bindings-https.15 res10-crd20261001#bindings-https.44 "+
			"res10-crd20261001#bindings-https.45 "+tc.name+" is the content of the complete result for Accept application/did-url-dereferencing", func(t *testing.T) {
			resp, body := request(t, srv, identifier, spec.MediaTypeDIDURLDereferencing)
			if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != spec.MediaTypeDIDURLDereferencing {
				t.Fatalf("%d %s", resp.StatusCode, body)
			}
			var dr struct {
				Content               json.RawMessage `json:"content"`
				DereferencingMetadata map[string]any  `json:"dereferencingMetadata"`
			}
			if err := json.Unmarshal([]byte(body), &dr); err != nil {
				t.Fatal(err)
			}
			if string(dr.Content) != tc.body || dr.DereferencingMetadata["contentType"] != spec.MediaTypeLDJSON {
				t.Fatal(body)
			}
			res := client.Dereference(t.Context(), didURL, resolution.DereferenceOptions{})
			if res.DereferencingMetadata.Error != nil {
				t.Fatal(res.DereferencingMetadata.Error)
			}
			tc.check(t, res.ContentStream)
		})
	}
	t.Run("res10-crd20261001#bindings-https.11 an unknown fragment is NOT_FOUND", func(t *testing.T) {
		resp, body := request(t, srv, "did%3Aexample%3Arelationships%23nothing", spec.MediaTypeDID)
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "NOT_FOUND") {
			t.Fatal(resp.StatusCode, body)
		}
	})
}

// TestDocumentAndURIListContent covers the other content types of the
// dereferencer through Handler: a document produced in the representation
// of contentType, and a URI list answered with 303 when asked for alone.
func TestDocumentAndURIListContent(t *testing.T) {
	srv, client := server(t)
	t.Run("res10-crd20261001#bindings-https.55 res10-crd20261001#bindings-https.56 a document is produced in the representation of contentType", func(t *testing.T) {
		resp, body := request(t, srv, "did:example:relationships?versionId=1", spec.MediaTypeDIDJSON)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != spec.MediaTypeDIDJSON ||
			!strings.HasPrefix(body, `{"id":"did:example:relationships"`) {
			t.Fatal(resp.StatusCode, body)
		}
	})
	t.Run("res10-crd20261001#bindings-https.48 res10-crd20261001#bindings-https.50 a URI list asked for alone is a 303", func(t *testing.T) {
		resp, body := request(t, srv, "did:example:relationships?service=files&relativeRef=/a.pdf", spec.MediaTypeURIList)
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "https://files.example/a.pdf" || body != "" {
			t.Fatal(resp.StatusCode, resp.Header, body)
		}
		dr := client.Dereference(t.Context(), testutil.MustURL("did:example:relationships?service=files&relativeRef=/a.pdf"),
			resolution.DereferenceOptions{Accept: spec.MediaTypeURIList})
		if l, ok := dr.ContentStream.([]string); !ok || len(l) != 1 || l[0] != "https://files.example/a.pdf" {
			t.Fatalf("%+v", dr)
		}
	})
}

// TestClientFragmentDecoding checks how Client reads JSON content of a
// fragment: objects the consumer accepts as a method or a service become
// vm.Method or vm.Service, other objects document.Map, other JSON bytes.
func TestClientFragmentDecoding(t *testing.T) {
	cases := []struct {
		name, ct, body string
		check          func(any) bool
	}{
		{"a method", spec.MediaTypeJSON, methodJSON, func(v any) bool { _, ok := v.(vm.Method); return ok }},
		{"a service", spec.MediaTypeLDJSON, serviceJSON, func(v any) bool { _, ok := v.(vm.Service); return ok }},
		{"a method the consumer refuses", spec.MediaTypeLDJSON, `{"id":"#k","type":"Multikey","controller":"not a DID"}`,
			func(v any) bool { m, ok := v.(document.Map); return ok && m.Len() == 3 }},
		{"a service the consumer refuses", spec.MediaTypeLDJSON, `{"id":"#s","type":3,"serviceEndpoint":"https://e.example/"}`,
			func(v any) bool { _, ok := v.(document.Map); return ok }},
		{"another object", spec.MediaTypeJSON, mapJSON, func(v any) bool { _, ok := v.(document.Map); return ok }},
		{"an array", spec.MediaTypeJSON, `[1]`, func(v any) bool { b, ok := v.([]byte); return ok && string(b) == "[1]" }},
		{"not JSON", spec.MediaTypeJSON, `{`, func(v any) bool { b, ok := v.([]byte); return ok && string(b) == "{" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.ct)
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(srv.Close)
			c, err := universal.NewClient(srv.URL+universal.DefaultPathPrefix, srv.Client(), consumer.New())
			if err != nil {
				t.Fatal(err)
			}
			dr := c.Dereference(t.Context(), testutil.MustURL("did:example:relationships#x"), resolution.DereferenceOptions{Accept: tc.ct})
			if dr.DereferencingMetadata.Error != nil || !tc.check(dr.ContentStream) {
				t.Fatalf("%T %+v", dr.ContentStream, dr)
			}
		})
	}
}
