package universal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
)

func fullBody(doc string, rm, dm string) string {
	return `{"didDocument":` + doc + `,"didResolutionMetadata":` + rm + `,"didDocumentMetadata":` + dm + `}`
}

func TestClientRequestForm(t *testing.T) {
	srv, last := recorder(t, respondJSON(200, spec.MediaTypeDIDResolution, fullBody(docV11, `{"contentType":"application/did"}`, `{}`)))
	c, _ := newClient(t, srv)
	ctx := t.Context()

	t.Run("res10-crd20261001#bindings-https.4 the request URL starts with the resolver endpoint", func(t *testing.T) {
		c.Resolve(ctx, mustDID(t, testDID), resolution.ResolutionOptions{})
		if r := last(); !strings.HasPrefix(r.path, DefaultPathPrefix) || !r.tls {
			t.Fatal(r)
		}
	})
	for _, id := range []string{
		"res10-crd20261001#bindings-https.6 the DID resolution function",
		"res10-crd20261001#bindings-https.7 the input DID is appended to the request URL",
	} {
		t.Run(id, func(t *testing.T) {
			c.Resolve(ctx, mustDID(t, testDID), resolution.ResolutionOptions{})
			if r := last(); r.rawPath != DefaultPathPrefix+testDID || r.query != "" {
				t.Fatal(r)
			}
		})
	}
	for _, id := range []string{
		"res10-crd20261001#bindings-https.9 Accept application/did-resolution asks for the complete result",
		"res10-crd20261001#bindings-https.10 a complete DID resolution result",
	} {
		t.Run(id, func(t *testing.T) {
			res := c.Resolve(ctx, mustDID(t, testDID), resolution.ResolutionOptions{})
			if r := last(); r.accept != spec.MediaTypeDIDResolution || res.ResolutionMetadata.Error != nil {
				t.Fatal(r, res.ResolutionMetadata.Error)
			}
		})
	}
	t.Run("res10-crd20261001#bindings-https.11 Accept carries the accept resolution option", func(t *testing.T) {
		c.Resolve(ctx, mustDID(t, testDID), resolution.ResolutionOptions{Accept: "application/did+json"})
		if r := last(); r.accept != "application/did+json" {
			t.Fatal(r)
		}
	})
	for _, id := range []string{
		"res10-crd20261001#bindings-https.12 the DID URL dereferencing function",
		"res10-crd20261001#bindings-https.13 the input DID URL is appended to the request URL",
	} {
		t.Run(id, func(t *testing.T) {
			c.Dereference(ctx, mustURL(t, "did:example:123/path"), resolution.DereferenceOptions{})
			if r := last(); r.rawPath != DefaultPathPrefix+"did:example:123/path" {
				t.Fatal(r)
			}
			// A query or fragment is encoded so that neither is lost or read
			// as a request option.
			c.Dereference(ctx, mustURL(t, "did:example:123?service=files&relativeRef=/resume.pdf#x"), resolution.DereferenceOptions{})
			if r := last(); r.rawPath != DefaultPathPrefix+"did%3Aexample%3A123%3Fservice%3Dfiles%26relativeRef%3D%2Fresume.pdf%23x" || r.query != "" {
				t.Fatal(r)
			}
		})
	}
	for _, id := range []string{
		"res10-crd20261001#bindings-https.15 Accept application/did-url-dereferencing asks for the complete result",
		"res10-crd20261001#bindings-https.16 a complete DID URL dereferencing result",
	} {
		t.Run(id, func(t *testing.T) {
			c.Dereference(ctx, mustURL(t, "did:example:123#k"), resolution.DereferenceOptions{})
			if r := last(); r.accept != spec.MediaTypeDIDURLDereferencing {
				t.Fatal(r)
			}
		})
	}
	t.Run("res10-crd20261001#bindings-https.17 Accept carries the accept dereferencing option", func(t *testing.T) {
		c.Dereference(ctx, mustURL(t, "did:example:123#k"), resolution.DereferenceOptions{Accept: "text/uri-list"})
		if r := last(); r.accept != "text/uri-list" {
			t.Fatal(r)
		}
	})
	vt := time.Date(2021, 5, 1, 10, 0, 0, 0, time.UTC)
	for _, id := range []string{
		"res10-crd20261001#bindings-https.18 the GET binding",
		"res10-crd20261001#bindings-https.19 when options other than accept are given",
		"res10-crd20261001#bindings-https.20 the input DID is URL-encoded",
		"res10-crd20261001#bindings-https.21 options except accept are query parameters",
		"res10-crd20261001#bindings-https.22 an HTTP GET request is executed",
		"res10-crd20261001#bindings-https.23 the GET request invokes the remote resolver",
	} {
		t.Run(id, func(t *testing.T) {
			res := c.Resolve(ctx, mustDID(t, "did:example:12%3A34"), resolution.ResolutionOptions{
				Accept: "application/did", VersionID: "2", VersionTime: &vt, NoCache: true, ExpandRelativeURLs: true,
				Extra: map[string]any{"ext": "v", "n": json.Number("3")},
			})
			r := last()
			if r.method != http.MethodGet || r.rawPath != DefaultPathPrefix+"did%3Aexample%3A12%253A34" || r.accept != "application/did" || len(r.body) != 0 {
				t.Fatal(r)
			}
			want := "expandRelativeUrls=true&ext=v&n=3&noCache=true&versionId=2&versionTime=2021-05-01T10%3A00%3A00Z"
			if r.query != want {
				t.Fatalf("query %s", r.query)
			}
			_ = res
			c.Dereference(ctx, mustURL(t, "did:example:123#k"), resolution.DereferenceOptions{
				VerificationRelationship: "authentication", Extra: map[string]any{"flag": true},
			})
			if r := last(); r.rawPath != DefaultPathPrefix+"did%3Aexample%3A123%23k" || r.query != "flag=true&verificationRelationship=authentication" {
				t.Fatal(r)
			}
		})
	}
	pc, _ := newClient(t, srv, WithPOST(true))
	for _, id := range []string{
		"res10-crd20261001#bindings-https.25 the POST binding",
		"res10-crd20261001#bindings-https.26 when options other than accept are given",
		"res10-crd20261001#bindings-https.27 options except accept are a JSON body",
		"res10-crd20261001#bindings-https.28 an HTTP POST request is executed",
		"res10-crd20261001#bindings-https.29 the POST request invokes the remote resolver",
	} {
		t.Run(id, func(t *testing.T) {
			pc.Resolve(ctx, mustDID(t, testDID), resolution.ResolutionOptions{Accept: "application/did", VersionID: "2", NoCache: true})
			r := last()
			if r.method != http.MethodPost || r.rawPath != DefaultPathPrefix+testDID || r.contentType != "application/json" {
				t.Fatal(r)
			}
			var body map[string]any
			if err := json.Unmarshal(r.body, &body); err != nil || len(body) != 2 || body["versionId"] != "2" || body["noCache"] != true {
				t.Fatalf("%s %v", r.body, err)
			}
			pc.Dereference(ctx, mustURL(t, "did:example:123#k"), resolution.DereferenceOptions{VerificationRelationship: "authentication"})
			if r := last(); string(r.body) != `{"verificationRelationship":"authentication"}` {
				t.Fatalf("%s", r.body)
			}
			pc.Resolve(ctx, mustDID(t, testDID), resolution.ResolutionOptions{})
			if r := last(); r.method != http.MethodPost || len(r.body) != 0 || r.contentType != "" {
				t.Fatal(r)
			}
		})
	}
}

func TestClientEndpoint(t *testing.T) {
	cons := newConsumer()
	t.Run("res10-crd20261001#bindings-https.2 all HTTPS bindings use TLS", func(t *testing.T) {
		for _, ep := range []string{"http://resolver.example/1.0/identifiers/", "resolver.example", "https:///x",
			"https://resolver.example/?q=1", "https://resolver.example/#f", "https://u@resolver.example/", "%zz"} {
			if _, err := NewClient(ep, http.DefaultClient, cons); err == nil {
				t.Errorf("%s accepted", ep)
			}
		}
	})
	t.Run("res10-crd20261001#resolver-architectures.1 the caller names the trusted resolver", func(t *testing.T) {
		if _, err := NewClient("", http.DefaultClient, cons); err == nil {
			t.Fatal("no endpoint accepted")
		}
		c, err := NewClient("https://resolver.example/1.0/identifiers", http.DefaultClient, cons)
		if err != nil || c.endpoint != "https://resolver.example/1.0/identifiers/" {
			t.Fatal(c, err)
		}
	})
	if _, err := NewClient("https://resolver.example/", nil, cons); err == nil {
		t.Fatal("nil client accepted")
	}
	if _, err := NewClient("https://resolver.example/", http.DefaultClient, nil); err == nil {
		t.Fatal("nil consumer accepted")
	}
	c, _ := NewClient("https://resolver.example/", http.DefaultClient, cons, WithResponseLimit(0), WithTimeout(0))
	if c.cfg.limit != DefaultResponseLimit || c.cfg.timeout != DefaultTimeout {
		t.Fatal(c.cfg)
	}
}

func TestClientIPCertificate(t *testing.T) {
	// httptest serves 127.0.0.1 with a certificate issued for the IP
	// address, and the client accepts it.
	t.Run("res10-crd20261001#bindings-https.3 a certificate issued for an IP address is accepted", func(t *testing.T) {
		r := &fakeResolver{result: okResult()}
		c, _, srv := pair(t, r, nil, nil)
		if !strings.HasPrefix(srv.URL, "https://127.0.0.1:") {
			t.Fatal(srv.URL)
		}
		if res := c.Resolve(t.Context(), mustDID(t, testDID), resolution.ResolutionOptions{}); res.ResolutionMetadata.Error != nil || res.Document == nil {
			t.Fatal(res.ResolutionMetadata.Error)
		}
	})
}

func TestClientMutualTLS(t *testing.T) {
	t.Run("res10-crd20261001#resolver-architectures.2 TLS with mutual authentication through the injected client", func(t *testing.T) {
		r := &fakeResolver{result: okResult()}
		cert, leaf := clientCertificate(t)
		pool := x509.NewCertPool()
		pool.AddCert(leaf)
		srv := httptest.NewUnstartedServer(NewHandler(r, nil))
		srv.Config.ErrorLog = log.New(io.Discard, "", 0)
		srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
		srv.StartTLS()
		defer srv.Close()

		tr := srv.Client().Transport.(*http.Transport).Clone()
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
		c, _ := NewClient(srv.URL+DefaultPathPrefix, &http.Client{Transport: tr}, newConsumer())
		if res := c.Resolve(t.Context(), mustDID(t, testDID), resolution.ResolutionOptions{}); res.ResolutionMetadata.Error != nil {
			t.Fatal(res.ResolutionMetadata.Error)
		}
		// Without the client certificate the resolver refuses the channel.
		c2, _ := NewClient(srv.URL+DefaultPathPrefix, srv.Client(), newConsumer())
		res := c2.Resolve(t.Context(), mustDID(t, testDID), resolution.ResolutionOptions{})
		if res.ResolutionMetadata.Error.Code() != resolution.CodeInternalError {
			t.Fatal(res.ResolutionMetadata.Error)
		}
	})
}

// clientCertificate returns a self-signed certificate for TLS client
// authentication.
func clientCertificate(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "did-go test client"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

func TestClientParsesWithContentType(t *testing.T) {
	t.Run("res10-crd20261001#did-resolution-metadata.4 the caller parses the didDocument with contentType", func(t *testing.T) {
		srv, _ := recorder(t, respondJSON(200, spec.MediaTypeDIDResolution,
			fullBody(`{"id":"did:example:123"}`, `{"contentType":"application/did+json","retrieved":"x"}`, `{"created":"2020-01-01T00:00:00Z"}`)))
		c, cons := newClient(t, srv)
		res := c.Resolve(t.Context(), mustDID(t, testDID), resolution.ResolutionOptions{})
		if res.ResolutionMetadata.Error != nil || res.Document == nil || res.Document.ID().String() != testDID {
			t.Fatal(res.ResolutionMetadata.Error)
		}
		if got := cons.seen(); len(got) != 1 || got[0] != spec.MediaTypeDIDJSON {
			t.Fatal(got)
		}
		if string(res.Raw) != `{"id":"did:example:123"}` || res.Info.DetectedVersion != spec.V10 {
			t.Fatal(string(res.Raw), res.Info)
		}
		if res.ResolutionMetadata.Extra["retrieved"] != "x" || res.DocumentMetadata.Created == nil {
			t.Fatal(res.ResolutionMetadata, res.DocumentMetadata)
		}
	})
	// Without contentType the payload decides.
	srv, _ := recorder(t, respondJSON(200, spec.MediaTypeDIDResolution, fullBody(docV11, `{}`, `{}`)))
	c, cons := newClient(t, srv)
	res := c.Resolve(t.Context(), mustDID(t, testDID), resolution.ResolutionOptions{})
	if res.ResolutionMetadata.ContentType != spec.MediaTypeDID || cons.seen()[0] != spec.MediaTypeJSON {
		t.Fatal(res.ResolutionMetadata, cons.seen())
	}
}

func TestClientResponses(t *testing.T) {
	ctx := t.Context()
	d := mustDID(t, testDID)
	cases := []struct {
		name    string
		respond http.HandlerFunc
		check   func(resolution.Result) bool
	}{
		{"document only", respondJSON(200, "application/did; charset=utf-8", docV11), func(r resolution.Result) bool {
			return r.Document != nil && r.ResolutionMetadata.ContentType == "application/did; charset=utf-8" && string(r.Raw) == docV11
		}},
		{"wrong document", respondJSON(200, spec.MediaTypeDID, `{"id":"did:example:999"}`), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error.Code() == resolution.CodeInvalidDIDDocument && r.Document == nil
		}},
		{"unparsable document", respondJSON(200, "text/plain", "hello"), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error.Code() == resolution.CodeInvalidDIDDocument
		}},
		{"wrong document in result", respondJSON(200, spec.MediaTypeDIDResolution, fullBody(`{"id":"did:example:9"}`, `{"contentType":"application/did"}`, `{}`)), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error.Code() == resolution.CodeInvalidDIDDocument
		}},
		{"garbage result", respondJSON(200, spec.MediaTypeDIDResolution, `{"didDocument":`), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error.Code() == resolution.CodeInternalError
		}},
		{"result without document", respondJSON(200, spec.MediaTypeDIDResolution, fullBody(`null`, `{}`, `{}`)), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error.Code() == resolution.CodeInternalError
		}},
		{"error in result", respondJSON(404, spec.MediaTypeDIDResolution, fullBody(`null`, `{"error":{"type":"https://www.w3.org/ns/did#NOT_FOUND","detail":"gone"}}`, `{}`)), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error.Code() == resolution.CodeNotFound && r.ResolutionMetadata.Error.Detail == "gone"
		}},
		{"error status without error", respondJSON(500, spec.MediaTypeDIDResolution, fullBody(docV11, `{}`, `{}`)), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error.Code() == resolution.CodeInternalError && r.Document == nil
		}},
		{"problem", respondJSON(501, MediaTypeProblem, `{"type":"https://www.w3.org/ns/did#METHOD_NOT_SUPPORTED","title":"x"}`), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error.Code() == resolution.CodeMethodNotSupported
		}},
		{"bogus problem", respondJSON(400, MediaTypeProblem, `{"title":"no type"}`), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error.Code() == resolution.CodeInvalidDID
		}},
		{"html error", respondJSON(406, "text/html", "<h1>no</h1>"), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error.Code() == resolution.CodeRepresentationNotSupported
		}},
		{"plain 404", respondJSON(404, "", ""), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error.Code() == resolution.CodeNotFound
		}},
		{"plain 501", respondJSON(501, "", ""), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error.Code() == resolution.CodeFeatureNotSupported
		}},
		{"teapot", respondJSON(418, "", ""), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error.Code() == resolution.CodeInternalError
		}},
		{"redirect not followed", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://evil.example/", http.StatusFound)
		}, func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error.Code() == resolution.CodeInternalError
		}},
		{"plain 410", respondJSON(410, "", ""), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error == nil && r.DocumentMetadata.Deactivated && r.Document == nil
		}},
		{"deactivated result", respondJSON(410, spec.MediaTypeDIDResolution, fullBody(`null`, `{}`, `{"deactivated":true}`)), func(r resolution.Result) bool {
			return r.ResolutionMetadata.Error == nil && r.DocumentMetadata.Deactivated && r.Document == nil
		}},
	}
	for _, tc := range cases {
		srv, _ := recorder(t, tc.respond)
		c, _ := newClient(t, srv)
		if res := c.Resolve(ctx, d, resolution.ResolutionOptions{}); !tc.check(res) {
			t.Errorf("%s: %+v", tc.name, res)
		}
	}
}

func TestClientLimits(t *testing.T) {
	ctx := t.Context()
	d := mustDID(t, testDID)
	big := strings.Repeat("x", 4096)
	srv, _ := recorder(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4096")
		_, _ = w.Write([]byte(big))
	})
	c, _ := newClient(t, srv, WithResponseLimit(1024))
	if res := c.Resolve(ctx, d, resolution.ResolutionOptions{}); !strings.Contains(res.ResolutionMetadata.Error.Detail, "declares") {
		t.Fatal(res.ResolutionMetadata.Error)
	}
	srv, _ = recorder(t, func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i < 8; i++ {
			_, _ = w.Write([]byte(big))
			w.(http.Flusher).Flush()
		}
	})
	c, _ = newClient(t, srv, WithResponseLimit(8000))
	if res := c.Resolve(ctx, d, resolution.ResolutionOptions{}); !strings.Contains(res.ResolutionMetadata.Error.Detail, "larger than") {
		t.Fatal(res.ResolutionMetadata.Error)
	}
	release := make(chan struct{})
	srv, _ = recorder(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	c, _ = newClient(t, srv, WithTimeout(50*time.Millisecond))
	res := c.Resolve(ctx, d, resolution.ResolutionOptions{})
	if res.ResolutionMetadata.Error.Code() != resolution.CodeInternalError {
		t.Fatal(res.ResolutionMetadata.Error)
	}
	dr := c.Dereference(ctx, mustURL(t, "did:example:123#k"), resolution.DereferenceOptions{})
	if dr.DereferencingMetadata.Error.Code() != resolution.CodeInternalError {
		t.Fatal(dr.DereferencingMetadata.Error)
	}
	// Invalid options never reach the network.
	if res := c.Resolve(ctx, d, resolution.ResolutionOptions{Accept: "not a media type"}); res.ResolutionMetadata.Error.Code() != resolution.CodeInvalidOptions {
		t.Fatal(res.ResolutionMetadata.Error)
	}
	if dr := c.Dereference(ctx, mustURL(t, "did:example:123#k"), resolution.DereferenceOptions{Accept: "?"}); dr.DereferencingMetadata.Error.Code() != resolution.CodeInvalidOptions {
		t.Fatal(dr.DereferencingMetadata.Error)
	}
	if res := c.Resolve(ctx, d, resolution.ResolutionOptions{Extra: map[string]any{"bad": func() {}}}); res.ResolutionMetadata.Error.Code() != resolution.CodeInvalidOptions {
		t.Fatal(res.ResolutionMetadata.Error)
	}
	if _, err := queryValue(make(chan int)); err == nil {
		t.Fatal("queryValue")
	}
	ctxDone, cancel := context.WithCancel(ctx)
	cancel()
	if res := c.Resolve(ctxDone, d, resolution.ResolutionOptions{}); res.ResolutionMetadata.Error.Code() != resolution.CodeInternalError {
		t.Fatal(res.ResolutionMetadata.Error)
	}
}

func TestClientDereferenceResponses(t *testing.T) {
	ctx := t.Context()
	u := mustURL(t, "did:example:123?service=files")
	derefBody := func(content, md, cm string) string {
		return `{"content":` + content + `,"dereferencingMetadata":` + md + `,"contentMetadata":` + cm + `}`
	}
	cases := []struct {
		name    string
		respond http.HandlerFunc
		check   func(resolution.DereferenceResult) bool
	}{
		{"document content", respondJSON(200, spec.MediaTypeDIDURLDereferencing, derefBody(docV11, `{"contentType":"application/did"}`, `{}`)), func(r resolution.DereferenceResult) bool {
			doc, ok := r.ContentStream.(*document.Document)
			return ok && doc.ID().String() == testDID
		}},
		{"contentStream key", respondJSON(200, spec.MediaTypeDIDURLDereferencing, `{"contentStream":"abc","dereferencingMetadata":{"contentType":"text/plain"},"contentMetadata":{}}`), func(r resolution.DereferenceResult) bool {
			b, ok := r.ContentStream.([]byte)
			return ok && string(b) == `"abc"`
		}},
		{"uri list in result", respondJSON(200, spec.MediaTypeDIDURLDereferencing, derefBody(`["https://a.example/x"]`, `{}`, `{"contentType":"text/uri-list"}`)), func(r resolution.DereferenceResult) bool {
			l, ok := r.ContentStream.([]string)
			return ok && len(l) == 1 && l[0] == "https://a.example/x"
		}},
		{"uri list string in result", respondJSON(200, spec.MediaTypeDIDURLDereferencing, derefBody(`"https://a.example/x\r\n# c\r\nhttps://b.example/"`, `{"contentType":"text/uri-list"}`, `{}`)), func(r resolution.DereferenceResult) bool {
			l, ok := r.ContentStream.([]string)
			return ok && len(l) == 2
		}},
		{"uri list malformed", respondJSON(200, spec.MediaTypeDIDURLDereferencing, derefBody(`{}`, `{"contentType":"text/uri-list"}`, `{}`)), func(r resolution.DereferenceResult) bool {
			_, ok := r.ContentStream.([]byte)
			return ok
		}},
		{"error", respondJSON(400, spec.MediaTypeDIDURLDereferencing, derefBody(`null`, `{"error":{"type":"https://w3id.org/security#INVALID_VERIFICATION_METHOD"}}`, `{}`)), func(r resolution.DereferenceResult) bool {
			return r.DereferencingMetadata.Error.Code() == resolution.CodeInvalidVerificationMethod && r.ContentStream == nil
		}},
		{"error status", respondJSON(400, spec.MediaTypeDIDURLDereferencing, derefBody(`null`, `{}`, `{}`)), func(r resolution.DereferenceResult) bool {
			return r.DereferencingMetadata.Error.Code() == resolution.CodeInvalidDIDURL
		}},
		{"deactivated", respondJSON(410, spec.MediaTypeDIDURLDereferencing, derefBody(`null`, `{}`, `{"deactivated":true}`)), func(r resolution.DereferenceResult) bool {
			return r.ContentMetadata.Deactivated && r.DereferencingMetadata.Error == nil
		}},
		{"plain 410", respondJSON(410, "", ""), func(r resolution.DereferenceResult) bool {
			return r.ContentMetadata.Deactivated
		}},
		{"no content", respondJSON(200, spec.MediaTypeDIDURLDereferencing, derefBody(`null`, `{}`, `{}`)), func(r resolution.DereferenceResult) bool {
			return r.DereferencingMetadata.Error.Code() == resolution.CodeInternalError
		}},
		{"garbage", respondJSON(200, spec.MediaTypeDIDURLDereferencing, `[`), func(r resolution.DereferenceResult) bool {
			return r.DereferencingMetadata.Error.Code() == resolution.CodeInternalError
		}},
		{"content alone", respondJSON(200, "image/png", "\x89PNG"), func(r resolution.DereferenceResult) bool {
			b, ok := r.ContentStream.([]byte)
			return ok && string(b) == "\x89PNG" && r.DereferencingMetadata.ContentType == "image/png"
		}},
		{"document alone", respondJSON(200, spec.MediaTypeDID, docV11), func(r resolution.DereferenceResult) bool {
			_, ok := r.ContentStream.(*document.Document)
			return ok
		}},
		{"uri list alone", respondJSON(200, "text/uri-list", "https://a.example/\n"), func(r resolution.DereferenceResult) bool {
			l, ok := r.ContentStream.([]string)
			return ok && len(l) == 1
		}},
		{"303 without location", respondJSON(303, "", ""), func(r resolution.DereferenceResult) bool {
			return r.DereferencingMetadata.Error.Code() == resolution.CodeInternalError
		}},
		{"problem", respondJSON(404, MediaTypeProblem, `{"type":"https://www.w3.org/ns/did#NOT_FOUND"}`), func(r resolution.DereferenceResult) bool {
			return r.DereferencingMetadata.Error.Code() == resolution.CodeNotFound
		}},
		{"plain 400", respondJSON(400, "", ""), func(r resolution.DereferenceResult) bool {
			return r.DereferencingMetadata.Error.Code() == resolution.CodeInvalidDIDURL
		}},
	}
	for _, tc := range cases {
		srv, _ := recorder(t, tc.respond)
		c, _ := newClient(t, srv)
		if res := c.Dereference(ctx, u, resolution.DereferenceOptions{}); !tc.check(res) {
			t.Errorf("%s: %+v", tc.name, res)
		}
	}
}
