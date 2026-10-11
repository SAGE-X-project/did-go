package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
)

// testServer is an httptest TLS server reached under the host example.com,
// which its certificate names. The client dials the server for every host,
// so a DID names it as did:web:example.com%3A<port>.
type testServer struct {
	srv  *httptest.Server
	port string
}

func newServer(t *testing.T, h http.HandlerFunc) *testServer {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return &testServer{srv: srv, port: port}
}

// client returns an HTTP client that trusts the server certificate and dials
// the server whatever host a URL names.
func (s *testServer) client() *http.Client {
	tr := s.srv.Client().Transport.(*http.Transport).Clone()
	addr := s.srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: tr}
}

// did returns the did:web DID of host:port with optional path segments.
func (s *testServer) did(host string, path ...string) string {
	out := "did:web:" + host + "%3A" + s.port
	for _, p := range path {
		out += ":" + p
	}
	return out
}

func docJSON(id string) string {
	return fmt.Sprintf(`{"@context":["https://www.w3.org/ns/did/v1"],"id":%q,"verificationMethod":[{"id":"%s#key-0","type":"JsonWebKey2020","controller":%q,"publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"0-e2i2_Ua1S5HbTYnVB0lj2Z2ytXu2-tYmDFf8f5NjU"}}],"authentication":["%s#key-0"],"service":[{"id":"%s#svc","type":"X","serviceEndpoint":"https://example.com/x"}]}`, id, id, id, id, id)
}

func serveDoc(t *testing.T, contentType string, body func(s *testServer) string) (*testServer, *Method) {
	t.Helper()
	var s *testServer
	s = newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		_, _ = w.Write([]byte(body(s)))
	})
	return s, New(nil, s.client())
}

func readErr(t *testing.T, m *Method, d string) error {
	t.Helper()
	res, err := m.Read(t.Context(), mustDID(t, d), method.ReadOptions{})
	if err == nil {
		t.Fatalf("Read %s succeeded: %+v", d, res)
	}
	return err
}

func TestReadFetchesOverHTTPS(t *testing.T) {
	var (
		mu  sync.Mutex
		got *http.Request
		s   *testServer
	)
	s = newServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Clone(context.Background())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/did+ld+json; charset=utf-8")
		w.Header().Set("Set-Cookie", "tracker=1")
		_, _ = w.Write([]byte(docJSON(s.did("example.com", "user", "alice"))))
	})
	jar, _ := cookiejar.New(nil)
	hc := s.client()
	hc.Jar = jar
	m := New(nil, hc)
	d := s.did("example.com", "user", "alice")
	t.Run("didweb-ea423c1#read-resolve.7 an HTTP GET over a secure HTTPS connection", func(t *testing.T) {
		res, err := m.Read(t.Context(), mustDID(t, d), method.ReadOptions{MediaType: spec.MediaTypeDIDJSON, NoCache: true})
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		if got.Method != http.MethodGet || got.URL.Path != "/user/alice/did.json" || got.TLS == nil || got.Host != "example.com:"+s.port {
			t.Fatalf("%s %s %v %s", got.Method, got.URL.Path, got.TLS, got.Host)
		}
		if a := got.Header.Get("Accept"); !strings.HasPrefix(a, "application/did+json, application/did,") {
			t.Fatal(a)
		}
		if got.Header.Get("Cache-Control") != "no-cache" {
			t.Fatal("NoCache not sent")
		}
		if res.ContentType != spec.MediaTypeDIDLDJSON || string(res.Data) != docJSON(d) {
			t.Fatalf("%s %s", res.ContentType, res.Data)
		}
		u, _ := url.Parse("https://example.com")
		if len(jar.Cookies(u)) != 0 {
			t.Fatal("cookies stored")
		}
	})
	t.Run("didweb-ea423c1#read-resolve.7 the agent must verify the server certificate", func(t *testing.T) {
		hc := s.client()
		hc.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
		if err := readErr(t, New(nil, hc), d); errors.Is(err, method.ErrNotFound) || !strings.Contains(err.Error(), "verification") {
			t.Fatal(err)
		}
		hc = s.client()
		hc.Transport.(*http.Transport).TLSClientConfig.MinVersion = tls.VersionTLS10
		if err := readErr(t, New(nil, hc), d); !strings.Contains(err.Error(), "below 1.2") {
			t.Fatal(err)
		}
		// A client without the test CA cannot negotiate a secure connection.
		plain := &http.Client{Transport: &http.Transport{DialContext: s.client().Transport.(*http.Transport).DialContext}}
		var we *Error
		if err := readErr(t, New(nil, plain), d); !errors.As(err, &we) || we.Code != CodeFetchFailed {
			t.Fatal(err)
		}
	})
	t.Run("didweb-ea423c1#method-specific-identifier.1 the domain must match the TLS certificate", func(t *testing.T) {
		// The test certificate names example.com, not example.org.
		var we *Error
		if err := readErr(t, m, s.did("example.org", "user", "alice")); !errors.As(err, &we) || we.Code != CodeFetchFailed {
			t.Fatal(err)
		}
	})
}

func TestReadVerifiesDocumentID(t *testing.T) {
	t.Run("didweb-ea423c1#read-resolve.8 the document id must be the DID being resolved", func(t *testing.T) {
		s, m := serveDoc(t, "application/json", func(s *testServer) string { return docJSON("did:web:attacker.example") })
		err := readErr(t, m, s.did("example.com"))
		var we *Error
		if !errors.As(err, &we) || we.Code != CodeInvalidDidDocument || we.Statement != stmtVerifyID ||
			!errors.Is(err, method.ErrInvalidDocument) || errors.Is(err, method.ErrInvalidInput) {
			t.Fatal(err)
		}
		if strings.Contains(err.Error(), "attacker") {
			t.Fatal("error carries document content")
		}
		for _, body := range []string{"", "null", "[]", "<html>error</html>", `{"id":1}`, `{}`,
			docJSON(s.did("example.com")) + `{}`, docJSON(s.did("example.com")) + ` x`} {
			_, m := serveDoc(t, "application/json", func(*testServer) string { return body })
			if err := readErr(t, m, s.did("example.com")); !errors.Is(err, method.ErrInvalidDocument) || errors.Is(err, method.ErrInvalidInput) {
				t.Errorf("%q: %v", body, err)
			}
		}
	})
}

func TestReadRejectsRelativeDIDURLs(t *testing.T) {
	// §key-material-and-document-handling: "Whenever a DID URL is present
	// within a did:web document, it must be an absolute URL."
	cases := map[string]func(id string) string{
		"controller": func(id string) string { return fmt.Sprintf(`{"id":%q,"controller":["#c"]}`, id) },
		"method id": func(id string) string {
			return fmt.Sprintf(`{"id":%q,"verificationMethod":[{"id":"#k","controller":%q}]}`, id, id)
		},
		"method controller": func(id string) string {
			return fmt.Sprintf(`{"id":%q,"verificationMethod":[{"id":"%s#k","controller":"rel"}]}`, id, id)
		},
		"relationship ref":      func(id string) string { return fmt.Sprintf(`{"id":%q,"authentication":["#k"]}`, id) },
		"relationship embedded": func(id string) string { return fmt.Sprintf(`{"id":%q,"keyAgreement":[{"id":"#k"}]}`, id) },
		"service":               func(id string) string { return fmt.Sprintf(`{"id":%q,"service":[{"id":"#s"}]}`, id) },
		"bad url":               func(id string) string { return fmt.Sprintf(`{"id":%q,"controller":"%%zz"}`, id) },
	}
	for name, body := range cases {
		s, m := serveDoc(t, "application/json", func(s *testServer) string { return body(s.did("example.com")) })
		err := readErr(t, m, s.did("example.com"))
		var we *Error
		if !errors.As(err, &we) || we.Statement != sectionKeys || we.Code != CodeInvalidDidDocument ||
			!errors.Is(err, method.ErrInvalidDocument) || errors.Is(err, method.ErrInvalidInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Values of other types are left to the consumer.
	s, m := serveDoc(t, "application/json", func(s *testServer) string {
		id := s.did("example.com")
		return fmt.Sprintf(`{"id":%q,"controller":[1],"verificationMethod":[1,"#x"],"service":[1]}`, id)
	})
	if _, err := m.Read(t.Context(), mustDID(t, s.did("example.com")), method.ReadOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestReadContentLabel(t *testing.T) {
	for header, want := range map[string]string{
		"application/did":                 spec.MediaTypeDID,
		"application/did+json":            spec.MediaTypeDIDJSON,
		"application/json; charset=utf-8": spec.MediaTypeJSON,
		"application/ld+json":             spec.MediaTypeLDJSON,
		"text/plain":                      spec.MediaTypeJSON,
		"application/octet-stream":        spec.MediaTypeJSON,
		"":                                spec.MediaTypeJSON,
		"invalid/":                        spec.MediaTypeJSON,
	} {
		s, m := serveDoc(t, header, func(s *testServer) string { return docJSON(s.did("example.com")) })
		if header == "" {
			// Without a header the server sniffs; force it empty.
			s = newServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header()["Content-Type"] = nil
				_, _ = w.Write([]byte(docJSON(s.did("example.com"))))
			})
			m = New(nil, s.client())
		}
		res, err := m.Read(t.Context(), mustDID(t, s.did("example.com")), method.ReadOptions{})
		if err != nil || res.ContentType != want {
			t.Errorf("%q: %v %v", header, res, err)
		}
	}
}

func TestReadMetadata(t *testing.T) {
	var s *testServer
	s = newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		_, _ = w.Write([]byte(docJSON(s.did("example.com"))))
	})
	res, err := New(nil, s.client()).Read(t.Context(), mustDID(t, s.did("example.com")), method.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"core10#did-document-metadata.4", "res10-crd20261001#did-document-metadata.4"} {
		t.Run(id+" updated is the Last-Modified time of did.json", func(t *testing.T) {
			want := time.Date(2015, 10, 21, 7, 28, 0, 0, time.UTC)
			if res.Metadata.Updated == nil || !res.Metadata.Updated.Equal(want) || res.Metadata.Updated.Location() != time.UTC {
				t.Fatal(res.Metadata.Updated)
			}
			if err := res.Metadata.Check(mustDID(t, s.did("example.com")), spec.V11); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, id := range []string{
		"core10#did-document-metadata.2", "res10-crd20261001#did-document-metadata.2",
		"core10#did-document-metadata.10", "res10-crd20261001#did-document-metadata.10",
	} {
		t.Run(id+" a web server gives no creation time or version id", func(t *testing.T) {
			if res.Metadata.Created != nil || res.Metadata.VersionID != "" {
				t.Fatal(res.Metadata)
			}
		})
	}
	// An unparsable Last-Modified is ignored.
	s2, m2 := serveDoc(t, "", func(s *testServer) string { return docJSON(s.did("example.com")) })
	md := metadataOf(http.Header{"Last-Modified": []string{"yesterday"}})
	if !md.IsEmpty() {
		t.Fatal(md)
	}
	if res, err := m2.Read(t.Context(), mustDID(t, s2.did("example.com")), method.ReadOptions{}); err != nil || !res.Metadata.IsEmpty() {
		t.Fatal(res, err)
	}
}

func TestReadStatus(t *testing.T) {
	for status, check := range map[int]func(*method.ReadResult, error) bool{
		http.StatusNotFound: func(_ *method.ReadResult, err error) bool { return errors.Is(err, method.ErrNotFound) },
		http.StatusGone: func(r *method.ReadResult, err error) bool {
			return err == nil && r.Metadata.Deactivated && r.Data == nil
		},
		http.StatusInternalServerError: func(_ *method.ReadResult, err error) bool {
			var we *Error
			return errors.As(err, &we) && we.Code == CodeFetchFailed && !errors.Is(err, method.ErrNotFound)
		},
		http.StatusForbidden: func(_ *method.ReadResult, err error) bool { return err != nil },
	} {
		s := newServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
		res, err := New(nil, s.client()).Read(t.Context(), mustDID(t, s.did("example.com")), method.ReadOptions{})
		if !check(res, err) {
			t.Errorf("%d: %v %v", status, res, err)
		}
	}
}

func TestReadLimits(t *testing.T) {
	big := strings.Repeat(" ", 2048)
	t.Run("oversized with Content-Length", func(t *testing.T) {
		s := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "4096")
			_, _ = w.Write([]byte(big + big))
		})
		err := readErr(t, New(nil, s.client(), WithMaxResponseBytes(1024)), s.did("example.com"))
		if !strings.Contains(err.Error(), "declares") {
			t.Fatal(err)
		}
	})
	t.Run("oversized streamed", func(t *testing.T) {
		s := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			for i := 0; i < 64; i++ {
				_, _ = w.Write([]byte(big))
				w.(http.Flusher).Flush()
			}
		})
		err := readErr(t, New(nil, s.client(), WithMaxResponseBytes(4096)), s.did("example.com"))
		if !strings.Contains(err.Error(), "larger than") {
			t.Fatal(err)
		}
	})
	t.Run("redirect loop", func(t *testing.T) {
		var hits atomic.Int32
		s := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			n := hits.Add(1)
			http.Redirect(w, r, "/.well-known/did.json?n="+fmt.Sprint(n), http.StatusFound)
		})
		err := readErr(t, New(nil, s.client(), WithMaxRedirects(2)), s.did("example.com"))
		if !errors.Is(err, errRedirect) || hits.Load() != 3 {
			t.Fatal(hits.Load(), err)
		}
	})
	t.Run("redirects are followed within the limit on the same host", func(t *testing.T) {
		var s *testServer
		s = newServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/moved/did.json" {
				http.Redirect(w, r, "/moved/did.json", http.StatusMovedPermanently)
				return
			}
			_, _ = w.Write([]byte(docJSON(s.did("example.com"))))
		})
		if _, err := New(nil, s.client()).Read(t.Context(), mustDID(t, s.did("example.com")), method.ReadOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := readErr(t, New(nil, s.client(), WithMaxRedirects(-1)), s.did("example.com")); !errors.Is(err, errRedirect) {
			t.Fatal(err)
		}
	})
	t.Run("didweb-ea423c1#read-resolve.7 a redirect must not leave HTTPS", func(t *testing.T) {
		s := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://example.com/did.json", http.StatusFound)
		})
		err := readErr(t, New(nil, s.client(), WithCrossHostRedirects(true)), s.did("example.com"))
		if !errors.Is(err, errRedirect) {
			t.Fatal(err)
		}
	})
	t.Run("cross-host redirect", func(t *testing.T) {
		var s *testServer
		s = newServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Host == "example.com:"+s.port {
				http.Redirect(w, r, "https://www.example.com:"+s.port+"/x/did.json", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte(docJSON(s.did("example.com"))))
		})
		if err := readErr(t, New(nil, s.client()), s.did("example.com")); !errors.Is(err, errRedirect) {
			t.Fatal(err)
		}
		if _, err := New(nil, s.client(), WithCrossHostRedirects(true)).Read(t.Context(), mustDID(t, s.did("example.com")), method.ReadOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		release := make(chan struct{})
		s := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		})
		defer close(release)
		err := readErr(t, New(nil, s.client(), WithTimeout(50*time.Millisecond)), s.did("example.com"))
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	})
	t.Run("canceled context", func(t *testing.T) {
		s, m := serveDoc(t, "", func(s *testServer) string { return docJSON(s.did("example.com")) })
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := m.Read(ctx, mustDID(t, s.did("example.com")), method.ReadOptions{}); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("options keep defaults for invalid values", func(t *testing.T) {
		m := New(nil, nil, WithMaxResponseBytes(0), WithTimeout(0))
		if m.cfg.maxBytes != DefaultMaxResponseBytes || m.cfg.timeout != DefaultTimeout || m.cfg.maxRedirects != DefaultMaxRedirects {
			t.Fatal(m.cfg)
		}
	})
}

func TestReadInputs(t *testing.T) {
	m := New(nil, nil)
	d := mustDID(t, "did:web:example.com")
	now := time.Now()
	for _, opts := range []method.ReadOptions{{VersionID: "1"}, {VersionTime: &now}} {
		if _, err := m.Read(t.Context(), d, opts); !errors.Is(err, method.ErrNotSupported) {
			t.Fatal(err)
		}
	}
	if _, err := m.Read(t.Context(), d, method.ReadOptions{}); err == nil || !strings.Contains(err.Error(), "no HTTP client") {
		t.Fatal(err)
	}
	if _, err := m.Read(t.Context(), mustDID(t, "did:web:127.0.0.1"), method.ReadOptions{}); !errors.Is(err, method.ErrInvalidInput) {
		t.Fatal(err)
	}
	if got := acceptHeader("bad;;"); strings.HasPrefix(got, "bad") {
		t.Fatal(got)
	}
}

func TestOperationsByController(t *testing.T) {
	m := New(nil, nil)
	d := mustDID(t, "did:web:example.com")
	if _, err := m.Create(t.Context(), nil, method.CreateOptions{}); !errors.Is(err, method.ErrNotSupported) {
		t.Fatal(err)
	}
	if _, err := m.Update(t.Context(), d, nil, method.UpdateOptions{}); !errors.Is(err, method.ErrNotSupported) {
		t.Fatal(err)
	}
	if _, err := m.Deactivate(t.Context(), d, method.DeactivateOptions{}); !errors.Is(err, method.ErrNotSupported) {
		t.Fatal(err)
	}
	if p := m.Produces(); p == nil || len(p) != 0 {
		t.Fatal(p)
	}
	if _, err := method.NewRegistry(m); err != nil {
		t.Fatal(err)
	}
}

// stubProducer writes the id and a relationship reference of a document.
type stubProducer struct {
	err error
	rel string
}

func (s stubProducer) Produce(d *document.Document, _ representation.ProduceOptions) ([]byte, string, error) {
	if s.err != nil {
		return nil, "", s.err
	}
	out := map[string]any{"id": d.ID().String()}
	if s.rel != "" {
		out["authentication"] = []string{s.rel}
	}
	data, err := json.Marshal(out)
	return data, spec.MediaTypeDID, err
}

func TestDocumentFile(t *testing.T) {
	d := mustDID(t, "did:web:example.com:user:alice")
	doc, err := document.NewBuilder(d).Build()
	if err != nil {
		t.Fatal(err)
	}
	data, mt, err := New(stubProducer{}, nil).DocumentFile(doc, representation.ProduceOptions{})
	if err != nil || mt != spec.MediaTypeDID || string(data) != `{"id":"did:web:example.com:user:alice"}` {
		t.Fatal(string(data), mt, err)
	}
	var we *Error
	if _, _, err := New(stubProducer{rel: "#k"}, nil).DocumentFile(doc, representation.ProduceOptions{}); !errors.Is(err, method.ErrInvalidInput) ||
		!errors.As(err, &we) || we.Code != CodeInvalidDidDocument {
		t.Fatal(err)
	}
	if _, _, err := New(stubProducer{err: errors.New("boom")}, nil).DocumentFile(doc, representation.ProduceOptions{}); err == nil {
		t.Fatal("producer error lost")
	}
	if _, _, err := New(nil, nil).DocumentFile(doc, representation.ProduceOptions{}); err == nil {
		t.Fatal("no producer")
	}
	if _, _, err := New(stubProducer{}, nil).DocumentFile(nil, representation.ProduceOptions{}); !errors.Is(err, method.ErrInvalidInput) {
		t.Fatal("nil document")
	}
	keyDoc, _ := document.NewBuilder(mustDID(t, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")).Build()
	if _, _, err := New(stubProducer{}, nil).DocumentFile(keyDoc, representation.ProduceOptions{}); !errors.Is(err, method.ErrInvalidInput) {
		t.Fatal(err)
	}
}

func TestErrorText(t *testing.T) {
	e := wrap(CodeFetchFailed, stmtGet, errors.New("cause"), "x %d", 1)
	if e.Error() != "web: fetchFailed: x 1 (didweb-ea423c1#read-resolve.7): cause" {
		t.Fatal(e.Error())
	}
	if raise(CodeNotFound, stmtGet, "y").Error() != "web: notFound: y (didweb-ea423c1#read-resolve.7)" {
		t.Fatal("raise")
	}
}

func TestErrorClasses(t *testing.T) {
	classes := []error{method.ErrInvalidInput, method.ErrInvalidDocument, method.ErrNotFound, method.ErrNotSupported}
	for code, want := range map[string]error{
		CodeInvalidDid:         method.ErrInvalidInput,
		CodeInvalidURL:         method.ErrInvalidInput,
		CodeInvalidDidDocument: method.ErrInvalidDocument,
		CodeNotFound:           method.ErrNotFound,
		CodeFetchFailed:        nil,
	} {
		err := raise(code, stmtGet, "x")
		for _, class := range classes {
			if got := errors.Is(err, class); got != (class == want) {
				t.Errorf("%s: errors.Is(%v) = %v", code, class, got)
			}
		}
	}
}
