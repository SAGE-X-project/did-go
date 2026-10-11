package didkit_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sage-x-project/did-go/didkit"
	"github.com/sage-x-project/did-go/method/key"
	"github.com/sage-x-project/did-go/method/web"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
)

// webServer serves body for every request over TLS. Its client trusts the
// test certificate, which names example.com, and dials the server for every
// host, so the DID is did:web:example.com%3A<port>.
func webServer(t *testing.T, body func(id string) string) (*http.Client, string) {
	t.Helper()
	var id string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/did")
		_, _ = io.WriteString(w, body(id))
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	id = "did:web:example.com%3A" + port
	tr := srv.Client().Transport.(*http.Transport).Clone()
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: tr}, id
}

func webDoc(docID, ref string) string {
	return fmt.Sprintf(`{"@context":["https://www.w3.org/ns/did/v1.1"],"id":%q,"authentication":[%q]}`, docID, ref)
}

// did:web and did:key wired together: the driver's document errors reach
// the caller as INVALID_DID_DOCUMENT.
func TestDIDWebThroughDidkit(t *testing.T) {
	cases := []struct {
		name string
		body func(id string) string
		want resolution.Code
	}{
		{"a conforming did:web document resolves", func(id string) string { return webDoc(id, id+"#k") }, ""},
		{"res10-crd20261001#resolving.7 didweb-ea423c1#read-resolve.8 a document whose id is not the DID is INVALID_DID_DOCUMENT",
			func(string) string { return webDoc("did:web:attacker.example", "did:web:attacker.example#k") }, resolution.CodeInvalidDIDDocument},
		{"a did:web document with a relative DID URL is INVALID_DID_DOCUMENT",
			func(id string) string { return webDoc(id, "#k") }, resolution.CodeInvalidDIDDocument},
		{"a response that is not a JSON object is INVALID_DID_DOCUMENT",
			func(string) string { return "<html></html>" }, resolution.CodeInvalidDIDDocument},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hc, id := webServer(t, c.body)
			p := producer.New()
			r, err := didkit.NewResolver(key.New(p), web.New(p, hc))
			if err != nil {
				t.Fatal(err)
			}
			res := resolve(t, r, id, resolution.ResolutionOptions{})
			wantCode(t, res, c.want)
			if c.want == "" && res.Document.ID().String() != id {
				t.Fatal("wrong document")
			}
			wantCode(t, resolve(t, r, exampleKeyDID, resolution.ResolutionOptions{}), "")
		})
	}
}
