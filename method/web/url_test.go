package web

import (
	"errors"
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/method"
)

func mustDID(t *testing.T, s string) did.DID {
	t.Helper()
	d, err := did.Parse(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return d
}

func urlOf(t *testing.T, s string) string {
	t.Helper()
	u, err := URL(mustDID(t, s))
	if err != nil {
		t.Fatalf("URL(%s): %v", s, err)
	}
	return u.String()
}

func TestURLTransformation(t *testing.T) {
	// The examples of the specification's Create (Register) and Optional
	// Path Considerations sections.
	vectors := []struct{ did, url string }{
		{"did:web:w3c-ccg.github.io", "https://w3c-ccg.github.io/.well-known/did.json"},
		{"did:web:w3c-ccg.github.io:user:alice", "https://w3c-ccg.github.io/user/alice/did.json"},
		{"did:web:example.com%3A3000:user:alice", "https://example.com:3000/user/alice/did.json"},
		{"did:web:example.com%3A3000", "https://example.com:3000/.well-known/did.json"},
		{"did:web:example.com:u:bob", "https://example.com/u/bob/did.json"},
	}
	for _, id := range []string{
		"didweb-ea423c1#read-resolve.1 the Read steps produce the document URL",
		"didweb-ea423c1#read-resolve.2 colons of the method-specific identifier become slashes",
		"didweb-ea423c1#read-resolve.3 a percent-encoded port colon is decoded",
		"didweb-ea423c1#read-resolve.4 the URL starts with https://",
		"didweb-ea423c1#read-resolve.5 /.well-known is appended when there is no path",
		"didweb-ea423c1#read-resolve.6 /did.json completes the URL",
	} {
		t.Run(id, func(t *testing.T) {
			for _, v := range vectors {
				if got := urlOf(t, v.did); got != v.url {
					t.Errorf("%s: got %s want %s", v.did, got, v.url)
				}
			}
		})
	}
}

func TestMethodName(t *testing.T) {
	t.Run("didweb-ea423c1#method-name.1 only did:web DIDs are resolved", func(t *testing.T) {
		_, err := URL(mustDID(t, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"))
		if !errors.Is(err, method.ErrInvalidInput) {
			t.Fatal(err)
		}
		var we *Error
		if !errors.As(err, &we) || we.Code != CodeInvalidDid || we.Statement != stmtMethodName {
			t.Fatal(err)
		}
		if New(nil, nil).Name() != "web" {
			t.Fatal("Name")
		}
	})
	t.Run("didweb-ea423c1#method-name.2 the method name is lowercase", func(t *testing.T) {
		if _, err := did.Parse("did:WEB:example.com"); err == nil {
			t.Fatal("uppercase method name accepted")
		}
		if got := urlOf(t, "DID:web:example.com"); got != "https://example.com/.well-known/did.json" {
			t.Fatal(got)
		}
	})
}

func TestMethodSpecificIdentifier(t *testing.T) {
	t.Run("didweb-ea423c1#method-specific-identifier.1 IP addresses are refused", func(t *testing.T) {
		for _, s := range []string{
			"did:web:127.0.0.1", "did:web:127.0.0.1%3A443", "did:web:127.1", "did:web:2130706433",
			"did:web:0x7f.1", "did:web:10.0.0.1:user",
		} {
			_, err := URL(mustDID(t, s))
			var we *Error
			if !errors.As(err, &we) || we.Statement != stmtNoIP {
				t.Errorf("%s: %v", s, err)
			}
		}
	})
	t.Run("didweb-ea423c1#method-specific-identifier.1 the domain is a DNS name", func(t *testing.T) {
		for _, s := range []string{
			"did:web:-example.com", "did:web:example-.com", "did:web:exa_mple.com", "did:web:example..com",
			"did:web:example.com%2F", "did:web:" + strings.Repeat("a", 64) + ".com",
			"did:web:" + strings.Repeat("a.", 127) + "com",
		} {
			if _, err := URL(mustDID(t, s)); !errors.Is(err, method.ErrInvalidInput) {
				t.Errorf("%s: %v", s, err)
			}
		}
	})
	t.Run("didweb-ea423c1#method-specific-identifier.2 a port colon is percent-encoded", func(t *testing.T) {
		if got := urlOf(t, "did:web:example.com%3a8443"); got != "https://example.com:8443/.well-known/did.json" {
			t.Fatal(got)
		}
		// An unencoded colon delimits a path segment, not a port.
		if got := urlOf(t, "did:web:example.com:3000"); got != "https://example.com/3000/did.json" {
			t.Fatal(got)
		}
		for _, s := range []string{"did:web:example.com%3A", "did:web:example.com%3Aabc", "did:web:example.com%3A0",
			"did:web:example.com%3A70000", "did:web:example.com%3A123456", "did:web:example.com%3A%2B1"} {
			var we *Error
			if _, err := URL(mustDID(t, s)); !errors.As(err, &we) || we.Statement != stmtPort {
				t.Errorf("%s: %v", s, err)
			}
		}
	})
	t.Run("didweb-ea423c1#method-specific-identifier.3 directories are delimited by colons", func(t *testing.T) {
		if got := urlOf(t, "did:web:example.com:a:b:c%20d"); got != "https://example.com/a/b/c%20d/did.json" {
			t.Fatal(got)
		}
		// Segments that would leave the DID's own path are refused.
		for _, s := range []string{
			"did:web:example.com::a", "did:web:example.com:..:admin", "did:web:example.com:.",
			"did:web:example.com:%2E%2E:x", "did:web:example.com:a%2Fb", "did:web:example.com:a%5Cb",
			"did:web:example.com:a%3Fb", "did:web:example.com:a%23b", "did:web:example.com:a%00b",
		} {
			var we *Error
			if _, err := URL(mustDID(t, s)); !errors.As(err, &we) || we.Statement != stmtPath {
				t.Errorf("%s: %v", s, err)
			}
		}
	})
}

func TestDIDFromURL(t *testing.T) {
	t.Run("didweb-ea423c1#create-register.1 the port colon of a created DID is percent-encoded", func(t *testing.T) {
		vectors := map[string]string{
			"https://w3c-ccg.github.io/.well-known/did.json":     "did:web:w3c-ccg.github.io",
			"https://w3c-ccg.github.io/user/alice/did.json":      "did:web:w3c-ccg.github.io:user:alice",
			"https://example.com:3000/user/alice/did.json":       "did:web:example.com%3A3000:user:alice",
			"https://Example.COM:443/.well-known/did.json":       "did:web:example.com",
			"https://example.com/a%20b/c~d/did.json":             "did:web:example.com:a%20b:c%7Ed",
			"https://example.com:8443/.well-known/did.json":      "did:web:example.com%3A8443",
			"https://example.com/.well-known/sub/x/did.json":     "did:web:example.com:.well-known:sub:x",
			"https://example.com/users/%E2%9C%93/did.json":       "did:web:example.com:users:%E2%9C%93",
			"https://example.com/a:b/did.json":                   "did:web:example.com:a%3Ab",
			"https://example.com/caf%C3%A9%2Bx/did.json":         "did:web:example.com:caf%C3%A9%2Bx",
			"https://example.com:3000/.well-known/did.json":      "did:web:example.com%3A3000",
			"https://sub.example.co.uk/p/did.json":               "did:web:sub.example.co.uk:p",
			"https://xn--bcher-kva.example/.well-known/did.json": "did:web:xn--bcher-kva.example",
		}
		for in, want := range vectors {
			d, err := DIDFromURL(in)
			if err != nil || d.String() != want {
				t.Errorf("%s: got %v, %v want %s", in, d, err, want)
				continue
			}
			// Round trip: the DID resolves to the same document location.
			u, err := URL(d)
			if err != nil {
				t.Errorf("%s: URL: %v", want, err)
			} else if back, _ := DIDFromURL(u.String()); back != d {
				t.Errorf("%s: round trip %s", want, back)
			}
		}
		for _, in := range []string{
			"http://example.com/.well-known/did.json", "https://user@example.com/.well-known/did.json",
			"https://example.com/.well-known/did.json?x=1", "https://example.com/.well-known/did.json#f",
			"https://example.com/.well-known/did.json?", "https://127.0.0.1/.well-known/did.json",
			"https://[::1]/.well-known/did.json", "https://example.com/did.json", "https://example.com/x/doc.json",
			"https://example.com//did.json", "https://example.com/a/../did.json", "https://example.com:0/x/did.json",
			"https://example.com:99999/x/did.json", "mailto:x@example.com", "https://exa mple.com/x/did.json",
			"https://example.com/a%2Fb/did.json",
		} {
			if _, err := DIDFromURL(in); !errors.Is(err, method.ErrInvalidInput) {
				t.Errorf("%s accepted: %v", in, err)
			}
		}
	})
}
