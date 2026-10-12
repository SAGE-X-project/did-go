package sage

import (
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
)

// Chapter 06 ID-01: the identifier grammar, the size bounds and the URL
// restrictions are checked before any record is observed.
func TestCheckID(t *testing.T) {
	good := []string{
		"did:sage:web:agents.example.com:billing-bot",
		"did:sage:eip155:11155111:0xc7ecf7ad6ee71cb0d94f0eb00f46f1ddf432a808:0x1234abcd",
		"did:sage:web:agents.example.com:billing-bot#key-1",
		"did:sage:k-1:a:" + strings.Repeat("b", 64),
	}
	for _, s := range good {
		if e := checkID(s); e != nil {
			t.Errorf("%s rejected: %v", s, e)
		}
	}
	bad := map[string]Code{
		"did:sage:x":          CodeIDMalformed,
		"did:sage:web:a":      CodeIDMalformed,
		"did:sage:Web:a:b":    CodeIDMalformed,
		"did:sage:1web:a:b":   CodeIDMalformed,
		"did:sage:web::b":     CodeIDMalformed,
		"did:sage:web:a%41:b": CodeIDMalformed,
		"did:sage:web:a:" + strings.Repeat("b", 65):    CodeIDMalformed,
		"did:sage:web:a:b/path":                        CodeIDMalformed,
		"did:sage:web:a:b?service=x":                   CodeIDMalformed,
		"did:sage:web:a:b#k#j":                         CodeIDMalformed,
		"did:sage:web:a:b#" + strings.Repeat("k", 33):  CodeIDMalformed,
		"DID:sage:web:a:b":                             CodeIDMalformed,
		"did:key:z6Mk":                                 CodeIDMalformed,
		"did:sage:web:a:" + strings.Repeat("b.", 128):  CodeSizeExceeded,
		"did:sage:web:a:b#" + strings.Repeat("k", 300): CodeSizeExceeded,
	}
	for s, code := range bad {
		if e := checkID(s); e == nil || e.Code != code {
			t.Errorf("%.60s: %v, want %s", s, e, code)
		}
	}
	if malformed("did:key:z6Mk") != nil || malformed("did") != nil {
		t.Error("malformed reported a non-sage string")
	}
}

// RESOLVE-02 step 1: a malformed or oversized identifier never reaches the
// Source, on any path.
func TestMalformedNeverObserved(t *testing.T) {
	src := newSource()
	long := mustDID(t, "did:sage:web:a:"+strings.Repeat("b.", 130))
	odd := mustDID(t, "did:sage:web:a%41:b")
	if _, err := newDriver(t, src).Read(t.Context(), odd, method.ReadOptions{}); err == nil {
		t.Error("driver observed a malformed identifier")
	}
	r := newResolver(t, src)
	res, code := r.ResolveWithCode(t.Context(), long, resolution.ResolutionOptions{})
	wantCode(t, res, CodeSizeExceeded, code, resolution.CodeInvalidDID)
	res, code = r.ResolveWithCode(t.Context(), mustDID(t, "did:sage:x"), resolution.ResolutionOptions{})
	wantCode(t, res, CodeIDMalformed, code, resolution.CodeInvalidDID)
	for _, d := range []string{"did:sage:x", "did:example:123"} {
		if res := Respond(t.Context(), src, Request{DID: mustDID(t, d)}, producer.New()); res.Problem == nil || res.Problem.Code != CodeIDMalformed {
			t.Errorf("Respond(%s): %+v", d, res)
		}
	}
	if src.count() != 0 {
		t.Errorf("%d observations of malformed identifiers", src.count())
	}
}
