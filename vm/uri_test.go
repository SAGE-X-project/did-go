package vm

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func TestURIChecks(t *testing.T) {
	urls := map[string]bool{
		"https://example.com/":       true,
		"did:example:123#key":        true,
		"#frag":                      true,
		"mailto:a@example.com":       true,
		"https://example.com/ü":      true,
		"":                           false,
		"https://a b":                false,
		"https://a/\\b":              false,
		"https://a/%zz":              false,
		"https:///":                  false,
		"1http://x":                  false,
		"ht^tp://x":                  false,
		"https://[::1]:8080/":        true,
		"foo://host:port/x":          false,
		"https://example.com/%2Fa%2": false,
	}
	for s, want := range urls {
		if IsURL(s) != want {
			t.Errorf("IsURL(%q) = %v", s, !want)
		}
	}
	uris := map[string]bool{
		"https://example.com/":                          true,
		"urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66": true,
		"did:example:123#key-1":                         true,
		"https://[2001:db8::1]/":                        true,
		"#key-1":                                        false,
		"https://example.com/a b":                       false,
		"https://example.com/[x]":                       false,
		"https://example.com/ü":                         false,
		"https://example.com/#a#b":                      false,
		"https://example.com/%4":                        false,
		"https://[::1":                                  false,
		"1x:y":                                          false,
	}
	for s, want := range uris {
		if IsURI(s) != want {
			t.Errorf("IsURI(%q) = %v", s, !want)
		}
	}
	normal := map[string]bool{
		"https://example.com/":           true,
		"https://example.com/a/b?q#f":    true,
		"urn:uuid:6e8bc430":              true,
		"did:example:123":                true,
		"https://user@example.com:8443/": true,
		"https://example.com/%2F":        true,
		"HTTPS://example.com/":           false,
		"https://Example.com/":           false,
		"https://example.com":            false,
		"https://example.com:443/":       false,
		"https://example.com:/":          false,
		"https://example.com/a/./b":      false,
		"https://example.com/a/../b":     false,
		"https://example.com/%7E":        false,
		"https://example.com/%2f":        false,
		"https://example.com/.":          false,
		"https://example.com/..":         false,
		"not a uri":                      false,
	}
	for s, want := range normal {
		if IsNormalizedURI(s) != want {
			t.Errorf("IsNormalizedURI(%q) = %v", s, !want)
		}
	}
	if removeDotSegments("/a/b/c/./../../g") != "/a/g" || removeDotSegments("mid/content=5/../6") != "mid/6" || removeDotSegments("../x") != "x" {
		t.Fatal("RFC 3986 §5.2.4 examples")
	}
	if removeDotSegments("/..") != "/" || removeDotSegments(".") != "" {
		t.Fatal("dot segment edge cases")
	}
}

func TestJSONValues(t *testing.T) {
	good := []any{nil, true, "s", 1, int64(2), uint8(3), 1.5, float32(2.5), json.Number("7"), []any{map[string]any{"a": nil}}}
	for _, v := range good {
		if err := CheckJSONValue(v); err != nil {
			t.Errorf("%v: %v", v, err)
		}
	}
	deep := any("leaf")
	for i := 0; i < 70; i++ {
		deep = []any{deep}
	}
	bad := []any{math.NaN(), float32(math.Inf(1)), "\xff", map[string]any{"\xff": 1}, map[string]any{"a": []any{struct{}{}}}, time.Now(), deep}
	for _, v := range bad {
		if err := CheckJSONValue(v); err == nil {
			t.Errorf("%v: want error", v)
		}
	}
	src := map[string]any{"a": []any{map[string]any{"b": "c"}}}
	c := CloneJSONMap(src)
	c["a"].([]any)[0].(map[string]any)["b"] = "x"
	if src["a"].([]any)[0].(map[string]any)["b"] != "c" || CloneJSONMap(nil) != nil {
		t.Fatal("deep clone")
	}
	if !strings.Contains((&Error{Property: "p", Statement: "s", Reason: "r"}).Error(), "p: r (s)") {
		t.Fatal("error format")
	}
}

func TestMethodClone(t *testing.T) {
	ts := time.Unix(100, 0)
	m := baseMethod(t, "JsonWebKey")
	m.Expires, m.Revoked = &ts, &ts
	m.PublicKeyJwk = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "a"}
	m.SecretKeyJwk = map[string]any{"kty": "OKP", "crv": "Ed25519", "d": "a"}
	c := m.Clone()
	*c.Expires = time.Unix(5, 0)
	c.PublicKeyJwk["x"] = "b"
	c.SecretKeyJwk["d"] = "b"
	if !m.Expires.Equal(ts) || m.PublicKeyJwk["x"] != "a" || m.SecretKeyJwk["d"] != "a" {
		t.Fatal("clone shares memory")
	}
}
