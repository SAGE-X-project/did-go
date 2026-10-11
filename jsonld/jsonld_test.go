package jsonld

import (
	"encoding/json"
	"go/build"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/spec"
)

func TestBaseContexts(t *testing.T) {
	t.Run("did11-cr20260305#remote-resource-integrity.1 the v1.1 base context is embedded and matches the pinned digest", func(t *testing.T) {
		url, data, err := BaseContext(spec.V11)
		if err != nil || url != spec.ContextURLV11 || len(data) == 0 {
			t.Fatalf("got %s %d %v", url, len(data), err)
		}
		if ContextSHA256V11 != "ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85" {
			t.Fatal("the pin must be the digest DID 1.1 §6.2.4 lists")
		}
		data[0] = 'x'
		if _, again, _ := BaseContext(spec.V11); again[0] == 'x' {
			t.Fatal("BaseContext must return a copy")
		}
	})
	t.Run("the v1 base context is embedded and pinned", func(t *testing.T) {
		url, _, err := BaseContext(spec.V10)
		if err != nil || url != spec.ContextURLV10 {
			t.Fatalf("got %s %v", url, err)
		}
	})
	t.Run("a digest mismatch is an error", func(t *testing.T) {
		if err := verify([]byte("tampered"), ContextSHA256V10); err == nil {
			t.Fatal("mismatch accepted")
		}
		if _, _, err := BaseContext(spec.VUnknown); err == nil {
			t.Fatal("VUnknown has no base context")
		}
	})
}

// definitions returns every term an embedded context defines, including the
// terms of scoped contexts.
func definitions(t *testing.T, v spec.Version) []string {
	t.Helper()
	_, data, err := BaseContext(v)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Context map[string]any `json:"@context"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	var walk func(map[string]any)
	walk = func(m map[string]any) {
		for k, v := range m {
			if strings.HasPrefix(k, "@") {
				continue
			}
			set[k] = true
			if def, ok := v.(map[string]any); ok {
				if scoped, ok := def["@context"].(map[string]any); ok {
					walk(scoped)
				}
			}
		}
	}
	walk(doc.Context)
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestTermsFromSpec(t *testing.T) {
	for _, v := range spec.Supported() {
		p, _ := spec.ProfileOf(v)
		if got := definitions(t, v); !slices.Equal(got, p.Terms()) {
			t.Errorf("%s: embedded context defines %v, spec lists %v", v, got, p.Terms())
		}
	}
}

func TestVersionOfContext(t *testing.T) {
	if v, ok := VersionOfContext(spec.ContextURLV10); !ok || v != spec.V10 {
		t.Fatal("v1")
	}
	if v, ok := VersionOfContext(spec.ContextURLV11); !ok || v != spec.V11 {
		t.Fatal("v1.1")
	}
	if _, ok := VersionOfContext(CIDContextURL); ok {
		t.Fatal("the CID context is not a DID base context")
	}
}

func TestEntries(t *testing.T) {
	if !slices.Equal(RepresentationEntries(), []string{"@context"}) || !IsRepresentationEntry("@context") || IsRepresentationEntry("@id") {
		t.Fatal("representation entries")
	}
	if !IsKeyword("@id") || IsKeyword("id") {
		t.Fatal("IsKeyword")
	}
}

func list(t *testing.T, vs ...document.Value) document.List {
	t.Helper()
	l, err := document.NewList(vs...)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func inline(t *testing.T) document.Map {
	t.Helper()
	scoped, _ := document.NewMap(document.Entry{Key: "nested", Value: document.String("https://e.example/nested")},
		document.Entry{Key: "@protected", Value: document.Boolean(true)})
	def, _ := document.NewMap(document.Entry{Key: "@id", Value: document.String("https://e.example/T")},
		document.Entry{Key: "@context", Value: scoped})
	m, _ := document.NewMap(document.Entry{Key: "ext", Value: document.String("https://e.example/ext")},
		document.Entry{Key: "T", Value: def}, document.Entry{Key: "@version", Value: document.Double(1.1)},
		document.Entry{Key: "U", Value: mapWith(t, "@context", document.String("https://e.example/remote"))})
	return m
}

func mapWith(t *testing.T, k string, v document.Value) document.Map {
	t.Helper()
	m, err := document.NewMap(document.Entry{Key: k, Value: v})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseContext(t *testing.T) {
	t.Run("did11-cr20260305#json-ld-processors.1 a string, a map or a list of strings and maps", func(t *testing.T) {
		for _, v := range []document.Value{document.String(spec.ContextURLV11), inline(t),
			list(t, document.String(spec.ContextURLV11), inline(t)), list(t)} {
			c, err := ParseContext(v)
			if err != nil {
				t.Fatalf("%#v: %v", v, err)
			}
			if _, isList := v.(document.List); c.IsList() != isList {
				t.Fatal("IsList")
			}
		}
		for _, bad := range []document.Value{document.Integer(1), document.String(""), list(t, document.String(spec.ContextURLV11), document.Null{})} {
			if _, err := ParseContext(bad); err == nil {
				t.Errorf("%#v accepted", bad)
			}
		}
	})
	c, _ := ParseContext(list(t, document.String(spec.ContextURLV10), document.String("https://e.example/v1")))
	if first, ok := c.First(); !ok || first != spec.ContextURLV10 || c.Len() != 2 {
		t.Fatal("First")
	}
	if l, ok := c.Value().(document.List); !ok || l.Len() != 2 {
		t.Fatal("Value keeps the list")
	}
	single, _ := ParseContext(document.String(spec.ContextURLV11))
	if single.Value() != document.String(spec.ContextURLV11) {
		t.Fatal("Value keeps the string")
	}
	empty, _ := ParseContext(list(t))
	if _, ok := empty.First(); ok {
		t.Fatal("empty list has no first value")
	}
	if m, _ := ParseContext(inline(t)); func() bool { _, ok := m.First(); return ok }() {
		t.Fatal("a map has no first string")
	}
}

func encode(t *testing.T, v document.Value) string {
	t.Helper()
	switch x := v.(type) {
	case document.String:
		return string(x)
	case document.List:
		parts := make([]string, x.Len())
		for i := range parts {
			parts[i] = encode(t, x.At(i))
		}
		return "[" + strings.Join(parts, " ") + "]"
	case document.Map:
		return "{map}"
	}
	t.Fatalf("unexpected %#v", v)
	return ""
}

func TestProductionContext(t *testing.T) {
	ext := document.String("https://e.example/v1")
	cases := []struct {
		name     string
		v        spec.Version
		existing document.Value
		want     string
	}{
		{"core10#production-0.3 the v1 context alone is the JSON String", spec.V10, nil, spec.ContextURLV10},
		{"did11-cr20260305#json-ld-processors.4 the v1.1 context alone is the JSON String", spec.V11, nil, spec.ContextURLV11},
		{"did11-cr20260305#json-ld-processors.4 additional contexts follow the base context", spec.V11,
			list(t, document.String(spec.ContextURLV11), ext, inline(t)), "[" + spec.ContextURLV11 + " https://e.example/v1 {map}]"},
		{"core10#production-0.3 another version's base context is replaced", spec.V10,
			list(t, document.String(spec.ContextURLV11), ext), "[" + spec.ContextURLV10 + " https://e.example/v1]"},
		{"a list of one base context stays a list", spec.V11, list(t, document.String(spec.ContextURLV10)), "[" + spec.ContextURLV11 + "]"},
		{"a string base context stays a string", spec.V10, document.String(spec.ContextURLV11), spec.ContextURLV10},
		{"cid10#context-injection.1 a context without the base context gets it injected first", spec.V11, ext,
			"[" + spec.ContextURLV11 + " https://e.example/v1]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ProductionContext(c.v, c.existing)
			if err != nil {
				t.Fatal(err)
			}
			if s := encode(t, got); s != c.want {
				t.Fatalf("got %s, want %s", s, c.want)
			}
		})
	}
	if _, err := ProductionContext(spec.VUnknown, nil); err == nil {
		t.Fatal("VUnknown accepted")
	}
	if _, err := ProductionContext(spec.V11, document.Integer(3)); err == nil {
		t.Fatal("a malformed @context accepted")
	}
}

func TestTermLookup(t *testing.T) {
	t.Run("did11-cr20260305#json-ld-processors.8 the v1.1 base context defines the DID 1.1 terms", func(t *testing.T) {
		c, _ := ParseContext(document.String(spec.ContextURLV11))
		terms, ok := c.Terms()
		if !ok || !terms.Defines("publicKeyMultibase") || !terms.Defines("expires") || terms.Defines("fooExtension") || !terms.Defines("@id") {
			t.Fatal("v1.1 terms")
		}
	})
	t.Run("core10#consumption-0.2 the v1 base context does not define expires", func(t *testing.T) {
		c, _ := ParseContext(list(t, document.String(spec.ContextURLV10)))
		terms, ok := c.Terms()
		if !ok || terms.Defines("expires") || !terms.Defines("serviceEndpoint") {
			t.Fatal("v1 terms")
		}
	})
	t.Run("inline contexts define their terms, including scoped ones", func(t *testing.T) {
		c, _ := ParseContext(list(t, document.String(spec.ContextURLV11), inline(t)))
		terms, ok := c.Terms()
		if !ok || !terms.Defines("ext") || !terms.Defines("T") || !terms.Defines("nested") || !terms.Defines("U") {
			t.Fatal("inline terms")
		}
	})
	t.Run("a context that is not known locally makes the lookup undecided", func(t *testing.T) {
		for _, url := range []string{"https://w3id.org/security/suites/ed25519-2020/v1", CIDContextURL} {
			c, _ := ParseContext(list(t, document.String(spec.ContextURLV10), document.String(url)))
			if _, ok := c.Terms(); ok {
				t.Fatalf("%s must be unknown", url)
			}
		}
	})
}

// TestNoRemoteRetrieval checks that the JSON-LD tool and the players cannot
// retrieve a context: none of them imports a network package.
func TestNoRemoteRetrieval(t *testing.T) {
	t.Run("cid10#json-ld-context.1 no context is retrieved; did-go performs no JSON-LD processing that would resolve the CID context", func(t *testing.T) {
		for _, dir := range []string{".", "../producer", "../consumer", "../internal/wire"} {
			pkg, err := build.ImportDir(dir, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range pkg.Imports {
				if strings.HasPrefix(imp, "net") || imp == "os" {
					t.Errorf("%s imports %s", dir, imp)
				}
			}
		}
	})
}
