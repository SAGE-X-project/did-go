package dereferencer

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/wire"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

const fragmentTarget = `{"id":"did:example:resources#target","label":"public fragment map","values":[false,2,"sample"]}`

func fragmentDocument(t *testing.T, raw string) *document.Document {
	t.Helper()
	d, _, err := consumer.New().Consume([]byte(raw), spec.MediaTypeDID, representation.ConsumeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func fragmentBytes(t *testing.T, value any) []byte {
	t.Helper()
	if m, ok := value.(document.Map); ok {
		n, err := wire.FromValue(m)
		if err != nil {
			t.Fatal(err)
		}
		return wire.Encode(n)
	}
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fragmentEqual(t *testing.T, value any, expected string) {
	t.Helper()
	decode := func(b []byte) any {
		var v any
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		if err := d.Decode(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if !reflect.DeepEqual(decode(fragmentBytes(t, value)), decode([]byte(expected))) {
		t.Fatalf("fragment changed: %s", fragmentBytes(t, value))
	}
}

func TestRecursiveFragmentMaps(t *testing.T) {
	nested := `{"ignored":[null,false,9,{"id":false}],"list":[{"child":` + fragmentTarget + `}]}`
	method := `{"id":"#sign","type":"ExampleKey","controller":"did:example:resources","extra":` + nested + `}`
	fixtures := map[string]string{
		"public-extension-name": `"verificationMethod":[{"id":"#sign","type":"ExampleKey","controller":"did:example:resources","extra":{"secretKeyJwk":` + nested + `}}]`,
		"method-extra":          `"verificationMethod":[` + method + `]`,
		"service-extra":         `"service":[{"id":"#one","type":"Messaging","serviceEndpoint":"https://example.invalid/","extra":` + nested + `}]`,
		"endpoint-map":          `"service":[{"id":"#one","type":"Messaging","serviceEndpoint":` + nested + `}]`,
		"endpoint-set":          `"service":[{"id":"#one","type":"Messaging","serviceEndpoint":["https://example.invalid/",` + nested + `]}]`,
		"public-jwk":            `"verificationMethod":[{"id":"#sign","type":"JsonWebKey","controller":"did:example:resources","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","extra":` + nested + `}}]`,
		"extension":             `"extension":` + nested,
	}
	for _, p := range vm.Purposes() {
		fixtures["embedded-"+p.String()] = `"` + p.String() + `":[` + method + `]`
	}
	for name, body := range fixtures {
		t.Run(name, func(t *testing.T) {
			d := fragmentDocument(t, `{"id":"did:example:resources",`+body+`}`)
			before := document.NewBuilderFrom(d)
			original, err := before.Build()
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"target", "absent"} {
				got := resolveFragment(d, id, spec.MediaTypeDID)
				if id == "absent" {
					if got.ContentStream != nil || got.DereferencingMetadata.Error == nil || got.DereferencingMetadata.Error.Type != resolutionNotFound() {
						t.Fatal("missing fragment must remain absent")
					}
					continue
				}
				if got.DereferencingMetadata.Error != nil || got.DereferencingMetadata.ContentType != "application/ld+json" || !got.ContentMetadata.IsEmpty() {
					t.Fatalf("fragment failed: %+v", got)
				}
				if _, ok := got.ContentStream.(document.Map); !ok {
					t.Fatalf("ordinary map result changed type: %T", got.ContentStream)
				}
				fragmentEqual(t, got.ContentStream, fragmentTarget)
			}
			if !reflect.DeepEqual(d, original) {
				t.Fatal("search changed immutable input")
			}
		})
	}
	t.Run("relative-id", func(t *testing.T) {
		target := strings.ReplaceAll(fragmentTarget, "did:example:resources#target", "#target")
		d := fragmentDocument(t, `{"id":"did:example:resources","service":[{"type":"Messaging","serviceEndpoint":{"nested":`+target+`}}]}`)
		got := resolveFragment(d, "target", spec.MediaTypeDID)
		if got.DereferencingMetadata.Error != nil {
			t.Fatal(got.DereferencingMetadata.Error)
		}
		fragmentEqual(t, got.ContentStream, target)
	})
}

func resolutionNotFound() string { return "https://www.w3.org/ns/did#NOT_FOUND" }

func TestFragmentNumbersAndFirstMatch(t *testing.T) {
	match := func(id string) bool { return id == "#target" }
	for _, tt := range []struct {
		name, number string
		plain        bool
	}{
		{"ordinary", "2", false}, {"wide-integer", "18446744073709551615", true}, {"precise-decimal", "0.12345678901234567890123456789", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			expected := `{"id":"#target","number":` + tt.number + `}`
			d := fragmentDocument(t, `{"id":"did:example:resources","verificationMethod":[{"id":"#sign","type":"ExampleKey","controller":"did:example:resources","extra":{"wideSibling":18446744073709551615,"child":`+expected+`}}]}`)
			first := resolveFragment(d, "target", spec.MediaTypeDID)
			if first.DereferencingMetadata.Error != nil {
				t.Fatal(first.DereferencingMetadata.Error)
			}
			fragmentEqual(t, first.ContentStream, expected)
			raw, plain := first.ContentStream.(map[string]any)
			if plain != tt.plain {
				t.Fatalf("numeric map type %T", first.ContentStream)
			}
			if plain {
				raw["number"] = "changed"
				fragmentEqual(t, resolveFragment(d, "target", spec.MediaTypeDID).ContentStream, expected)
			}
		})
	}
	t.Run("native-uint64", func(t *testing.T) {
		id, _ := did.Parse("did:example:resources")
		ref, _ := did.ParseURL("did:example:resources#key")
		m := vm.Method{ID: ref, Type: "ExampleKey", Controller: id, Extra: map[string]any{"child": map[string]any{"id": "#target", "number": uint64(18446744073709551615)}}}
		d, err := document.NewBuilder(id).VerificationMethod(m).Build()
		if err != nil {
			t.Fatal(err)
		}
		fragmentEqual(t, resolveFragment(d, "target", spec.MediaTypeDID).ContentStream, `{"id":"#target","number":18446744073709551615}`)
	})

	n, err := wire.FromAny(map[string]any{"list": []any{map[string]any{"id": "#target", "label": "first"}, map[string]any{"id": "#target", "label": "later"}}})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	got, ok := findJSONFragment(n, func(id string) bool { calls++; return match(id) })
	if !ok || calls != 1 {
		t.Fatal("did not stop at first match", calls)
	}
	fragmentEqual(t, got, `{"id":"#target","label":"first"}`)
	ordered, err := wire.FromAny(map[string]any{"b": map[string]any{"id": "#target", "label": "later"}, "a": map[string]any{"id": "#target", "label": "sorted first"}})
	if err != nil {
		t.Fatal(err)
	}
	first, ok := findJSONFragment(ordered, match)
	if !ok {
		t.Fatal("sorted map target missing")
	}
	fragmentEqual(t, first, `{"id":"#target","label":"sorted first"}`)

	d := fragmentDocument(t, `{"id":"did:example:resources","verificationMethod":[{"id":"#first","type":"ExampleKey","controller":"did:example:resources","extra":{"child":{"id":"#target","label":"first method"}}},{"id":"#target","type":"ExampleKey","controller":"did:example:resources"}]}`)
	fragmentEqual(t, resolveFragment(d, "target", spec.MediaTypeDID).ContentStream, `{"id":"#target","label":"first method"}`)
}

func TestFragmentPublicBoundaryAndInvalidContainers(t *testing.T) {
	id, _ := did.ParseURL("did:example:resources#key")
	controller, _ := did.Parse("did:example:resources")
	m := vm.Method{ID: id, Controller: controller, Type: "ExampleKey", SecretKeyJwk: map[string]any{"id": "#private", "note": "non-key marker"}}
	if _, ok := findMethodFragment(m, func(s string) bool { return s == "#private" }); ok {
		t.Fatal("private method field entered public traversal")
	}
	got, ok := findMethodFragment(m, func(s string) bool { return s == id.String() })
	if _, typed := got.(vm.Method); !ok || !typed {
		t.Fatal("typed method result changed")
	}
	m.Extra = map[string]any{"invalid": func() {}}
	if _, ok := findMethodFragment(m, func(string) bool { return false }); ok {
		t.Fatal("invalid method container accepted")
	}
	// An invalid container cannot be built by Document.Builder; this direct
	// helper control verifies graceful failure without constructing a document.
	service := vm.Service{Type: []string{"Messaging"}, ServiceEndpoint: []vm.Endpoint{{Map: map[string]any{"invalid": func() {}}}}}
	b := document.NewBuilder(controller).Service(service)
	if _, err := b.Build(); err == nil {
		t.Fatal("invalid service document accepted")
	}
	if _, ok := findJSONFragment(wire.Node{}, func(string) bool { return true }); ok {
		t.Fatal("non-map selected")
	}
	// Matching a typed service precedes traversal of its child maps.
	d := fragmentDocument(t, `{"id":"did:example:resources","service":[{"id":"#target","type":"Messaging","serviceEndpoint":{"child":{"id":"#target"}}}]}`)
	if _, ok := resolveFragment(d, "target", spec.MediaTypeDID).ContentStream.(vm.Service); !ok {
		t.Fatal("typed service result changed")
	}
}
