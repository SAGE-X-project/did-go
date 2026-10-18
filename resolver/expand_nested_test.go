package resolver

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/testutil"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

const expansionBase = "did:example:resources"

func expansionDocument(t *testing.T, raw string) *document.Document {
	t.Helper()
	d, _, e := consumer.New().Consume([]byte(raw), spec.MediaTypeDID, representation.ConsumeOptions{})
	if e != nil {
		t.Fatal(e)
	}
	return d
}

func TestExpandNestedPublicMaps(t *testing.T) {
	target := `{"id":"#target","nested":[{"id":"/path?mode=one#piece","label":"#unchanged"}],"nonString":{"id":7},"invalid":{"id":"%ZZ"}}`
	want := strings.ReplaceAll(strings.ReplaceAll(target, `"#target"`, `"did:example:resources#target"`), `"/path?mode=one#piece"`, `"did:example:resources/path?mode=one#piece"`)
	methodText := `{"id":"#sign","type":"ExampleKey","controller":"did:example:resources","extra":` + target + `}`
	fixtures := map[string]string{
		"method-extra":    `"verificationMethod":[` + methodText + `]`,
		"public-jwk":      `"verificationMethod":[{"id":"#sign","type":"JsonWebKey","controller":"did:example:resources","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","extra":` + target + `}}]`,
		"service-extra":   `"service":[{"id":"#service","type":"Messaging","serviceEndpoint":"https://example.invalid/","extra":` + target + `}]`,
		"endpoint-single": `"service":[{"id":"#service","type":"Messaging","serviceEndpoint":` + target + `}]`,
		"endpoint-set":    `"service":[{"id":"#service","type":"Messaging","serviceEndpoint":["https://example.invalid/",` + target + `]}]`,
		"root-extension":  `"extension":` + target,
	}
	for _, p := range vm.Purposes() {
		fixtures["embedded-"+p.String()] = `"` + p.String() + `":[` + methodText + `]`
	}
	for name, body := range fixtures {
		t.Run(name, func(t *testing.T) {
			raw := `{"id":"did:example:resources",` + body + `}`
			doc := expansionDocument(t, raw)
			before := expansionDocument(t, raw)
			got, e := expand(doc)
			if e != nil {
				t.Fatal(e)
			}
			// Independent literal substitutions describe only the known fixture IDs.
			expected := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(body, target, want), `"id":"#sign"`, `"id":"did:example:resources#sign"`), `"id":"#service"`, `"id":"did:example:resources#service"`)
			if !reflect.DeepEqual(got, expansionDocument(t, `{"id":"did:example:resources",`+expected+`}`)) {
				t.Fatal("nested ID or unrelated field changed")
			}
			if !reflect.DeepEqual(doc, before) {
				t.Fatal("immutable source changed")
			}
			again, e := expand(got)
			if e != nil || !reflect.DeepEqual(again, got) {
				t.Fatal("expansion was not idempotent", e)
			}
		})
	}
}

func TestExpandJSONPreservesValues(t *testing.T) {
	base, _ := did.ParseURL(expansionBase)
	for name, number := range map[string]any{"uint64": uint64(18446744073709551615), "precise": json.Number("0.12345678901234567890123456789"), "signed": int64(-9223372036854775808), "ordinary": float64(1.25)} {
		t.Run(name, func(t *testing.T) {
			input := map[string]any{"id": "#target", "number": number, "values": []any{nil, false, 3, "#label", map[string]any{"id": "#child"}}, "invalid": map[string]any{"id": "%ZZ"}, "absolute": map[string]any{"id": "https://example.invalid/a"}, "nonString": map[string]any{"id": []any{map[string]any{"id": "#nested"}}}}
			before := vm.CloneJSONMap(input)
			got := expandJSONMap(input, base)
			want := vm.CloneJSONMap(before)
			want["id"] = expansionBase + "#target"
			want["values"].([]any)[4].(map[string]any)["id"] = expansionBase + "#child"
			want["nonString"].(map[string]any)["id"].([]any)[0].(map[string]any)["id"] = expansionBase + "#nested"
			if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(input, before) {
				t.Fatal("JSON value/type changed")
			}
			got["values"].([]any)[4].(map[string]any)["id"] = "changed"
			if !reflect.DeepEqual(input, before) {
				t.Fatal("expanded map aliases input")
			}
		})
	}
	if expandJSONMap(nil, base) != nil {
		t.Fatal("nil map became present")
	}
	if got := expandJSONMap(map[string]any{}, base); got == nil || len(got) != 0 {
		t.Fatal("empty map shape changed")
	}
	if expandJSONValue([]any(nil), base).([]any) != nil {
		t.Fatal("nil list became present")
	}
	empty := expandJSONValue([]any{}, base).([]any)
	if empty == nil || len(empty) != 0 {
		t.Fatal("empty list shape changed")
	}
}

func TestExpandRelationshipsAndPublicBoundary(t *testing.T) {
	id, _ := did.Parse(expansionBase)
	base := id.URL()
	ref, _ := did.ParseReference("#key")
	private := map[string]any{"id": "#unchanged-private", "note": "non-key marker"}
	m := vm.Method{ID: ref, Controller: id, Type: "ExampleKey", Extra: map[string]any{"idNot": "#unchanged", "child": map[string]any{"id": "#public"}}, SecretKeyJwk: private}
	before := m.Clone()
	got := expandMethod(m, base)
	if got.ID.String() != expansionBase+"#key" || got.Extra["child"].(map[string]any)["id"] != expansionBase+"#public" || !reflect.DeepEqual(got.SecretKeyJwk, private) || !reflect.DeepEqual(m, before) {
		t.Fatal("public expansion changed private material or source")
	}
	b := document.NewBuilder(id).VerificationMethod(vm.Method{ID: ref, Controller: id, Type: "ExampleKey"})
	for _, p := range vm.Purposes() {
		b.Relationship(p, vm.Ref(ref))
	}
	b.RepresentationEntry("@context", document.String("#keep-context"))
	doc, e := b.Build()
	if e != nil {
		t.Fatal(e)
	}
	out, e := expand(doc)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range vm.Purposes() {
		r, _ := out.Relationship(p)[0].Reference()
		if r.String() != expansionBase+"#key" {
			t.Fatal("relationship reference not expanded", p)
		}
	}
	if !reflect.DeepEqual(out.RepresentationEntries(), doc.RepresentationEntries()) {
		t.Fatal("representation entry changed")
	}
}

func TestExpandRelativeOptionControls(t *testing.T) {
	raw := `{"id":"did:example:resources","service":[{"id":"#one","type":"Messaging","serviceEndpoint":{"id":"#nested","label":"#unchanged"}}]}`
	drv := &testutil.Driver{Method: "example", Media: []string{spec.MediaTypeDID}, Func: testutil.Static(raw, spec.MediaTypeDID, document.Metadata{})}
	reg, e := method.NewRegistry(drv)
	if e != nil {
		t.Fatal(e)
	}
	r, e := New(reg, consumer.New(), producer.New())
	if e != nil {
		t.Fatal(e)
	}
	id, _ := did.Parse(expansionBase)
	for _, enabled := range []bool{false, true, false} {
		v := r.Resolve(t.Context(), id, resolution.ResolutionOptions{ExpandRelativeURLs: enabled})
		if v.ResolutionMetadata.Error != nil || v.Document == nil {
			t.Fatal(v.ResolutionMetadata.Error)
		}
		want := "#nested"
		if enabled {
			want = expansionBase + want
		}
		if v.Document.Services()[0].ServiceEndpoint[0].Map["id"] != want {
			t.Fatal("expand option not respected")
		}
	}
}

func TestExpandReferenceControls(t *testing.T) {
	base, _ := did.ParseURL(expansionBase)
	for _, tt := range []struct{ name, input, want string }{
		{"fragment", "#target", expansionBase + "#target"},
		{"path", "/path?mode=one#piece", expansionBase + "/path?mode=one#piece"},
		{"query", "?mode=one", expansionBase + "?mode=one"},
		{"absolute", "https://example.invalid/path", "https://example.invalid/path"},
		{"invalid", "%ZZ", "%ZZ"},
		{"empty", "", ""},
		{"network-path", "//example.invalid/path", "//example.invalid/path"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := absoluteString(tt.input, base); got != tt.want {
				t.Fatalf("reference changed: %q want %q", got, tt.want)
			}
			input := map[string]any{"id": tt.input, "label": tt.input, "secretKeyJwk": map[string]any{"id": "#extension-only", "note": "non-key marker"}}
			got := expandJSONMap(input, base)
			if got["id"] != tt.want || got["label"] != tt.input || got["secretKeyJwk"].(map[string]any)["id"] != expansionBase+"#extension-only" {
				t.Fatal("field roles were not preserved")
			}
		})
	}
}
