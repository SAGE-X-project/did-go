package resolution

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/sage-x-project/did-go/spec"
)

func TestResolutionMetadata(t *testing.T) {
	t.Run("res10-crd20261001#did-resolution-metadata.2 contentType is optional", func(t *testing.T) {
		if err := (ResolutionMetadata{}).Validate(spec.V11); err != nil {
			t.Fatal(err)
		}
		if b, _ := json.Marshal(ResolutionMetadata{}); string(b) != "{}" {
			t.Fatalf("got %s", b)
		}
	})
	t.Run("res10-crd20261001#did-resolution-metadata.3 contentType is an ASCII media type", func(t *testing.T) {
		if err := (ResolutionMetadata{ContentType: "application/did+ld+json"}).Validate(spec.V11); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"application/dïd", "nonsense", "application/*", "*/*"} {
			if (ResolutionMetadata{ContentType: bad}).Validate(spec.V11) == nil {
				t.Errorf("%q accepted", bad)
			}
		}
	})
	t.Run("res10-crd20261001#did-url-dereferencing-metadata.3 dereferencing contentType is an ASCII media type", func(t *testing.T) {
		m := DereferencingMetadata{ContentType: "text/uri-list"}
		if m.Validate(spec.V11) != nil || (DereferencingMetadata{ContentType: "tëxt/uri-list"}).Validate(spec.V11) == nil {
			t.Fatal("contentType check")
		}
	})
	proofCases := []string{
		"res10-crd20261001#did-resolution-metadata.6 resolution metadata may include proof",
		"res10-crd20261001#did-resolution-metadata.7 proof is a set of maps",
		"res10-crd20261001#did-url-dereferencing-metadata.6 dereferencing metadata may include proof",
		"res10-crd20261001#did-url-dereferencing-metadata.7 proof is a set of maps",
	}
	for _, name := range proofCases {
		t.Run(name, func(t *testing.T) {
			m := ResolutionMetadata{Proof: []map[string]any{{"type": "DataIntegrityProof", "created": "2021-01-01T00:00:00Z"}}}
			if err := m.Validate(spec.V11); err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(m)
			if err != nil || string(b) != `{"proof":[{"created":"2021-01-01T00:00:00Z","type":"DataIntegrityProof"}]}` {
				t.Fatalf("got %s %v", b, err)
			}
			var back ResolutionMetadata
			if err := json.Unmarshal([]byte(`{"proof":{"type":"x"}}`), &back); err == nil {
				t.Fatal("single proof object accepted")
			}
			if (ResolutionMetadata{Proof: []map[string]any{nil}}).Validate(spec.V11) == nil {
				t.Fatal("nil proof accepted")
			}
			if (ResolutionMetadata{Proof: []map[string]any{{"x": math.Inf(1)}}}).Validate(spec.V11) == nil {
				t.Fatal("invalid proof value accepted")
			}
		})
	}
	t.Run("JSON round trip with error", func(t *testing.T) {
		m := ResolutionMetadata{ContentType: "application/did", Error: NewError(CodeNotFound, "x"), Extra: map[string]any{"duration": json.Number("12")}}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var back ResolutionMetadata
		if err := json.Unmarshal(b, &back); err != nil || back.Error.Type != m.Error.Type || back.ContentType != m.ContentType || back.Extra["duration"] != json.Number("12") {
			t.Fatalf("got %+v %v", back, err)
		}
		for _, bad := range []string{`{"error":"notFound"}`, `[]`, `{"contentType":1}`} {
			if err := json.Unmarshal([]byte(bad), &back); err == nil {
				t.Errorf("%s accepted", bad)
			}
		}
		if _, err := json.Marshal(ResolutionMetadata{Extra: map[string]any{"error": 1}}); err == nil {
			t.Fatal("colliding Extra encoded")
		}
		if _, err := json.Marshal(ResolutionMetadata{Extra: map[string]any{"x": func() {}}}); err == nil {
			t.Fatal("non-JSON Extra encoded")
		}
		if (ResolutionMetadata{Extra: map[string]any{"contentType": "x"}}).Validate(spec.V11) == nil {
			t.Fatal("colliding Extra validated")
		}
	})
}

func TestMetadataStructure(t *testing.T) {
	values := map[string]any{"s": "x", "m": map[string]any{"b": false}, "l": []any{nil, "a"}, "n": nil}
	t.Run("core10#metadata-structure.1 metadata is a map of properties", func(t *testing.T) {
		b, err := json.Marshal(ResolutionMetadata{Extra: values})
		if err != nil || b[0] != '{' {
			t.Fatalf("got %s %v", b, err)
		}
	})
	t.Run("core10#metadata-structure.2 property names are strings", func(t *testing.T) {
		var back ResolutionMetadata
		if err := json.Unmarshal([]byte(`{"a":1,"b":"c"}`), &back); err != nil || len(back.Extra) != 2 {
			t.Fatal(err)
		}
	})
	t.Run("core10#metadata-structure.3 values are string, map, list, set, boolean or null", func(t *testing.T) {
		if err := (ResolutionMetadata{Extra: values}).Validate(spec.V10); err != nil {
			t.Fatal(err)
		}
		if (ResolutionMetadata{Extra: map[string]any{"n": 1}}).Validate(spec.V10) == nil {
			t.Fatal("DID Core 1.0 metadata must not hold numbers")
		}
	})
	t.Run("core10#metadata-structure.4 nested values follow the same rule", func(t *testing.T) {
		if (ResolutionMetadata{Extra: map[string]any{"m": map[string]any{"l": []any{2.5}}}}).Validate(spec.V10) == nil {
			t.Fatal("nested number accepted under DID Core 1.0")
		}
	})
	t.Run("core10#metadata-structure.7 the structure serializes as JSON", func(t *testing.T) {
		if (ResolutionMetadata{Extra: map[string]any{"f": func() {}}}).Validate(spec.V10) == nil {
			t.Fatal("non-serializable value accepted")
		}
		if _, err := json.Marshal(ResolutionMetadata{Extra: values}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("res10-crd20261001#metadata-structure.1 metadata is a map of properties", func(t *testing.T) {
		var back ResolutionMetadata
		if json.Unmarshal([]byte(`["a"]`), &back) == nil {
			t.Fatal("non-object accepted")
		}
	})
	t.Run("res10-crd20261001#metadata-structure.2 property names are strings", func(t *testing.T) {
		if err := (ResolutionMetadata{Extra: map[string]any{"name": "v"}}).Validate(spec.V11); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("res10-crd20261001#metadata-structure.3 numbers are allowed, nested too", func(t *testing.T) {
		m := ResolutionMetadata{Extra: map[string]any{"n": 1, "m": map[string]any{"l": []any{2.5, json.Number("3")}}}}
		if err := m.Validate(spec.V11); err != nil {
			t.Fatal(err)
		}
		if (ResolutionMetadata{Extra: map[string]any{"t": struct{}{}}}).Validate(spec.V11) == nil {
			t.Fatal("struct accepted")
		}
	})
	t.Run("res10-crd20261001#metadata-structure.4 the structure serializes as JSON", func(t *testing.T) {
		if (ResolutionMetadata{Extra: map[string]any{"x": math.NaN()}}).Validate(spec.V11) == nil {
			t.Fatal("NaN accepted")
		}
	})
}
