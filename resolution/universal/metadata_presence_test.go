package universal

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/resolution"
)

// Two owned TLS hops exercise the actual downstream client and handler, with
// independent literal maps as the oracle. Proofs here are structural data.
func TestProxiedMetadataPresence(t *testing.T) {
	for _, tt := range []struct{ name, metadata string }{
		{"absent", `{"versionId":"7","proof":[{"type":"PublicFixture"}],"extension":{"retained":true}}`},
		{"false", `{"versionId":"7","deactivated":false,"proof":[{"type":"PublicFixture"}],"extension":{"retained":true}}`},
		{"true", `{"versionId":"7","deactivated":true,"proof":[{"type":"PublicFixture"}],"extension":{"retained":true}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var md document.Metadata
			if err := json.Unmarshal([]byte(tt.metadata), &md); err != nil {
				t.Fatal(err)
			}
			up := &fakeResolver{result: resolution.Result{Raw: []byte(docV11), DocumentMetadata: md,
				ResolutionMetadata: resolution.ResolutionMetadata{Extra: map[string]any{"source": "owned upstream"}}}}
			if md.Deactivated {
				up.result.Raw = nil
			}
			first, _, _ := pair(t, up, nil, nil)
			downstream, _, _ := pair(t, first, first, nil)
			got := downstream.Resolve(t.Context(), mustDID(t, testDID), resolution.ResolutionOptions{})
			if got.ResolutionMetadata.Error != nil {
				t.Fatal(got.ResolutionMetadata.Error)
			}
			encoded, err := json.Marshal(got.DocumentMetadata)
			if err != nil {
				t.Fatal(err)
			}
			var actual, want map[string]any
			if err := json.Unmarshal(encoded, &actual); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tt.metadata), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(actual, want) {
				t.Fatalf("metadata changed: %s", encoded)
			}
			if md.Deactivated {
				if got.Document != nil {
					t.Fatal("deactivated document returned")
				}
			} else if got.Document == nil || got.Document.ID().String() != testDID {
				t.Fatal("active document missing")
			}
		})
	}
}
