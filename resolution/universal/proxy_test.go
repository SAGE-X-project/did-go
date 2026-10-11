package universal

import (
	"reflect"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
)

func TestProxiedResolution(t *testing.T) {
	created := time.Date(2019, 3, 23, 6, 35, 22, 0, time.UTC)
	upstreamResult := resolution.Result{
		Raw: []byte(docV11),
		ResolutionMetadata: resolution.ResolutionMetadata{
			ContentType: spec.MediaTypeDID,
			Proof:       []map[string]any{{"type": "DataIntegrityProof", "proofValue": "zUpstream"}},
			Extra:       map[string]any{"retrieved": "2024-06-01T19:13:24Z", "driver": map[string]any{"name": "x"}},
		},
		DocumentMetadata: document.Metadata{
			Created:   &created,
			VersionID: "7",
			Proof:     []map[string]any{{"type": "DataIntegrityProof", "proofValue": "zDoc"}},
			Extra:     map[string]any{"method": map[string]any{"seqNo": "11"}},
		},
	}
	upstream := &fakeResolver{result: upstreamResult}
	// The upstream resolver is reached by the downstream resolver over the
	// HTTPS binding; the downstream resolver serves its own clients.
	upClient, _, _ := pair(t, upstream, nil, nil)
	client, _, _ := pair(t, upClient, upClient, nil)

	t.Run("res10-crd20261001#resolver-architectures-proxied.2 a downstream resolver preserves upstream metadata", func(t *testing.T) {
		res := client.Resolve(t.Context(), mustDID(t, testDID), resolution.ResolutionOptions{})
		if res.ResolutionMetadata.Error != nil {
			t.Fatal(res.ResolutionMetadata.Error)
		}
		if !reflect.DeepEqual(res.ResolutionMetadata, upstreamResult.ResolutionMetadata) {
			t.Fatalf("resolution metadata\n got %#v\nwant %#v", res.ResolutionMetadata, upstreamResult.ResolutionMetadata)
		}
		if !reflect.DeepEqual(res.DocumentMetadata, upstreamResult.DocumentMetadata) {
			t.Fatalf("document metadata\n got %#v\nwant %#v", res.DocumentMetadata, upstreamResult.DocumentMetadata)
		}
		if string(res.Raw) != docV11 || res.Document.ID().String() != testDID {
			t.Fatal(string(res.Raw))
		}
	})
	t.Run("proxied errors keep their type and detail", func(t *testing.T) {
		upstream.mu.Lock()
		upstream.result = resolution.ErrorResult(resolution.NewError(resolution.CodeMethodNotSupported, "upstream has no driver"))
		upstream.mu.Unlock()
		res := client.Resolve(t.Context(), mustDID(t, testDID), resolution.ResolutionOptions{})
		e := res.ResolutionMetadata.Error
		if e.Code() != resolution.CodeMethodNotSupported || e.Detail != "upstream has no driver" {
			t.Fatal(e)
		}
	})
}
