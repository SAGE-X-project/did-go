package sage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
)

type pairedSource func(context.Context, did.DID) (Record, error)

func (f pairedSource) Observe(ctx context.Context, d did.DID) (Record, error) { return f(ctx, d) }

type pairedProducer func(*document.Document, representation.ProduceOptions) ([]byte, string, error)

func (f pairedProducer) Produce(d *document.Document, o representation.ProduceOptions) ([]byte, string, error) {
	return f(d, o)
}

// These expected documents are authored from DIDP-01/03, not another projection
// call. The second source record differs in key, relationship, service and version.
func pairedExpected(version string, modern bool, nextKey []byte) string {
	prefix, typ := `{"id":"`+testDID+`",`, "JsonWebKey2020"
	if modern {
		prefix = `{"@context":"https://www.w3.org/ns/did/v1.1","id":"` + testDID + `",`
		typ = "JsonWebKey"
	}
	if version == "8" {
		return prefix + fmt.Sprintf(`"verificationMethod":[{"id":"%s#next","type":"%s","controller":"%s","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"%s"}}],"authentication":["%s#next"],"assertionMethod":["%s#next"],"service":[{"id":"%s#a2a","type":"A2AInterface","serviceEndpoint":"https://next.example/a2a"}]}`, testDID, typ, testDID, b64(nextKey), testDID, testDID, testDID)
	}
	return prefix + fmt.Sprintf(`"verificationMethod":[{"id":"%s#agree","type":"%s","controller":"%s","publicKeyJwk":{"kty":"OKP","crv":"X25519","x":"%s"}},{"id":"%s#sign","type":"%s","controller":"%s","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"%s"}}],"authentication":["%s#sign"],"assertionMethod":["%s#sign"],"keyAgreement":["%s#agree"],"service":[{"id":"%s#a2a","type":"A2AInterface","serviceEndpoint":"https://agent.example/a2a"}]}`, testDID, typ, testDID, b64(xKey), testDID, typ, testDID, b64(edKey), testDID, testDID, testDID, testDID)
}

func equalPairedJSON(t *testing.T, raw []byte, expected string) {
	t.Helper()
	var got, want any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		t.Fatal(err)
	}
	if !sameJSON(got, want) {
		t.Fatalf("actual %s, expected %s", raw, expected)
	}
}

func TestObserveViewsSingleObservation(t *testing.T) {
	nextKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
	first, second := activeRecord(t), activeRecord(t)
	second.Version, second.Controller = "8", "controller-2"
	second.Keys = []Key{{Name: "next", Alg: AlgEd25519, Material: nextKey, State: KeyAccepted}}
	second.Services[0].URI = "https://next.example/a2a"
	second.Observation.Time++
	second.Observation.Issued = issued(1_799_999_001)
	calls, writes := 0, 0
	src := pairedSource(func(context.Context, did.DID) (Record, error) {
		calls++
		switch calls {
		case 1:
			return first, nil
		case 2:
			return second, nil
		default:
			return Record{}, errors.New("unexpected observation")
		}
	})
	p := pairedProducer(func(d *document.Document, o representation.ProduceOptions) ([]byte, string, error) {
		modern := writes%2 == 1
		writes++
		if o.IncludeSecret || o.JSONLD != modern || (modern && o.Version != spec.V11) || (!modern && o.Version != spec.V10) {
			t.Fatal("projection options", o)
		}
		return producer.New().Produce(d, o)
	})
	for i, version := range []string{"7", "8"} {
		views, e := ObserveViews(context.Background(), src, first.DID, p)
		if e != nil || views == nil || calls != i+1 || writes != (i+1)*2 {
			t.Fatal("not a single fresh observation", e, calls, writes)
		}
		for n, view := range []ProjectionView{views.Core10, views.DID11} {
			equalPairedJSON(t, view.Data, pairedExpected(version, n == 1, nextKey))
			wantType := MediaTypeCore10
			if n == 1 {
				wantType = MediaTypeDID11
			}
			if view.ContentType != wantType {
				t.Fatal("wrong media type", view.ContentType)
			}
			raw, err := json.Marshal(view.Metadata)
			if err != nil {
				t.Fatal(err)
			}
			equalPairedJSON(t, raw, fmt.Sprintf(`{"deactivated":false,"versionId":"%s","sage":{"state":"active","controller":"controller-%d","source":"web-registry-1","observedAt":%d,"observedTime":%d}}`, version, i+1, 1_799_999_000+i, testObserved+int64(i)))
		}
	}
}

func TestObserveViewsStates(t *testing.T) {
	for _, state := range []string{"active", "created", "deactivated", "unusable"} {
		t.Run(state, func(t *testing.T) {
			r := activeRecord(t)
			if state == "unusable" {
				r.Keys[0].State = KeyRevoked
				r.Keys[1].Expires = issued(testObserved)
			} else {
				r.State = State(state)
			}
			src := newSource(r)
			views, e := ObserveViews(context.Background(), src, r.DID, producer.New())
			if e != nil || views == nil || src.count() != 1 {
				t.Fatal(e)
			}
			for _, v := range []ProjectionView{views.Core10, views.DID11} {
				var doc map[string]any
				if err := json.Unmarshal(v.Data, &doc); err != nil {
					t.Fatal(err)
				}
				if state != "active" {
					if len(doc["verificationMethod"].([]any)) != 0 {
						t.Fatal("unusable key projected")
					}
					for _, rel := range []string{"authentication", "assertionMethod", "keyAgreement"} {
						if _, ok := doc[rel]; ok {
							t.Fatal("inactive relationship", rel)
						}
					}
				}
				if len(doc["service"].([]any)) != 1 || v.Metadata.Deactivated != (state == "deactivated") || !v.Metadata.DeactivatedPresent {
					t.Fatal("lost service or state")
				}
			}
			// Keep standard DID Resolution's deactivated-null policy separate.
			driver, err := NewDriver(src, producer.New())
			if err != nil {
				t.Fatal(err)
			}
			res, err := driver.Read(context.Background(), r.DID, method.ReadOptions{MediaType: MediaTypeCore10})
			if err != nil || (len(res.Data) == 0) != (state == "deactivated") || src.count() != 2 {
				t.Fatal("standard Read policy changed", err)
			}
		})
	}
}

func TestObserveViewsOwnership(t *testing.T) {
	r := activeRecord(t)
	src := newSource(r)
	buffer := make([]byte, 0, maxResponse)
	p := pairedProducer(func(d *document.Document, o representation.ProduceOptions) ([]byte, string, error) {
		data, mt, err := producer.New().Produce(d, o)
		buffer = append(buffer[:0], data...)
		return buffer, mt, err
	})
	views, e := ObserveViews(context.Background(), src, r.DID, p)
	if e != nil {
		t.Fatal(e)
	}
	equalPairedJSON(t, views.Core10.Data, pairedExpected("7", false, nil))
	equalPairedJSON(t, views.DID11.Data, pairedExpected("7", true, nil))
	buffer[0] = 'x'
	views.Core10.Data[0] = 'y'
	views.Core10.Metadata.Extra["sage"].(map[string]any)["controller"] = "changed"
	if views.DID11.Data[0] != '{' || views.DID11.Metadata.Extra["sage"].(map[string]any)["controller"] != "controller-1" || Metadata(r).Extra["sage"].(map[string]any)["controller"] != "controller-1" {
		t.Fatal("returned views share ownership")
	}
	next, e := ObserveViews(context.Background(), src, r.DID, p)
	if e != nil || src.count() != 2 || next.Core10.Metadata.Extra["sage"].(map[string]any)["controller"] != "controller-1" {
		t.Fatal("returned mutation affected another call", e)
	}
	equalPairedJSON(t, next.Core10.Data, pairedExpected("7", false, nil))
}

func TestObserveViewsFailures(t *testing.T) {
	for _, mode := range []string{"nil-context", "nil-source", "nil-producer", "invalid-id", "pre-cancel", "source-error", "mismatch", "invalid-record", "cancel-source", "first-error", "second-error", "wrong-media", "too-large", "invalid-key", "cancel-first", "cancel-second"} {
		t.Run(mode, func(t *testing.T) {
			r := activeRecord(t)
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			calls, writes := 0, 0
			var source Source = pairedSource(func(context.Context, did.DID) (Record, error) {
				calls++
				switch mode {
				case "source-error":
					return Record{}, NewError(CodeRecordStale, "private detail")
				case "mismatch":
					r.DID = mustDID(t, "did:sage:web:registry.example:another")
				case "invalid-record":
					r.Version = "0"
				case "invalid-key":
					r.Keys[0].Alg, r.Keys[0].Material = AlgP256, append([]byte{4}, make([]byte, 64)...)
				case "cancel-source":
					stop()
				}
				return r, nil
			})
			var p representation.Producer = pairedProducer(func(d *document.Document, o representation.ProduceOptions) ([]byte, string, error) {
				writes++
				if mode == "first-error" || (mode == "second-error" && writes == 2) {
					return []byte("partial"), "", errors.New("fixture unavailable")
				}
				if mode == "wrong-media" && writes == 2 {
					return []byte("{}"), MediaTypeCore10, nil
				}
				if mode == "too-large" && writes == 2 {
					return bytes.Repeat([]byte{' '}, maxResponse+1), MediaTypeDID11, nil
				}
				if (mode == "cancel-first" && writes == 1) || (mode == "cancel-second" && writes == 2) {
					stop()
				}
				return producer.New().Produce(d, o)
			})
			callContext := ctx
			id := r.DID
			switch mode {
			case "nil-context":
				callContext = nil
			case "nil-source":
				source = nil
			case "nil-producer":
				p = nil
			case "invalid-id":
				id = mustDID(t, "did:example:unrelated")
			case "pre-cancel":
				stop()
			}
			views, e := ObserveViews(callContext, source, id, p)
			if views != nil || e == nil {
				t.Fatal("failure returned a partial pair", mode, e)
			}
			wantCalls, wantWrites, code := 1, 0, CodeRecordInvalid
			switch mode {
			case "nil-context", "nil-source", "nil-producer":
				wantCalls = 0
			case "invalid-id":
				wantCalls, code = 0, CodeIDMalformed
			case "pre-cancel":
				wantCalls, code = 0, CodeRecordUnreachable
			case "source-error":
				code = CodeRecordStale
				if strings.Contains(e.publicDetail(), "private detail") {
					t.Fatal("source detail became public")
				}
			case "cancel-source":
				code = CodeRecordUnreachable
			case "first-error", "cancel-first":
				wantWrites = 1
			case "second-error", "wrong-media", "too-large", "cancel-second":
				wantWrites = 2
			}
			if mode == "cancel-first" || mode == "cancel-second" {
				code = CodeRecordUnreachable
			}
			if mode == "too-large" {
				code = CodeSizeExceeded
			}
			if calls != wantCalls || writes != wantWrites || e.Code != code {
				t.Fatal("wrong failure boundary", calls, writes, e)
			}
			if strings.Contains(mode, "cancel") && !errors.Is(e, context.Canceled) {
				t.Fatal("cancellation cause lost")
			}
		})
	}
}

func TestSnapshotRecordOwnsMutableMembers(t *testing.T) {
	r := snapshotRecord(activeRecord(t))
	r.Keys[0].Expires = issued(testObserved + 1)
	copy := snapshotRecord(r)
	r.Keys[0].Material[0] ^= 1
	*r.Keys[0].Expires = 0
	*r.Observation.Issued = 0
	r.Services[0].URI = "https://changed.example/"
	if bytes.Equal(r.Keys[0].Material, copy.Keys[0].Material) || *copy.Keys[0].Expires != testObserved+1 || *copy.Observation.Issued != 1_799_999_000 || copy.Services[0].URI != "https://agent.example/a2a" {
		t.Fatal("snapshot aliases source data")
	}
	r.Observation.Issued = nil
	r.Observation.BlockHash = "0x" + strings.Repeat("a", 64)
	if next := snapshotRecord(r); next.Observation.Issued != nil || next.Observation.BlockHash != r.Observation.BlockHash {
		t.Fatal("block observation changed")
	}
}
