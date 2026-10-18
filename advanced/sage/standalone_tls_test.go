package sage

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/universal"
	"github.com/sage-x-project/did-go/vm"
)

// This compatibility check runs against the public dependency with GOWORK=off
// in CI. All requests use owned loopback TLS and an in-memory Source; it does
// not exercise registry authority, signing, or a deployed SAGE consumer.
func TestStandaloneSAGETLS(t *testing.T) {
	for _, post := range []bool{false, true} {
		mode := "GET"
		if post {
			mode = "POST"
		}
		t.Run(mode, func(t *testing.T) {
			for _, name := range []string{"core10", "did11", "envelope", "sign", "absent-key", "missing", "stale", "invalid-record", "created", "deactivated"} {
				t.Run(name, func(t *testing.T) {
					rec := activeRecord(t)
					if name == "created" {
						rec.State = StateCreated
					}
					if name == "deactivated" {
						rec.State = StateDeactivated
					}
					if name == "invalid-record" {
						rec.Keys[1].State = KeyRevoked
					}
					src := newSource(rec)
					if name == "missing" {
						src = newSource()
					}
					if name == "stale" {
						src.errs[testDID] = NewError(CodeRecordStale, "")
					}
					handler := NewHandler(newResolver(t, src), prefix)
					var requests atomic.Int32
					server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						requests.Add(1)
						if r.TLS == nil || r.Method != mode {
							t.Errorf("expected %s over TLS", mode)
						}
						handler.ServeHTTP(w, r)
					}))
					defer server.Close()
					client, err := universal.NewClient(server.URL+prefix, server.Client(), consumer.New(), universal.WithPOST(post))
					if err != nil {
						t.Fatal(err)
					}
					if name == "sign" || name == "absent-key" {
						fragment := "sign"
						if name == "absent-key" {
							fragment = "absent"
						}
						u, err := did.ParseURL(testDID + "#" + fragment)
						if err != nil {
							t.Fatal(err)
						}
						result := client.Dereference(t.Context(), u, resolution.DereferenceOptions{})
						if name == "absent-key" {
							if result.DereferencingMetadata.Error == nil || result.DereferencingMetadata.Error.Type != resolution.CodeNotFound.TypeURL() || result.ContentStream != nil {
								t.Fatalf("missing key: %+v", result)
							}
						} else {
							method, ok := result.ContentStream.(vm.Method)
							if result.DereferencingMetadata.Error != nil || !ok || method.ID.String() != testDID+"#sign" || method.Controller.String() != testDID || method.PublicKeyJwk["crv"] != "Ed25519" || method.PublicKeyJwk["x"] != b64(edKey) {
								t.Fatalf("signing key: %+v", result)
							}
						}
					} else {
						opts := resolution.ResolutionOptions{}
						if name == "core10" {
							opts.Accept = MediaTypeCore10
						}
						if name == "did11" {
							opts.Accept = MediaTypeDID11
						}
						result := client.Resolve(t.Context(), rec.DID, opts)
						wantError := resolution.Code("")
						if name == "missing" {
							wantError = resolution.CodeNotFound
						}
						if name == "stale" || name == "invalid-record" {
							wantError = resolution.CodeInternalError
						}
						if wantError != "" {
							if result.ResolutionMetadata.Error == nil || result.ResolutionMetadata.Error.Type != wantError.TypeURL() || result.Document != nil || len(result.Raw) != 0 || !result.DocumentMetadata.IsEmpty() {
								t.Fatalf("%s: %+v", name, result)
							}
						} else {
							if result.ResolutionMetadata.Error != nil {
								t.Fatalf("%s: %+v", name, result)
							}
							if name == "deactivated" {
								if result.Document != nil || !result.DocumentMetadata.Deactivated || result.DocumentMetadata.VersionID != "7" {
									t.Fatalf("deactivated: %+v", result)
								}
							} else {
								if result.Document == nil || result.Document.ID().String() != testDID {
									t.Fatalf("document: %+v", result)
								}
								methods := result.Document.VerificationMethods()
								if name == "created" {
									if len(methods) != 0 || len(result.Document.Relationship(vm.Authentication)) != 0 {
										t.Fatalf("created exposes keys: %+v", methods)
									}
								} else {
									typ := "JsonWebKey2020"
									if name == "did11" {
										typ = "JsonWebKey"
									}
									if len(methods) != 2 || methods[0].ID.String() != testDID+"#agree" || methods[0].PublicKeyJwk["crv"] != "X25519" || methods[0].PublicKeyJwk["x"] != b64(xKey) || methods[1].ID.String() != testDID+"#sign" || methods[1].PublicKeyJwk["crv"] != "Ed25519" || methods[1].PublicKeyJwk["x"] != b64(edKey) || methods[0].Type != typ || methods[1].Type != typ {
										t.Fatalf("methods: %+v", methods)
									}
									if name == "envelope" && result.DocumentMetadata.VersionID != "7" {
										t.Fatalf("metadata: %+v", result.DocumentMetadata)
									}
								}
							}
						}
					}
					if requests.Load() != 1 || src.count() != 1 {
						t.Fatalf("requests=%d observations=%d, want one each", requests.Load(), src.count())
					}
				})
			}
		})
	}
}
