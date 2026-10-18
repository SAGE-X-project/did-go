package sage

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method/key"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
)

// RESOLVE-03 requires an explicit boolean for all SAGE record states.
// Generic document.Metadata still permits absence; that policy is unchanged.
func TestSAGEResponseMetadata(t *testing.T) {
	for _, state := range []State{StateCreated, StateActive, StateDeactivated} {
		t.Run(string(state), func(t *testing.T) {
			rec := activeRecord(t)
			rec.State = state
			result := Respond(t.Context(), newSource(rec), Request{DID: rec.DID, Accept: MediaTypeEnvelope}, producer.New())
			var envelope map[string]json.RawMessage
			if result.Problem != nil || json.Unmarshal(result.Body, &envelope) != nil || len(envelope) != 3 {
				t.Fatalf("envelope: %+v", result)
			}
			var md map[string]json.RawMessage
			if json.Unmarshal(envelope["didDocumentMetadata"], &md) != nil {
				t.Fatal("missing metadata")
			}
			want := "false"
			if state == StateDeactivated {
				want = "true"
			}
			if string(md["deactivated"]) != want || string(md["versionId"]) != `"7"` || md["sage"] == nil {
				t.Fatalf("metadata: %s", envelope["didDocumentMetadata"])
			}
			var roundTrip document.Metadata
			if json.Unmarshal(envelope["didDocumentMetadata"], &roundTrip) != nil || !roundTrip.DeactivatedPresent || !roundTrip.Clone().DeactivatedPresent {
				t.Fatal("presence lost")
			}
		})
	}
	t.Run("generic-absence", func(t *testing.T) {
		raw, err := json.Marshal(document.Metadata{})
		if err != nil || string(raw) != "{}" {
			t.Fatalf("generic metadata changed: %s %v", raw, err)
		}
	})
}

// Only the root's typed negotiation refusal carries representation.unsupported.
func TestSAGEAcceptDiagnostics(t *testing.T) {
	for _, name := range []string{"unsupported", "supported", "unknown-option", "malformed-accept", "other-method", "stale"} {
		t.Run(name, func(t *testing.T) {
			src := newSource(activeRecord(t))
			r := newResolver(t, src, key.New(producer.New()))
			d := mustDID(t, testDID)
			opts := resolution.ResolutionOptions{Accept: "text/html"}
			want := CodeRepresentationUnsupported
			mapped := resolution.CodeFeatureNotSupported
			calls := 0
			typed := true
			switch name {
			case "supported":
				opts.Accept = MediaTypeDID11
				want = ""
				mapped = ""
				calls = 1
				typed = false
			case "unknown-option":
				opts.Extra = map[string]any{"unknown": true}
				want = ""
				typed = false
			case "malformed-accept":
				opts.Accept = "application/did;q=invalid"
				want = ""
				mapped = resolution.CodeInvalidOptions
				typed = false
			case "other-method":
				d = mustDID(t, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
				want = ""
			case "stale":
				opts.Accept = MediaTypeDID11
				src.errs[testDID] = NewError(CodeRecordStale, "")
				want = CodeRecordStale
				mapped = resolution.CodeInternalError
				calls = 1
				typed = false
			}
			result, code := r.ResolveWithCode(t.Context(), d, opts)
			if code != want || src.count() != calls {
				t.Fatalf("code=%q calls=%d, want %q/%d", code, src.count(), want, calls)
			}
			e := result.ResolutionMetadata.Error
			if mapped == "" {
				if e != nil || result.Document == nil {
					t.Fatalf("success: %+v", result)
				}
				return
			}
			if e == nil || e.Type != mapped.TypeURL() || e.IsAcceptNotSupported() != typed || result.Document != nil || !result.DocumentMetadata.IsEmpty() {
				t.Fatalf("failure: %+v", result)
			}
		})
	}
}

// Actual owned TLS GET/POST traffic verifies the problem extension without
// reclassifying malformed requests, other methods or unsupported options.
func TestSAGEResponseTLS(t *testing.T) {
	for _, verb := range []string{http.MethodGet, http.MethodPost} {
		t.Run(verb, func(t *testing.T) {
			for _, name := range []string{"unsupported", "supported", "unknown-option", "malformed-accept", "other-method", "wrong-method"} {
				t.Run(name, func(t *testing.T) {
					src := newSource(activeRecord(t))
					h := NewHandler(newResolver(t, src, key.New(producer.New())), prefix)
					server := httptest.NewTLSServer(h)
					defer server.Close()
					id := testDID
					accept := "text/html"
					status := http.StatusNotImplemented
					wantCode := "representation.unsupported"
					mapped := resolution.CodeFeatureNotSupported.TypeURL()
					calls := 0
					method := verb
					body := "{}"
					query := ""
					switch name {
					case "supported":
						accept = "application/did-resolution"
						status = http.StatusOK
						wantCode = ""
						mapped = ""
						calls = 1
					case "unknown-option":
						wantCode = ""
						if verb == http.MethodPost {
							body = `{"unknown":true}`
						} else {
							id = strings.ReplaceAll(testDID, ":", "%3A")
							query = "?unknown=true"
						}
					case "malformed-accept":
						accept = "application/did;q=invalid"
						status = http.StatusBadRequest
						wantCode = ""
						mapped = resolution.CodeInvalidOptions.TypeURL()
					case "other-method":
						id = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
						wantCode = ""
					case "wrong-method":
						method = http.MethodPut
						status = http.StatusMethodNotAllowed
						wantCode = ""
						mapped = "about:blank"
					}
					req, err := http.NewRequestWithContext(t.Context(), method, server.URL+prefix+"/"+id+query, strings.NewReader(body))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Accept", accept)
					req.Header.Set("Content-Type", "application/json")
					res, err := server.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if err := res.Body.Close(); err != nil {
							t.Error(err)
						}
					}()
					var wire map[string]json.RawMessage
					if json.NewDecoder(res.Body).Decode(&wire) != nil {
						t.Fatal("invalid response JSON")
					}
					if res.StatusCode != status || src.count() != calls {
						t.Fatalf("status=%d calls=%d, want %d/%d: %v", res.StatusCode, src.count(), status, calls, wire)
					}
					if name == "supported" {
						var md map[string]json.RawMessage
						if json.Unmarshal(wire["didDocumentMetadata"], &md) != nil || string(md["deactivated"]) != "false" {
							t.Fatal("active presence lost on TLS")
						}
					} else {
						var typ, code string
						_ = json.Unmarshal(wire["type"], &typ)
						_ = json.Unmarshal(wire["sageCode"], &code)
						if typ != mapped || code != wantCode || (wantCode == "" && wire["sageCode"] != nil) || wire["didDocument"] != nil {
							t.Fatalf("problem: %v", wire)
						}
					}
				})
			}
		})
	}
}
