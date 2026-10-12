package sage

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/producer"
)

// DIDP-02, SAGE interface: the value is matched as one media type without
// parameters.
func TestSelect(t *testing.T) {
	ok := map[string]Selection{
		"":                     SelectCore10,
		"*/*":                  SelectCore10,
		"application/did+json": SelectCore10,
		"application/did":      SelectDID11,
		"application/json":     SelectEnvelope,
	}
	for accept, want := range ok {
		if got, e := Select(accept); e != nil || got != want {
			t.Errorf("Select(%q) = %v, %v", accept, got, e)
		}
	}
	for _, accept := range []string{
		"application/did+ld+json",
		"application/did-resolution",
		"application/did;q=0.9, application/did+json",
		"application/did, application/did+json",
		"application/did; charset=utf-8",
		"Application/DID",
		" application/did",
		"text/html",
	} {
		if _, e := Select(accept); e == nil || e.Code != CodeRepresentationUnsupported || e.Problem().Status != 406 {
			t.Errorf("Select(%q) accepted: %v", accept, e)
		}
	}
}

func TestRespond(t *testing.T) {
	r := activeRecord(t)
	src := newSource(r)
	for accept, want := range map[string]string{"": MediaTypeCore10, "application/did": MediaTypeDID11} {
		res := Respond(t.Context(), src, Request{DID: r.DID, Accept: accept}, producer.New())
		if res.Problem != nil || res.ContentType != want {
			t.Errorf("accept %q: %+v", accept, res)
		}
	}
	// RESOLVE-05: application/json is the three-member envelope with the
	// DID Core 1.0 projection.
	res := Respond(t.Context(), src, Request{DID: r.DID, Accept: "application/json"}, producer.New())
	var env map[string]json.RawMessage
	if res.Problem != nil || res.ContentType != "application/json" || json.Unmarshal(res.Body, &env) != nil || len(env) != 3 {
		t.Fatalf("envelope %+v", res)
	}
	if string(env["didResolutionMetadata"]) != `{"contentType":"application/did+json"}` {
		t.Errorf("resolution metadata %s", env["didResolutionMetadata"])
	}
	if string(env["didDocument"]) != produce(t, r, Core10) {
		t.Errorf("envelope document %s", env["didDocument"])
	}
}

// RESOLVE-03: a deactivated record still resolves for inspection on the
// SAGE interface, with its projection and deactivated metadata.
func TestRespondDeactivated(t *testing.T) {
	r := activeRecord(t)
	r.State = StateDeactivated
	res := Respond(t.Context(), newSource(r), Request{DID: r.DID, Accept: "application/json"}, producer.New())
	var env struct {
		Metadata map[string]any `json:"didDocumentMetadata"`
	}
	if res.Problem != nil || json.Unmarshal(res.Body, &env) != nil || env.Metadata["deactivated"] != true {
		t.Errorf("deactivated %+v", res)
	}
}

func TestRespondFailures(t *testing.T) {
	r := activeRecord(t)
	src := newSource(r)
	other := mustDID(t, "did:sage:web:registry.example:agent-2")
	src.errs[other.String()] = errors.New("network")
	cases := []struct {
		req  Request
		code Code
	}{
		{Request{DID: r.DID, Accept: "application/did+ld+json"}, CodeRepresentationUnsupported},
		{Request{DID: mustDID(t, "did:sage:web:registry.example:none")}, CodeRecordNotFound},
		{Request{DID: other}, CodeRecordUnreachable},
	}
	for _, c := range cases {
		if res := Respond(t.Context(), src, c.req, producer.New()); res.Problem == nil || res.Problem.Code != c.code {
			t.Errorf("%+v: %+v", c.req, res)
		}
	}
	if src.calls != 2 {
		t.Errorf("an unsupported accept still observed the record: %d observations", src.calls)
	}
	mismatch := newSource()
	mismatch.records[other.String()] = r
	if res := Respond(t.Context(), mismatch, Request{DID: other}, producer.New()); res.Problem == nil || res.Problem.Code != CodeRecordInvalid {
		t.Errorf("record of another identifier: %+v", res)
	}
	bad := activeRecord(t)
	bad.Version = "0"
	if res := Respond(t.Context(), newSource(bad), Request{DID: bad.DID}, producer.New()); res.Problem == nil || res.Problem.Code != CodeRecordInvalid {
		t.Errorf("invalid record: %+v", res)
	}
	big := stubProducer{data: []byte(`{"id":"` + strings.Repeat("a", maxResponse-20) + `"}`), mt: MediaTypeCore10}
	if res := Respond(t.Context(), src, Request{DID: r.DID, Accept: "application/json"}, big); res.Problem == nil || res.Problem.Code != CodeSizeExceeded {
		t.Errorf("oversized envelope: %+v", res)
	}
	invalidJSON := stubProducer{data: []byte("{"), mt: MediaTypeCore10}
	if res := Respond(t.Context(), src, Request{DID: r.DID, Accept: "application/json"}, invalidJSON); res.Problem == nil || res.Problem.Code != CodeRecordInvalid {
		t.Errorf("invalid document bytes: %+v", res)
	}
}
