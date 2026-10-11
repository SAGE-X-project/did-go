package consumer

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

func consume(t *testing.T, c *Consumer, data, mt string, opts representation.ConsumeOptions) (*document.Document, representation.ConsumeInfo) {
	t.Helper()
	d, info, err := c.Consume([]byte(data), mt, opts)
	if err != nil {
		t.Fatalf("Consume(%s): %v", mt, err)
	}
	return d, info
}

func wantStep(t *testing.T, err error, step int) {
	t.Helper()
	var de *representation.DetectError
	if !errors.As(err, &de) || de.Step != step {
		t.Fatalf("got %v, want detection error at step %d", err, step)
	}
}

func wantConsumerError(t *testing.T, err error, statement string) {
	t.Helper()
	var ce *Error
	if !errors.As(err, &ce) || ce.Statement != statement || !strings.HasPrefix(ce.Error(), "consumer: ") {
		t.Fatalf("got %v, want *consumer.Error citing %q", err, statement)
	}
}

func wantConformanceError(t *testing.T, err error, statement string) {
	t.Helper()
	var ce *document.ConformanceError
	if !errors.As(err, &ce) || ce.Statement != statement {
		t.Fatalf("got %v, want *document.ConformanceError citing %q", err, statement)
	}
}

type detectionVector struct {
	ID                string  `json:"id"`
	MediaType         string  `json:"mediaType"`
	Context           *string `json:"context"`
	Version           string  `json:"version"`
	JSONLD            bool    `json:"jsonld"`
	Assumed           bool    `json:"assumed"`
	UnexpectedContext string  `json:"unexpectedContext"`
	ErrorStep         int     `json:"errorStep"`
	StrictErrorStep   int     `json:"strictErrorStep"`
	LowPrecision      *struct {
		Declared, Detected string
	} `json:"lowPrecision"`
}

func (v detectionVector) payload() string {
	if v.Context == nil {
		return `{"id":"did:example:123"}`
	}
	return `{"@context":"` + *v.Context + `","id":"did:example:123"}`
}

// TestDetectionVectors runs D1 to D11 of docs/10 §2.5 through the consumer.
func TestDetectionVectors(t *testing.T) {
	data, err := os.ReadFile("../representation/testdata/detection.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []detectionVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	c := New()
	t.Run("core10#production-and-consumption.15 the media type determines the representation", func(t *testing.T) {
		for _, v := range file.Vectors {
			t.Run(v.ID, func(t *testing.T) { runDetection(t, c, v) })
		}
	})
	t.Run("did11-cr20260305#production-and-consumption.15 the media type determines the representation", func(t *testing.T) {
		d, info := consume(t, c, `{"@context":"https://www.w3.org/ns/did/v1.1","id":"did:example:1"}`, "application/did+json", representation.ConsumeOptions{})
		if info.DetectedVersion != spec.V10 || info.IsJSONLD || info.UnexpectedContext != spec.ContextURLV11 {
			t.Fatalf("did+json decides V10 JSON whatever the payload says: %+v", info)
		}
		if _, ok := d.RepresentationEntries().Get("@context"); !ok {
			t.Fatal("@context kept as a representation-specific entry (D6)")
		}
	})
}

func runDetection(t *testing.T, c *Consumer, v detectionVector) {
	d, info, err := c.Consume([]byte(v.payload()), v.MediaType, representation.ConsumeOptions{})
	if v.ErrorStep != 0 {
		wantStep(t, err, v.ErrorStep)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if d.ID().String() != "did:example:123" {
		t.Fatal("document")
	}
	if info.DetectedVersion.String() != v.Version || info.IsJSONLD != v.JSONLD || info.Assumed != v.Assumed ||
		info.UnexpectedContext != v.UnexpectedContext || (info.LowPrecision == nil) != (v.LowPrecision == nil) {
		t.Fatalf("got %+v", info)
	}
	if lp := info.LowPrecision; lp != nil && (lp.Declared != v.LowPrecision.Declared || lp.Detected != v.LowPrecision.Detected) {
		t.Fatalf("LowPrecision = %+v", lp)
	}
	_, _, err = c.Consume([]byte(v.payload()), v.MediaType, representation.ConsumeOptions{Strict: true})
	if v.StrictErrorStep != 0 {
		wantStep(t, err, v.StrictErrorStep)
	} else if err != nil {
		t.Fatalf("strict: %v", err)
	}
}

type documentVector struct {
	ID         string          `json:"id"`
	MediaType  string          `json:"mediaType"`
	Version    string          `json:"version"`
	JSONLD     bool            `json:"jsonld"`
	Error      string          `json:"error"`
	Statement  string          `json:"statement"`
	Extensions []string        `json:"extensions"`
	Document   json.RawMessage `json:"document"`
}

// TestDocumentVectors runs the document conformance vectors of docs/10 §2.6.
func TestDocumentVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/documents.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []documentVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	c := New()
	for _, v := range file.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			d, info, err := c.Consume(v.Document, v.MediaType, representation.ConsumeOptions{})
			switch v.Error {
			case "consumer":
				wantConsumerError(t, err, v.Statement)
				return
			case "conformance":
				wantConformanceError(t, err, v.Statement)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if info.DetectedVersion.String() != v.Version || info.IsJSONLD != v.JSONLD {
				t.Fatalf("info %+v", info)
			}
			if !slices.Equal(d.Extensions().Keys(), v.Extensions) && len(v.Extensions)+d.Extensions().Len() > 0 {
				t.Fatalf("extensions %v, want %v", d.Extensions().Keys(), v.Extensions)
			}
		})
	}
}

func TestConformanceStatementsC1C3(t *testing.T) {
	c := New()
	t.Run("C1 a DID 1.1 document is consumed into the core model", func(t *testing.T) {
		d, _ := consume(t, c, `{"@context":"https://www.w3.org/ns/did/v1.1","id":"did:example:123456789abcdefghi","authentication":[{"id":"did:example:123456789abcdefghi#keys-1","type":"Multikey","controller":"did:example:123456789abcdefghi","publicKeyMultibase":"z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"}]}`, "application/did", representation.ConsumeOptions{})
		rs := d.Relationship(vm.Authentication)
		m, ok := rs[0].Method()
		if len(rs) != 1 || !ok || m.Type != vm.TypeMultikey || m.PublicKeyMultibase == "" {
			t.Fatalf("authentication %+v", rs)
		}
	})
	t.Run("C2 a DID Core 1.0 document with an extension type is normalized into the same model", func(t *testing.T) {
		d, info := consume(t, c, `{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/ed25519-2020/v1"],"id":"did:example:123456789abcdefghi","authentication":[{"id":"did:example:123456789abcdefghi#keys-1","type":"Ed25519VerificationKey2020","controller":"did:example:123456789abcdefghi","publicKeyMultibase":"zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"}]}`, "application/did+ld+json", representation.ConsumeOptions{})
		m, _ := d.Relationship(vm.Authentication)[0].Method()
		if info.DetectedVersion != spec.V10 || m.Type != "Ed25519VerificationKey2020" || m.PublicKeyMultibase != "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV" {
			t.Fatalf("got %+v %+v", info, m)
		}
	})
	t.Run("C3 both key materials are a conformance error", func(t *testing.T) {
		_, _, err := c.Consume([]byte(`{"id":"did:example:1","verificationMethod":[{"id":"did:example:1#k1","type":"Multikey","controller":"did:example:1","publicKeyMultibase":"z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu","publicKeyJwk":{"kty":"OKP"}}]}`), "application/did", representation.ConsumeOptions{})
		wantConformanceError(t, err, "cid10#verification-material.1")
	})
}

func TestInputs(t *testing.T) {
	c := New()
	doc := `{"id":"did:example:1"}`
	t.Run("core10#production-and-consumption.13 a media type is required input", func(t *testing.T) {
		_, _, err := c.Consume([]byte(doc), "", representation.ConsumeOptions{})
		wantStep(t, err, 5)
		_, _, err = c.Consume([]byte(`not json`), "text/plain", representation.ConsumeOptions{})
		wantStep(t, err, 5)
		_, _, err = c.Consume([]byte(doc), "application/did;;", representation.ConsumeOptions{})
		wantStep(t, err, 5)
	})
	t.Run("did11-cr20260305#production-and-consumption.13 a representation and a media type are the input", func(t *testing.T) {
		d, _ := consume(t, c, doc, "Application/DID; charset=utf-8", representation.ConsumeOptions{})
		if d.ID().String() != "did:example:1" {
			t.Fatal("id")
		}
	})
	t.Run("core10#production-and-consumption.14 options: Require, Strict and Expected", func(t *testing.T) {
		_, _, err := c.Consume([]byte(doc), "application/did", representation.ConsumeOptions{Require: spec.V10})
		wantStep(t, err, 6)
		_, info := consume(t, c, doc, "application/json", representation.ConsumeOptions{Expected: spec.V10})
		if info.DetectedVersion != spec.V10 || !info.Assumed {
			t.Fatalf("%+v", info)
		}
	})
	t.Run("did11-cr20260305#production-and-consumption.14 consumer options: limits and undefined terms", func(t *testing.T) {
		_, _, err := New(WithLimits(10, 0)).Consume([]byte(doc+"          "), "application/did", representation.ConsumeOptions{})
		wantConsumerError(t, err, "")
		_, _, err = New(WithLimits(0, 1)).Consume([]byte(`{"id":"did:example:1","x":[1]}`), "application/did", representation.ConsumeOptions{})
		wantConsumerError(t, err, "")
		consume(t, New(WithLimits(-1, -1)), doc, "application/did", representation.ConsumeOptions{})
	})
}

func TestRoot(t *testing.T) {
	c := New()
	for _, in := range []string{`[]`, `"did:example:1"`, `1`, `null`, `true`} {
		t.Run("core10#consumption.3 root "+in, func(t *testing.T) {
			_, _, err := c.Consume([]byte(in), "application/did+json", representation.ConsumeOptions{})
			wantConsumerError(t, err, "core10#consumption.3")
		})
		t.Run("did11-cr20260305#consumption.3 root "+in, func(t *testing.T) {
			_, _, err := c.Consume([]byte(in), "application/did", representation.ConsumeOptions{})
			wantConsumerError(t, err, "did11-cr20260305#consumption.3")
		})
	}
	t.Run("core10#consumption.2 every member of the root object is an entry of the document", func(t *testing.T) {
		d, _ := consume(t, c, `{"id":"did:example:1","alsoKnownAs":["https://a.example/"],"x":{"y":[1,2.5]}}`, "application/did+json", representation.ConsumeOptions{})
		x, ok := d.Extensions().Get("x")
		if len(d.AlsoKnownAs()) != 1 || !ok {
			t.Fatal("entries")
		}
		y, _ := x.(document.Map).Get("y")
		if y.(document.List).At(0) != document.Integer(1) || y.(document.List).At(1) != document.Double(2.5) {
			t.Fatal("integer and double")
		}
	})
	t.Run("core10#consumption.1 the JSON representation is deserialized by the consumption rules", func(t *testing.T) {
		_, _, err := c.Consume([]byte(`{"id":"did:example:1","x":9223372036854775808}`), "application/did+json", representation.ConsumeOptions{})
		wantConsumerError(t, err, "")
	})
	t.Run("malformed JSON, duplicate members and invalid UTF-8 are errors", func(t *testing.T) {
		for _, in := range []string{`{"id":"did:example:1",}`, `{"id":"did:example:1","id":"did:example:2"}`, "{\"id\":\"did:example:\xff\"}"} {
			_, _, err := c.Consume([]byte(in), "application/did", representation.ConsumeOptions{})
			wantConsumerError(t, err, "")
			if strings.Contains(err.Error(), "did:example") {
				t.Fatal("error messages must not echo the input")
			}
		}
	})
}

func TestEntryBuckets(t *testing.T) {
	c := New()
	t.Run("core10#production-and-consumption.16 @context is a representation-specific entry under every media type", func(t *testing.T) {
		for _, mt := range []string{"application/did+json", "application/did+ld+json"} {
			d, _ := consume(t, c, `{"@context":"https://www.w3.org/ns/did/v1","id":"did:example:1"}`, mt, representation.ConsumeOptions{})
			if v, ok := d.RepresentationEntries().Get("@context"); !ok || v != document.String(spec.ContextURLV10) || d.Extensions().Len() != 0 {
				t.Fatalf("%s: @context not in the representation-specific map", mt)
			}
		}
	})
	t.Run("did11-cr20260305#production-and-consumption.16 @context is kept verbatim", func(t *testing.T) {
		d, _ := consume(t, c, `{"@context":["https://www.w3.org/ns/did/v1.1",{"ext":"https://e.example/ext"}],"id":"did:example:1","ext":1}`, "application/did", representation.ConsumeOptions{})
		v, _ := d.RepresentationEntries().Get("@context")
		if l, ok := v.(document.List); !ok || l.Len() != 2 {
			t.Fatalf("@context %#v", v)
		}
		if _, ok := d.Extensions().Get("ext"); !ok {
			t.Fatal("a term defined by an inline context is kept")
		}
	})
	t.Run("core10#production-and-consumption.17 unrecognized entries are extensions, not representation-specific (FR-D7)", func(t *testing.T) {
		d, _ := consume(t, c, `{"id":"did:example:1","fooExtension":42,"@id":"x"}`, "application/did+json", representation.ConsumeOptions{})
		if v, ok := d.Extensions().Get("fooExtension"); !ok || v != document.Integer(42) {
			t.Fatal("fooExtension")
		}
		if d.RepresentationEntries().Len() != 0 || d.Extensions().Len() != 2 {
			t.Fatal("only known representation-specific entries go to that map")
		}
	})
	t.Run("did11-cr20260305#production-and-consumption.17 additional method and service properties are kept", func(t *testing.T) {
		d, _ := consume(t, c, `{"id":"did:example:1","verificationMethod":[{"id":"did:example:1#k","type":"X","controller":"did:example:1","n":1.50}],"service":[{"type":"A","serviceEndpoint":{"o":1},"r":[]}]}`, "application/did", representation.ConsumeOptions{})
		if d.VerificationMethods()[0].Extra["n"] != json.Number("1.50") {
			t.Fatal("method Extra")
		}
		s := d.Services()[0]
		if _, ok := s.Extra["r"]; !ok || s.ServiceEndpoint[0].Map["o"] != json.Number("1") {
			t.Fatal("service Extra")
		}
	})
}

func TestNonConforming(t *testing.T) {
	c := New()
	t.Run("core10#production-and-consumption.18 non-conforming documents are errors", func(t *testing.T) {
		_, _, err := c.Consume([]byte(`{"id":"did:example:1","service":[{"id":"did:example:1#s","type":"A","serviceEndpoint":"HTTPS://A.example/"}]}`), "application/did+json", representation.ConsumeOptions{})
		wantConformanceError(t, err, "core10#services.11")
	})
	t.Run("did11-cr20260305#production-and-consumption.18 non-conforming DIDs and documents are errors", func(t *testing.T) {
		cases := map[string]string{
			`{"id":1}`:                                                              "cid10#subjects.2",
			`{"id":"did:example:1","controller":1}`:                                 "core10#did-controller.2",
			`{"id":"did:example:1","controller":["x"]}`:                             "core10#did-controller.2",
			`{"id":"did:example:1","alsoKnownAs":"x"}`:                              "cid10#also-known-as.2",
			`{"id":"did:example:1","alsoKnownAs":[1]}`:                              "cid10#also-known-as.2",
			`{"id":"did:example:1","verificationMethod":{}}`:                        "cid10#verification-methods.1",
			`{"id":"did:example:1","verificationMethod":[1]}`:                       "cid10#verification-methods.1",
			`{"id":"did:example:1","authentication":"x"}`:                           "cid10#authentication.3",
			`{"id":"did:example:1","authentication":[1]}`:                           "cid10#authentication.3",
			`{"id":"did:example:1","authentication":["//x"]}`:                       "cid10#authentication.3",
			`{"id":"did:example:1","service":{}}`:                                   "cid10#services.2",
			`{"id":"did:example:1","service":[1]}`:                                  "cid10#services.2",
			`{"id":"did:example:1","service":[{"id":1}]}`:                           "cid10#services.6",
			`{"id":"did:example:1","service":[{"type":[1]}]}`:                       "cid10#services.9",
			`{"id":"did:example:1","service":[{"type":"A","serviceEndpoint":[1]}]}`: "cid10#services.12",
		}
		for _, m := range []struct{ name, value, statement string }{
			{"id", `1`, "cid10#verification-methods.3"}, {"id", `"//x"`, "cid10#verification-methods.3"},
			{"type", `1`, "cid10#verification-methods.6"}, {"controller", `"x"`, "cid10#verification-methods.3"},
			{"expires", `1`, "cid10#verification-methods.9"}, {"revoked", `"2020-01-01"`, "cid10#verification-methods.11"},
			{"publicKeyMultibase", `1`, "core10#verification-material.7"}, {"secretKeyMultibase", `1`, "cid10#Multikey.5"},
			{"publicKeyJwk", `"x"`, "cid10#JsonWebKey.3"}, {"secretKeyJwk", `[]`, "cid10#JsonWebKey.11"},
		} {
			cases[`{"id":"did:example:1","verificationMethod":[{"`+m.name+`":`+m.value+`}]}`] = m.statement
		}
		for in, statement := range cases {
			_, _, err := c.Consume([]byte(in), "application/did", representation.ConsumeOptions{})
			wantConsumerError(t, err, statement)
		}
		for _, in := range []string{`{"id":"did:example:1","x":1e999}`, `{"@context":"https://www.w3.org/ns/did/v1.1","id":"did:example:1","x":[1e999]}`,
			`{"id":"did:example:1","@context":[9223372036854775808]}`} {
			_, _, err := New(KeepUndefinedTerms()).Consume([]byte(in), "application/did+json", representation.ConsumeOptions{})
			wantConsumerError(t, err, "")
		}
	})
	t.Run("core10#services.7 two services with the same id are an error", func(t *testing.T) {
		_, _, err := c.Consume([]byte(`{"id":"did:example:1","service":[{"id":"#s","type":"A","serviceEndpoint":"https://a.example/"},{"id":"did:example:1#s","type":"A","serviceEndpoint":"https://b.example/"}]}`), "application/did", representation.ConsumeOptions{})
		wantConformanceError(t, err, "cid10#services.7")
	})
}

func TestDataTypes(t *testing.T) {
	c := New()
	t.Run("did11-cr20260305#consumption.1 datetimes, shapes and references", func(t *testing.T) {
		d, _ := consume(t, c, `{"id":"did:example:1","controller":["did:example:1"],`+
			`"verificationMethod":[{"id":"#k","type":"Multikey","controller":"did:example:1","expires":"2030-01-02T12:04:05+01:00","revoked":"2031-01-01T00:00:00.5Z"}],`+
			`"assertionMethod":["#k"],"service":[{"id":"#s","type":["A"],"serviceEndpoint":"https://a.example/"}]}`, "application/did", representation.ConsumeOptions{})
		if d.ControllerShape() != vm.ShapeSet || len(d.Controllers()) != 1 {
			t.Fatal("controller set of one")
		}
		m := d.VerificationMethods()[0]
		if m.Expires == nil || m.Expires.UTC().Hour() != 11 || m.Revoked.Nanosecond() != 500000000 {
			t.Fatalf("datetimes %v %v", m.Expires, m.Revoked)
		}
		s := d.Services()[0]
		if s.TypeShape != vm.ShapeSet || s.EndpointShape != vm.ShapeSingle {
			t.Fatalf("service shapes %s %s", s.TypeShape, s.EndpointShape)
		}
		if ref, ok := d.Relationship(vm.AssertionMethod)[0].Reference(); !ok || ref.String() != "#k" {
			t.Fatal("reference")
		}
	})
}

func TestJSONLD(t *testing.T) {
	c := New()
	body := `"id":"did:example:1","verificationMethod":[{"id":"did:example:1#k","type":"Multikey","controller":"did:example:1","publicKeyMultibase":"z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu","x":1}],` +
		`"service":[{"id":"did:example:1#s","type":"A","serviceEndpoint":"https://a.example/","y":2}],"fooExtension":42}`
	t.Run("did11-cr20260305#json-ld-processors.8 terms the v1.1 context does not define are dropped", func(t *testing.T) {
		d, _ := consume(t, c, `{"@context":"https://www.w3.org/ns/did/v1.1",`+body, "application/did", representation.ConsumeOptions{})
		m := d.VerificationMethods()[0]
		if d.Extensions().Len() != 0 || m.Extra != nil || d.Services()[0].Extra != nil || m.PublicKeyMultibase == "" {
			t.Fatalf("undefined terms kept: %v %v %v", d.Extensions().Keys(), m.Extra, d.Services()[0].Extra)
		}
	})
	t.Run("core10#consumption-0.2 terms the v1 context does not define are dropped", func(t *testing.T) {
		v10 := strings.Replace(body, `"x":1`, `"expires":"2030-01-01T00:00:00Z"`, 1)
		d, _ := consume(t, c, `{"@context":"https://www.w3.org/ns/did/v1",`+v10, "application/did+ld+json", representation.ConsumeOptions{})
		m := d.VerificationMethods()[0]
		if d.Extensions().Len() != 0 || m.Expires != nil || d.Services()[0].Extra != nil {
			t.Fatal("expires, y and fooExtension are not defined by the v1 context")
		}
		if m.PublicKeyMultibase != "" {
			t.Fatal("the v1 context leaves publicKeyMultibase to suite contexts (DID Core 1.0 Example 1), so it is dropped")
		}
	})
	t.Run("undefined terms are kept when a context is not known locally, for JSON, and with KeepUndefinedTerms", func(t *testing.T) {
		unknown, _ := consume(t, c, `{"@context":["https://www.w3.org/ns/did/v1","https://e.example/v1"],`+body, "application/did+ld+json", representation.ConsumeOptions{})
		plain, _ := consume(t, c, `{`+body, "application/did", representation.ConsumeOptions{})
		kept, _ := consume(t, New(KeepUndefinedTerms()), `{"@context":"https://www.w3.org/ns/did/v1.1",`+body, "application/did", representation.ConsumeOptions{})
		for name, d := range map[string]*document.Document{"unknown context": unknown, "JSON": plain, "KeepUndefinedTerms": kept} {
			if d.Extensions().Len() != 1 || d.VerificationMethods()[0].Extra["x"] == nil || d.Services()[0].Extra["y"] == nil {
				t.Errorf("%s: terms dropped", name)
			}
		}
	})
	t.Run("core10#consumption-0.1 JSON-LD is consumed by the JSON consumption rules", func(t *testing.T) {
		ld, _ := consume(t, New(KeepUndefinedTerms()), `{"@context":"https://www.w3.org/ns/did/v1",`+body, "application/did+ld+json", representation.ConsumeOptions{})
		plain, _ := consume(t, c, `{`+body, "application/did+json", representation.ConsumeOptions{})
		stripped, err := document.NewBuilderFrom(plain).RepresentationEntry("@context", document.String(spec.ContextURLV10)).Build()
		if err != nil || !reflect.DeepEqual(ld, stripped) {
			t.Fatal("JSON-LD consumption differs from JSON consumption beyond @context")
		}
	})
	t.Run("did11-cr20260305#json-ld-processors.1 @context must have a JSON-LD form", func(t *testing.T) {
		for _, mt := range []string{"application/did", "application/ld+json"} {
			_, _, err := c.Consume([]byte(`{"@context":["https://www.w3.org/ns/did/v1.1",1],"id":"did:example:1"}`), mt, representation.ConsumeOptions{})
			wantConsumerError(t, err, "did11-cr20260305#json-ld-processors.1")
		}
		_, _, err := c.Consume([]byte(`{"@context":["https://www.w3.org/ns/did/v1",""],"id":"did:example:1"}`), "application/did+ld+json", representation.ConsumeOptions{})
		wantConsumerError(t, err, "core10#consumption-0.1")
		_, _, err = c.Consume([]byte(`{"@context":["https://www.w3.org/ns/did/v1.1",1e999],"id":"did:example:1"}`), "application/did", representation.ConsumeOptions{})
		wantConsumerError(t, err, "did11-cr20260305#json-ld-processors.1")
		d, _ := consume(t, c, `{"@context":[1],"id":"did:example:1"}`, "application/did+json", representation.ConsumeOptions{})
		if _, ok := d.RepresentationEntries().Get("@context"); !ok {
			t.Fatal("did+json keeps any @context verbatim")
		}
	})
}
