package producer

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

const (
	subject = "did:example:123456789abcdefghi"
	mk      = "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
)

func mustDID(t *testing.T, s string) did.DID {
	t.Helper()
	d, err := did.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustRef(t *testing.T, s string) did.DIDURL {
	t.Helper()
	u, err := did.ParseReference(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func key(t *testing.T, id string) vm.Method {
	t.Helper()
	return vm.Method{ID: mustRef(t, id), Type: "Multikey", Controller: mustDID(t, subject), PublicKeyMultibase: mk}
}

func build(t *testing.T, b *document.Builder) *document.Document {
	t.Helper()
	d, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// simple is the C1 document of docs/10 §2.6 without its @context.
func simple(t *testing.T) *document.Document {
	t.Helper()
	return build(t, document.NewBuilder(mustDID(t, subject)).Relationship(vm.Authentication, vm.Embed(key(t, subject+"#keys-1"))))
}

func produce(t *testing.T, p *Producer, d *document.Document, opts representation.ProduceOptions) (string, string) {
	t.Helper()
	data, mt, err := p.Produce(d, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatalf("invalid JSON: %s", data)
	}
	return string(data), mt
}

const simpleBody = `"id":"did:example:123456789abcdefghi","authentication":[{"id":"did:example:123456789abcdefghi#keys-1",` +
	`"type":"Multikey","controller":"did:example:123456789abcdefghi","publicKeyMultibase":"` + mk + `"}]}`

func TestProfiles(t *testing.T) {
	p := New()
	d := simple(t)
	cases := []struct {
		name    string
		opts    representation.ProduceOptions
		body    string
		mt      string
		version spec.Version
	}{
		{"core10#production.4 V10 JSON is application/did+json", representation.ProduceOptions{Version: spec.V10},
			`{` + simpleBody, spec.MediaTypeDIDJSON, spec.V10},
		{"core10#production-0.6 V10 JSON-LD is application/did+ld+json", representation.ProduceOptions{Version: spec.V10, JSONLD: true},
			`{"@context":"https://www.w3.org/ns/did/v1",` + simpleBody, spec.MediaTypeDIDLDJSON, spec.V10},
		{"did11-cr20260305#production.4 V11 JSON is application/did", representation.ProduceOptions{Version: spec.V11},
			`{` + simpleBody, spec.MediaTypeDID, spec.V11},
		{"did11-cr20260305#json-ld-processors.7 V11 JSON-LD is application/did", representation.ProduceOptions{Version: spec.V11, JSONLD: true},
			`{"@context":"https://www.w3.org/ns/did/v1.1",` + simpleBody, spec.MediaTypeDID, spec.V11},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, mt := produce(t, p, d, c.opts)
			if got != c.body || mt != c.mt {
				t.Fatalf("got %s %s\nwant %s %s", mt, got, c.mt, c.body)
			}
			if representation.MediaTypeFor(c.version, c.opts.JSONLD) != mt {
				t.Fatal("media type differs from the profile")
			}
		})
	}
	t.Run("core10#production-and-consumption.11 the media type of the representation is returned", func(t *testing.T) {
		for _, mt := range representation.CoreMediaTypes() {
			opts, _ := representation.OptionsFor(mt)
			if _, got := produce(t, p, d, opts); got != mt {
				t.Errorf("%s: returned %s", mt, got)
			}
		}
	})
	t.Run("did11-cr20260305#production-and-consumption.11 the DID 1.1 media type is returned", func(t *testing.T) {
		if _, mt := produce(t, p, d, representation.ProduceOptions{}); mt != spec.MediaTypeDID {
			t.Fatal(mt)
		}
	})
	t.Run("did11-cr20260305#media-types.1 every production is identified by a media type", func(t *testing.T) {
		for _, v := range spec.Supported() {
			for _, ld := range []bool{false, true} {
				_, mt := produce(t, p, d, representation.ProduceOptions{Version: v, JSONLD: ld})
				if !representation.IsDIDMediaType(mt) {
					t.Errorf("%s %v: %q", v, ld, mt)
				}
			}
		}
	})
	t.Run("cid10#context-injection.2 JSON production without JSON-LD writes no @context", func(t *testing.T) {
		withCtx := build(t, document.NewBuilderFrom(d).RepresentationEntry("@context", document.String(spec.ContextURLV11)))
		for _, v := range spec.Supported() {
			if got, _ := produce(t, p, withCtx, representation.ProduceOptions{Version: v}); strings.Contains(got, "@context") {
				t.Errorf("%s: %s", v, got)
			}
		}
	})
}

func rich(t *testing.T) *document.Document {
	t.Helper()
	return richWith(t, document.String(spec.ContextURLV11))
}

func richWith(t *testing.T, ctx document.Value) *document.Document {
	t.Helper()
	exp := time.Date(2030, 1, 2, 12, 4, 5, 999, time.FixedZone("x", 3600))
	m := key(t, subject+"#keys-2")
	m.Expires = &exp
	m.Extra = map[string]any{"zeta": json.Number("1.50"), "alpha": []any{"b", map[string]any{"y": true, "x": nil}}}
	ext, _ := document.NewMap(document.Entry{Key: "b", Value: document.Integer(1)}, document.Entry{Key: "a", Value: document.Double(2)})
	return build(t, document.NewBuilder(mustDID(t, subject)).
		Controller(mustDID(t, "did:example:c")).ControllerShape(vm.ShapeSet).
		AlsoKnownAs("https://a.example/").
		VerificationMethod(key(t, subject+"#keys-1"), m).
		Relationship(vm.AssertionMethod, vm.Ref(mustRef(t, "#keys-2"))).
		Relationship(vm.CapabilityDelegation, vm.Ref(mustRef(t, subject+"#keys-1"))).
		Service(vm.Service{ID: subject + "#svc", Type: []string{"LinkedDomains"}, TypeShape: vm.ShapeSet,
			ServiceEndpoint: []vm.Endpoint{{Map: map[string]any{"origins": []any{"https://a.example/"}}}},
			Extra:           map[string]any{"routingKeys": []any{}}}).
		Extension("fooExtension", document.Integer(42)).Extension("zz", ext).
		RepresentationEntry("@context", ctx).
		RepresentationEntry("@sage", document.Boolean(true)))
}

const richBody = `"id":"did:example:123456789abcdefghi","controller":["did:example:c"],"alsoKnownAs":["https://a.example/"],` +
	`"verificationMethod":[{"id":"did:example:123456789abcdefghi#keys-1","type":"Multikey","controller":"did:example:123456789abcdefghi","publicKeyMultibase":"` + mk + `"},` +
	`{"id":"did:example:123456789abcdefghi#keys-2","type":"Multikey","controller":"did:example:123456789abcdefghi","expires":"2030-01-02T11:04:05Z","publicKeyMultibase":"` + mk + `",` +
	`"alpha":["b",{"x":null,"y":true}],"zeta":1.50}],"assertionMethod":["#keys-2"],"capabilityDelegation":["did:example:123456789abcdefghi#keys-1"],` +
	`"service":[{"id":"did:example:123456789abcdefghi#svc","type":["LinkedDomains"],"serviceEndpoint":{"origins":["https://a.example/"]},"routingKeys":[]}],` +
	`"@sage":true,"fooExtension":42,"zz":{"b":1,"a":2.0}}`

func TestAllEntries(t *testing.T) {
	p := New()
	d := rich(t)
	t.Run("did11-cr20260305#production-and-consumption.10 every entry and representation-specific entry is serialized", func(t *testing.T) {
		got, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V11, JSONLD: true})
		if want := `{"@context":"https://www.w3.org/ns/did/v1.1",` + richBody; got != want {
			t.Fatalf("got  %s\nwant %s", got, want)
		}
	})
	t.Run("core10#production-and-consumption.10 the same entries in DID Core 1.0 JSON", func(t *testing.T) {
		got, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V10})
		if want := `{` + richBody; got != want {
			t.Fatalf("got  %s\nwant %s", got, want)
		}
	})
	t.Run("core10#production-and-consumption.8 the input is the data model and the representation-specific entries map", func(t *testing.T) {
		got, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V11})
		if !strings.Contains(got, `"@sage":true`) || strings.Contains(got, "@context") {
			t.Fatal(got)
		}
	})
	t.Run("did11-cr20260305#production-and-consumption.8 the existing @context entry is used for JSON-LD", func(t *testing.T) {
		ext := build(t, document.NewBuilder(mustDID(t, subject)).RepresentationEntry("@context", mustList(t,
			document.String(spec.ContextURLV11), document.String("https://e.example/v1"))))
		got, _ := produce(t, p, ext, representation.ProduceOptions{JSONLD: true})
		if got != `{"@context":["https://www.w3.org/ns/did/v1.1","https://e.example/v1"],"id":"did:example:123456789abcdefghi"}` {
			t.Fatal(got)
		}
	})
	t.Run("core10#production.2 all entries are members of the root JSON Object", func(t *testing.T) {
		got, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V11})
		var root map[string]json.RawMessage
		if err := json.Unmarshal([]byte(got), &root); err != nil || len(root) != 10 {
			t.Fatalf("%d members: %v", len(root), err)
		}
	})
	t.Run("did11-cr20260305#production.2 all entries are members of the root JSON Object", func(t *testing.T) {
		got, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V11, JSONLD: true})
		if !strings.HasPrefix(got, "{") || !strings.HasSuffix(got, "}") || strings.Count(got, `"fooExtension"`) != 1 {
			t.Fatal(got)
		}
	})
	t.Run("core10#production.3 entries contain substructures", func(t *testing.T) {
		got, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V11})
		if !strings.Contains(got, `"zz":{"b":1,"a":2.0}`) || !strings.Contains(got, `"alpha":["b",{"x":null,"y":true}]`) {
			t.Fatal(got)
		}
	})
	t.Run("did11-cr20260305#production.3 entries contain substructures", func(t *testing.T) {
		got, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V11, JSONLD: true})
		if !strings.Contains(got, `"serviceEndpoint":{"origins":["https://a.example/"]}`) {
			t.Fatal(got)
		}
	})
}

func mustList(t *testing.T, vs ...document.Value) document.List {
	t.Helper()
	l, err := document.NewList(vs...)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestDataTypes(t *testing.T) {
	p := New()
	t.Run("core10#production.1 map, list, datetime, string, integer, double, boolean and null", func(t *testing.T) {
		l := mustList(t, document.String("s"), document.Integer(-1), document.Double(3), document.Boolean(true), document.Null{},
			document.NewDateTime(time.Date(2020, 12, 21, 4, 17, 47, 123, time.FixedZone("x", 9*3600))))
		d := build(t, document.NewBuilder(mustDID(t, subject)).Extension("x", l))
		got, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V10})
		if !strings.Contains(got, `"x":["s",-1,3.0,true,null,"2020-12-20T19:17:47Z"]`) {
			t.Fatal(got)
		}
	})
	t.Run("did11-cr20260305#production.1 a datetime is UTC without sub-second precision", func(t *testing.T) {
		got, _ := produce(t, p, rich(t), representation.ProduceOptions{})
		if !strings.Contains(got, `"expires":"2030-01-02T11:04:05Z"`) {
			t.Fatal(got)
		}
	})
	t.Run("core10#production-0.1 JSON-LD uses the JSON production rules", func(t *testing.T) {
		d := rich(t)
		ld, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V10, JSONLD: true})
		plain, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V10})
		if strings.Replace(ld, `"@context":"https://www.w3.org/ns/did/v1",`, "", 1) != plain {
			t.Fatalf("JSON-LD differs from JSON beyond @context:\n%s\n%s", ld, plain)
		}
	})
	t.Run("did11-cr20260305#json-ld-processors.2 JSON-LD uses the JSON production rules", func(t *testing.T) {
		d := rich(t)
		ld, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V11, JSONLD: true})
		plain, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V11})
		if strings.Replace(ld, `"@context":"https://www.w3.org/ns/did/v1.1",`, "", 1) != plain {
			t.Fatal("JSON-LD differs from JSON beyond @context")
		}
	})
}

func TestContext(t *testing.T) {
	p := New()
	d := simple(t)
	t.Run("core10#production-0.2 JSON-LD production includes @context", func(t *testing.T) {
		got, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V10, JSONLD: true})
		if !strings.HasPrefix(got, `{"@context":`) {
			t.Fatal(got)
		}
	})
	t.Run("core10#production-0.3 @context is the v1 string or a list starting with it", func(t *testing.T) {
		v11 := build(t, document.NewBuilderFrom(d).RepresentationEntry("@context", mustList(t,
			document.String(spec.ContextURLV11), document.String("https://e.example/v1"))))
		got, _ := produce(t, p, v11, representation.ProduceOptions{Version: spec.V10, JSONLD: true})
		if !strings.HasPrefix(got, `{"@context":["https://www.w3.org/ns/did/v1","https://e.example/v1"],`) {
			t.Fatal(got)
		}
	})
	t.Run("did11-cr20260305#json-ld-processors.3 JSON-LD production includes @context", func(t *testing.T) {
		got, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V11, JSONLD: true})
		if !strings.HasPrefix(got, `{"@context":"https://www.w3.org/ns/did/v1.1"`) {
			t.Fatal(got)
		}
	})
	t.Run("did11-cr20260305#json-ld-processors.4 @context is the v1.1 string or a list starting with it", func(t *testing.T) {
		v10 := build(t, document.NewBuilderFrom(d).RepresentationEntry("@context", mustList(t, document.String(spec.ContextURLV10))))
		got, _ := produce(t, p, v10, representation.ProduceOptions{Version: spec.V11, JSONLD: true})
		if !strings.HasPrefix(got, `{"@context":["https://www.w3.org/ns/did/v1.1"],`) {
			t.Fatal(got)
		}
	})
	t.Run("cid10#context-injection.1 a document without @context gets the DID 1.1 context, which declares the CID terms", func(t *testing.T) {
		got, _ := produce(t, p, d, representation.ProduceOptions{JSONLD: true})
		if !strings.HasPrefix(got, `{"@context":"https://www.w3.org/ns/did/v1.1"`) {
			t.Fatal(got)
		}
	})
	t.Run("did11-cr20260305#json-ld-processors.1 a malformed existing @context is refused", func(t *testing.T) {
		bad := build(t, document.NewBuilderFrom(d).RepresentationEntry("@context", document.Integer(1)))
		_, _, err := p.Produce(bad, representation.ProduceOptions{JSONLD: true})
		wantError(t, err, "did11-cr20260305#json-ld-processors.4")
		_, _, err = p.Produce(bad, representation.ProduceOptions{Version: spec.V10, JSONLD: true})
		wantError(t, err, "core10#production-0.3")
		if _, _, err := p.Produce(bad, representation.ProduceOptions{}); err != nil {
			t.Fatal("JSON production does not write @context:", err)
		}
	})
}

func wantError(t *testing.T, err error, statement string) {
	t.Helper()
	var pe *Error
	var ce *document.ConformanceError
	switch {
	case errors.As(err, &pe):
		if pe.Statement != statement || !strings.Contains(pe.Error(), "producer:") {
			t.Fatalf("got %v, want statement %s", err, statement)
		}
	case errors.As(err, &ce):
		if ce.Statement != statement {
			t.Fatalf("got %v, want statement %s", err, statement)
		}
	default:
		t.Fatalf("got %v, want an error citing %s", err, statement)
	}
}

func jwkMethod(t *testing.T) vm.Method {
	t.Helper()
	return vm.Method{
		ID: mustRef(t, subject+"#jwk"), Type: "JsonWebKey", Controller: mustDID(t, subject),
		PublicKeyJwk: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
		SecretKeyJwk: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"},
	}
}

func TestSecretMaterial(t *testing.T) {
	p := New()
	m := jwkMethod(t)
	d := build(t, document.NewBuilder(mustDID(t, subject)).VerificationMethod(m))
	t.Run("cid10#JsonWebKey.12 secret key material is not written by default", func(t *testing.T) {
		for _, v := range spec.Supported() {
			got, _ := produce(t, p, d, representation.ProduceOptions{Version: v, JSONLD: true})
			if strings.Contains(got, "secretKey") || strings.Contains(got, `"d"`) || !strings.Contains(got, "publicKeyJwk") {
				t.Fatalf("%s: %s", v, got)
			}
		}
	})
	t.Run("core10#production-and-consumption.9 IncludeSecret writes secret key material on request", func(t *testing.T) {
		got, _ := produce(t, p, d, representation.ProduceOptions{IncludeSecret: true})
		if !strings.Contains(got, `"secretKeyJwk":{"crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"`) {
			t.Fatal(got)
		}
	})
	t.Run("did11-cr20260305#production-and-consumption.9 options select version, JSON-LD and secrets", func(t *testing.T) {
		got, mt := produce(t, p, d, representation.ProduceOptions{Version: spec.VUnknown})
		if mt != spec.MediaTypeDID || strings.Contains(got, "secretKeyJwk") {
			t.Fatal("VUnknown means spec.Latest and secrets stay out")
		}
	})
}

func TestNonConforming(t *testing.T) {
	p := New()
	svc := vm.Service{Type: []string{"A"}, ServiceEndpoint: []vm.Endpoint{{URL: "https://e.example"}}}
	noID := build(t, document.NewBuilder(mustDID(t, subject)).Service(svc))
	t.Run("core10#production-and-consumption.12 V10 production requires service.id (docs/10 C6)", func(t *testing.T) {
		_, _, err := p.Produce(noID, representation.ProduceOptions{Version: spec.V10})
		wantError(t, err, "core10#services.3")
		if _, _, err := p.Produce(noID, representation.ProduceOptions{Version: spec.V11}); err != nil {
			t.Fatal("V11 production of a service without id must succeed:", err)
		}
	})
	t.Run("did11-cr20260305#production-and-consumption.12 a document that Validate rejects is not produced", func(t *testing.T) {
		rel := build(t, document.NewBuilder(mustDID(t, subject)).VerificationMethod(key(t, "#k")))
		_, _, err := p.Produce(rel, representation.ProduceOptions{Version: spec.V10, JSONLD: true})
		wantError(t, err, "core10#verification-methods.6")
		if _, _, err := p.Produce(rel, representation.ProduceOptions{Version: spec.V11}); err != nil {
			t.Fatal("relative method ids are DID 1.1 conforming:", err)
		}
		notNormal := svc
		notNormal.ID = subject + "#s"
		notNormal.ServiceEndpoint = []vm.Endpoint{{URL: "HTTPS://E.example/"}}
		nn := build(t, document.NewBuilder(mustDID(t, subject)).Service(notNormal))
		_, _, err = p.Produce(nn, representation.ProduceOptions{Version: spec.V10})
		wantError(t, err, "core10#services.11")
	})
	t.Run("no document, an unsupported version and unwritable values are refused", func(t *testing.T) {
		if _, _, err := p.Produce(nil, representation.ProduceOptions{}); err == nil {
			t.Fatal("nil document")
		}
		if _, _, err := p.Produce(noID, representation.ProduceOptions{Version: spec.Version(7)}); err == nil {
			t.Fatal("unsupported version")
		}
		badNum := json.Number("1.2.3")
		jm := jwkMethod(t)
		jm.SecretKeyJwk = nil
		jm.PublicKeyJwk["ext"] = badNum
		em := key(t, subject+"#e")
		em.Extra = map[string]any{"n": badNum}
		sm := jwkMethod(t)
		sm.SecretKeyJwk["n"] = badNum
		bs := svc
		bs.ID = "#s"
		bs.ServiceEndpoint = []vm.Endpoint{{Map: map[string]any{"n": badNum}}}
		for name, b := range map[string]*document.Builder{
			"jwk":      document.NewBuilder(mustDID(t, subject)).VerificationMethod(jm),
			"extra":    document.NewBuilder(mustDID(t, subject)).Relationship(vm.Authentication, vm.Embed(em)),
			"secret":   document.NewBuilder(mustDID(t, subject)).VerificationMethod(sm),
			"endpoint": document.NewBuilder(mustDID(t, subject)).Service(bs),
			"service":  document.NewBuilder(mustDID(t, subject)).Service(vm.Service{ID: "#t", Type: []string{"A"}, ServiceEndpoint: svc.ServiceEndpoint, Extra: map[string]any{"n": badNum}}),
			"ext":      document.NewBuilder(mustDID(t, subject)).Extension("@context", document.String("x")),
		} {
			if _, _, err := p.Produce(build(t, b), representation.ProduceOptions{IncludeSecret: true}); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	})
}

func TestServiceIDs(t *testing.T) {
	p := New()
	s := func(id string) vm.Service {
		return vm.Service{ID: id, Type: []string{"A"}, ServiceEndpoint: []vm.Endpoint{{URL: "https://e.example/"}}}
	}
	t.Run("core10#services.6 no two produced service entries share an id", func(t *testing.T) {
		if _, err := document.NewBuilder(mustDID(t, subject)).Service(s("#a"), s(subject+"#a")).Build(); err == nil {
			t.Fatal("a document with two services of the same id must not reach the producer")
		}
		d := build(t, document.NewBuilder(mustDID(t, subject)).Service(s(subject+"#a"), s(subject+"#b")))
		got, _ := produce(t, p, d, representation.ProduceOptions{Version: spec.V10})
		var root struct {
			Service []struct {
				ID string `json:"id"`
			} `json:"service"`
		}
		if err := json.Unmarshal([]byte(got), &root); err != nil || len(root.Service) != 2 || root.Service[0].ID == root.Service[1].ID {
			t.Fatal(got)
		}
	})
}

func TestShapes(t *testing.T) {
	p := New()
	ep := []vm.Endpoint{{URL: "https://e.example/"}}
	d := build(t, document.NewBuilder(mustDID(t, subject)).Controller(mustDID(t, subject)).
		Service(vm.Service{ID: "#a", Type: []string{"A"}, ServiceEndpoint: ep},
			vm.Service{ID: "#b", Type: []string{"A"}, TypeShape: vm.ShapeSet, ServiceEndpoint: ep, EndpointShape: vm.ShapeSet},
			vm.Service{ID: "#c", Type: []string{"A", "B"}, ServiceEndpoint: append(ep, vm.Endpoint{URL: "https://f.example/"})}))
	got, _ := produce(t, p, d, representation.ProduceOptions{})
	want := `{"id":"did:example:123456789abcdefghi","controller":"did:example:123456789abcdefghi","service":[` +
		`{"id":"#a","type":"A","serviceEndpoint":"https://e.example/"},` +
		`{"id":"#b","type":["A"],"serviceEndpoint":["https://e.example/"]},` +
		`{"id":"#c","type":["A","B"],"serviceEndpoint":["https://e.example/","https://f.example/"]}]}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	empty := build(t, document.NewBuilder(mustDID(t, subject)).ControllerShape(vm.ShapeSet))
	if got, _ := produce(t, p, empty, representation.ProduceOptions{}); got != `{"id":"did:example:123456789abcdefghi","controller":[]}` {
		t.Fatal(got)
	}
}

func TestDeterministic(t *testing.T) {
	p := New()
	first, _ := produce(t, p, rich(t), representation.ProduceOptions{JSONLD: true})
	for range 20 {
		if again, _ := produce(t, p, rich(t), representation.ProduceOptions{JSONLD: true}); again != first {
			t.Fatal("output differs between runs")
		}
	}
}

func TestUndefinedTerms(t *testing.T) {
	strict := New(RejectUndefinedTerms())
	d := rich(t)
	t.Run("did11-cr20260305#json-ld-processors.6 RejectUndefinedTerms refuses terms the @context does not define", func(t *testing.T) {
		_, _, err := strict.Produce(d, representation.ProduceOptions{JSONLD: true})
		wantError(t, err, "did11-cr20260305#json-ld-processors.6")
		if !strings.Contains(err.Error(), "alpha") {
			t.Fatalf("the first undefined term is the method's additional property: %v", err)
		}
	})
	t.Run("core10#production-0.5 RejectUndefinedTerms refuses undefined terms in DID Core 1.0 JSON-LD", func(t *testing.T) {
		v10 := build(t, document.NewBuilder(mustDID(t, subject)).Relationship(vm.Authentication, vm.Embed(key(t, subject+"#k"))))
		_, _, err := strict.Produce(v10, representation.ProduceOptions{Version: spec.V10, JSONLD: true})
		wantError(t, err, "core10#production-0.5")
		if _, _, err := strict.Produce(v10, representation.ProduceOptions{Version: spec.V11, JSONLD: true}); err != nil {
			t.Fatal("publicKeyMultibase is defined by the v1.1 context:", err)
		}
		ext := build(t, document.NewBuilder(mustDID(t, subject)).Extension("fooExtension", document.Integer(1)))
		_, _, err = strict.Produce(ext, representation.ProduceOptions{JSONLD: true})
		wantError(t, err, "did11-cr20260305#json-ld-processors.6")
		svc := build(t, document.NewBuilder(mustDID(t, subject)).Service(vm.Service{ID: "#s", Type: []string{"A"},
			ServiceEndpoint: []vm.Endpoint{{URL: "https://e.example/"}}, Extra: map[string]any{"x": 1}}))
		_, _, err = strict.Produce(svc, representation.ProduceOptions{JSONLD: true})
		wantError(t, err, "did11-cr20260305#json-ld-processors.6")
	})
	t.Run("core10#production-0.5 a DID Core 1.0 document that also names the v1.1 context is produced", func(t *testing.T) {
		v10 := build(t, document.NewBuilder(mustDID(t, subject)).
			RepresentationEntry("@context", mustList(t, document.String(spec.ContextURLV10), document.String(spec.ContextURLV11))).
			Relationship(vm.Authentication, vm.Embed(key(t, subject+"#k"))))
		got, _ := produce(t, strict, v10, representation.ProduceOptions{Version: spec.V10, JSONLD: true})
		if !strings.HasPrefix(got, `{"@context":["https://www.w3.org/ns/did/v1","https://www.w3.org/ns/did/v1.1"],`) {
			t.Fatal(got)
		}
	})
	t.Run("the check is skipped for JSON and for contexts that are not known locally", func(t *testing.T) {
		if _, _, err := strict.Produce(d, representation.ProduceOptions{}); err != nil {
			t.Fatal(err)
		}
		known := richWith(t, mustList(t, document.String(spec.ContextURLV11), document.String("https://e.example/v1")))
		if _, _, err := strict.Produce(known, representation.ProduceOptions{JSONLD: true}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("did11-cr20260305#production-and-consumption.10 RejectUndefinedTerms writes nothing rather than dropping entries", func(t *testing.T) {
		data, mt, err := strict.Produce(d, representation.ProduceOptions{JSONLD: true})
		if err == nil || data != nil || mt != "" {
			t.Fatalf("got %s %s %v", data, mt, err)
		}
	})
	t.Run("did11-cr20260305#production-and-consumption.10 by default every entry is written, also undefined terms", func(t *testing.T) {
		got, _ := produce(t, New(), d, representation.ProduceOptions{JSONLD: true})
		if !strings.Contains(got, `"fooExtension":42`) || !strings.Contains(got, `"alpha"`) {
			t.Fatal(got)
		}
	})
}
