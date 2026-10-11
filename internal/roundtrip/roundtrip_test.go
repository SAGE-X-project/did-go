package roundtrip

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

const mk = "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"

// extContext is a context that did-go does not know, so a consumer keeps
// every term of a document that lists it (jsonld.Context.Terms).
const extContext = "https://e.example/ext/v1"

type profile struct {
	name string
	opts representation.ProduceOptions
}

func profiles() []profile {
	return []profile{
		{"V10 JSON", representation.ProduceOptions{Version: spec.V10}},
		{"V10 JSON-LD", representation.ProduceOptions{Version: spec.V10, JSONLD: true}},
		{"V11 JSON", representation.ProduceOptions{Version: spec.V11}},
		{"V11 JSON-LD", representation.ProduceOptions{Version: spec.V11, JSONLD: true}},
	}
}

// gen builds random documents that conform to a profile: absolute ids,
// service ids and normalized endpoints for DID Core 1.0; and, for JSON-LD,
// the @context the producer writes (with an unknown extra context so that no
// term is dropped). Numbers in JSON values are json.Number, which is how the
// consumer returns them; datetimes are whole UTC seconds.
type gen struct {
	r   *rand.Rand
	p   profile
	sub string
}

func (g gen) pick(n int) int { return g.r.IntN(n) }

func (g gen) mustDID(s string) did.DID {
	d, err := did.Parse(s)
	if err != nil {
		panic(err)
	}
	return d
}

func (g gen) ref(frag string) did.DIDURL {
	s := g.sub + "#" + frag
	if g.p.opts.Version == spec.V11 && g.pick(2) == 0 {
		s = "#" + frag
	}
	u, err := did.ParseReference(s)
	if err != nil {
		panic(err)
	}
	return u
}

func (g gen) jsonValue(depth int) any {
	switch k := g.pick(7); {
	case k == 0:
		return nil
	case k == 1:
		return g.pick(2) == 0
	case k == 2:
		return fmt.Sprintf("s%d\n\"é", g.pick(100))
	case k == 3:
		return json.Number([]string{"0", "-12", "1.50", "2e3", "123456789012345678901234567890"}[g.pick(5)])
	case k == 4 && depth < 3:
		l := []any{}
		for range g.pick(3) {
			l = append(l, g.jsonValue(depth+1))
		}
		return l
	case k == 5 && depth < 3:
		return g.jsonMap(depth + 1)
	}
	return "x"
}

func (g gen) jsonMap(depth int) map[string]any {
	m := map[string]any{}
	for i := range g.pick(3) {
		m[fmt.Sprintf("k%d", i)] = g.jsonValue(depth)
	}
	return m
}

func (g gen) infra(depth int) document.Value {
	switch k := g.pick(7); {
	case k == 0:
		return document.Null{}
	case k == 1:
		return document.Boolean(g.pick(2) == 0)
	case k == 2:
		return document.String(fmt.Sprintf("v%d\t", g.pick(100)))
	case k == 3:
		return document.Integer(g.r.Int64() - 1<<62)
	case k == 4:
		return document.Double([]float64{0.5, -2, 1e21, 3.25e-7}[g.pick(4)])
	case k == 5 && depth < 3:
		items := make([]document.Value, g.pick(3))
		for i := range items {
			items[i] = g.infra(depth + 1)
		}
		l, _ := document.NewList(items...)
		return l
	case k == 6 && depth < 3:
		var entries []document.Entry
		for i := range g.pick(3) {
			entries = append(entries, document.Entry{Key: fmt.Sprintf("z%d", 3-i), Value: g.infra(depth + 1)})
		}
		m, _ := document.NewMap(entries...)
		return m
	}
	return document.String("y")
}

func (g gen) method(frag string) vm.Method {
	m := vm.Method{ID: g.ref(frag), Type: "Multikey", Controller: g.mustDID(g.sub)}
	switch g.pick(3) {
	case 0:
		m.PublicKeyMultibase = mk
	case 1:
		m.Type = "JsonWebKey"
		m.PublicKeyJwk = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
	}
	if g.pick(2) == 0 {
		t := time.Date(2030, time.Month(1+g.pick(12)), 1+g.pick(28), g.pick(24), 0, 7, 0, time.UTC)
		m.Expires = &t
	}
	if g.pick(3) == 0 {
		m.Extra = map[string]any{"extra": g.jsonValue(0)}
	}
	return m
}

func (g gen) service(i int) vm.Service {
	s := vm.Service{ID: g.sub + fmt.Sprintf("#s%d", i), Type: []string{"A"}, ServiceEndpoint: []vm.Endpoint{{URL: "https://a.example/p"}}}
	if g.p.opts.Version == spec.V11 && g.pick(3) == 0 {
		s.ID = ""
	}
	if g.pick(2) == 0 {
		s.Type = append(s.Type, "B")
	}
	s.TypeShape = []vm.Shape{vm.ShapeDefault, vm.ShapeSet}[g.pick(2)]
	if g.pick(2) == 0 {
		s.ServiceEndpoint = append(s.ServiceEndpoint, vm.Endpoint{Map: g.jsonMap(1)})
	}
	s.EndpointShape = []vm.Shape{vm.ShapeDefault, vm.ShapeSet}[g.pick(2)]
	if g.pick(3) == 0 {
		s.Extra = map[string]any{"routing": g.jsonValue(0)}
	}
	return s
}

func (g gen) document() *document.Document {
	b := document.NewBuilder(g.mustDID(g.sub))
	if g.p.opts.JSONLD {
		var ctx document.Value
		p, _ := spec.ProfileOf(g.p.opts.Version)
		ctx, _ = document.NewList(document.String(p.ContextURL), document.String(extContext))
		b.RepresentationEntry("@context", ctx)
	}
	switch g.pick(3) {
	case 0:
		b.Controller(g.mustDID(g.sub))
	case 1:
		b.Controller(g.mustDID("did:example:c1"), g.mustDID("did:example:c2")).ControllerShape(vm.ShapeSet)
	}
	if g.pick(2) == 0 {
		b.AlsoKnownAs("https://a.example/", "did:example:other")
	}
	for i := range g.pick(3) {
		b.VerificationMethod(g.method(fmt.Sprintf("vm%d", i)))
	}
	for _, p := range vm.Purposes() {
		if g.pick(2) == 0 {
			b.Relationship(p, vm.Ref(g.ref("vm0")), vm.Embed(g.method("emb-"+p.String())))
		}
	}
	for i := range g.pick(3) {
		b.Service(g.service(i))
	}
	for i := range g.pick(3) {
		b.Extension(fmt.Sprintf("ext%d", 3-i), g.infra(0))
	}
	d, err := b.Build()
	if err != nil {
		panic(err)
	}
	return d
}

// TestConsumeProduce checks consume(produce(d)) == d for every profile.
func TestConsumeProduce(t *testing.T) {
	p, c := producer.New(), consumer.New()
	for _, prof := range profiles() {
		t.Run(prof.name, func(t *testing.T) {
			r := rand.New(rand.NewPCG(1, uint64(len(prof.name))))
			for i := range 300 {
				d := gen{r: r, p: prof, sub: "did:example:123456789abcdefghi"}.document()
				data, mt, err := p.Produce(d, prof.opts)
				if err != nil {
					t.Fatalf("case %d: produce: %v", i, err)
				}
				back, info, err := c.Consume(data, mt, representation.ConsumeOptions{Require: prof.opts.Version, Strict: true})
				if err != nil {
					t.Fatalf("case %d: consume %s: %v", i, data, err)
				}
				if info.IsJSONLD != prof.opts.JSONLD {
					t.Fatalf("case %d: IsJSONLD %v", i, info.IsJSONLD)
				}
				if !reflect.DeepEqual(back, d) {
					t.Fatalf("case %d: the round trip changed the document:\n%s\n%+v\n%+v", i, data, d, back)
				}
			}
		})
	}
}

// TestProduceConsume checks produce(consume(b)) == b for canonical input:
// documents written in the producer's member order, compact, with sorted
// keys in Go-map values, and for random documents the producer's own
// output.
func TestProduceConsume(t *testing.T) {
	p, c := producer.New(), consumer.New()
	canonical := []struct{ mt, data string }{
		{spec.MediaTypeDIDJSON, `{"id":"did:example:1","controller":"did:example:1","service":[{"id":"did:example:1#s","type":["A"],"serviceEndpoint":"https://a.example/"}],"fooExtension":42}`},
		{spec.MediaTypeDIDLDJSON, `{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/ed25519-2020/v1"],"id":"did:example:123456789abcdefghi","authentication":[{"id":"did:example:123456789abcdefghi#keys-1","type":"Ed25519VerificationKey2020","controller":"did:example:123456789abcdefghi","publicKeyMultibase":"zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"}]}`},
		{spec.MediaTypeDID, `{"@context":"https://www.w3.org/ns/did/v1.1","id":"did:example:123456789abcdefghi","authentication":[{"id":"did:example:123456789abcdefghi#keys-1","type":"Multikey","controller":"did:example:123456789abcdefghi","publicKeyMultibase":"` + mk + `"}]}`},
		{spec.MediaTypeDID, `{"id":"did:example:1","controller":[],"verificationMethod":[{"id":"#k","type":"X","controller":"did:example:1","expires":"2030-01-01T00:00:00Z","a":{"b":[1.50,null]}}],"assertionMethod":["#k"],"service":[{"type":"A","serviceEndpoint":["https://a.example/",{"x":1}],"z":true}],"ext":{"b":2.0,"a":[-1,"s"]}}`},
	}
	for i, v := range canonical {
		t.Run(fmt.Sprintf("canonical %d %s", i, v.mt), func(t *testing.T) {
			d, info, err := c.Consume([]byte(v.data), v.mt, representation.ConsumeOptions{})
			if err != nil {
				t.Fatal(err)
			}
			out, mt, err := p.Produce(d, representation.ProduceOptions{Version: info.DetectedVersion, JSONLD: info.IsJSONLD})
			if err != nil || mt != v.mt || string(out) != v.data {
				t.Fatalf("got %s %s %v\nwant %s", mt, out, err, v.data)
			}
		})
	}
	for _, prof := range profiles() {
		t.Run("generated "+prof.name, func(t *testing.T) {
			r := rand.New(rand.NewPCG(2, uint64(len(prof.name))))
			for i := range 300 {
				b, mt, err := p.Produce(gen{r: r, p: prof, sub: "did:example:xyz"}.document(), prof.opts)
				if err != nil {
					t.Fatal(err)
				}
				d, _, err := c.Consume(b, mt, representation.ConsumeOptions{})
				if err != nil {
					t.Fatal(err)
				}
				again, mt2, err := p.Produce(d, prof.opts)
				if err != nil || mt2 != mt || string(again) != string(b) {
					t.Fatalf("case %d:\n got %s\nwant %s", i, again, b)
				}
			}
		})
	}
}

// TestConversion converts between representations through the data model
// (DID 1.1 §6.1 note "Conversion between representations"): DID Core 1.0
// input re-produced as DID 1.1 and back.
func TestConversion(t *testing.T) {
	p, c := producer.New(), consumer.New()
	v10 := `{"@context":["https://www.w3.org/ns/did/v1","https://e.example/ext/v1"],"id":"did:example:1","service":[{"id":"did:example:1#s","type":"A","serviceEndpoint":"https://a.example/"}]}`
	d, _, err := c.Consume([]byte(v10), spec.MediaTypeDIDLDJSON, representation.ConsumeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v11, mt, err := p.Produce(d, representation.ProduceOptions{Version: spec.V11, JSONLD: true})
	want := `{"@context":["https://www.w3.org/ns/did/v1.1","https://e.example/ext/v1"],"id":"did:example:1","service":[{"id":"did:example:1#s","type":"A","serviceEndpoint":"https://a.example/"}]}`
	if err != nil || mt != spec.MediaTypeDID || string(v11) != want {
		t.Fatalf("uplevel: %s %s %v", mt, v11, err)
	}
	d11, _, err := c.Consume(v11, mt, representation.ConsumeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	back, _, err := p.Produce(d11, representation.ProduceOptions{Version: spec.V10, JSONLD: true})
	if err != nil || string(back) != v10 {
		t.Fatalf("downlevel: %s %v", back, err)
	}
}
