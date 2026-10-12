package sage

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func produce(t *testing.T, r Record, p Projection) string {
	t.Helper()
	data, e := Produce(r, p, producer.New())
	if e != nil {
		t.Fatalf("Produce: %v", e)
	}
	return string(data)
}

// DIDP-01 and RESOLVE-01: the DID Core 1.0 projection has no @context and
// JsonWebKey2020 methods; the DID 1.1 projection has the v1.1 context as a
// single string and JsonWebKey methods. Keys and services keep the record's
// ASCII order, and a JWK has exactly kty, crv and x.
func TestProjectionsOfActiveRecord(t *testing.T) {
	r := activeRecord(t)
	vmJSON := func(typ string) string {
		return `"verificationMethod":[` +
			`{"id":"` + testDID + `#agree","type":"` + typ + `","controller":"` + testDID + `","publicKeyJwk":{"crv":"X25519","kty":"OKP","x":"` + b64(xKey) + `"}},` +
			`{"id":"` + testDID + `#sign","type":"` + typ + `","controller":"` + testDID + `","publicKeyJwk":{"crv":"Ed25519","kty":"OKP","x":"` + b64(edKey) + `"}}],` +
			`"authentication":["` + testDID + `#sign"],"assertionMethod":["` + testDID + `#sign"],` +
			`"keyAgreement":["` + testDID + `#agree"],` +
			`"service":[{"id":"` + testDID + `#a2a","type":"A2AInterface","serviceEndpoint":"https://agent.example/a2a"}]}`
	}
	want10 := `{"id":"` + testDID + `",` + vmJSON("JsonWebKey2020")
	want11 := `{"@context":"https://www.w3.org/ns/did/v1.1","id":"` + testDID + `",` + vmJSON("JsonWebKey")
	if got := produce(t, r, Core10); got != want10 {
		t.Errorf("DID Core 1.0 projection\n got %s\nwant %s", got, want10)
	}
	if got := produce(t, r, DID11); got != want11 {
		t.Errorf("DID 1.1 projection\n got %s\nwant %s", got, want11)
	}
}

// DIDP-03: both projections agree on id, verification method ids,
// controllers, JWKs, relationships and services; they differ only in
// @context, media type and verification method type. A standard consumer
// accepts each under its media type in strict mode.
func TestProjectionEquivalence(t *testing.T) {
	r := activeRecord(t)
	docs := map[Projection]*document.Document{}
	for _, p := range []Projection{Core10, DID11} {
		d, _, err := consumer.New().Consume([]byte(produce(t, r, p)), p.MediaType(), representation.ConsumeOptions{Strict: true})
		if err != nil {
			t.Fatalf("%s projection is not consumable: %v", p.MediaType(), err)
		}
		docs[p] = d
	}
	a, b := docs[Core10], docs[DID11]
	if a.ID() != b.ID() || len(a.VerificationMethods()) != len(b.VerificationMethods()) {
		t.Fatal("projections differ in id or method count")
	}
	for i, m := range a.VerificationMethods() {
		n := b.VerificationMethods()[i]
		if m.ID != n.ID || m.Controller != n.Controller || !sameJSON(m.PublicKeyJwk, n.PublicKeyJwk) ||
			m.Type != "JsonWebKey2020" || n.Type != vm.TypeJsonWebKey {
			t.Errorf("method %d differs beyond its type: %+v %+v", i, m, n)
		}
	}
	for _, p := range vm.Purposes() {
		if !sameJSON(refs(a.Relationship(p)), refs(b.Relationship(p))) {
			t.Errorf("relationship %s differs", p)
		}
	}
	if !sameJSON(a.Services(), b.Services()) {
		t.Error("services differ")
	}
}

func refs(rs []vm.Relationship) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID().String())
	}
	return out
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// RESOLVE-01 as amended (DID Core 1.0 §5.3, CID 1.0 §2.3): a created or
// deactivated record has an empty verificationMethod array and no
// relationship member, never an empty relationship array.
func TestCreatedAndDeactivatedProjectNoRelationship(t *testing.T) {
	for _, st := range []State{StateCreated, StateDeactivated} {
		r := activeRecord(t)
		r.State = st
		for _, p := range []Projection{Core10, DID11} {
			got := produce(t, r, p)
			if !strings.Contains(got, `"verificationMethod":[]`) {
				t.Errorf("%s %s: no empty verificationMethod array: %s", st, p.MediaType(), got)
			}
			for _, rel := range []string{"authentication", "assertionMethod", "keyAgreement"} {
				if strings.Contains(got, rel) {
					t.Errorf("%s %s: %s present: %s", st, p.MediaType(), rel, got)
				}
			}
			if _, _, err := consumer.New().Consume([]byte(got), p.MediaType(), representation.ConsumeOptions{Strict: true}); err != nil {
				t.Errorf("%s %s: not consumable: %v", st, p.MediaType(), err)
			}
		}
	}
}

// DIDP-01: a record with no accepted X25519 key projects no keyAgreement
// member; an empty relationship is omitted in both projections.
func TestNoEmptyRelationship(t *testing.T) {
	r := activeRecord(t)
	r.Keys = r.Keys[1:]
	for _, p := range []Projection{Core10, DID11} {
		got := produce(t, r, p)
		if strings.Contains(got, "keyAgreement") || !strings.Contains(got, `"authentication":["`+testDID+`#sign"]`) {
			t.Errorf("%s: %s", p.MediaType(), got)
		}
	}
}

// RESOLVE-01: revoked keys and keys expired at the observation time
// (unusable when now >= expires, chapter 09 §1) are not projected; a key
// that expires after the observation is.
func TestRevokedAndExpiredKeysAreNotProjected(t *testing.T) {
	r := activeRecord(t)
	r.Keys = append(r.Keys,
		Key{Name: "z-expired", Alg: AlgP256, Material: p256, State: KeyAccepted, Expires: issued(testObserved)},
		Key{Name: "z-later", Alg: AlgSecp256k1, Material: k1Base, State: KeyAccepted, Expires: issued(testObserved + 1)},
		Key{Name: "z-revoked", Alg: AlgEd25519, Material: mustHex(strings.Repeat("ab", 32)), State: KeyRevoked},
	)
	d, e := Document(r, Core10)
	if e != nil {
		t.Fatal(e)
	}
	var names []string
	for _, m := range d.VerificationMethods() {
		names = append(names, m.ID.Fragment())
	}
	if strings.Join(names, ",") != "agree,sign,z-later" {
		t.Errorf("projected keys %v", names)
	}
}

// TABLE-03 and RESOLVE-01: EC keys project x and y from the uncompressed
// point.
func TestECKeyJWK(t *testing.T) {
	for _, c := range []struct {
		alg, crv string
		raw      []byte
	}{{AlgP256, "P-256", p256}, {AlgSecp256k1, "secp256k1", k1Base}} {
		jwk, err := keyJWK(Key{Name: "k", Alg: c.alg, Material: c.raw})
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"kty": "EC", "crv": c.crv, "x": b64(c.raw[1:33]), "y": b64(c.raw[33:])}
		if !sameJSON(jwk, want) {
			t.Errorf("%s JWK %v", c.alg, jwk)
		}
	}
}

// RESOLVE-01: wrong curves, invalid points and noncanonical encodings are
// rejected; the record is invalid.
func TestInvalidKeyBytesAreRejected(t *testing.T) {
	offCurve := append([]byte{4}, make([]byte, 64)...)
	offCurve[64] = 1
	bigX := append([]byte{4}, mustHex(strings.Repeat("ff", 64))...)
	cases := []Key{
		{Name: "k", Alg: AlgP256, Material: offCurve},
		{Name: "k", Alg: AlgSecp256k1, Material: offCurve},
		{Name: "k", Alg: AlgSecp256k1, Material: bigX},
		{Name: "k", Alg: AlgEd25519, Material: mustHex("ed" + strings.Repeat("ff", 30) + "7f")},
		{Name: "k", Alg: "rsa", Material: edKey},
	}
	for _, k := range cases {
		if _, err := keyJWK(k); err == nil {
			t.Errorf("%s key %x accepted", k.Alg, k.Material)
		}
	}
	r := activeRecord(t)
	r.Keys = append(r.Keys, Key{Name: "z", Alg: AlgP256, Material: offCurve, State: KeyAccepted})
	if _, e := Document(r, Core10); e == nil || e.Code != CodeRecordInvalid {
		t.Errorf("record with an invalid key: %v", e)
	}
}

// RESOLVE-03: didDocumentMetadata has deactivated, versionId and the sage
// object with state, controller, observedAt, source and observedTime;
// observedAt is the issued integer for web and the block hash for eip155.
// No canonicalId or equivalentId is written (DIDP-04).
func TestMetadata(t *testing.T) {
	r := activeRecord(t)
	data, err := json.Marshal(Metadata(r))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"sage":{"controller":"controller-1","observedAt":1799999000,"observedTime":1800000000,"source":"web-registry-1","state":"active"},"versionId":"7"}`
	if string(data) != want {
		t.Errorf("metadata %s", data)
	}
	r.State = StateDeactivated
	r.Observation = Observation{BlockHash: "0xabc", Source: "chain-1", Time: testObserved}
	md := Metadata(r)
	if !md.Deactivated || md.Extra["sage"].(map[string]any)["observedAt"] != "0xabc" || md.CanonicalID != "" || md.EquivalentID != nil {
		t.Errorf("metadata %+v", md)
	}
	if err := md.Check(r.DID, spec.V11); err != nil {
		t.Errorf("metadata does not conform: %v", err)
	}
}

type stubProducer struct {
	data []byte
	mt   string
	err  error
}

func (s stubProducer) Produce(*document.Document, representation.ProduceOptions) ([]byte, string, error) {
	return s.data, s.mt, s.err
}

func TestProduceFailures(t *testing.T) {
	r := activeRecord(t)
	cases := []struct {
		p    stubProducer
		code Code
	}{
		{stubProducer{err: errors.New("no")}, CodeRecordInvalid},
		{stubProducer{data: []byte("{}"), mt: spec.MediaTypeDIDLDJSON}, CodeRecordInvalid},
		{stubProducer{data: make([]byte, maxResponse+1), mt: MediaTypeCore10}, CodeSizeExceeded},
	}
	for _, c := range cases {
		if _, e := Produce(r, Core10, c.p); e == nil || e.Code != c.code {
			t.Errorf("Produce with %+v: %v", c.p.err, e)
		}
	}
	if _, e := Document(r, Projection(9)); e == nil || e.Code != CodeRepresentationUnsupported {
		t.Errorf("unknown projection: %v", e)
	}
	bad := r
	bad.Version = "0"
	if _, e := Produce(bad, Core10, producer.New()); e == nil || e.Code != CodeRecordInvalid {
		t.Errorf("invalid record: %v", e)
	}
}

func TestProjectionMediaTypes(t *testing.T) {
	if Core10.MediaType() != "application/did+json" || DID11.MediaType() != "application/did" {
		t.Error("media types")
	}
	for mt, want := range map[string]Projection{"application/did+json": Core10, "application/did": DID11} {
		if p, ok := projectionOf(mt); !ok || p != want {
			t.Errorf("projectionOf(%s)", mt)
		}
	}
	if _, ok := projectionOf("application/did+ld+json"); ok {
		t.Error("did+ld+json is not a SAGE projection media type")
	}
}
