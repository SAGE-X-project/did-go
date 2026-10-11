package key

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/multiformats"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// Test vectors of the did:key specification (didkey-2cc490c, the Create
// example and appendix "Test Vectors").
const (
	vecEd25519   = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	vecEd25519b  = "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"
	vecX25519    = "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"
	vecP256      = "zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"
	vecP384      = "z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54"
	vecSecp256k1 = "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"
	vecBLS       = "zUC7EK3ZakmukHhuncwkbySmomv3FmrkmS36E4Ks5rsb6VQSRpoCrx6Hb8e2Nk6UvJFSdyw9NK1scFXJp21gNNYFjVWNgaqyGnkyhtagagCpQb5B7tagJu3HDbjQ8h5ypoHjwBb"
)

// createExample is the "An example of a did:key DID Document" of the
// specification's Create section without its keyAgreement entry, which the
// Document Creation Algorithm adds only with encryption key derivation.
const createExample = `{
  "@context": ["https://www.w3.org/ns/did/v1.1"],
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "verificationMethod": [{
    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "type": "Multikey",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  }],
  "authentication": ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"],
  "assertionMethod": ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"],
  "capabilityDelegation": ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"],
  "capabilityInvocation": ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"]
}`

// stubProducer is a minimal stand-in for the producer player: it writes the
// properties a did:key document uses as JSON, with @context only for a
// JSON-LD representation.
type stubProducer struct{ err error }

func (s stubProducer) Produce(d *document.Document, opts representation.ProduceOptions) ([]byte, string, error) {
	if s.err != nil {
		return nil, "", s.err
	}
	out := map[string]any{"id": d.ID().String()}
	if opts.JSONLD {
		if ctx, ok := d.RepresentationEntries().Get("@context"); ok {
			var urls []any
			for _, v := range ctx.(document.List).Items() {
				urls = append(urls, string(v.(document.String)))
			}
			out["@context"] = urls
		}
	}
	var methods []any
	for _, m := range d.VerificationMethods() {
		methods = append(methods, methodJSON(m))
	}
	out["verificationMethod"] = methods
	for _, p := range vm.Purposes() {
		rel := d.Relationship(p)
		if rel == nil {
			continue
		}
		var refs []any
		for _, r := range rel {
			refs = append(refs, r.ID().String())
		}
		out[p.String()] = refs
	}
	data, err := json.Marshal(out)
	return data, representation.MediaTypeFor(opts.Version, opts.JSONLD), err
}

func methodJSON(m vm.Method) map[string]any {
	j := map[string]any{"id": m.ID.String(), "type": m.Type, "controller": m.Controller.String()}
	if m.PublicKeyMultibase != "" {
		j["publicKeyMultibase"] = m.PublicKeyMultibase
	}
	if m.PublicKeyJwk != nil {
		j["publicKeyJwk"] = m.PublicKeyJwk
	}
	return j
}

func decodeJSON(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func v11() representation.ProduceOptions {
	return representation.ProduceOptions{Version: spec.V11, JSONLD: true}
}

func v10LD() representation.ProduceOptions {
	return representation.ProduceOptions{Version: spec.V10, JSONLD: true}
}

func expand(t *testing.T, m *Method, identifier string, opts representation.ProduceOptions) *document.Document {
	t.Helper()
	d, err := m.Document(identifier, opts)
	if err != nil {
		t.Fatalf("Document(%s): %v", identifier, err)
	}
	return d
}

// wantCode checks that err is a did:key *Error with code.
func wantCode(t *testing.T, err error, code string) Error {
	t.Helper()
	var ke *Error
	if !errors.As(err, &ke) || ke.Code != code {
		t.Fatalf("error %v, want code %s", err, code)
	}
	return *ke
}

// multibase builds a did:key multibase value from a multicodec and key data.
func multibase(t *testing.T, codec uint64, raw []byte) string {
	t.Helper()
	data := append(multiformats.AppendVarint(nil, codec), raw...)
	s, err := multiformats.EncodeMultibase(multiformats.HeaderBase58BTC, data)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func contextURLs(t *testing.T, d *document.Document) []string {
	t.Helper()
	v, ok := d.RepresentationEntries().Get("@context")
	if !ok {
		return nil
	}
	var out []string
	for _, item := range v.(document.List).Items() {
		out = append(out, string(item.(document.String)))
	}
	return out
}
