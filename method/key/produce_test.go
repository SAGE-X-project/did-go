package key_test

import (
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/internal/testutil"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/method/key"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
)

// TestReadWithStrictProducer reads did:key documents in every DID media
// type with a producer made with producer.RejectUndefinedTerms, which
// refuses JSON-LD documents holding terms their @context does not define.
// The Context Creation Algorithm adds https://www.w3.org/ns/did/v1.1, which
// defines the method terms, also to DID Core 1.0 output, so every
// representation is produced.
func TestReadWithStrictProducer(t *testing.T) {
	strict := producer.New(producer.RejectUndefinedTerms())
	drivers := map[string]*key.Method{
		"Multikey":            key.New(strict),
		"JsonWebKey":          key.New(strict, key.WithPublicKeyFormat(key.FormatJsonWebKey)),
		"encryption Multikey": key.New(strict, key.WithEncryptionKeyDerivation(true)),
		"encryption JsonWebKey": key.New(strict, key.WithEncryptionKeyDerivation(true),
			key.WithPublicKeyFormat(key.FormatJsonWebKey)),
	}
	d := testutil.MustDID("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
	for name, m := range drivers {
		for _, mt := range representation.CoreMediaTypes() {
			t.Run("core10#production-0.5 did11-cr20260305#json-ld-processors.6 didkey-2cc490c#context-creation-algorithm.2 "+name+" "+mt, func(t *testing.T) {
				rr, err := m.Read(t.Context(), d, method.ReadOptions{MediaType: mt})
				if err != nil {
					t.Fatal(err)
				}
				if mt == spec.MediaTypeDIDLDJSON && !strings.HasPrefix(string(rr.Data), `{"@context":["`+spec.ContextURLV10+`","`+spec.ContextURLV11+`"],`) {
					t.Fatal(string(rr.Data))
				}
			})
		}
	}
}
