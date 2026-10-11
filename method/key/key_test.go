package key

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/crypto"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

func mustDID(t *testing.T, s string) did.DID {
	t.Helper()
	d, err := did.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDriverContract(t *testing.T) {
	m := New(stubProducer{})
	if m.Name() != "key" || !slices.Equal(m.Produces(), representation.CoreMediaTypes()) {
		t.Fatal(m.Name(), m.Produces())
	}
	if _, err := method.NewRegistry(m); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(Formats(), []string{FormatMultikey, FormatJsonWebKey, FormatJsonWebKey2020}) {
		t.Fatal(Formats())
	}
	if _, err := m.Update(t.Context(), mustDID(t, ed25519DID), nil, method.UpdateOptions{}); !errors.Is(err, method.ErrNotSupported) {
		t.Fatal(err)
	}
	if _, err := m.Deactivate(t.Context(), mustDID(t, ed25519DID), method.DeactivateOptions{}); !errors.Is(err, method.ErrNotSupported) {
		t.Fatal(err)
	}
}

func TestReadCreateExampleVector(t *testing.T) {
	res, err := New(stubProducer{}).Read(t.Context(), mustDID(t, ed25519DID), method.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ContentType != spec.MediaTypeDID {
		t.Fatal(res.ContentType)
	}
	if got, want := decodeJSON(t, res.Data), decodeJSON(t, []byte(createExample)); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestReadEd25519WithX25519Vector(t *testing.T) {
	res, err := New(stubProducer{}, WithEncryptionKeyDerivation(true)).Read(t.Context(), mustDID(t, ed25519DID), method.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := decodeJSON(t, res.Data)
	encID := ed25519DID + "#" + vecX25519
	// The specification's example embeds the X25519 method in keyAgreement;
	// its Document Creation Algorithm adds it to verificationMethod and
	// references it, which is what the driver does.
	if ka := got["keyAgreement"].([]any); len(ka) != 1 || ka[0] != encID {
		t.Fatal(ka)
	}
	vms := got["verificationMethod"].([]any)
	enc := vms[1].(map[string]any)
	want := map[string]any{"id": encID, "type": "Multikey", "controller": ed25519DID, "publicKeyMultibase": vecX25519}
	if !reflect.DeepEqual(enc, want) {
		t.Fatal(enc)
	}
}

func TestReadVectors(t *testing.T) {
	for _, v := range []string{vecEd25519, vecEd25519b, vecP256, vecP384} {
		t.Run(v, func(t *testing.T) {
			res, err := New(stubProducer{}).Read(t.Context(), mustDID(t, "did:key:"+v), method.ReadOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got := decodeJSON(t, res.Data)
			vms := got["verificationMethod"].([]any)
			first := vms[0].(map[string]any)
			if len(vms) != 1 || first["publicKeyMultibase"] != v || first["id"] != "did:key:"+v+"#"+v {
				t.Fatal(got)
			}
			// The published key verifies signatures through package crypto.
			k, err := crypto.ParseMultikey(first["publicKeyMultibase"].(string))
			if err != nil || k.Raw() == nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadIsDeterministic(t *testing.T) {
	m := New(stubProducer{}, WithEncryptionKeyDerivation(true))
	a, err := m.Read(t.Context(), mustDID(t, ed25519DID), method.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		b, _ := m.Read(t.Context(), mustDID(t, ed25519DID), method.ReadOptions{})
		if !bytes.Equal(a.Data, b.Data) {
			t.Fatal("Read is not deterministic")
		}
	}
}

func TestReadMediaTypes(t *testing.T) {
	m := New(stubProducer{})
	for _, c := range []struct {
		mediaType string
		context   bool
	}{{spec.MediaTypeDID, true}, {spec.MediaTypeDIDLDJSON, true}, {spec.MediaTypeDIDJSON, false}} {
		res, err := m.Read(t.Context(), mustDID(t, ed25519DID), method.ReadOptions{MediaType: c.mediaType})
		if err != nil || res.ContentType != c.mediaType {
			t.Fatal(c.mediaType, err)
		}
		if _, ok := decodeJSON(t, res.Data)["@context"]; ok != c.context {
			t.Fatalf("%s: @context present = %v", c.mediaType, ok)
		}
	}
	res, err := New(stubProducer{}, WithDefaultMediaType(spec.MediaTypeDIDJSON)).Read(t.Context(), mustDID(t, ed25519DID), method.ReadOptions{})
	if err != nil || res.ContentType != spec.MediaTypeDIDJSON {
		t.Fatal(err)
	}
	if _, err := m.Read(t.Context(), mustDID(t, ed25519DID), method.ReadOptions{MediaType: "text/html"}); !errors.Is(err, method.ErrNotSupported) {
		t.Fatal(err)
	}
	if _, err := New(stubProducer{}, WithDefaultMediaType("text/html")).Create(t.Context(), nil,
		method.CreateOptions{Extra: map[string]any{ExtraPublicKey: vecEd25519}}); !errors.Is(err, method.ErrNotSupported) {
		t.Fatal(err)
	}
}

func TestReadErrors(t *testing.T) {
	m := New(stubProducer{})
	now := time.Now()
	for _, opts := range []method.ReadOptions{{VersionID: "1"}, {VersionTime: &now}} {
		if _, err := m.Read(t.Context(), mustDID(t, ed25519DID), opts); !errors.Is(err, method.ErrNotSupported) {
			t.Fatal(err)
		}
	}
	if _, err := m.Read(t.Context(), mustDID(t, "did:web:example.com"), method.ReadOptions{}); !errors.Is(err, method.ErrInvalidInput) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := m.Read(ctx, mustDID(t, ed25519DID), method.ReadOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	if _, err := New(stubProducer{err: boom}).Read(t.Context(), mustDID(t, ed25519DID), method.ReadOptions{}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if _, err := New(nil).Read(t.Context(), mustDID(t, ed25519DID), method.ReadOptions{}); err == nil {
		t.Fatal("Read without a producer succeeded")
	}
}

func TestReadMetadata(t *testing.T) {
	// did:key has no Create, Update or version history in any registry, so
	// the created, updated and versionId recommendations cannot apply.
	res, err := New(stubProducer{}).Read(t.Context(), mustDID(t, ed25519DID), method.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"core10#did-document-metadata.2", "res10-crd20261001#did-document-metadata.2",
		"core10#did-document-metadata.4", "res10-crd20261001#did-document-metadata.4",
		"core10#did-document-metadata.10", "res10-crd20261001#did-document-metadata.10",
	} {
		t.Run(id+" did:key documents carry no created, updated or versionId", func(t *testing.T) {
			if !res.Metadata.IsEmpty() {
				t.Fatal(res.Metadata)
			}
		})
	}
}

func TestCreate(t *testing.T) {
	m := New(stubProducer{})
	ed, _, _ := ed25519.GenerateKey(rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	vecKey, _ := crypto.ParseMultikey(vecEd25519)
	for name, k := range map[string]any{"crypto": vecKey, "ed25519": ed, "ecdsa": &p256.PublicKey, "multikey": vecEd25519} {
		t.Run(name, func(t *testing.T) {
			res, err := m.Create(t.Context(), nil, method.CreateOptions{Extra: map[string]any{ExtraPublicKey: k}})
			if err != nil {
				t.Fatal(err)
			}
			if res.DID.Method() != "key" || res.Document.ID() != res.DID || !res.Metadata.IsEmpty() {
				t.Fatal(res.DID)
			}
			read, err := m.Read(t.Context(), res.DID, method.ReadOptions{})
			if err != nil {
				t.Fatal(err)
			}
			produced, _, _ := stubProducer{}.Produce(res.Document, v11())
			if !bytes.Equal(read.Data, produced) {
				t.Fatal("Create and Read disagree")
			}
		})
	}
	res, _ := m.Create(t.Context(), nil, method.CreateOptions{Extra: map[string]any{ExtraPublicKey: vecKey}})
	if res.DID.String() != ed25519DID {
		t.Fatal(res.DID)
	}
}

func TestCreateErrors(t *testing.T) {
	m := New(stubProducer{})
	doc, _ := document.NewBuilder(mustDID(t, ed25519DID)).Build()
	cases := map[string]struct {
		input *document.Document
		extra map[string]any
	}{
		"input document":  {doc, map[string]any{ExtraPublicKey: vecEd25519}},
		"no key":          {nil, nil},
		"bad multikey":    {nil, map[string]any{ExtraPublicKey: "z1"}},
		"unsupported key": {nil, map[string]any{ExtraPublicKey: 42}},
		"zero key":        {nil, map[string]any{ExtraPublicKey: crypto.PublicKey{}}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := m.Create(t.Context(), c.input, method.CreateOptions{Extra: c.extra})
			if !errors.Is(err, method.ErrInvalidInput) {
				t.Fatal(err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := m.Create(ctx, nil, method.CreateOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	x, _ := crypto.ParseMultikey(vecX25519)
	if res, err := m.Create(t.Context(), nil, method.CreateOptions{Extra: map[string]any{ExtraPublicKey: x}}); err != nil ||
		res.Document.VerificationMethods()[0].PublicKeyMultibase != vecX25519 {
		t.Fatal(err)
	}
}

func TestDIDFromKey(t *testing.T) {
	k, _ := crypto.ParseMultikey(vecP256)
	d, err := DIDFromKey(k)
	if err != nil || d.String() != "did:key:"+vecP256 {
		t.Fatal(d, err)
	}
	if _, err := DIDFromKey(crypto.PublicKey{}); !errors.Is(err, method.ErrInvalidInput) {
		t.Fatal(err)
	}
}

func TestErrorType(t *testing.T) {
	e := raise(CodeInvalidDid, "didkey-2cc490c#document-creation-algorithm.11", "bad %s", "x")
	if e.Error() != "key: invalidDid: bad x (didkey-2cc490c#document-creation-algorithm.11)" {
		t.Fatal(e.Error())
	}
	if !errors.Is(e, method.ErrInvalidInput) || errors.Is(e, method.ErrNotSupported) {
		t.Fatal("unwrap")
	}
	if !errors.Is(raise(CodeUnsupportedPublicKeyType, "", ""), method.ErrNotSupported) {
		t.Fatal("unsupported unwrap")
	}
}

func TestDocumentsAreValid(t *testing.T) {
	for _, f := range []string{FormatMultikey, FormatJsonWebKey} {
		m := New(stubProducer{}, WithPublicKeyFormat(f), WithEncryptionKeyDerivation(true))
		for _, v := range []string{vecEd25519, vecP256, vecP384, vecX25519} {
			d := expand(t, m, "did:key:"+v, v11())
			for _, vers := range spec.Supported() {
				// JsonWebKey methods get the CID kid and alg warnings: the
				// did:key fragment is the multibase value and the Encode JWK
				// Algorithm writes only the required members.
				// DID Core 1.0 also gets the downlevel warning for the
				// Multikey and JsonWebKey types, which its context lacks.
				for _, finding := range document.Validate(d, vers) {
					if vers == spec.V10 && strings.HasSuffix(finding.Property, ".type") && finding.Severity == document.SeverityWarning {
						continue
					}
					if finding.Severity == document.SeverityError || f == FormatMultikey {
						t.Errorf("%s %s %s: %v", f, v, vers, finding)
					}
				}
			}
			for _, p := range []vm.Purpose{vm.Authentication, vm.AssertionMethod} {
				ref, _ := d.Relationship(p)[0].Reference()
				if _, cerr := document.SelectMethod(d, ref, p); cerr != nil {
					t.Fatal(cerr)
				}
			}
		}
	}
}
