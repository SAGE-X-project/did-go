package key

import (
	"bytes"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/sage-x-project/did-go/crypto"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

const ed25519DID = "did:key:" + vecEd25519

func TestDocumentCreationIdentifier(t *testing.T) {
	m := New(stubProducer{})
	t.Run("didkey-2cc490c#document-creation-algorithm.4 the identifier splits at colons into four components", func(t *testing.T) {
		d := expand(t, m, "did:key:1:"+vecEd25519, v11())
		if d.ID().String() != "did:key:1:"+vecEd25519 {
			t.Fatal(d.ID())
		}
		if got := d.VerificationMethods()[0].ID.String(); got != "did:key:1:"+vecEd25519+"#"+vecEd25519 {
			t.Fatal(got)
		}
		_, err := m.Document("did:key:1:2:"+vecEd25519, v11())
		wantCode(t, err, CodeInvalidDid)
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.5 three components mean version 1", func(t *testing.T) {
		a := expand(t, m, ed25519DID, v11())
		b := expand(t, m, "did:key:1:"+vecEd25519, v11())
		if a.VerificationMethods()[0].PublicKeyMultibase != b.VerificationMethods()[0].PublicKeyMultibase {
			t.Fatal("version 1 and the default differ")
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.6 the identifier is checked before expansion", func(t *testing.T) {
		if _, err := m.Document(ed25519DID, v11()); err != nil {
			t.Fatal(err)
		}
		_, err := m.Document("did:key", v11())
		wantCode(t, err, CodeInvalidDid)
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.7 the scheme is did", func(t *testing.T) {
		ke := wantCode(t, errOf(m.Document("dod:key:"+vecEd25519, v11())), CodeInvalidDid)
		if ke.Statement != "didkey-2cc490c#document-creation-algorithm.7" {
			t.Fatal(ke.Statement)
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.8 the method is key", func(t *testing.T) {
		ke := wantCode(t, errOf(m.Document("did:web:"+vecEd25519, v11())), CodeInvalidDid)
		if ke.Statement != "didkey-2cc490c#document-creation-algorithm.8" {
			t.Fatal(ke.Statement)
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.9 the version is a positive integer", func(t *testing.T) {
		for _, v := range []string{"0", "x", "", "-1", "1.0", "99999999999999999999"} {
			_, err := m.Document("did:key:"+v+":"+vecEd25519, v11())
			ke := wantCode(t, err, CodeInvalidDid)
			if ke.Statement != "didkey-2cc490c#document-creation-algorithm.9" {
				t.Fatalf("%q: %s", v, ke.Statement)
			}
		}
		expand(t, m, "did:key:2:"+vecEd25519, v11())
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.10 the multibase value begins with z", func(t *testing.T) {
		// The identifier ABNF also allows base64url (u); the algorithm does not.
		_, err := m.Document("did:key:u7QEi", v11())
		ke := wantCode(t, err, CodeInvalidDid)
		if ke.Statement != "didkey-2cc490c#document-creation-algorithm.10" {
			t.Fatal(ke.Statement)
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.11 a failed check raises invalidDid", func(t *testing.T) {
		for _, id := range []string{"dod:key:z1", "did:x:z1", "did:key:0:z1", "did:key:a1"} {
			_, err := m.Document(id, v11())
			wantCode(t, err, CodeInvalidDid)
			if !errors.Is(err, method.ErrInvalidInput) {
				t.Fatalf("%s: %v does not unwrap to ErrInvalidInput", id, err)
			}
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.14 document.id must be a valid DID", func(t *testing.T) {
		_, err := m.Document("did:key:z6Mk%zz", v11())
		ke := wantCode(t, err, CodeInvalidDid)
		if ke.Statement != "didkey-2cc490c#document-creation-algorithm.14" {
			t.Fatal(ke.Statement)
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.13 document.id is the identifier", func(t *testing.T) {
		if got := expand(t, m, ed25519DID, v11()).ID().String(); got != ed25519DID {
			t.Fatal(got)
		}
	})
}

func errOf(_ any, err error) error { return err }

func TestDocumentCreationProperties(t *testing.T) {
	m := New(stubProducer{})
	d := expand(t, m, ed25519DID, v11())
	sigID := ed25519DID + "#" + vecEd25519
	t.Run("didkey-2cc490c#document-creation-algorithm.3 the document starts empty", func(t *testing.T) {
		if d.Controllers() != nil || d.AlsoKnownAs() != nil || d.Services() != nil ||
			d.Extensions().Len() != 0 || d.Relationship(vm.KeyAgreement) != nil {
			t.Fatal("unexpected properties")
		}
		if keys := d.RepresentationEntries().Keys(); !slices.Equal(keys, []string{"@context"}) {
			t.Fatal(keys)
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.12 the signature method comes from the Signature Method Creation Algorithm", func(t *testing.T) {
		sig, err := m.cfg.signatureMethod(mustIdent(t, ed25519DID))
		if err != nil {
			t.Fatal(err)
		}
		if got := d.VerificationMethods()[0]; got.ID != sig.ID || got.PublicKeyMultibase != sig.PublicKeyMultibase {
			t.Fatal(got)
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.15 verificationMethod starts with the signature method", func(t *testing.T) {
		ms := d.VerificationMethods()
		if len(ms) != 1 || ms[0].ID.String() != sigID {
			t.Fatal(ms)
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.16 the four signature relationships reference the method", func(t *testing.T) {
		for _, p := range []vm.Purpose{vm.Authentication, vm.AssertionMethod, vm.CapabilityInvocation, vm.CapabilityDelegation} {
			rel := d.Relationship(p)
			ref, ok := rel[0].Reference()
			if len(rel) != 1 || !ok || ref.String() != sigID {
				t.Fatalf("%s: %v", p, rel)
			}
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.22 the document is returned", func(t *testing.T) {
		res, err := m.Read(t.Context(), d.ID(), method.ReadOptions{})
		if err != nil {
			t.Fatal(err)
		}
		want, _, _ := stubProducer{}.Produce(d, v11())
		if !bytes.Equal(res.Data, want) {
			t.Fatal("Read differs from the expanded document")
		}
	})
}

func TestDocumentCreationOptions(t *testing.T) {
	t.Run("didkey-2cc490c#document-creation-algorithm.1 experimental public key types are disabled by default", func(t *testing.T) {
		_, err := New(stubProducer{}, WithPublicKeyFormat(FormatJsonWebKey2020)).Document(ed25519DID, v11())
		wantCode(t, err, CodeInvalidPublicKeyType)
		d := expand(t, New(stubProducer{}, WithPublicKeyFormat(FormatJsonWebKey2020), WithExperimentalPublicKeyTypes(true)), ed25519DID, v11())
		if got := d.VerificationMethods()[0].Type; got != FormatJsonWebKey2020 {
			t.Fatal(got)
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.2 defaultContext starts with the DID v1 context for DID Core 1.0", func(t *testing.T) {
		m := New(stubProducer{})
		if got := contextURLs(t, expand(t, m, ed25519DID, v10LD())); len(got) == 0 || got[0] != spec.ContextURLV10 {
			t.Fatal(got)
		}
		// DID 1.1 producers write the v1.1 context first (docs/09 §5), so the
		// recommendation is not followed for DID 1.1 output.
		if got := contextURLs(t, expand(t, m, ed25519DID, v11())); got[0] != spec.ContextURLV11 {
			t.Fatal(got)
		}
	})
}

func TestEncryptionKeyDerivation(t *testing.T) {
	m := New(stubProducer{}, WithEncryptionKeyDerivation(true))
	d := expand(t, m, ed25519DID, v11())
	encID := ed25519DID + "#" + vecX25519
	t.Run("didkey-2cc490c#document-creation-algorithm.17 derivation runs only when enabled", func(t *testing.T) {
		if expand(t, New(stubProducer{}), ed25519DID, v11()).Relationship(vm.KeyAgreement) != nil {
			t.Fatal("keyAgreement without derivation")
		}
		if d.Relationship(vm.KeyAgreement) == nil {
			t.Fatal("no keyAgreement with derivation")
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.18 the encryption method comes from the Encryption Method Creation Algorithm", func(t *testing.T) {
		enc, ok, err := m.cfg.encryptionMethod(mustIdent(t, ed25519DID))
		if err != nil || !ok || enc.ID.String() != encID {
			t.Fatal(enc, ok, err)
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.19 the encryption method is added to verificationMethod", func(t *testing.T) {
		ms := d.VerificationMethods()
		if len(ms) != 2 || ms[1].ID.String() != encID || ms[1].PublicKeyMultibase != vecX25519 {
			t.Fatal(ms)
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.20 keyAgreement references the encryption method", func(t *testing.T) {
		rel := d.Relationship(vm.KeyAgreement)
		if ref, ok := rel[0].Reference(); len(rel) != 1 || !ok || ref.String() != encID {
			t.Fatal(rel)
		}
	})
	t.Run("didkey-2cc490c#derive-encryption-key-algorithm.1 derivation yields a new public encryption key", func(t *testing.T) {
		ms := d.VerificationMethods()
		if ms[0].PublicKeyMultibase == ms[1].PublicKeyMultibase {
			t.Fatal("the encryption key is the signature key")
		}
	})
	t.Run("didkey-2cc490c#derive-encryption-key-algorithm.2 the multibase value is base-58-btc decoded", func(t *testing.T) {
		_, err := m.Document("did:key:z0OIl", v11())
		wantCode(t, err, CodeInvalidDid)
	})
	t.Run("didkey-2cc490c#derive-encryption-key-algorithm.3 the multicodec header is varint decoded", func(t *testing.T) {
		codec, raw, err := decodePublicKey(vecEd25519)
		if err != nil || codec != codecEd25519 || len(raw) != 32 {
			t.Fatal(codec, err)
		}
	})
	t.Run("didkey-2cc490c#derive-encryption-key-algorithm.4 the key bytes follow the header", func(t *testing.T) {
		k, _ := crypto.ParseMultikey(vecEd25519)
		_, raw, _ := decodePublicKey(vecEd25519)
		if !bytes.Equal(raw, k.Raw()) {
			t.Fatal("raw key bytes differ")
		}
	})
	t.Run("didkey-2cc490c#derive-encryption-key-algorithm.6 the derived key has multicodec 0xec", func(t *testing.T) {
		codec, _, err := decodePublicKey(d.VerificationMethods()[1].PublicKeyMultibase)
		if err != nil || codec != codecX25519 {
			t.Fatalf("0x%x %v", codec, err)
		}
	})
	t.Run("didkey-2cc490c#derive-encryption-key-algorithm.7 the derived key bytes are the X25519 key", func(t *testing.T) {
		ed, _ := crypto.ParseMultikey(vecEd25519)
		x, _ := crypto.DeriveX25519(ed)
		_, raw, _ := decodePublicKey(d.VerificationMethods()[1].PublicKeyMultibase)
		if !bytes.Equal(raw, x.Raw()) {
			t.Fatal("derived key bytes differ")
		}
	})
	t.Run("didkey-2cc490c#derive-encryption-key-algorithm.8 keys other than Ed25519 derive nothing", func(t *testing.T) {
		p := expand(t, m, "did:key:"+vecP256, v11())
		if p.Relationship(vm.KeyAgreement) != nil || len(p.VerificationMethods()) != 1 {
			t.Fatal("a P-256 key got a derived key agreement method")
		}
	})
}

func TestEncryptionMethodCreation(t *testing.T) {
	ident := mustIdent(t, ed25519DID)
	c := New(nil, WithEncryptionKeyDerivation(true)).cfg
	enc, _, err := c.encryptionMethod(ident)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.1 the method has only the algorithm's properties", func(t *testing.T) {
		if enc.Expires != nil || enc.Revoked != nil || enc.Extra != nil || enc.PublicKeyJwk != nil || enc.SecretKeyMultibase != "" {
			t.Fatal(enc)
		}
	})
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.2 the key comes from the Derive Encryption Key Algorithm", func(t *testing.T) {
		if enc.PublicKeyMultibase != vecX25519 {
			t.Fatal(enc.PublicKeyMultibase)
		}
	})
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.3 the X25519 key is 32 bytes", func(t *testing.T) {
		if _, err := publicKey(codecX25519, make([]byte, 32), "s"); err != nil {
			t.Fatal(err)
		}
		_, err := publicKey(codecX25519, make([]byte, 31), "didkey-2cc490c#encryption-method-creation-algorithm.3")
		wantCode(t, err, CodeInvalidPublicKeyLength)
	})
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.4 the multibase value is z and base-58-btc of 0xec and the key", func(t *testing.T) {
		ed, _ := crypto.ParseMultikey(vecEd25519)
		x, _ := crypto.DeriveX25519(ed)
		if got := multibase(t, codecX25519, x.Raw()); got != enc.PublicKeyMultibase {
			t.Fatal(got)
		}
	})
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.5 the id is the identifier, # and the multibase value", func(t *testing.T) {
		if enc.ID.String() != ed25519DID+"#"+vecX25519 {
			t.Fatal(enc.ID)
		}
	})
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.6 an invalid DID URL raises invalidDidUrl", func(t *testing.T) {
		_, err := c.buildMethod(ident, "z a", crypto.PublicKey{}, encryptionRole())
		wantCode(t, err, CodeInvalidDidURL)
	})
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.7 the format is options.publicKeyFormat", func(t *testing.T) {
		jc := New(nil, WithPublicKeyFormat(FormatJsonWebKey), WithEncryptionKeyDerivation(true)).cfg
		got, _, err := jc.encryptionMethod(ident)
		if err != nil || got.Type != FormatJsonWebKey {
			t.Fatal(got, err)
		}
	})
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.8 an unknown format raises unsupportedPublicKeyType", func(t *testing.T) {
		uc := New(nil, WithPublicKeyFormat("X25519KeyAgreementKey2020")).cfg
		_, err := uc.buildMethod(ident, vecX25519, crypto.PublicKey{}, encryptionRole())
		ke := wantCode(t, err, CodeUnsupportedPublicKeyType)
		if ke.Statement != "didkey-2cc490c#encryption-method-creation-algorithm.8" || !errors.Is(err, method.ErrNotSupported) {
			t.Fatal(ke)
		}
	})
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.9 experimental formats need the option", func(t *testing.T) {
		ec := New(nil, WithPublicKeyFormat(FormatJsonWebKey2020)).cfg
		_, err := ec.buildMethod(ident, vecX25519, mustKey(t, vecX25519), encryptionRole())
		ke := wantCode(t, err, CodeInvalidPublicKeyType)
		if ke.Statement != "didkey-2cc490c#encryption-method-creation-algorithm.9" {
			t.Fatal(ke.Statement)
		}
		ec.experimental = true
		if _, err := ec.buildMethod(ident, vecX25519, mustKey(t, vecX25519), encryptionRole()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.10 the type is the format", func(t *testing.T) {
		if enc.Type != FormatMultikey {
			t.Fatal(enc.Type)
		}
	})
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.11 the controller is the identifier", func(t *testing.T) {
		if enc.Controller.String() != ed25519DID {
			t.Fatal(enc.Controller)
		}
	})
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.12 an identifier that is not a valid DID never yields a method", func(t *testing.T) {
		bad := identifier{text: "did:key:%zz", multibaseValue: vecX25519}
		_, err := c.buildMethod(bad, vecX25519, mustKey(t, vecX25519), encryptionRole())
		var ke *Error
		if !errors.As(err, &ke) {
			t.Fatal(err)
		}
		// The id check runs first and fails for the same identifier.
		if ke.Code != CodeInvalidDidURL && ke.Code != CodeInvalidDid {
			t.Fatal(ke)
		}
		ok := identifier{text: ed25519DID, multibaseValue: vecX25519}
		if _, err := c.buildMethod(ok, vecX25519, mustKey(t, vecX25519), encryptionRole()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.13 Multikey sets publicKeyMultibase", func(t *testing.T) {
		if enc.PublicKeyMultibase != vecX25519 || enc.PublicKeyJwk != nil {
			t.Fatal(enc)
		}
	})
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.14 JsonWebKey sets publicKeyJwk", func(t *testing.T) {
		jc := New(nil, WithPublicKeyFormat(FormatJsonWebKey), WithEncryptionKeyDerivation(true)).cfg
		got, _, _ := jc.encryptionMethod(ident)
		want := map[string]any{"kty": "OKP", "crv": "X25519", "x": "bl_3kgKpz9jgsg350CNuHa_kQL3B60Gi-98WmdQW2h8"}
		if !maps.Equal(got.PublicKeyJwk, want) || got.PublicKeyMultibase != "" {
			t.Fatal(got.PublicKeyJwk)
		}
	})
	t.Run("didkey-2cc490c#encryption-method-creation-algorithm.15 the method is returned and valid", func(t *testing.T) {
		if err := enc.Validate(); err != nil {
			t.Fatal(err)
		}
	})
}

func mustIdent(t *testing.T, text string) identifier {
	t.Helper()
	id, err := parseIdentifier(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustKey(t *testing.T, mbv string) crypto.PublicKey {
	t.Helper()
	k, err := crypto.ParseMultikey(mbv)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestContextCreation(t *testing.T) {
	m := New(stubProducer{})
	t.Run("didkey-2cc490c#context-creation-algorithm.1 the array starts with defaultContext", func(t *testing.T) {
		if got := contextURLs(t, expand(t, m, ed25519DID, v10LD())); got[0] != spec.ContextURLV10 {
			t.Fatal(got)
		}
		if got := contextURLs(t, expand(t, m, ed25519DID, v11())); got[0] != spec.ContextURLV11 {
			t.Fatal(got)
		}
	})
	t.Run("didkey-2cc490c#context-creation-algorithm.2 each method type adds its context once", func(t *testing.T) {
		got := contextURLs(t, expand(t, m, ed25519DID, v10LD()))
		if !slices.Equal(got, []string{spec.ContextURLV10, spec.ContextURLV11}) {
			t.Fatal(got)
		}
		derive := New(stubProducer{}, WithEncryptionKeyDerivation(true), WithPublicKeyFormat(FormatJsonWebKey))
		if got := contextURLs(t, expand(t, derive, ed25519DID, v11())); !slices.Equal(got, []string{spec.ContextURLV11}) {
			t.Fatal(got)
		}
		exp := New(stubProducer{}, WithPublicKeyFormat(FormatJsonWebKey2020), WithExperimentalPublicKeyTypes(true))
		if got := contextURLs(t, expand(t, exp, ed25519DID, v10LD())); !slices.Equal(got, []string{spec.ContextURLV10}) {
			t.Fatal("a type outside the table added a context:", got)
		}
	})
	t.Run("didkey-2cc490c#context-creation-algorithm.3 the array becomes @context, only for JSON-LD", func(t *testing.T) {
		plain := representation.ProduceOptions{Version: spec.V10}
		if got := contextURLs(t, expand(t, m, ed25519DID, plain)); got != nil {
			t.Fatal(got)
		}
		if got := contextURLs(t, expand(t, m, ed25519DID, representation.ProduceOptions{JSONLD: true})); got[0] != spec.ContextURLV11 {
			t.Fatal("VUnknown is not treated as the latest version:", got)
		}
	})
	t.Run("didkey-2cc490c#document-creation-algorithm.21 @context comes from the Context Creation Algorithm", func(t *testing.T) {
		d := expand(t, m, ed25519DID, v11())
		want := contextArray(spec.V11, d.VerificationMethods())
		got, _ := d.RepresentationEntries().Get("@context")
		if got.(interface{ Len() int }).Len() != want.Len() {
			t.Fatal(got)
		}
	})
}
