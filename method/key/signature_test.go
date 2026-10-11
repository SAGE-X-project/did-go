package key

import (
	"bytes"
	"errors"
	"maps"
	"testing"

	"github.com/sage-x-project/did-go/crypto"
	"github.com/sage-x-project/did-go/internal/multiformats"
	"github.com/sage-x-project/did-go/method"
)

func TestSignatureMethodCreation(t *testing.T) {
	c := New(nil).cfg
	ident := mustIdent(t, ed25519DID)
	sig, err := c.signatureMethod(ident)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.1 the method has only the algorithm's properties", func(t *testing.T) {
		if sig.Expires != nil || sig.Revoked != nil || sig.Extra != nil || sig.PublicKeyJwk != nil || sig.SecretKeyJwk != nil {
			t.Fatal(sig)
		}
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.2 the key comes from the Decode Public Key Algorithm", func(t *testing.T) {
		codec, raw, _ := decodePublicKey(vecEd25519)
		k, _ := crypto.ParseMultikey(sig.PublicKeyMultibase)
		if codec != codecEd25519 || !bytes.Equal(raw, k.Raw()) {
			t.Fatal("decoded key differs")
		}
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.3 a key of the wrong length raises invalidPublicKeyLength", func(t *testing.T) {
		for _, c := range []struct {
			codec uint64
			size  int
		}{{codecEd25519, 31}, {codecEd25519, 33}, {codecP256, 32}, {codecP384, 48}, {codecSecp256k1, 32}, {codecX25519, 33}} {
			_, err := New(nil).Document("did:key:"+multibase(t, c.codec, make([]byte, c.size)), v11())
			ke := wantCode(t, err, CodeInvalidPublicKeyLength)
			if ke.Statement != "didkey-2cc490c#signature-method-creation-algorithm.3" {
				t.Fatal(ke.Statement)
			}
		}
		for _, v := range []string{vecEd25519, vecEd25519b, vecP256, vecP384, vecX25519} {
			if _, err := New(nil).Document("did:key:"+v, v11()); err != nil {
				t.Fatalf("%s: %v", v, err)
			}
		}
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.4 the key bytes must encode a key of their type", func(t *testing.T) {
		identity := make([]byte, 32)
		identity[0] = 1
		_, err := New(nil).Document("did:key:"+multibase(t, codecEd25519, identity), v11())
		wantCode(t, err, CodeInvalidPublicKey)
		// secp256k1 is in the table but has no standard library implementation.
		_, err = New(nil).Document("did:key:"+vecSecp256k1, v11())
		wantCode(t, err, CodeUnsupportedPublicKeyType)
		if !errors.Is(err, method.ErrNotSupported) {
			t.Fatal(err)
		}
		// BLS12-381 G2 (0xeb) is outside the table.
		_, err = New(nil).Document("did:key:"+vecBLS, v11())
		wantCode(t, err, CodeUnsupportedPublicKeyType)
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.6 an invalid key raises invalidPublicKey", func(t *testing.T) {
		raw := mustKey(t, vecP256).Raw()
		raw[0] = 4 // not a compressed point
		_, err := New(nil).Document("did:key:"+multibase(t, codecP256, raw), v11())
		ke := wantCode(t, err, CodeInvalidPublicKey)
		if ke.Statement != "didkey-2cc490c#signature-method-creation-algorithm.6" || !errors.Is(err, method.ErrInvalidInput) {
			t.Fatal(ke)
		}
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.7 the id is the identifier, # and the multibase value", func(t *testing.T) {
		if sig.ID.String() != ed25519DID+"#"+vecEd25519 {
			t.Fatal(sig.ID)
		}
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.8 an invalid DID URL raises invalidDidUrl", func(t *testing.T) {
		_, err := methodID(ed25519DID, "a b", "didkey-2cc490c#signature-method-creation-algorithm.8")
		wantCode(t, err, CodeInvalidDidURL)
		_, err = c.buildMethod(ident, "z a", mustKey(t, vecEd25519), signatureRole())
		wantCode(t, err, CodeInvalidDidURL)
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.9 the format is options.publicKeyFormat", func(t *testing.T) {
		got, err := New(nil, WithPublicKeyFormat(FormatJsonWebKey)).cfg.signatureMethod(ident)
		if err != nil || got.Type != FormatJsonWebKey {
			t.Fatal(got, err)
		}
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.10 an unknown format raises unsupportedPublicKeyType", func(t *testing.T) {
		for _, f := range []string{"Ed25519VerificationKey2020", "Bogus", ""} {
			_, err := New(nil, WithPublicKeyFormat(f)).Document(ed25519DID, v11())
			ke := wantCode(t, err, CodeUnsupportedPublicKeyType)
			if ke.Statement != "didkey-2cc490c#signature-method-creation-algorithm.10" {
				t.Fatal(ke.Statement)
			}
		}
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.11 experimental formats need the option", func(t *testing.T) {
		_, err := New(nil, WithPublicKeyFormat(FormatJsonWebKey2020)).Document(ed25519DID, v11())
		ke := wantCode(t, err, CodeInvalidPublicKeyType)
		if ke.Statement != "didkey-2cc490c#signature-method-creation-algorithm.11" || !errors.Is(err, method.ErrInvalidInput) {
			t.Fatal(ke)
		}
		for _, f := range []string{FormatMultikey, FormatJsonWebKey} {
			if _, err := New(nil, WithPublicKeyFormat(f)).Document(ed25519DID, v11()); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.12 the type is the format", func(t *testing.T) {
		got, _ := New(nil, WithPublicKeyFormat(FormatJsonWebKey2020), WithExperimentalPublicKeyTypes(true)).cfg.signatureMethod(ident)
		if got.Type != FormatJsonWebKey2020 || sig.Type != FormatMultikey {
			t.Fatal(got.Type, sig.Type)
		}
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.13 the controller is the identifier", func(t *testing.T) {
		if sig.Controller.String() != ed25519DID {
			t.Fatal(sig.Controller)
		}
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.14 an identifier that is not a valid DID never yields a method", func(t *testing.T) {
		// A string that is a valid DID URL with a fragment is always a valid
		// DID before the fragment, so the id check rejects every identifier
		// this check would reject.
		bad := identifier{text: "did:key:%zz", multibaseValue: vecEd25519}
		_, err := c.buildMethod(bad, vecEd25519, mustKey(t, vecEd25519), signatureRole())
		if err == nil {
			t.Fatal("invalid identifier accepted")
		}
		if sig.Controller.IsZero() {
			t.Fatal("no controller")
		}
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.15 Multikey sets publicKeyMultibase to the multibase value", func(t *testing.T) {
		if sig.PublicKeyMultibase != vecEd25519 {
			t.Fatal(sig.PublicKeyMultibase)
		}
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.16 JsonWebKey sets publicKeyJwk with the Encode JWK Algorithm", func(t *testing.T) {
		got, err := New(nil, WithPublicKeyFormat(FormatJsonWebKey)).cfg.signatureMethod(mustIdent(t, "did:key:"+vecP256))
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"kty": "EC", "crv": "P-256",
			"x": "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns", "y": "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM"}
		if !maps.Equal(got.PublicKeyJwk, want) || got.PublicKeyMultibase != "" {
			t.Fatal(got.PublicKeyJwk)
		}
	})
	t.Run("didkey-2cc490c#signature-method-creation-algorithm.17 the method is returned and valid", func(t *testing.T) {
		if err := sig.Validate(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDecodePublicKey(t *testing.T) {
	t.Run("didkey-2cc490c#decode-public-key-algorithm.1 decoding yields a codec and key bytes", func(t *testing.T) {
		codec, raw, err := decodePublicKey(vecP384)
		if err != nil || codec != codecP384 || len(raw) != 49 {
			t.Fatal(codec, len(raw), err)
		}
	})
	t.Run("didkey-2cc490c#decode-public-key-algorithm.2 the value is decoded with the base-58-btc alphabet", func(t *testing.T) {
		for _, v := range []string{"z0OIl", "z", "u7QE"} {
			_, _, err := decodePublicKey(v)
			wantCode(t, err, CodeInvalidDid)
		}
	})
	t.Run("didkey-2cc490c#decode-public-key-algorithm.3 the multicodec header is varint decoded", func(t *testing.T) {
		codec, _, err := decodePublicKey(vecP256)
		if err != nil || codec != 0x1200 {
			t.Fatalf("0x%x %v", codec, err)
		}
		// 0x80 announces a continuation byte that is missing.
		_, _, err = decodePublicKey(mustMultibaseBytes(t, []byte{0x80}))
		wantCode(t, err, CodeInvalidDid)
	})
	t.Run("didkey-2cc490c#decode-public-key-algorithm.4 the key bytes are what follows the header", func(t *testing.T) {
		_, raw, _ := decodePublicKey(vecP256)
		if !bytes.Equal(raw, mustKey(t, vecP256).Raw()) {
			t.Fatal("key bytes differ")
		}
	})
	t.Run("didkey-2cc490c#decode-public-key-algorithm.5 both values are returned", func(t *testing.T) {
		codec, raw, err := decodePublicKey(vecX25519)
		if err != nil || codec != codecX25519 || len(raw) != 32 {
			t.Fatal(codec, err)
		}
	})
}

func mustMultibaseBytes(t *testing.T, data []byte) string {
	t.Helper()
	s, err := multiformats.EncodeMultibase(multiformats.HeaderBase58BTC, data)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
