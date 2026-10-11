package crypto

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"math/big"
	"slices"
	"testing"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/internal/multiformats"
	"github.com/sage-x-project/did-go/vm"
)

// Test vectors of the did:key specification (didkey-2cc490c, appendix "Test
// Vectors" and the Create example).
const (
	vecEd25519   = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	vecEd25519b  = "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"
	vecX25519    = "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"
	vecP256      = "zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"
	vecP384      = "z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54"
	vecSecp256k1 = "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"
	vecBLS       = "zUC7EK3ZakmukHhuncwkbySmomv3FmrkmS36E4Ks5rsb6VQSRpoCrx6Hb8e2Nk6UvJFSdyw9NK1scFXJp21gNNYFjVWNgaqyGnkyhtagagCpQb5B7tagJu3HDbjQ8h5ypoHjwBb"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustParse(t *testing.T, value string) PublicKey {
	t.Helper()
	k, err := ParseMultikey(value)
	if err != nil {
		t.Fatalf("ParseMultikey(%s): %v", value, err)
	}
	return k
}

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error %v, want %v", err, target)
	}
}

func TestParseMultikeyVectors(t *testing.T) {
	for _, c := range []struct {
		value string
		typ   KeyType
		size  int
	}{
		{vecEd25519, Ed25519, 32}, {vecEd25519b, Ed25519, 32}, {vecX25519, X25519, 32},
		{vecP256, P256, 33}, {vecP384, P384, 49},
	} {
		k := mustParse(t, c.value)
		if k.Type() != c.typ || len(k.Raw()) != c.size || k.IsZero() {
			t.Fatalf("%s: type %s, %d bytes", c.value, k.Type(), len(k.Raw()))
		}
		again, err := k.Multikey()
		if err != nil || again != c.value {
			t.Fatalf("%s: re-encoded as %s (%v)", c.value, again, err)
		}
	}
}

func TestUnsupportedKeyTypes(t *testing.T) {
	t.Run("secp256k1 is not in the Multikey table", func(t *testing.T) {
		_, err := ParseMultikey(vecSecp256k1)
		wantErr(t, err, ErrInvalidEncoding)
	})
	t.Run("BLS12-381 G2 is recognized but not implemented", func(t *testing.T) {
		_, err := ParseMultikey(vecBLS)
		wantErr(t, err, ErrUnsupportedKeyType)
	})
	t.Run("unknown key type names", func(t *testing.T) {
		_, err := NewPublicKey("secp256k1", make([]byte, 33))
		wantErr(t, err, ErrUnsupportedKeyType)
		if _, err := (PublicKey{}).Multikey(); !errors.Is(err, ErrUnsupportedKeyType) {
			t.Fatal(err)
		}
		if (PublicKey{}).JWK() != nil || (PublicKey{}).CryptoKey() != nil {
			t.Fatal("zero key encoded")
		}
	})
	t.Run("secp256k1 JWK", func(t *testing.T) {
		_, err := ParseJWK(map[string]any{"kty": "EC", "crv": "secp256k1", "x": "AA", "y": "AA"})
		wantErr(t, err, ErrUnsupportedKeyType)
	})
	if !slices.Equal(SupportedKeyTypes(), []KeyType{Ed25519, P256, P384, X25519}) {
		t.Fatal(SupportedKeyTypes())
	}
}

func TestEd25519Validation(t *testing.T) {
	good := mustParse(t, vecEd25519).Raw()
	t.Run("valid key", func(t *testing.T) {
		if _, err := NewPublicKey(Ed25519, good); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("wrong length", func(t *testing.T) {
		_, err := NewPublicKey(Ed25519, good[1:])
		wantErr(t, err, ErrInvalidKey)
	})
	t.Run("non-canonical y (y = p)", func(t *testing.T) {
		enc := bytes.Repeat([]byte{0xff}, 32)
		enc[0], enc[31] = 0xed, 0x7f
		_, err := NewPublicKey(Ed25519, enc)
		wantErr(t, err, ErrInvalidKey)
		if !errors.Is(err, errNonCanonical) {
			t.Fatal(err)
		}
	})
	t.Run("x = 0 with the sign bit set", func(t *testing.T) {
		enc := make([]byte, 32)
		enc[0], enc[31] = 1, 0x80
		_, err := NewPublicKey(Ed25519, enc)
		if !errors.Is(err, errNonCanonical) {
			t.Fatal(err)
		}
	})
	t.Run("small order points", func(t *testing.T) {
		identity := make([]byte, 32)
		identity[0] = 1
		order4 := make([]byte, 32) // y = 0
		for _, enc := range [][]byte{identity, order4} {
			_, err := NewPublicKey(Ed25519, enc)
			if !errors.Is(err, errSmallOrder) {
				t.Fatalf("%x: %v", enc, err)
			}
		}
	})
	t.Run("not on the curve", func(t *testing.T) {
		found := false
		for y := byte(2); y < 64 && !found; y++ {
			enc := make([]byte, 32)
			enc[0] = y
			if _, err := NewPublicKey(Ed25519, enc); errors.Is(err, errNotOnCurve) {
				found = true
			}
		}
		if !found {
			t.Fatal("no off-curve y found")
		}
	})
	t.Run("random keys from the standard library", func(t *testing.T) {
		for range 16 {
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := FromCryptoKey(pub); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestECDSAValidation(t *testing.T) {
	for _, typ := range []KeyType{P256, P384} {
		c, _ := typ.curve()
		t.Run(string(typ), func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(c, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			k, err := FromCryptoKey(&priv.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			raw := k.Raw()
			if _, err := NewPublicKey(typ, raw); err != nil {
				t.Fatal(err)
			}
			bad := slices.Clone(raw)
			bad[0] = 4
			_, err = NewPublicKey(typ, bad)
			wantErr(t, err, ErrInvalidKey)
			_, err = NewPublicKey(typ, raw[1:])
			wantErr(t, err, ErrInvalidKey)
			offCurve := slices.Clone(raw)
			found := false
			for i := 0; i < 64 && !found; i++ {
				offCurve[len(offCurve)-1]++
				if _, err := NewPublicKey(typ, offCurve); errors.Is(err, ErrInvalidKey) {
					found = true
				}
			}
			if !found {
				t.Fatal("no off-curve x found")
			}
			if !k.CryptoKey().(*ecdsa.PublicKey).Equal(&priv.PublicKey) {
				t.Fatal("CryptoKey differs")
			}
		})
	}
}

func TestFromCryptoKey(t *testing.T) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := FromCryptoKey(x.PublicKey())
	if err != nil || k.Type() != X25519 {
		t.Fatal(err)
	}
	if !bytes.Equal(k.CryptoKey().(*ecdh.PublicKey).Bytes(), x.PublicKey().Bytes()) {
		t.Fatal("X25519 round trip")
	}
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	nist, _ := ecdh.P256().GenerateKey(rand.Reader)
	var nilECDSA *ecdsa.PublicKey
	for _, bad := range []stdcrypto.PublicKey{&p224.PublicKey, nist.PublicKey(), "key", nil} {
		if _, err := FromCryptoKey(bad); !errors.Is(err, ErrUnsupportedKeyType) {
			t.Fatalf("%T: %v", bad, err)
		}
	}
	if _, err := FromCryptoKey(nilECDSA); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
	if _, err := FromCryptoKey(&ecdsa.PublicKey{Curve: elliptic.P256()}); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
	if _, err := NewPublicKey(X25519, make([]byte, 31)); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
	ed := mustParse(t, vecEd25519)
	if !ed.Equal(mustParse(t, vecEd25519)) || ed.Equal(mustParse(t, vecEd25519b)) {
		t.Fatal("Equal")
	}
	if !bytes.Equal(ed.CryptoKey().(ed25519.PublicKey), ed.Raw()) {
		t.Fatal("Ed25519 CryptoKey")
	}
}

// Expected JWK values of the did:key test vectors, as published with the
// did:key specification's fixtures. The P-384 coordinates are computed
// independently from the compressed point with y^2 = x^3 - 3x + b.
func vectorJWKs(t *testing.T) map[string]map[string]any {
	t.Helper()
	return map[string]map[string]any{
		vecEd25519: {"kty": "OKP", "crv": "Ed25519", "x": "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY"},
		vecX25519:  {"kty": "OKP", "crv": "X25519", "x": "bl_3kgKpz9jgsg350CNuHa_kQL3B60Gi-98WmdQW2h8"},
		vecP256: {"kty": "EC", "crv": "P-256",
			"x": "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns", "y": "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM"},
		vecP384: expandP384(t, vecP384),
	}
}

func expandP384(t *testing.T, value string) map[string]any {
	t.Helper()
	_, data, err := multiformats.DecodeMultibase(value)
	if err != nil {
		t.Fatal(err)
	}
	raw := data[2:]
	params := elliptic.P384().Params()
	x := new(big.Int).SetBytes(raw[1:])
	y2 := new(big.Int).Exp(x, big.NewInt(3), params.P)
	y2.Sub(y2, new(big.Int).Mul(big.NewInt(3), x))
	y2.Add(y2, params.B).Mod(y2, params.P)
	y := new(big.Int).ModSqrt(y2, params.P)
	if y.Bit(0) != uint(raw[0]&1) {
		y.Sub(params.P, y)
	}
	xb, yb := make([]byte, 48), make([]byte, 48)
	x.FillBytes(xb)
	y.FillBytes(yb)
	return map[string]any{"kty": "EC", "crv": "P-384",
		"x": multiformats.EncodeBase64URL(xb), "y": multiformats.EncodeBase64URL(yb)}
}

func TestEncodeJWK(t *testing.T) {
	t.Run("didkey-2cc490c#encode-jwk-algorithm.2 kty and crv come from the key type", func(t *testing.T) {
		for value, want := range vectorJWKs(t) {
			got := mustParse(t, value).JWK()
			if got["kty"] != want["kty"] || got["crv"] != want["crv"] {
				t.Fatalf("%s: %v", value, got)
			}
		}
	})
	t.Run("didkey-2cc490c#encode-jwk-algorithm.3 EC keys are expanded to x and y", func(t *testing.T) {
		for _, value := range []string{vecP256, vecP384} {
			got, want := mustParse(t, value).JWK(), vectorJWKs(t)[value]
			if got["x"] != want["x"] || got["y"] != want["y"] {
				t.Fatalf("%s: got %v want %v", value, got, want)
			}
		}
	})
	t.Run("didkey-2cc490c#encode-jwk-algorithm.4 OKP keys encode x only", func(t *testing.T) {
		for _, value := range []string{vecEd25519, vecX25519} {
			got, want := mustParse(t, value).JWK(), vectorJWKs(t)[value]
			if got["x"] != want["x"] {
				t.Fatalf("%s: got %v want %v", value, got, want)
			}
			if _, ok := got["y"]; ok {
				t.Fatalf("%s: OKP key with y", value)
			}
		}
	})
	t.Run("didkey-2cc490c#encode-jwk-algorithm.5 exactly the members RFC 7638 requires", func(t *testing.T) {
		for value, want := range vectorJWKs(t) {
			if got := mustParse(t, value).JWK(); !maps.Equal(got, want) {
				t.Fatalf("%s: got %v want %v", value, got, want)
			}
		}
	})
	t.Run("didkey-2cc490c#encode-jwk-algorithm.6 d is not present", func(t *testing.T) {
		for value := range vectorJWKs(t) {
			jwk := mustParse(t, value).JWK()
			if _, ok := jwk["d"]; ok {
				t.Fatal("d present")
			}
			m := vm.Method{ID: mustURL(t), Type: vm.TypeJsonWebKey, Controller: mustURL(t).DID(), PublicKeyJwk: jwk}
			if err := m.Validate(); err != nil {
				t.Fatal(err)
			}
			withD := maps.Clone(jwk)
			withD["d"] = "AA"
			if _, err := ParseJWK(withD); !errors.Is(err, ErrInvalidEncoding) {
				t.Fatal("JWK with d accepted")
			}
		}
	})
	t.Run("didkey-2cc490c#encode-jwk-algorithm.1 the JWK conforms to RFC 7517, 7518 and 8037", func(t *testing.T) {
		for value := range vectorJWKs(t) {
			k := mustParse(t, value)
			back, err := ParseJWK(k.JWK())
			if err != nil || !back.Equal(k) {
				t.Fatalf("%s: %v", value, err)
			}
		}
	})
}

func mustURL(t *testing.T) did.DIDURL {
	t.Helper()
	u, err := did.ParseURL("did:key:" + vecEd25519 + "#" + vecEd25519)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestParseJWKErrors(t *testing.T) {
	p256 := mustParse(t, vecP256).JWK()
	cases := []struct {
		name string
		jwk  map[string]any
		want error
	}{
		{"nil", nil, ErrInvalidEncoding},
		{"no kty", map[string]any{"crv": "Ed25519"}, ErrInvalidEncoding},
		{"RSA", map[string]any{"kty": "RSA", "n": "AQ", "e": "AQAB"}, ErrUnsupportedKeyType},
		{"OKP Ed448", map[string]any{"kty": "OKP", "crv": "Ed448", "x": "AA"}, ErrUnsupportedKeyType},
		{"x missing", map[string]any{"kty": "OKP", "crv": "Ed25519"}, ErrInvalidEncoding},
		{"x not base64url", map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "+/=="}, ErrInvalidEncoding},
		{"x short", map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}, ErrInvalidEncoding},
		{"y missing", map[string]any{"kty": "EC", "crv": "P-256", "x": p256["x"]}, ErrInvalidEncoding},
		{"x missing EC", map[string]any{"kty": "EC", "crv": "P-256", "y": p256["y"]}, ErrInvalidEncoding},
		{"point off the curve", map[string]any{"kty": "EC", "crv": "P-256", "x": p256["y"], "y": p256["x"]}, ErrInvalidKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseJWK(c.jwk)
			wantErr(t, err, c.want)
		})
	}
}

func TestFromMethod(t *testing.T) {
	base := vm.Method{ID: mustURL(t), Type: vm.TypeMultikey, Controller: mustURL(t).DID(), PublicKeyMultibase: vecEd25519}
	t.Run("cid10#verification-material.2 keys convert between Multikey and JWK", func(t *testing.T) {
		k, err := FromMethod(base)
		if err != nil {
			t.Fatal(err)
		}
		jwkMethod := base.Clone()
		jwkMethod.Type, jwkMethod.PublicKeyMultibase, jwkMethod.PublicKeyJwk = vm.TypeJsonWebKey, "", k.JWK()
		k2, err := FromMethod(jwkMethod)
		if err != nil || !k2.Equal(k) {
			t.Fatal(err)
		}
	})
	t.Run("cid10#verification-material.3 conversion does not change the method", func(t *testing.T) {
		m := base.Clone()
		m.PublicKeyJwk = nil
		before := m.Clone()
		k, _ := FromMethod(m)
		raw := k.Raw()
		raw[0] ^= 0xff
		if m.PublicKeyMultibase != before.PublicKeyMultibase || bytes.Equal(k.Raw(), raw) {
			t.Fatal("conversion leaked into the method or the key")
		}
		if again, _ := k.Multikey(); again != before.PublicKeyMultibase {
			t.Fatal("the external representation changed")
		}
		j := k.JWK()
		j["x"] = "changed"
		if k.JWK()["x"] == "changed" {
			t.Fatal("JWK shares state with the key")
		}
	})
	t.Run("no key material", func(t *testing.T) {
		m := base.Clone()
		m.PublicKeyMultibase = ""
		_, err := FromMethod(m)
		wantErr(t, err, ErrInvalidEncoding)
	})
	t.Run("malformed Multikey", func(t *testing.T) {
		_, err := ParseMultikey("u" + vecEd25519[1:])
		wantErr(t, err, ErrInvalidEncoding)
	})
}

func TestDeriveX25519(t *testing.T) {
	t.Run("didkey-2cc490c#derive-encryption-key-algorithm.5 the Ed25519 vector maps to its X25519 key", func(t *testing.T) {
		x, err := DeriveX25519(mustParse(t, vecEd25519))
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := x.Multikey(); got != vecX25519 {
			t.Fatalf("derived %s, want %s", got, vecX25519)
		}
	})
	t.Run("didkey-2cc490c#derive-encryption-key-algorithm.5 matches the standard library conversion of a private key", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		k, _ := FromCryptoKey(pub)
		x, err := DeriveX25519(k)
		if err != nil {
			t.Fatal(err)
		}
		// X25519 scalar of an Ed25519 seed: the clamped first half of
		// SHA-512(seed) (RFC 8032 §5.1.5); ecdh clamps it.
		h := sha512Sum(priv.Seed())
		xpriv, err := ecdh.X25519().NewPrivateKey(h[:32])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(xpriv.PublicKey().Bytes(), x.Raw()) {
			t.Fatal("derived X25519 key differs from the private key conversion")
		}
	})
	t.Run("only Ed25519 keys derive", func(t *testing.T) {
		_, err := DeriveX25519(mustParse(t, vecP256))
		wantErr(t, err, ErrUnsupportedKeyType)
		forged := PublicKey{typ: Ed25519, raw: make([]byte, 32)}
		_, err = DeriveX25519(forged)
		wantErr(t, err, ErrInvalidKey)
	})
}

func TestMultikeyHelpers(t *testing.T) {
	// The multicodec prefix of every supported type is in the vm table.
	for _, typ := range SupportedKeyTypes() {
		if _, ok := multikeyCodec(typ); !ok {
			t.Fatalf("no Multikey row for %s", typ)
		}
	}
}
