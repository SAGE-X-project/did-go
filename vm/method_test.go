package vm

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/internal/multiformats"
)

const ed25519Example = "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"

func mustURL(t *testing.T, s string) did.DIDURL {
	t.Helper()
	u, err := did.ParseReference(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mustDID(t *testing.T, s string) did.DID {
	t.Helper()
	d, err := did.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func baseMethod(t *testing.T, typ string) Method {
	t.Helper()
	return Method{ID: mustURL(t, "did:example:123#key-1"), Type: typ, Controller: mustDID(t, "did:example:123")}
}

// methodFromJSON maps a vector's JSON object onto Method for the test.
func methodFromJSON(t *testing.T, raw map[string]any) Method {
	t.Helper()
	m := Method{ID: mustURL(t, raw["id"].(string)), Type: raw["type"].(string), Controller: mustDID(t, raw["controller"].(string))}
	if s, ok := raw["publicKeyMultibase"].(string); ok {
		m.PublicKeyMultibase = s
	}
	if j, ok := raw["publicKeyJwk"].(map[string]any); ok {
		m.PublicKeyJwk = j
	}
	return m
}

func wantStatement(t *testing.T, err error, statement string) {
	t.Helper()
	var ve *Error
	if !errors.As(err, &ve) {
		t.Fatalf("got %v, want *vm.Error citing %s", err, statement)
	}
	if ve.Statement != statement {
		t.Fatalf("statement = %s, want %s (%v)", ve.Statement, statement, err)
	}
	if !strings.Contains(ve.Error(), statement) {
		t.Fatal("message must cite the statement")
	}
}

func TestMethodVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/methods.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Vectors []struct {
			ID     string         `json:"id"`
			Valid  bool           `json:"valid"`
			Method map[string]any `json:"method"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Vectors {
		t.Run(c.ID, func(t *testing.T) {
			err := methodFromJSON(t, c.Method).Validate()
			if (err == nil) != c.Valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, c.Valid)
			}
		})
	}
}

func TestMethodCoreProperties(t *testing.T) {
	t.Run("cid10#verification-methods.3 id, type and controller are required", func(t *testing.T) {
		m := baseMethod(t, "Multikey")
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
		noID, noType, noCtl := m, m, m
		noID.ID = did.DIDURL{}
		noType.Type = ""
		noCtl.Controller = did.DID{}
		wantStatement(t, noID.Validate(), "cid10#verification-methods.3")
		wantStatement(t, noType.Validate(), "cid10#verification-methods.6")
		wantStatement(t, noCtl.Validate(), "cid10#verification-methods.3")
	})
	t.Run("core10#verification-methods.3 the same three properties in DID Core 1.0", func(t *testing.T) {
		m := baseMethod(t, "Ed25519VerificationKey2020")
		m.Controller = did.DID{}
		if m.Validate() == nil {
			t.Fatal("missing controller accepted")
		}
	})
	t.Run("cid10#verification-methods.6 type is one type name, any name", func(t *testing.T) {
		for _, typ := range []string{"Ed25519VerificationKey2020", "JsonWebKey2020", "https://example.com/vocab#Key"} {
			if err := baseMethod(t, typ).Validate(); err != nil {
				t.Errorf("%s: %v", typ, err)
			}
		}
		for _, typ := range []string{"Multikey JsonWebKey", "Multikey\n", ""} {
			wantStatement(t, baseMethod(t, typ).Validate(), "cid10#verification-methods.6")
		}
	})
	t.Run("core10#verification-methods.7 a string referencing exactly one type", func(t *testing.T) {
		if baseMethod(t, "A B").Validate() == nil || baseMethod(t, "A").Validate() != nil {
			t.Fatal("type check")
		}
	})
	t.Run("cid10#verification-methods.5 id is a DID URL, which has URL syntax", func(t *testing.T) {
		m := baseMethod(t, "Multikey")
		if !IsURL(m.ID.String()) {
			t.Fatal("DID URL id must be a URL")
		}
	})
	t.Run("core10#verification-methods.6 id is a parsed DID URL", func(t *testing.T) {
		if _, err := did.ParseURL("did:example:123#key 1"); err == nil {
			t.Fatal("ids that are not DID URLs cannot be built")
		}
		if (Method{Type: "X", Controller: mustDID(t, "did:example:1")}).Validate() == nil {
			t.Fatal("zero id accepted")
		}
	})
	t.Run("cid10#verification-methods.7 controller has URL syntax", func(t *testing.T) {
		if !IsURL(baseMethod(t, "X").Controller.String()) {
			t.Fatal("DID controller must be a URL")
		}
	})
	t.Run("core10#verification-methods.9 controller is a DID", func(t *testing.T) {
		m := baseMethod(t, "X")
		if m.Controller.String() != "did:example:123" {
			t.Fatal("controller")
		}
		m.Controller = did.DID{}
		if m.Validate() == nil {
			t.Fatal("zero controller accepted")
		}
	})
	t.Run("did11-cr20260305#verification-methods.1 relative id and DID controller", func(t *testing.T) {
		m := baseMethod(t, "Multikey")
		m.ID = mustURL(t, "#key-1")
		if err := m.Validate(); err != nil {
			t.Fatalf("relative DID URL id rejected: %v", err)
		}
	})
	t.Run("core10#verification-methods.4 additional properties are kept", func(t *testing.T) {
		m := baseMethod(t, "Multikey")
		m.Extra = map[string]any{"blockchainAccountId": "eip155:1:0xab", "nested": map[string]any{"a": []any{1.5, true, nil}}}
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cid10#verification-methods.4 Extra must not shadow modeled properties or hold non-JSON values", func(t *testing.T) {
		m := baseMethod(t, "Multikey")
		m.Extra = map[string]any{"publicKeyMultibase": "z"}
		wantStatement(t, m.Validate(), "cid10#verification-methods.4")
		m.Extra = map[string]any{"f": func() {}}
		wantStatement(t, m.Validate(), "cid10#verification-methods.4")
	})
}

func TestMethodTimes(t *testing.T) {
	ts := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	zero := time.Time{}
	far := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	t.Run("cid10#verification-methods.8 expires is optional", func(t *testing.T) {
		m := baseMethod(t, "Multikey")
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
		m.Expires = &ts
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cid10#verification-methods.9 expires is a dateTimeStamp", func(t *testing.T) {
		m := baseMethod(t, "Multikey")
		m.Expires = &zero
		wantStatement(t, m.Validate(), "cid10#verification-methods.9")
		m.Expires = &far
		wantStatement(t, m.Validate(), "cid10#verification-methods.9")
	})
	t.Run("cid10#verification-methods.10 revoked is optional", func(t *testing.T) {
		m := baseMethod(t, "Multikey")
		m.Revoked = &ts
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cid10#verification-methods.11 revoked is a dateTimeStamp", func(t *testing.T) {
		m := baseMethod(t, "Multikey")
		m.Revoked = &zero
		wantStatement(t, m.Validate(), "cid10#verification-methods.11")
	})
}

func TestMethodMaterial(t *testing.T) {
	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
	t.Run("core10#verification-material.1 publicKeyJwk is optional", func(t *testing.T) {
		m := baseMethod(t, "JsonWebKey2020")
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
		if m.HasPublicKey() {
			t.Fatal("no key material")
		}
	})
	t.Run("core10#verification-material.2 publicKeyJwk is a JWK map", func(t *testing.T) {
		m := baseMethod(t, "JsonWebKey2020")
		m.PublicKeyJwk = jwk
		if err := m.Validate(); err != nil || !m.HasPublicKey() {
			t.Fatal(err)
		}
		m.PublicKeyJwk = map[string]any{"crv": "Ed25519"}
		wantStatement(t, m.Validate(), "cid10#JsonWebKey.3")
	})
	t.Run("core10#verification-material.3 publicKeyJwk without d or other private members", func(t *testing.T) {
		for _, member := range privateJWKMembers() {
			m := baseMethod(t, "JsonWebKey2020")
			m.PublicKeyJwk = map[string]any{"kty": "RSA", "n": "x", "e": "AQAB", member: "secret"}
			wantStatement(t, m.Validate(), "cid10#JsonWebKey.13")
		}
	})
	t.Run("core10#verification-material.6 publicKeyMultibase is optional", func(t *testing.T) {
		if err := baseMethod(t, "Ed25519VerificationKey2020").Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("core10#verification-material.7 publicKeyMultibase is Multibase for any type", func(t *testing.T) {
		for _, ok := range []string{"zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV", "uAQID", "mAQID", "fabcd"} {
			m := baseMethod(t, "Ed25519VerificationKey2020")
			m.PublicKeyMultibase = ok
			if err := m.Validate(); err != nil {
				t.Errorf("%q: %v", ok, err)
			}
		}
		for _, bad := range []string{"z", "x123", "z0OIl", "u+/=", "#abc"} {
			m := baseMethod(t, "Ed25519VerificationKey2020")
			m.PublicKeyMultibase = bad
			wantStatement(t, m.Validate(), "core10#verification-material.7")
		}
	})
	t.Run("core10#verification-material.8 at most one property per material", func(t *testing.T) {
		m := baseMethod(t, "Ed25519VerificationKey2020")
		m.PublicKeyMultibase, m.PublicKeyJwk = ed25519Example, jwk
		wantStatement(t, m.Validate(), "cid10#verification-material.1")
	})
	t.Run("cid10#verification-material.1 secret material at most once, public and secret together allowed", func(t *testing.T) {
		m := baseMethod(t, "JsonWebKey2020")
		m.SecretKeyJwk = map[string]any{"kty": "OKP", "crv": "Ed25519", "d": "x"}
		m.SecretKeyMultibase = "zabc"
		wantStatement(t, m.Validate(), "cid10#verification-material.1")
		m.SecretKeyMultibase = ""
		m.PublicKeyJwk = jwk
		if err := m.Validate(); err != nil {
			t.Fatalf("public and secret JWK are different material: %v", err)
		}
	})
	t.Run("kid recommendations are advisory, not errors", func(t *testing.T) {
		m := baseMethod(t, "JsonWebKey")
		m.PublicKeyJwk = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AA", "kid": "other"}
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("RFC 7638 thumbprint of a key", func(t *testing.T) {
		got, err := JWKThumbprint(jwk)
		if err != nil || got != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
			t.Fatalf("got %q %v (RFC 8037 appendix A.3)", got, err)
		}
		for _, k := range []map[string]any{{"kty": "EC", "crv": "P-256", "x": "a"}, {"kty": "X"}, {"kty": "RSA", "n": "a", "e": "b"}, {"kty": "oct", "k": "a"}} {
			_, err := JWKThumbprint(k)
			if (err == nil) != (k["kty"] == "RSA" || k["kty"] == "oct") {
				t.Errorf("%v: %v", k, err)
			}
		}
	})
}

func TestJsonWebKey(t *testing.T) {
	public := map[string]any{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}
	t.Run("cid10#JsonWebKey.1 the JsonWebKey rules apply to type JsonWebKey", func(t *testing.T) {
		m := baseMethod(t, "JsonWebKey")
		m.PublicKeyMultibase = ed25519Example
		wantStatement(t, m.Validate(), "cid10#verification-methods.3")
		m.Type = "JsonWebKey2020"
		if err := m.Validate(); err != nil {
			t.Fatalf("other types are not held to JsonWebKey rules: %v", err)
		}
	})
	t.Run("cid10#JsonWebKey.2 publicKeyJwk is optional", func(t *testing.T) {
		if err := baseMethod(t, "JsonWebKey").Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cid10#JsonWebKey.3 publicKeyJwk is an RFC 7517 map", func(t *testing.T) {
		m := baseMethod(t, "JsonWebKey")
		m.PublicKeyJwk = public
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []map[string]any{{}, {"kty": 1}, {"kty": "EC", "crv": "P-256", "x": func() {}}} {
			m.PublicKeyJwk = bad
			wantStatement(t, m.Validate(), "cid10#JsonWebKey.3")
		}
	})
	t.Run("cid10#JsonWebKey.4 no members of the private information class", func(t *testing.T) {
		m := baseMethod(t, "JsonWebKey")
		m.PublicKeyJwk = map[string]any{"kty": "EC", "crv": "P-256", "x": "a", "y": "b", "d": "c"}
		wantStatement(t, m.Validate(), "cid10#JsonWebKey.13")
	})
	t.Run("cid10#JsonWebKey.8 crv is required for EC keys", func(t *testing.T) {
		m := baseMethod(t, "JsonWebKey")
		m.PublicKeyJwk = map[string]any{"kty": "EC", "x": "a", "y": "b"}
		wantStatement(t, m.Validate(), "cid10#JsonWebKey.8")
	})
	t.Run("cid10#JsonWebKey.10 secretKeyJwk is optional", func(t *testing.T) {
		m := baseMethod(t, "JsonWebKey")
		m.PublicKeyJwk = public
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cid10#JsonWebKey.11 secretKeyJwk is an RFC 7517 map", func(t *testing.T) {
		m := baseMethod(t, "JsonWebKey")
		m.SecretKeyJwk = map[string]any{"kty": "EC", "crv": "P-256", "d": "c"}
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
		m.SecretKeyJwk = map[string]any{"d": "c"}
		wantStatement(t, m.Validate(), "cid10#JsonWebKey.11")
	})
	t.Run("cid10#JsonWebKey.13 nothing marked Private, including d", func(t *testing.T) {
		m := baseMethod(t, "JsonWebKey")
		m.PublicKeyJwk = map[string]any{"kty": "oct", "k": "c"}
		wantStatement(t, m.Validate(), "cid10#JsonWebKey.13")
	})
}

func TestMultikey(t *testing.T) {
	t.Run("cid10#Multikey.1 the Multikey rules apply to type Multikey only", func(t *testing.T) {
		m := baseMethod(t, "Multikey")
		m.PublicKeyMultibase = "uAQID"
		if m.Validate() == nil {
			t.Fatal("Multikey with header u accepted")
		}
		m.Type = "multikey"
		if err := m.Validate(); err != nil {
			t.Fatalf("other types get the generic checks only: %v", err)
		}
		m.Type = "Multikey"
		m.PublicKeyJwk, m.PublicKeyMultibase = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "a"}, ""
		wantStatement(t, m.Validate(), "cid10#verification-methods.3")
	})
	t.Run("cid10#Multikey.2 publicKeyMultibase is optional", func(t *testing.T) {
		if err := baseMethod(t, "Multikey").Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cid10#Multikey.3 publicKeyMultibase is a Multibase value with a public key header", func(t *testing.T) {
		m := baseMethod(t, "Multikey")
		m.PublicKeyMultibase = ed25519Example
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
		secret, _ := EncodeMultikey(codecFor(t, "Ed25519", true), make([]byte, 32))
		unknown, _ := multiformats.EncodeMultibase('z', []byte{0x01, 0x02, 0x03})
		for _, bad := range []string{secret, unknown} {
			m.PublicKeyMultibase = bad
			wantStatement(t, m.Validate(), "cid10#Multikey.3")
		}
	})
	t.Run("cid10#Multikey.4 secretKeyMultibase is optional", func(t *testing.T) {
		m := baseMethod(t, "Multikey")
		m.PublicKeyMultibase = ed25519Example
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cid10#Multikey.5 secretKeyMultibase is a Multibase value with a secret key header", func(t *testing.T) {
		m := baseMethod(t, "Multikey")
		m.SecretKeyMultibase, _ = EncodeMultikey(codecFor(t, "Ed25519", true), bytes.Repeat([]byte{7}, 32))
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
		m.SecretKeyMultibase = ed25519Example
		wantStatement(t, m.Validate(), "cid10#Multikey.5")
		m.SecretKeyMultibase = "x1"
		wantStatement(t, m.Validate(), "cid10#Multikey.5")
	})
	rows := []struct {
		name   string
		key    string
		secret bool
		prefix bool
	}{
		{"cid10#Multikey.6 P-256 public key: prefix 0x8024 and 33 bytes", "P-256", false, true},
		{"cid10#Multikey.7 P-256 public key: base-58-btc with header z", "P-256", false, false},
		{"cid10#Multikey.8 P-384 public key: prefix 0x8124 and 49 bytes", "P-384", false, true},
		{"cid10#Multikey.9 Ed25519 public key: prefix 0xed01 and 32 bytes", "Ed25519", false, true},
		{"cid10#Multikey.10 Ed25519 public key: base-58-btc with header z", "Ed25519", false, false},
		{"cid10#Multikey.11 BLS12-381 G2 public key: prefix 0xeb01 and 96 bytes", "BLS12-381-G2", false, true},
		{"cid10#Multikey.12 BLS12-381 G2 public key: base-58-btc with header z", "BLS12-381-G2", false, false},
		{"cid10#Multikey.13 SM2 public key: prefix 0x8624 and 33 bytes", "SM2", false, true},
		{"cid10#Multikey.14 SM2 public key: base-58-btc with header z", "SM2", false, false},
		{"cid10#Multikey.15 P-256 secret key: prefix 0x8626 and 32 bytes", "P-256", true, true},
		{"cid10#Multikey.16 P-256 secret key: base-58-btc with header z", "P-256", true, false},
		{"cid10#Multikey.17 P-384 secret key: prefix 0x8726 and 48 bytes", "P-384", true, true},
		{"cid10#Multikey.18 Ed25519 secret key: prefix 0x8026 and 32 bytes", "Ed25519", true, true},
		{"cid10#Multikey.19 Ed25519 secret key: base-58-btc with header z", "Ed25519", true, false},
		{"cid10#Multikey.20 BLS12-381 G2 secret key: prefix 0x8030 and 96 bytes", "BLS12-381-G2", true, true},
		{"cid10#Multikey.21 BLS12-381 G2 secret key: base-58-btc with header z", "BLS12-381-G2", true, false},
		{"cid10#Multikey.22 SM2 secret key: prefix 0x9026 and 32 bytes", "SM2", true, true},
		{"cid10#Multikey.23 SM2 secret key: base-58-btc with header z", "SM2", true, false},
		{"P-384 public key: base-58-btc with header z (stated without MUST)", "P-384", false, false},
		{"P-384 secret key: base-58-btc with header z (stated without MUST)", "P-384", true, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			c := codecFor(t, r.key, r.secret)
			id, _, _ := strings.Cut(r.name, " ")
			if strings.HasPrefix(id, "cid10#") && id != c.PrefixStatement && id != c.EncodingStatement {
				t.Fatalf("row cites %s/%s", c.PrefixStatement, c.EncodingStatement)
			}
			if r.prefix {
				checkCodecRow(t, c)
			} else {
				checkCodecEncoding(t, c)
			}
		})
	}
	t.Run("cid10#Multikey.20 the varint of 0x130a is accepted too", func(t *testing.T) {
		v, _ := multiformats.EncodeMultibase('z', append([]byte{0x8a, 0x26}, make([]byte, 96)...))
		if _, _, err := DecodeMultikey(v, true); err != nil {
			t.Fatal(err)
		}
	})
}

func codecFor(t *testing.T, name string, secret bool) MultikeyCodec {
	t.Helper()
	for _, c := range MultikeyCodecs() {
		if c.Name == name && c.Secret == secret {
			return c
		}
	}
	t.Fatalf("no codec %s", name)
	return MultikeyCodec{}
}

func checkCodecRow(t *testing.T, c MultikeyCodec) {
	t.Helper()
	key := bytes.Repeat([]byte{0x5a}, c.KeyLength)
	value, err := EncodeMultikey(c, key)
	if err != nil {
		t.Fatal(err)
	}
	got, raw, err := DecodeMultikey(value, c.Secret)
	if err != nil || !bytes.Equal(raw, key) || got.Name != c.Name {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := EncodeMultikey(c, key[1:]); err == nil {
		t.Fatal("encode with short key accepted")
	}
	short, _ := multiformats.EncodeMultibase('z', append(c.Prefix[:], key[1:]...))
	if _, _, err := DecodeMultikey(short, c.Secret); err == nil {
		t.Fatal("short key accepted")
	} else {
		wantStatement(t, err, c.PrefixStatement)
	}
	m := baseMethod(t, "Multikey")
	if c.Secret {
		m.SecretKeyMultibase = value
	} else {
		m.PublicKeyMultibase = value
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
}

func checkCodecEncoding(t *testing.T, c MultikeyCodec) {
	t.Helper()
	data := append(c.Prefix[:], bytes.Repeat([]byte{1}, c.KeyLength)...)
	other, _ := multiformats.EncodeMultibase('u', data)
	if _, _, err := DecodeMultikey(other, c.Secret); err == nil {
		t.Fatal("header u accepted for a Multikey value")
	}
	if _, _, err := DecodeMultikey("", c.Secret); err == nil {
		t.Fatal("empty value accepted")
	}
}
