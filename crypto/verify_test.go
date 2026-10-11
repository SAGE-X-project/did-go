package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
	"slices"
	"testing"
)

func sha512Sum(b []byte) [64]byte { return sha512.Sum512(b) }

func TestVerifyEd25519(t *testing.T) {
	// RFC 8032 §7.1, TEST 1.
	pub := mustHex(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	sig := mustHex(t, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	k, err := NewPublicKey(Ed25519, pub)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("RFC 8032 test 1 verifies", func(t *testing.T) {
		if err := k.Verify(nil, sig); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a changed message fails", func(t *testing.T) {
		wantErr(t, k.Verify([]byte("x"), sig), ErrInvalidSignature)
	})
	t.Run("a short signature fails", func(t *testing.T) {
		wantErr(t, k.Verify(nil, sig[:63]), ErrInvalidSignature)
	})
	t.Run("S not reduced modulo L fails", func(t *testing.T) {
		// S + L encodes the same scalar; strict verification rejects it.
		l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
		s := littleEndian(sig[32:])
		s.Add(s, l)
		enc := make([]byte, 32)
		s.FillBytes(enc)
		slices.Reverse(enc)
		mall := append(slices.Clone(sig[:32]), enc...)
		wantErr(t, k.Verify(nil, mall), ErrInvalidSignature)
	})
	t.Run("R of small order fails", func(t *testing.T) {
		bad := slices.Clone(sig)
		copy(bad[:32], make([]byte, 32))
		bad[0] = 1
		err := k.Verify(nil, bad)
		if !errors.Is(err, ErrInvalidSignature) || !errors.Is(err, errSmallOrder) {
			t.Fatal(err)
		}
	})
	t.Run("random keys", func(t *testing.T) {
		p, priv, _ := ed25519.GenerateKey(rand.Reader)
		k, _ := FromCryptoKey(p)
		msg := []byte("did-go")
		if err := k.Verify(msg, ed25519.Sign(priv, msg)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestVerifyECDSA(t *testing.T) {
	for _, typ := range []KeyType{P256, P384} {
		t.Run(string(typ), func(t *testing.T) {
			c, _ := typ.curve()
			priv, _ := ecdsa.GenerateKey(c, rand.Reader)
			k, _ := FromCryptoKey(&priv.PublicKey)
			msg := []byte("did-go")
			var digest []byte
			if typ == P256 {
				h := sha256.Sum256(msg)
				digest = h[:]
			} else {
				h := sha512.Sum384(msg)
				digest = h[:]
			}
			r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
			if err != nil {
				t.Fatal(err)
			}
			n := c.Params().N
			half := new(big.Int).Rsh(n, 1)
			low, high := new(big.Int).Set(s), new(big.Int).Sub(n, s)
			if s.Cmp(half) > 0 {
				low, high = high, low
			}
			size := coordinateSize(c)
			raw := func(r, s *big.Int) []byte {
				out := make([]byte, 2*size)
				r.FillBytes(out[:size])
				s.FillBytes(out[size:])
				return out
			}
			if err := k.Verify(msg, raw(r, low)); err != nil {
				t.Fatal(err)
			}
			if err := k.Verify(msg, raw(r, high)); err != nil {
				t.Fatal("default policy rejected a high-S signature:", err)
			}
			strict := Policy{RejectHighS: true}
			if err := k.VerifyWithPolicy(msg, raw(r, low), strict); err != nil {
				t.Fatal(err)
			}
			wantErr(t, k.VerifyWithPolicy(msg, raw(r, high), strict), ErrInvalidSignature)
			wantErr(t, k.Verify([]byte("other"), raw(r, low)), ErrInvalidSignature)
			wantErr(t, k.Verify(msg, raw(r, low)[1:]), ErrInvalidSignature)
		})
	}
	t.Run("a corrupted key is reported", func(t *testing.T) {
		k := mustParse(t, vecP256)
		k.point = slices.Clone(k.point)
		k.point[len(k.point)-1] ^= 1
		wantErr(t, k.Verify(nil, make([]byte, 64)), ErrInvalidKey)
		if k.CryptoKey() != nil {
			t.Fatal("corrupted key converted")
		}
	})
}

func TestVerifyUnsupported(t *testing.T) {
	wantErr(t, mustParse(t, vecX25519).Verify(nil, nil), ErrUnsupportedKeyType)
	wantErr(t, PublicKey{}.Verify(nil, nil), ErrUnsupportedKeyType)
	bad := PublicKey{typ: X25519, raw: []byte{1}}
	if bad.CryptoKey() != nil {
		t.Fatal("invalid X25519 key converted")
	}
}
