package multiformats

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"math/rand/v2"
	"strings"
	"testing"
)

// referenceEncode is an independent big-integer base conversion used to
// cross-check CID 1.0 §3.1.
func referenceEncode(data []byte, alphabet string) string {
	zeroes := 0
	for zeroes < len(data) && data[zeroes] == 0 {
		zeroes++
	}
	n := new(big.Int).SetBytes(data)
	base := big.NewInt(int64(len(alphabet)))
	var digits []byte
	mod := new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		digits = append(digits, alphabet[mod.Int64()])
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return strings.Repeat(alphabet[:1], zeroes) + string(digits)
}

func TestBaseEncode(t *testing.T) {
	cases := []struct {
		name     string
		in       []byte
		alphabet string
		want     string
	}{
		{"cid10#multibase-0.2 base58btc of Hello World!", []byte("Hello World!"), AlphabetBase58BTC, "2NEpo7TZRRrLZSi2U"},
		{"cid10#multibase-0.2 leading zero bytes keep one 1 each", []byte{0, 0, 1}, AlphabetBase58BTC, "112"},
		{"cid10#multibase-0.2 empty input", nil, AlphabetBase58BTC, ""},
		{"cid10#multibase-0.2 base64url alphabet uses base expansion", []byte{0xff}, AlphabetBase64URL, "D_"},
		{"cid10#multibase-0.2 base64url leading zero is A", []byte{0, 1}, AlphabetBase64URL, "AB"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := BaseEncode(c.in, c.alphabet)
			if err != nil || got != c.want {
				t.Fatalf("BaseEncode = %q, %v; want %q", got, err, c.want)
			}
		})
	}
	t.Run("alphabet too short", func(t *testing.T) {
		if _, err := BaseEncode([]byte{1}, "a"); err == nil {
			t.Fatal("want error")
		}
		if _, err := BaseDecode("a", "a"); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestAlgorithmsEquivalentOutput(t *testing.T) {
	t.Run("cid10#algorithms.1 output equals an independent big-integer conversion", func(t *testing.T) {
		r := rand.New(rand.NewPCG(1, 2))
		for i := 0; i < 500; i++ {
			data := make([]byte, r.IntN(70))
			for j := range data {
				data[j] = byte(r.IntN(256))
			}
			if r.IntN(4) == 0 && len(data) > 2 {
				data[0], data[1] = 0, 0
			}
			for _, a := range []string{AlphabetBase58BTC, AlphabetBase64URL} {
				got, _ := BaseEncode(data, a)
				if want := referenceEncode(data, a); got != want {
					t.Fatalf("encode %x: got %q want %q", data, got, want)
				}
				back, err := BaseDecode(got, a)
				if err != nil || !bytes.Equal(back, data) {
					t.Fatalf("decode %q: got %x, %v want %x", got, back, err, data)
				}
			}
		}
	})
}

func TestMultibase(t *testing.T) {
	const example = "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
	t.Run("cid10#multibase-0.4 decodes the characters after the header with its alphabet", func(t *testing.T) {
		h, data, err := DecodeMultibase(example)
		if err != nil || h != HeaderBase58BTC {
			t.Fatalf("decode: %c %v", h, err)
		}
		if len(data) != 34 || data[0] != 0xed || data[1] != 0x01 {
			t.Fatalf("want Ed25519 Multikey bytes, got %x", data)
		}
		again, err := EncodeMultibase(HeaderBase58BTC, data)
		if err != nil || again != example {
			t.Fatalf("re-encode = %q, %v", again, err)
		}
	})
	t.Run("cid10#multibase-0.2 prepends the header", func(t *testing.T) {
		s, err := EncodeMultibase(HeaderBase64URL, []byte{0xff})
		if err != nil || s != "uD_" {
			t.Fatalf("got %q %v", s, err)
		}
	})
	t.Run("cid10#multibase-0.4 rejects characters outside the alphabet", func(t *testing.T) {
		for _, s := range []string{"z0OIl", "u+/"} {
			if _, _, err := DecodeMultibase(s); err == nil {
				t.Fatalf("%q: want error", s)
			}
		}
	})
	t.Run("unknown or empty header", func(t *testing.T) {
		if _, _, err := DecodeMultibase(""); err == nil {
			t.Fatal("empty: want error")
		}
		if _, _, err := DecodeMultibase("f00"); err == nil {
			t.Fatal("f: want error")
		}
		if _, err := EncodeMultibase('f', nil); err == nil {
			t.Fatal("encode f: want error")
		}
	})
	t.Run("registry headers", func(t *testing.T) {
		if !IsHeader('z') || !IsHeader('u') || !IsHeader('m') || IsHeader('x') || IsHeader('#') {
			t.Fatal("IsHeader table wrong")
		}
	})
}

func TestBase64URL(t *testing.T) {
	s := EncodeBase64URL([]byte{0xfb, 0xff})
	if s != "-_8" {
		t.Fatalf("got %q", s)
	}
	b, err := DecodeBase64URL(s)
	if err != nil || !bytes.Equal(b, []byte{0xfb, 0xff}) {
		t.Fatalf("got %x %v", b, err)
	}
	for _, bad := range []string{"-_8=", "+/", "-_9"} {
		if _, err := DecodeBase64URL(bad); err == nil {
			t.Fatalf("%q: want error", bad)
		}
	}
}

func TestVarint(t *testing.T) {
	for _, v := range []uint64{0, 1, 0x7f, 0x80, 0xed, 0x1200, 1<<63 - 1} {
		b := AppendVarint(nil, v)
		got, n, err := ReadVarint(b)
		if err != nil || got != v || n != len(b) {
			t.Fatalf("%d: got %d,%d,%v", v, got, n, err)
		}
	}
	if b := AppendVarint(nil, 0x1200); !bytes.Equal(b, []byte{0x80, 0x24}) {
		t.Fatalf("0x1200 = %x, want 8024", b)
	}
	bad := [][]byte{nil, {0x80}, {0x80, 0x00}, bytes.Repeat([]byte{0xff}, 10)}
	for _, b := range bad {
		if _, _, err := ReadVarint(b); err == nil {
			t.Fatalf("%x: want error", b)
		}
	}
}

func TestMultihash(t *testing.T) {
	digest := sha256.Sum256([]byte("did-go"))
	t.Run("cid10#multihash.2 header, length and digest in that order", func(t *testing.T) {
		mh, err := EncodeMultihash(SHA2256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if mh[0] != 0x12 || mh[1] != 32 || !bytes.Equal(mh[2:], digest[:]) {
			t.Fatalf("got %x", mh)
		}
		if _, err := EncodeMultihash(SHA2384, digest[:]); err == nil {
			t.Fatal("wrong digest length: want error")
		}
		if _, err := EncodeMultihash(0x99, digest[:]); err == nil {
			t.Fatal("unknown header: want error")
		}
	})
	t.Run("cid10#multihash.3 digest must match the algorithm and the written length", func(t *testing.T) {
		mh, _ := EncodeMultihash(SHA2256, digest[:])
		code, d, err := DecodeMultihash(mh)
		if err != nil || code != SHA2256 || !bytes.Equal(d, digest[:]) {
			t.Fatalf("decode: %x %x %v", code, d, err)
		}
		short := append([]byte{0x12, 31}, digest[:31]...)
		mismatch := append([]byte{0x12, 32}, digest[:31]...)
		unknown := append([]byte{0x99, 32}, digest[:]...)
		for name, b := range map[string][]byte{"algorithm length": short, "written length": mismatch, "unknown": unknown, "empty": nil, "no length": {0x12}} {
			if _, _, err := DecodeMultihash(b); err == nil {
				t.Fatalf("%s: want error", name)
			}
		}
	})
	for _, c := range []uint64{SHA2256, SHA2384, SHA3256, SHA3384} {
		if _, ok := DigestLength(c); !ok {
			t.Fatalf("0x%x missing", c)
		}
	}
}
