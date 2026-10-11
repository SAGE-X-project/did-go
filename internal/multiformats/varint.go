package multiformats

import (
	"errors"
	"fmt"
)

// maxVarintLen is the longest unsigned varint the multiformats
// unsigned-varint specification allows (9 bytes, 63 bits).
const maxVarintLen = 9

// AppendVarint appends the unsigned varint (LEB128) encoding of v.
func AppendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// ReadVarint decodes an unsigned varint from the start of b and returns the
// value and the number of bytes read. Non-minimal encodings, values longer
// than nine bytes and truncated input are errors.
func ReadVarint(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(b) && i < maxVarintLen; i++ {
		c := b[i]
		v |= uint64(c&0x7f) << (7 * uint(i))
		if c&0x80 == 0 {
			if c == 0 && i > 0 {
				return 0, 0, errors.New("multiformats: varint is not minimally encoded")
			}
			return v, i + 1, nil
		}
	}
	if len(b) >= maxVarintLen {
		return 0, 0, errors.New("multiformats: varint longer than nine bytes")
	}
	return 0, 0, errors.New("multiformats: truncated varint")
}

// Multihash identifiers of CID 1.0 §2.5.
const (
	SHA2256 uint64 = 0x12
	SHA2384 uint64 = 0x20
	SHA3256 uint64 = 0x16
	SHA3384 uint64 = 0x15
)

// DigestLength returns the output length in bytes of a CID 1.0 §2.5 Multihash
// identifier, or false when CID does not define it.
func DigestLength(code uint64) (int, bool) {
	switch code {
	case SHA2256, SHA3256:
		return 32, true
	case SHA2384, SHA3384:
		return 48, true
	}
	return 0, false
}

// EncodeMultihash concatenates the varint header, the varint digest length
// and the digest, in that order (CID 1.0 §2.5).
func EncodeMultihash(code uint64, digest []byte) ([]byte, error) {
	want, ok := DigestLength(code)
	if !ok {
		return nil, fmt.Errorf("multiformats: Multihash header 0x%x is not defined by CID 1.0", code)
	}
	if len(digest) != want {
		return nil, fmt.Errorf("multiformats: digest is %d bytes, header 0x%x needs %d", len(digest), code, want)
	}
	out := AppendVarint(nil, code)
	out = AppendVarint(out, uint64(len(digest)))
	return append(out, digest...), nil
}

// DecodeMultihash removes the header and the digest length and returns the
// digest, which must match both the output length of the header's algorithm
// and the length written in the value (CID 1.0 §2.5).
func DecodeMultihash(b []byte) (uint64, []byte, error) {
	code, n, err := ReadVarint(b)
	if err != nil {
		return 0, nil, err
	}
	want, ok := DigestLength(code)
	if !ok {
		return 0, nil, fmt.Errorf("multiformats: Multihash header 0x%x is not defined by CID 1.0", code)
	}
	length, m, err := ReadVarint(b[n:])
	if err != nil {
		return 0, nil, err
	}
	digest := b[n+m:]
	if length != uint64(want) {
		return 0, nil, fmt.Errorf("multiformats: written length %d differs from the %d-byte output of header 0x%x", length, want, code)
	}
	if uint64(len(digest)) != length {
		return 0, nil, fmt.Errorf("multiformats: digest is %d bytes, the value says %d", len(digest), length)
	}
	return code, append([]byte(nil), digest...), nil
}
