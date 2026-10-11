package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
)

// coordinateSize returns the byte length of a field element of curve c.
func coordinateSize(c elliptic.Curve) int {
	return (c.Params().BitSize + 7) / 8
}

// decompress validates a SEC 1 compressed point of key type t (SEC 1
// §2.3.4) and returns the uncompressed point.
func decompress(t KeyType, raw []byte) ([]byte, error) {
	c, _ := t.curve()
	size := coordinateSize(c)
	if len(raw) != 1+size {
		return nil, fmt.Errorf("%w: %s key is %d bytes, want %d", ErrInvalidKey, t, len(raw), 1+size)
	}
	if raw[0] != 2 && raw[0] != 3 {
		return nil, fmt.Errorf("%w: %s key is not a compressed point", ErrInvalidKey, t)
	}
	x, y := elliptic.UnmarshalCompressed(c, raw)
	if x == nil {
		return nil, fmt.Errorf("%w: %s key is not a point on the curve", ErrInvalidKey, t)
	}
	point := make([]byte, 1+2*size)
	point[0] = 4
	x.FillBytes(point[1 : 1+size])
	y.FillBytes(point[1+size:])
	return uncompressed(t, point)
}

// uncompressed validates a SEC 1 uncompressed point of key type t with the
// standard library and returns it.
func uncompressed(t KeyType, point []byte) ([]byte, error) {
	c, _ := t.curve()
	if _, err := ecdsa.ParseUncompressedPublicKey(c, point); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidKey, t, err)
	}
	return point, nil
}

// compress returns the SEC 1 compressed form of an uncompressed point.
func compress(point []byte) []byte {
	size := (len(point) - 1) / 2
	out := make([]byte, 1+size)
	out[0] = 2 | point[len(point)-1]&1
	copy(out[1:], point[1:1+size])
	return out
}
