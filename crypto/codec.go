package crypto

import (
	"fmt"

	"github.com/sage-x-project/did-go/internal/multiformats"
	"github.com/sage-x-project/did-go/vm"
)

// JWK returns the public JSON Web Key of k, following the Encode JWK
// Algorithm of the did:key specification: kty and crv identify the key type
// (RFC 7518 §6.2.1 for EC keys, RFC 8037 §2 for OKP keys), x and, for EC
// keys, the y coordinate recovered from the compressed point are encoded as
// unpadded base64url of their full length, and no other member, in
// particular no "d", is written. It returns nil for the zero value.
func (k PublicKey) JWK() map[string]any {
	switch k.typ {
	case Ed25519, X25519:
		return map[string]any{"kty": "OKP", "crv": string(k.typ), "x": multiformats.EncodeBase64URL(k.raw)}
	case P256, P384:
		size := (len(k.point) - 1) / 2
		return map[string]any{
			"kty": "EC", "crv": string(k.typ),
			"x": multiformats.EncodeBase64URL(k.point[1 : 1+size]),
			"y": multiformats.EncodeBase64URL(k.point[1+size:]),
		}
	}
	return nil
}

// ParseMultikey decodes a publicKeyMultibase value of a Multikey method with
// the Multikey table of package vm and validates the key.
func ParseMultikey(value string) (PublicKey, error) {
	codec, raw, err := vm.DecodeMultikey(value, false)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: %w", ErrInvalidEncoding, err)
	}
	return NewPublicKey(KeyType(codec.Name), raw)
}

// ParseJWK decodes a public JSON Web Key: an OKP key with crv Ed25519 or
// X25519 (RFC 8037 §2) or an EC key with crv P-256 or P-384 (RFC 7518
// §6.2.1). Coordinates must be unpadded base64url of the full coordinate
// length (RFC 7518 §6.2.1.2, §6.2.1.3). A key with a private member is
// rejected, so that no private key passes through this package.
func ParseJWK(jwk map[string]any) (PublicKey, error) {
	if jwk == nil {
		return PublicKey{}, fmt.Errorf("%w: no JWK", ErrInvalidEncoding)
	}
	if _, ok := jwk["d"]; ok {
		return PublicKey{}, fmt.Errorf(`%w: a public JWK must not contain "d"`, ErrInvalidEncoding)
	}
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	t := KeyType(crv)
	switch {
	case kty == "OKP" && (t == Ed25519 || t == X25519):
		x, err := coordinate(jwk, "x", 32)
		if err != nil {
			return PublicKey{}, err
		}
		return NewPublicKey(t, x)
	case kty == "EC" && (t == P256 || t == P384):
		c, _ := t.curve()
		size := coordinateSize(c)
		x, err := coordinate(jwk, "x", size)
		if err != nil {
			return PublicKey{}, err
		}
		y, err := coordinate(jwk, "y", size)
		if err != nil {
			return PublicKey{}, err
		}
		point, err := uncompressed(t, append(append([]byte{4}, x...), y...))
		if err != nil {
			return PublicKey{}, err
		}
		return PublicKey{typ: t, raw: compress(point), point: point}, nil
	case kty == "":
		return PublicKey{}, fmt.Errorf(`%w: the JWK has no string "kty"`, ErrInvalidEncoding)
	}
	return PublicKey{}, fmt.Errorf("%w: JWK kty %q crv %q", ErrUnsupportedKeyType, kty, crv)
}

// coordinate decodes the base64url member name of jwk and checks its length.
func coordinate(jwk map[string]any, name string, size int) ([]byte, error) {
	s, ok := jwk[name].(string)
	if !ok {
		return nil, fmt.Errorf("%w: the JWK has no string %q", ErrInvalidEncoding, name)
	}
	b, err := multiformats.DecodeBase64URL(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidEncoding, name, err)
	}
	if len(b) != size {
		return nil, fmt.Errorf("%w: %s is %d bytes, want %d", ErrInvalidEncoding, name, len(b), size)
	}
	return b, nil
}

// FromMethod returns the public key of a verification method: the
// publicKeyJwk value when present, otherwise the publicKeyMultibase value
// decoded as a Multikey value. The method itself is not changed (CID 1.0
// §2.2.1: converting key formats must not affect the external
// representation).
func FromMethod(m vm.Method) (PublicKey, error) {
	switch {
	case m.PublicKeyJwk != nil:
		return ParseJWK(m.PublicKeyJwk)
	case m.PublicKeyMultibase != "":
		return ParseMultikey(m.PublicKeyMultibase)
	}
	return PublicKey{}, fmt.Errorf("%w: verification method %s has no public key material", ErrInvalidEncoding, m.ID)
}

// DeriveX25519 converts an Ed25519 public key into the X25519 public key of
// the birationally equivalent Montgomery curve, u = (1 + y) / (1 - y)
// (RFC 7748 §4.1), the conversion the did:key specification's Derive
// Encryption Key Algorithm refers to.
func DeriveX25519(k PublicKey) (PublicKey, error) {
	if k.typ != Ed25519 {
		return PublicKey{}, fmt.Errorf("%w: X25519 derivation needs an Ed25519 key, got %q", ErrUnsupportedKeyType, k.typ)
	}
	u, err := montgomeryU(k.raw)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return NewPublicKey(X25519, u)
}
