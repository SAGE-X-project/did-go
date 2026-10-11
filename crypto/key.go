// Package crypto is the key codec tool of did-go (docs/14 §2, docs/05 §7):
// it turns the public key material of a verification method, a Multikey
// publicKeyMultibase value (CID 1.0 §2.2.2) or a publicKeyJwk value (CID 1.0
// §2.2.3, RFC 7517, RFC 7518, RFC 8037), into a usable public key, encodes a
// public key in both forms, and verifies signatures.
//
// Supported key types are Ed25519, ECDSA P-256 and P-384 for signatures, and
// X25519 for key agreement. BLS12-381 G2, SM2 and secp256k1 keys are
// recognized but not supported: the standard library has no implementation
// of them, and did-go uses no other cryptographic library.
//
// The package holds no private key and never stores keys. Every value is
// immutable and safe for concurrent use.
package crypto

import (
	stdcrypto "crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"slices"

	"github.com/sage-x-project/did-go/vm"
)

// Error is the type of the constant errors of this package. Functions wrap
// them with more detail; callers test with errors.Is.
type Error string

// Error returns the message.
func (e Error) Error() string { return string(e) }

// Errors returned by this package.
const (
	// ErrUnsupportedKeyType: the key type is unknown, or known but not
	// implemented (BLS12-381 G2, SM2, secp256k1), or the operation does not
	// apply to it (signature verification with an X25519 key).
	ErrUnsupportedKeyType Error = "crypto: unsupported key type"
	// ErrInvalidEncoding: the Multikey or JWK value is malformed.
	ErrInvalidEncoding Error = "crypto: invalid key encoding"
	// ErrInvalidKey: the key bytes have the right form but are not a valid
	// public key of their type (not on the curve, not canonical, of small
	// order, or of the wrong length).
	ErrInvalidKey Error = "crypto: invalid public key"
	// ErrInvalidSignature: the signature is malformed or does not verify.
	ErrInvalidSignature Error = "crypto: invalid signature"
)

// KeyType names a public key type. The values are the names of the rows of
// the Multikey table in package vm.
type KeyType string

// Supported key types.
const (
	Ed25519 KeyType = "Ed25519"
	P256    KeyType = "P-256"
	P384    KeyType = "P-384"
	X25519  KeyType = "X25519"
)

// SupportedKeyTypes returns the key types this package implements, in a
// fresh slice.
func SupportedKeyTypes() []KeyType {
	return []KeyType{Ed25519, P256, P384, X25519}
}

// curve returns the elliptic curve of an ECDSA key type.
func (t KeyType) curve() (elliptic.Curve, bool) {
	switch t {
	case P256:
		return elliptic.P256(), true
	case P384:
		return elliptic.P384(), true
	}
	return nil, false
}

// PublicKey is a validated public key. The zero value is not a valid key;
// obtain one from NewPublicKey, FromCryptoKey, ParseMultikey, ParseJWK or
// FromMethod.
type PublicKey struct {
	typ KeyType
	// raw is the key data of the Multikey encoding: 32 bytes for Ed25519 and
	// X25519, the SEC 1 compressed point for P-256 and P-384.
	raw []byte
	// point is the SEC 1 uncompressed point of an ECDSA key.
	point []byte
}

// NewPublicKey validates raw as the key data of the Multikey encoding of
// type t (32 bytes for Ed25519 and X25519, a SEC 1 compressed point of 33
// bytes for P-256 and 49 bytes for P-384) and returns the key.
//
// An Ed25519 key must be the canonical encoding of a curve point that is not
// of small order (RFC 8032 §5.1.3, with the canonical y check that the RFC
// leaves to the implementation). An ECDSA key must be a point on its curve
// other than the point at infinity (SEC 1 §2.3.4). Every 32-byte string is
// an X25519 public key (RFC 7748 §5).
func NewPublicKey(t KeyType, raw []byte) (PublicKey, error) {
	switch t {
	case Ed25519:
		if len(raw) != ed25519.PublicKeySize {
			return PublicKey{}, fmt.Errorf("%w: Ed25519 key is %d bytes, want 32", ErrInvalidKey, len(raw))
		}
		if err := checkEdwardsPoint(raw); err != nil {
			return PublicKey{}, fmt.Errorf("%w: Ed25519: %w", ErrInvalidKey, err)
		}
		return PublicKey{typ: t, raw: slices.Clone(raw)}, nil
	case X25519:
		if len(raw) != 32 {
			return PublicKey{}, fmt.Errorf("%w: X25519 key is %d bytes, want 32", ErrInvalidKey, len(raw))
		}
		return PublicKey{typ: t, raw: slices.Clone(raw)}, nil
	case P256, P384:
		point, err := decompress(t, raw)
		if err != nil {
			return PublicKey{}, err
		}
		return PublicKey{typ: t, raw: slices.Clone(raw), point: point}, nil
	}
	return PublicKey{}, fmt.Errorf("%w: %q", ErrUnsupportedKeyType, t)
}

// FromCryptoKey converts a standard library public key: ed25519.PublicKey,
// *ecdsa.PublicKey on P-256 or P-384, or *ecdh.PublicKey on X25519.
func FromCryptoKey(k stdcrypto.PublicKey) (PublicKey, error) {
	switch x := k.(type) {
	case ed25519.PublicKey:
		return NewPublicKey(Ed25519, x)
	case *ecdsa.PublicKey:
		if x == nil {
			return PublicKey{}, fmt.Errorf("%w: nil ECDSA key", ErrInvalidKey)
		}
		var t KeyType
		switch x.Curve {
		case elliptic.P256():
			t = P256
		case elliptic.P384():
			t = P384
		default:
			return PublicKey{}, fmt.Errorf("%w: ECDSA curve is not P-256 or P-384", ErrUnsupportedKeyType)
		}
		point, err := ecdsaPoint(x)
		if err != nil {
			return PublicKey{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		return PublicKey{typ: t, raw: compress(point), point: point}, nil
	case *ecdh.PublicKey:
		if x == nil || x.Curve() != ecdh.X25519() {
			return PublicKey{}, fmt.Errorf("%w: ECDH key is not an X25519 key", ErrUnsupportedKeyType)
		}
		return NewPublicKey(X25519, x.Bytes())
	}
	return PublicKey{}, fmt.Errorf("%w: Go type %T", ErrUnsupportedKeyType, k)
}

// Type returns the key type.
func (k PublicKey) Type() KeyType { return k.typ }

// IsZero reports whether k is the zero value.
func (k PublicKey) IsZero() bool { return k.typ == "" }

// Raw returns the key data of the Multikey encoding, in a fresh slice.
func (k PublicKey) Raw() []byte { return slices.Clone(k.raw) }

// Equal reports whether k and o are the same key.
func (k PublicKey) Equal(o PublicKey) bool {
	return k.typ == o.typ && slices.Equal(k.raw, o.raw)
}

// CryptoKey returns a fresh standard library value for k: ed25519.PublicKey,
// *ecdsa.PublicKey or *ecdh.PublicKey. It returns nil for the zero value.
func (k PublicKey) CryptoKey() stdcrypto.PublicKey {
	switch k.typ {
	case Ed25519:
		return ed25519.PublicKey(slices.Clone(k.raw))
	case X25519:
		pub, err := ecdh.X25519().NewPublicKey(k.raw)
		if err != nil {
			return nil
		}
		return pub
	case P256, P384:
		c, _ := k.typ.curve()
		pub, err := ecdsa.ParseUncompressedPublicKey(c, k.point)
		if err != nil {
			return nil
		}
		return pub
	}
	return nil
}

// Multikey returns the publicKeyMultibase value of k: the base-58-btc
// header z followed by the base-58-btc encoding of the multicodec prefix
// and the key data (CID 1.0 §2.2.2).
func (k PublicKey) Multikey() (string, error) {
	codec, ok := multikeyCodec(k.typ)
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnsupportedKeyType, k.typ)
	}
	return vm.EncodeMultikey(codec, k.raw)
}

// multikeyCodec returns the public key row of the vm Multikey table for t.
func multikeyCodec(t KeyType) (vm.MultikeyCodec, bool) {
	for _, c := range vm.MultikeyCodecs() {
		if !c.Secret && c.Name == string(t) {
			return c, true
		}
	}
	return vm.MultikeyCodec{}, false
}

// ecdsaPoint returns the uncompressed point of k. The standard library
// panics on a PublicKey whose coordinates are unset, which is reported as an
// error instead.
func ecdsaPoint(k *ecdsa.PublicKey) (point []byte, err error) {
	defer func() {
		if recover() != nil {
			point, err = nil, errors.New("malformed ECDSA public key")
		}
	}()
	return k.Bytes()
}
