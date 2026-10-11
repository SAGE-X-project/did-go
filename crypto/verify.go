package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"
)

// Policy holds the choices signature verification makes where the
// standards allow more than one answer.
//
// Ed25519 verification is always strict: the public key and the R part of
// the signature must be canonical encodings of points that are not of small
// order, S must be reduced modulo the group order (RFC 8032 §5.1.7 step 1),
// and the cofactorless equation is checked (crypto/ed25519). This rejects
// the malleable and weak-key signatures that RFC 8032 permits
// implementations to accept.
//
// ECDSA signatures are the fixed-size concatenation r || s (IEEE P1363, the
// form of RFC 7518 §3.4 and of Data Integrity ECDSA proofs) over the SHA-256
// (P-256) or SHA-384 (P-384) digest of the message. FIPS 186-5 and RFC 7518
// accept both s and n - s, so by default a high-S signature is accepted.
// RejectHighS rejects s > n/2 for callers that need non-malleable
// signatures; signers must then normalize to low S.
type Policy struct {
	// RejectHighS rejects ECDSA signatures whose s is greater than half the
	// group order.
	RejectHighS bool
}

// Verify checks sig over msg with k under the default Policy.
func (k PublicKey) Verify(msg, sig []byte) error {
	return k.VerifyWithPolicy(msg, sig, Policy{})
}

// VerifyWithPolicy checks sig over msg with k under p. It returns nil for a
// valid signature, ErrInvalidSignature for an invalid one and
// ErrUnsupportedKeyType for a key that does not sign (X25519).
func (k PublicKey) VerifyWithPolicy(msg, sig []byte, p Policy) error {
	switch k.typ {
	case Ed25519:
		return verifyEd25519(k.raw, msg, sig)
	case P256, P384:
		return k.verifyECDSA(msg, sig, p)
	}
	return fmt.Errorf("%w: %q keys do not verify signatures", ErrUnsupportedKeyType, k.typ)
}

func verifyEd25519(pub, msg, sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: Ed25519 signature is %d bytes, want 64", ErrInvalidSignature, len(sig))
	}
	if err := checkEdwardsPoint(sig[:32]); err != nil {
		return fmt.Errorf("%w: R: %w", ErrInvalidSignature, err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return fmt.Errorf("%w: Ed25519 verification failed", ErrInvalidSignature)
	}
	return nil
}

func (k PublicKey) verifyECDSA(msg, sig []byte, p Policy) error {
	c, _ := k.typ.curve()
	size := coordinateSize(c)
	if len(sig) != 2*size {
		return fmt.Errorf("%w: %s signature is %d bytes, want %d", ErrInvalidSignature, k.typ, len(sig), 2*size)
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	n := c.Params().N
	if p.RejectHighS && s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		return fmt.Errorf("%w: high-S signature rejected by policy", ErrInvalidSignature)
	}
	var digest []byte
	if k.typ == P256 {
		h := sha256.Sum256(msg)
		digest = h[:]
	} else {
		h := sha512.Sum384(msg)
		digest = h[:]
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(c, k.point)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	if !ecdsa.Verify(pub, digest, r, s) {
		return fmt.Errorf("%w: %s verification failed", ErrInvalidSignature, k.typ)
	}
	return nil
}
