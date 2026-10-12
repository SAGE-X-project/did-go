package sage

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/sage-x-project/did-go/crypto"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// Projection is one of the two DID documents a resolver offers for a record
// (chapter 10 DIDP-01).
type Projection int

// Projections.
const (
	// Core10 is the RESOLVE-01 document: no @context, media type
	// application/did+json, verification method type JsonWebKey2020.
	Core10 Projection = iota + 1
	// DID11 has @context "https://www.w3.org/ns/did/v1.1" as a string,
	// media type application/did and verification method type JsonWebKey.
	DID11
)

// Media types of the projections.
const (
	MediaTypeCore10 = spec.MediaTypeDIDJSON
	MediaTypeDID11  = spec.MediaTypeDID
)

// typeJSONWebKey2020 is the DID Core 1.0 projection's verification method
// type, documented in the DID property extensions.
const typeJSONWebKey2020 = "JsonWebKey2020"

// MediaType returns the media type of p.
func (p Projection) MediaType() string {
	if p == DID11 {
		return MediaTypeDID11
	}
	return MediaTypeCore10
}

func (p Projection) valid() bool { return p == Core10 || p == DID11 }

func (p Projection) methodType() string {
	if p == DID11 {
		return vm.TypeJsonWebKey
	}
	return typeJSONWebKey2020
}

// produceOptions are the producer options that write p: the DID 1.1
// projection always carries @context, so it is written for JSON-LD
// processing, which puts the v1.1 base context first as a single string.
func (p Projection) produceOptions() representation.ProduceOptions {
	if p == DID11 {
		return representation.ProduceOptions{Version: spec.V11, JSONLD: true}
	}
	return representation.ProduceOptions{Version: spec.V10}
}

// projectionOf returns the projection of a DID media type, or false.
func projectionOf(mediaType string) (Projection, bool) {
	switch mediaType {
	case MediaTypeCore10:
		return Core10, true
	case MediaTypeDID11:
		return DID11, true
	}
	return 0, false
}

// Document builds projection p of r (DIDP-01 over RESOLVE-01). Both
// projections are built from the same record, so they agree on every member
// DIDP-03 lists. A record that fails the structural checks, or a key whose
// bytes are not a valid public key, is record.invalid.
func Document(r Record, p Projection) (*document.Document, *Error) {
	if !p.valid() {
		return nil, NewError(CodeRepresentationUnsupported, "unknown projection")
	}
	if e := r.check(); e != nil {
		return nil, e
	}
	b := document.NewBuilder(r.DID)
	var methods []vm.Method
	var signing, agreement []vm.Relationship
	projected := r.State == StateActive
	for _, k := range r.Keys {
		if !projected || !k.usable(r.Observation.Time) {
			continue // RESOLVE-01: revoked and expired keys stay in the record only.
		}
		jwk, err := keyJWK(k)
		if err != nil {
			return nil, NewError(CodeRecordInvalid, err.Error())
		}
		id, err := keyURL(r.DID, k.Name)
		if err != nil {
			return nil, NewError(CodeRecordInvalid, err.Error())
		}
		methods = append(methods, vm.Method{ID: id, Type: p.methodType(), Controller: r.DID, PublicKeyJwk: jwk})
		if k.signing() {
			signing = append(signing, vm.Ref(id))
		} else {
			agreement = append(agreement, vm.Ref(id))
		}
	}
	// RESOLVE-01: verificationMethod stays an array, empty when no key is
	// projected; a relationship with no member is omitted.
	b.VerificationMethod(methods...)
	if methods == nil {
		b.VerificationMethod()
	}
	if len(signing) > 0 {
		b.Relationship(vm.Authentication, signing...)
		b.Relationship(vm.AssertionMethod, signing...)
	}
	if len(agreement) > 0 {
		b.Relationship(vm.KeyAgreement, agreement...)
	}
	services := make([]vm.Service, 0, len(r.Services))
	for _, s := range r.Services {
		services = append(services, vm.Service{
			ID:              r.DID.String() + "#" + s.Name,
			Type:            []string{s.Type},
			ServiceEndpoint: []vm.Endpoint{{URL: s.URI}},
		})
	}
	b.Service(services...)
	d, err := b.Build()
	if err != nil {
		return nil, NewError(CodeRecordInvalid, err.Error())
	}
	return d, nil
}

// Metadata returns the RESOLVE-03 didDocumentMetadata of r: deactivated,
// versionId and the sage object. No canonicalId or equivalentId is written
// (DIDP-04).
func Metadata(r Record) document.Metadata {
	sage := map[string]any{
		"state":        string(r.State),
		"controller":   r.Controller,
		"source":       r.Observation.Source,
		"observedTime": r.Observation.Time,
	}
	if r.Observation.Issued != nil {
		sage["observedAt"] = *r.Observation.Issued
	} else {
		sage["observedAt"] = r.Observation.BlockHash
	}
	return document.Metadata{
		Deactivated: r.State == StateDeactivated,
		VersionID:   r.Version,
		Extra:       map[string]any{"sage": sage},
	}
}

// Produce writes projection p of r with producer and returns the bytes.
func Produce(r Record, p Projection, producer representation.Producer) ([]byte, *Error) {
	d, e := Document(r, p)
	if e != nil {
		return nil, e
	}
	data, mt, err := producer.Produce(d, p.produceOptions())
	if err != nil {
		return nil, NewError(CodeRecordInvalid, "producing the projection: "+err.Error())
	}
	if mt != p.MediaType() {
		return nil, NewError(CodeRecordInvalid, fmt.Sprintf("the producer wrote %s, not %s", mt, p.MediaType()))
	}
	if len(data) > maxResponse {
		return nil, NewError(CodeSizeExceeded, "the projection exceeds the resolution response bound")
	}
	return data, nil
}

// maxResponse is the RESOLVE-03 bound of a complete resolution response, in
// UTF-8 bytes.
const maxResponse = 262144

// keyURL is the verification method id: the DID plus the key name as its
// fragment (RESOLVE-01).
func keyURL(d did.DID, name string) (did.DIDURL, error) {
	return did.ParseURL(d.String() + "#" + name)
}

// keyJWK returns the RESOLVE-01 JWK of k: exactly kty, crv, x and, for EC
// keys, y, as unpadded base64url. Ed25519, P-256 and X25519 keys are
// validated by the did-go crypto codec; secp256k1 points are checked here,
// because the standard library has no secp256k1 curve.
func keyJWK(k Key) (map[string]any, error) {
	b64 := base64.RawURLEncoding.EncodeToString
	switch k.Alg {
	case AlgEd25519, AlgX25519:
		t, crv := crypto.Ed25519, "Ed25519"
		if k.Alg == AlgX25519 {
			t, crv = crypto.X25519, "X25519"
		}
		if _, err := crypto.NewPublicKey(t, k.Material); err != nil {
			return nil, fmt.Errorf("the key %q: %w", k.Name, err)
		}
		return map[string]any{"kty": "OKP", "crv": crv, "x": b64(k.Material)}, nil
	case AlgP256:
		if _, err := ecdh.P256().NewPublicKey(k.Material); err != nil {
			return nil, fmt.Errorf("the key %q is not a P-256 point: %w", k.Name, err)
		}
		return map[string]any{"kty": "EC", "crv": "P-256", "x": b64(k.Material[1:33]), "y": b64(k.Material[33:])}, nil
	case AlgSecp256k1:
		if !onSecp256k1(k.Material[1:33], k.Material[33:]) {
			return nil, fmt.Errorf("the key %q is not a secp256k1 point", k.Name)
		}
		return map[string]any{"kty": "EC", "crv": "secp256k1", "x": b64(k.Material[1:33]), "y": b64(k.Material[33:])}, nil
	}
	return nil, fmt.Errorf("the key %q has the unknown algorithm %q", k.Name, k.Alg)
}

// secp256k1 field prime p = 2^256 - 2^32 - 977 (SEC 2 §2.4.1).
var secp256k1P, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)

// onSecp256k1 reports whether (x, y) is an affine point of y^2 = x^3 + 7 over
// the secp256k1 field with coordinates below p (SEC 1 §2.3.4: the point at
// infinity has no uncompressed affine form).
func onSecp256k1(xb, yb []byte) bool {
	x, y := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
	if x.Cmp(secp256k1P) >= 0 || y.Cmp(secp256k1P) >= 0 {
		return false
	}
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, secp256k1P)
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, big.NewInt(7))
	rhs.Mod(rhs, secp256k1P)
	return lhs.Cmp(rhs) == 0
}
