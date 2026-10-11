package vm

import (
	"strings"
	"time"
	"unicode"

	"github.com/sage-x-project/did-go/did"
)

// Verification method types that did-go validates fully (CID 1.0 §2.2.2,
// §2.2.3). Any other type gets the generic checks only.
const (
	TypeMultikey   = "Multikey"
	TypeJsonWebKey = "JsonWebKey"
)

// Method is a verification method (CID 1.0 §2.2, DID Core 1.0 §5.2, DID 1.1
// §5.2). It is a plain value: use Clone for an independent copy, and
// Validate to check it. Documents store and return clones.
type Method struct {
	// ID is a DID URL, or a relative DID URL in DID 1.1.
	ID did.DIDURL
	// Type references exactly one verification method type.
	Type string
	// Controller is the DID that controls the method. It is a claim; the
	// binding is checked by document.SelectMethod.
	Controller did.DID
	// Expires is when the method should cease to be used, or nil.
	Expires *time.Time
	// Revoked is when the method must not be used any more, or nil.
	Revoked *time.Time
	// PublicKeyMultibase is a Multibase encoded public key, or "".
	PublicKeyMultibase string
	// PublicKeyJwk is a public JSON Web Key, or nil.
	PublicKeyJwk map[string]any
	// SecretKeyMultibase is a Multibase encoded secret key, or "".
	SecretKeyMultibase string
	// SecretKeyJwk is a secret JSON Web Key, or nil.
	SecretKeyJwk map[string]any
	// Extra holds additional properties (CID 1.0 §2.2 "MAY include
	// additional properties"), as JSON values.
	Extra map[string]any
}

// methodProperties are the property names Method models.
func methodProperties() []string {
	return []string{"id", "type", "controller", "expires", "revoked",
		"publicKeyMultibase", "publicKeyJwk", "secretKeyMultibase", "secretKeyJwk"}
}

// Clone returns a deep copy of m.
func (m Method) Clone() Method {
	c := m
	c.Expires = cloneTime(m.Expires)
	c.Revoked = cloneTime(m.Revoked)
	c.PublicKeyJwk = CloneJSONMap(m.PublicKeyJwk)
	c.SecretKeyJwk = CloneJSONMap(m.SecretKeyJwk)
	c.Extra = CloneJSONMap(m.Extra)
	return c
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

// HasPublicKey reports whether m carries public key material. A method
// without it is conforming but cannot verify proofs (docs/06 §2.1).
func (m Method) HasPublicKey() bool {
	return m.PublicKeyMultibase != "" || m.PublicKeyJwk != nil
}

// Validate applies the value checks of docs/06 §11 that hold in every DID
// version: id, type and controller are present; type is a single string;
// expires and revoked are datetimes; at most one property per material;
// Multibase form of key strings for any type; JWK form without private
// members; and the full Multikey and JsonWebKey rules for those types.
func (m Method) Validate() error {
	checks := []func() error{m.checkCore, m.checkTimes, m.checkMaterial, m.checkByType, m.checkExtra}
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func (m Method) checkCore() error {
	if m.ID.IsZero() {
		return errorf("id", "cid10#verification-methods.3", "a verification method has an id")
	}
	if m.Type == "" || strings.IndexFunc(m.Type, unicode.IsSpace) >= 0 {
		return errorf("type", "cid10#verification-methods.6", "type is one non-empty type name")
	}
	if m.Controller.IsZero() {
		return errorf("controller", "cid10#verification-methods.3", "a verification method has a controller")
	}
	return nil
}

func (m Method) checkTimes() error {
	for _, t := range []struct {
		name, statement string
		v               *time.Time
	}{{"expires", "cid10#verification-methods.9", m.Expires}, {"revoked", "cid10#verification-methods.11", m.Revoked}} {
		if t.v != nil && (t.v.IsZero() || t.v.UTC().Year() < 1 || t.v.UTC().Year() > 9999) {
			return errorf(t.name, t.statement, "not a dateTimeStamp that can be written with a four-digit year")
		}
	}
	return nil
}

func (m Method) checkMaterial() error {
	if m.PublicKeyMultibase != "" && m.PublicKeyJwk != nil {
		return errorf("publicKeyJwk", "cid10#verification-material.1", "publicKeyJwk and publicKeyMultibase express the same material")
	}
	if m.SecretKeyMultibase != "" && m.SecretKeyJwk != nil {
		return errorf("secretKeyJwk", "cid10#verification-material.1", "secretKeyJwk and secretKeyMultibase express the same material")
	}
	if m.PublicKeyMultibase != "" {
		if err := checkMultibase("publicKeyMultibase", "core10#verification-material.7", m.PublicKeyMultibase); err != nil {
			return err
		}
	}
	if m.SecretKeyMultibase != "" {
		if err := checkMultibase("secretKeyMultibase", "cid10#Multikey.5", m.SecretKeyMultibase); err != nil {
			return err
		}
	}
	if m.PublicKeyJwk != nil {
		if err := checkJWK("publicKeyJwk", m.PublicKeyJwk, true); err != nil {
			return err
		}
	}
	if m.SecretKeyJwk != nil {
		return checkJWK("secretKeyJwk", m.SecretKeyJwk, false)
	}
	return nil
}

func (m Method) checkByType() error {
	switch m.Type {
	case TypeMultikey:
		if m.PublicKeyJwk != nil || m.SecretKeyJwk != nil {
			return errorf("publicKeyJwk", "cid10#verification-methods.3", "a Multikey method expresses keys with publicKeyMultibase and secretKeyMultibase")
		}
		if m.PublicKeyMultibase != "" {
			if _, _, err := DecodeMultikey(m.PublicKeyMultibase, false); err != nil {
				return err
			}
		}
		if m.SecretKeyMultibase != "" {
			if _, _, err := DecodeMultikey(m.SecretKeyMultibase, true); err != nil {
				return err
			}
		}
	case TypeJsonWebKey:
		if m.PublicKeyMultibase != "" || m.SecretKeyMultibase != "" {
			return errorf("publicKeyMultibase", "cid10#verification-methods.3", "a JsonWebKey method expresses keys with publicKeyJwk and secretKeyJwk")
		}
	}
	return nil
}

func (m Method) checkExtra() error {
	return checkExtra(m.Extra, methodProperties(), "cid10#verification-methods.4")
}
