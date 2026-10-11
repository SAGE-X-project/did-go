package vm

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sage-x-project/did-go/internal/multiformats"
)

// privateJWKMembers are the JSON Web Key parameters registered with the
// "Private" usage location in the IANA JOSE JSON Web Key Parameters registry
// (RFC 7517 §8.1, RFC 7518 §7.5): EC and OKP "d", RSA "d", "p", "q", "dp",
// "dq", "qi", "oth" with its "r", "d", "t", and the symmetric key "k".
func privateJWKMembers() []string {
	return []string{"d", "p", "q", "dp", "dq", "qi", "oth", "r", "t", "k"}
}

// checkJWK checks that jwk is a JSON Web Key map (RFC 7517 §4): a string
// "kty", JSON values only, and the "crv" that RFC 7518 §6.2.1 and RFC 8037
// §2 require for EC and OKP keys. A public key must not contain any private
// member (CID 1.0 §2.2.3, DID Core 1.0 §5.2.1).
func checkJWK(property string, jwk map[string]any, public bool) error {
	formStatement, privStatement := "cid10#JsonWebKey.3", "cid10#JsonWebKey.13"
	if !public {
		formStatement = "cid10#JsonWebKey.11"
	}
	if err := checkJSONMap(jwk, 1); err != nil {
		return errorf(property, formStatement, "%v", err)
	}
	kty, ok := jwk["kty"].(string)
	if !ok || kty == "" {
		return errorf(property, formStatement, `a JSON Web Key has a string "kty" member`)
	}
	if kty == "EC" || kty == "OKP" {
		if crv, ok := jwk["crv"].(string); !ok || crv == "" {
			return errorf(property, "cid10#JsonWebKey.8", `a %s key has a string "crv" member`, kty)
		}
	}
	if public {
		for _, m := range privateJWKMembers() {
			if _, ok := jwk[m]; ok {
				return errorf(property, privStatement, "a public key must not contain the private member %q", m)
			}
		}
	}
	return nil
}

// thumbprintMembers returns the required members of RFC 7638 §3.2 for kty.
func thumbprintMembers(kty string) []string {
	switch kty {
	case "EC":
		return []string{"crv", "kty", "x", "y"}
	case "OKP":
		return []string{"crv", "kty", "x"}
	case "RSA":
		return []string{"e", "kty", "n"}
	case "oct":
		return []string{"k", "kty"}
	}
	return nil
}

// JWKThumbprint returns the RFC 7638 JWK Thumbprint of jwk with SHA-256,
// base64url encoded without padding.
func JWKThumbprint(jwk map[string]any) (string, error) {
	kty, _ := jwk["kty"].(string)
	members := thumbprintMembers(kty)
	if members == nil {
		return "", fmt.Errorf("vm: no thumbprint members for kty %q", kty)
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, name := range members {
		v, ok := jwk[name].(string)
		if !ok {
			return "", fmt.Errorf("vm: thumbprint member %q is missing or not a string", name)
		}
		if i > 0 {
			sb.WriteByte(',')
		}
		key, _ := json.Marshal(name)
		val, _ := json.Marshal(v)
		sb.Write(key)
		sb.WriteByte(':')
		sb.Write(val)
	}
	sb.WriteByte('}')
	sum := sha256.Sum256([]byte(sb.String()))
	return multiformats.EncodeBase64URL(sum[:]), nil
}
