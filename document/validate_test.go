package document

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

type expectation struct {
	Severity  string `json:"severity"`
	Statement string `json:"statement"`
}

func serviceFromJSON(raw map[string]any) vm.Service {
	s := vm.Service{}
	if id, ok := raw["id"].(string); ok {
		s.ID = id
	}
	for _, t := range raw["type"].([]any) {
		s.Type = append(s.Type, t.(string))
	}
	for _, e := range raw["serviceEndpoint"].([]any) {
		if u, ok := e.(string); ok {
			s.ServiceEndpoint = append(s.ServiceEndpoint, vm.Endpoint{URL: u})
		} else {
			s.ServiceEndpoint = append(s.ServiceEndpoint, vm.Endpoint{Map: e.(map[string]any)})
		}
	}
	return s
}

func checkOne(t *testing.T, fs []Finding, want *expectation) {
	t.Helper()
	if want == nil {
		if len(fs) != 0 {
			t.Fatalf("want no finding, got %v", fs)
		}
		return
	}
	if len(fs) != 1 || fs[0].Statement != want.Statement || fs[0].Severity.String() != want.Severity {
		t.Fatalf("got %v, want one %s citing %s", fs, want.Severity, want.Statement)
	}
}

func TestValidateVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/validate.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Vectors []struct {
			ID      string         `json:"id"`
			Service map[string]any `json:"service"`
			V10     *expectation   `json:"V10"`
			V11     *expectation   `json:"V11"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Vectors {
		t.Run(c.ID, func(t *testing.T) {
			d := build(t, builder(t).Service(serviceFromJSON(c.Service)))
			checkOne(t, Validate(d, spec.V10), c.V10)
			checkOne(t, Validate(d, spec.V11), c.V11)
		})
	}
}

func TestValidateMethods(t *testing.T) {
	t.Run("core10#verification-methods.6 DID Core 1.0 method ids are absolute DID URLs", func(t *testing.T) {
		d := build(t, builder(t).VerificationMethod(key(t, "#k1")).Relationship(vm.Authentication, vm.Embed(key(t, "#k2"))))
		fs := Validate(d, spec.V10)
		if len(fs) != 2 || fs[0].Statement != "core10#verification-methods.6" || !HasErrors(fs) {
			t.Fatalf("got %v", fs)
		}
		if fs := Validate(d, spec.V11); len(fs) != 0 {
			t.Fatalf("DID 1.1 allows relative ids: %v", fs)
		}
		abs := build(t, builder(t).VerificationMethod(key(t, subject+"#k1")))
		if fs := Validate(abs, spec.V10); len(fs) != 0 {
			t.Fatalf("absolute ids conform: %v", fs)
		}
	})
	t.Run("properties undefined in DID Core 1.0 are a downlevel warning", func(t *testing.T) {
		k := key(t, subject+"#k1")
		ts := time.Unix(1700000000, 0)
		k.Expires = &ts
		d := build(t, builder(t).VerificationMethod(k))
		fs := Validate(d, spec.V10)
		if len(fs) != 1 || fs[0].Severity != SeverityWarning || HasErrors(fs) || fs[0].Statement != "" {
			t.Fatalf("got %v", fs)
		}
		if len(Validate(d, spec.V11)) != 0 || len(Validate(d, spec.VUnknown)) != 0 {
			t.Fatal("expires is defined by DID 1.1")
		}
	})
	t.Run("an undecodable Multibase header is a warning", func(t *testing.T) {
		k := key(t, subject+"#k1")
		k.Type, k.PublicKeyMultibase = "Ed25519VerificationKey2020", "mAQID"
		fs := Validate(build(t, builder(t).VerificationMethod(k)), spec.V11)
		if len(fs) != 1 || fs[0].Severity != SeverityWarning || !strings.Contains(fs[0].String(), "warning") {
			t.Fatalf("got %v", fs)
		}
	})
	t.Run("nil document and bad version", func(t *testing.T) {
		if !HasErrors(Validate(nil, spec.V11)) || !HasErrors(Validate(build(t, builder(t)), spec.Version(9))) {
			t.Fatal("want an error finding")
		}
		f := Finding{SeverityError, "x#y.1", "p", "m"}
		if f.String() != "error: p: m (x#y.1)" {
			t.Fatalf("got %q", f.String())
		}
	})
}

func jwkMethod(t *testing.T, fragment string, jwk map[string]any) vm.Method {
	t.Helper()
	return vm.Method{ID: mustRef(t, subject+"#"+fragment), Type: "JsonWebKey", Controller: mustDID(t, subject), PublicKeyJwk: jwk}
}

func findings(t *testing.T, m vm.Method, v spec.Version) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range Validate(build(t, builder(t).VerificationMethod(m)), v) {
		if f.Severity != SeverityWarning {
			t.Fatalf("JWK advice must be a warning: %v", f)
		}
		out[f.Statement] = true
	}
	return out
}

func TestJWKAdvice(t *testing.T) {
	const thumb = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
	good := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": thumb, "alg": "Ed25519"}
	noKid := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
	otherKid := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "key-1", "alg": "Ed25519"}
	t.Run("cid10#JsonWebKey.5 kid as the fragment identifier", func(t *testing.T) {
		if f := findings(t, jwkMethod(t, thumb, good), spec.V11); len(f) != 0 {
			t.Fatalf("got %v", f)
		}
		if !findings(t, jwkMethod(t, "other", good), spec.V11)["cid10#JsonWebKey.5"] || !findings(t, jwkMethod(t, "k", noKid), spec.V11)["cid10#JsonWebKey.5"] {
			t.Fatal("missing warning")
		}
	})
	t.Run("core10#verification-material.4 kid as the fragment identifier", func(t *testing.T) {
		if !findings(t, jwkMethod(t, "other", good), spec.V10)["core10#verification-material.4"] {
			t.Fatal("missing warning")
		}
		if f := findings(t, jwkMethod(t, thumb, good), spec.V10); len(f) != 0 {
			t.Fatalf("got %v", f)
		}
	})
	t.Run("cid10#JsonWebKey.6 kid is the SHA-256 JWK thumbprint", func(t *testing.T) {
		if !findings(t, jwkMethod(t, "key-1", otherKid), spec.V11)["cid10#JsonWebKey.6"] {
			t.Fatal("missing warning")
		}
	})
	t.Run("core10#verification-material.5 kid is the public key fingerprint", func(t *testing.T) {
		if !findings(t, jwkMethod(t, "key-1", otherKid), spec.V10)["core10#verification-material.5"] {
			t.Fatal("missing warning")
		}
	})
	t.Run("cid10#JsonWebKey.7 alg should be included", func(t *testing.T) {
		noAlg := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": thumb}
		if !findings(t, jwkMethod(t, thumb, noAlg), spec.V11)["cid10#JsonWebKey.7"] {
			t.Fatal("missing warning")
		}
	})
	t.Run("cid10#JsonWebKey.9 kid is part of the method id", func(t *testing.T) {
		if !findings(t, jwkMethod(t, "x", otherKid), spec.V11)["cid10#JsonWebKey.9"] {
			t.Fatal("missing warning")
		}
		if findings(t, jwkMethod(t, "key-1", otherKid), spec.V11)["cid10#JsonWebKey.9"] {
			t.Fatal("kid inside the id must not warn")
		}
	})
}
