// Package jsonld is the JSON-LD tool of did-go (docs/14 §2): the embedded DID
// base contexts with their pinned SHA-256 digests, the representation-specific
// @context entry, and the term lookup that the producer and consumer use for
// the rules on undefined terms (DID Core 1.0 §6.3, DID 1.1 §6.2.3).
//
// did-go does not run the JSON-LD expansion or compaction algorithms and
// never retrieves a context over the network. The base contexts are treated
// as already retrieved (DID 1.1 §6.2.4); any other context URL is unknown to
// this package, which is why term lookup reports when it cannot decide.
package jsonld

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"

	"github.com/sage-x-project/did-go/spec"
)

// Pinned SHA-256 digests of the base contexts (docs/10 §3). The DID 1.1
// value is the one DID 1.1 §6.2.4 lists; the DID Core 1.0 value matches the
// file published at https://www.w3.org/ns/did/v1.
const (
	ContextSHA256V10 = "4f3eae5568c9c5f036a082088f9e192019ee06faa78973c87ff91d5421b88dad"
	ContextSHA256V11 = "ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85"
)

// CIDContextURL is the context of Controlled Identifiers v1.0 §4.2. did-go
// does not embed it and performs no JSON-LD processing that would resolve
// it, so it is an unknown context for term lookup.
const CIDContextURL = "https://www.w3.org/ns/cid/v1"

//go:embed contexts/did-v1.jsonld contexts/did-v1.1.jsonld
var contexts embed.FS

// contextFile returns the embedded file name and pinned digest for v.
func contextFile(v spec.Version) (string, string, error) {
	switch v {
	case spec.V10:
		return "contexts/did-v1.jsonld", ContextSHA256V10, nil
	case spec.V11:
		return "contexts/did-v1.1.jsonld", ContextSHA256V11, nil
	}
	return "", "", fmt.Errorf("jsonld: no base context for version %s", v)
}

// BaseContext returns the URL and the bytes of the base context of v. The
// bytes are a fresh copy, checked against the pinned SHA-256 on every call,
// so a build that embedded a different file fails instead of using it.
func BaseContext(v spec.Version) (string, []byte, error) {
	name, pin, err := contextFile(v)
	if err != nil {
		return "", nil, err
	}
	data, err := contexts.ReadFile(name)
	if err != nil {
		return "", nil, fmt.Errorf("jsonld: read %s: %w", name, err)
	}
	if err := verify(data, pin); err != nil {
		return "", nil, fmt.Errorf("jsonld: %s: %w", name, err)
	}
	p, _ := spec.ProfileOf(v)
	return p.ContextURL, data, nil
}

// verify compares the SHA-256 of data with a hexadecimal pin.
func verify(data []byte, pin string) error {
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != pin {
		return fmt.Errorf("SHA-256 %s differs from the pinned %s", got, pin)
	}
	return nil
}

// VersionOfContext returns the version whose base context URL is url.
func VersionOfContext(url string) (spec.Version, bool) {
	for _, v := range spec.Supported() {
		if p, _ := spec.ProfileOf(v); p.ContextURL == url {
			return v, true
		}
	}
	return spec.VUnknown, false
}
