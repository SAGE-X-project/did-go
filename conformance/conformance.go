// Package conformance publishes the requirement registry of did-go: every
// normative statement of the pinned specifications, its scope and the
// packages that own it (docs/14 §7).
//
// An inspector must not use this registry as its oracle. It is published so
// that an inspector can compare its own extraction with what did-go claims.
package conformance

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

//go:embed requirements.json
var registryJSON []byte

// Scope values of a Requirement.
const (
	InScope    = "in-scope"
	OutOfScope = "out-of-scope"
)

// Requirement is one normative statement of a pinned specification.
type Requirement struct {
	ID            string   `json:"id"`
	Spec          string   `json:"spec"`
	Section       string   `json:"section"`
	Term          string   `json:"term"`
	Text          string   `json:"text"`
	TextSHA256    string   `json:"textSHA256"`
	AlgorithmStep bool     `json:"algorithmStep"`
	Parent        *string  `json:"parent"`
	Scope         string   `json:"scope"`
	Reason        string   `json:"reason"`
	Owners        []string `json:"owners"`
}

type registry struct {
	Requirements []Requirement `json:"requirements"`
}

var load = sync.OnceValues(func() ([]Requirement, error) { return decode(registryJSON) })

// decode parses a registry file.
func decode(data []byte) ([]Requirement, error) {
	var r registry
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("conformance: decode registry: %w", err)
	}
	return r.Requirements, nil
}

// Requirements returns a fresh copy of the registry.
func Requirements() ([]Requirement, error) {
	reqs, err := load()
	if err != nil {
		return nil, err
	}
	out := make([]Requirement, len(reqs))
	for i, r := range reqs {
		r.Owners = append([]string(nil), r.Owners...)
		if r.Parent != nil {
			p := *r.Parent
			r.Parent = &p
		}
		out[i] = r
	}
	return out, nil
}
