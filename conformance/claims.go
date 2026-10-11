package conformance

import (
	"fmt"
	"slices"
	"strings"
)

// Conformance profiles accepted by Claims (docs/14 §7.4).
const (
	// ProfileDIDCore10 covers DID Core 1.0 (registry key core10).
	ProfileDIDCore10 = "did-core-1.0"
	// ProfileDID11 covers DID 1.1 together with the specifications it
	// depends on: Controlled Identifiers 1.0 and DID Resolution v1.0.
	ProfileDID11 = "did-1.1"
	// ProfileDIDKey covers the pinned did:key method specification.
	ProfileDIDKey = "did-key"
	// ProfileDIDWeb covers the pinned did:web method specification.
	ProfileDIDWeb = "did-web"
)

// profileSpecs maps each profile to the registry keys of its specifications.
var profileSpecs = map[string][]string{
	ProfileDIDCore10: {"core10"},
	ProfileDID11:     {"did11-cr20260305", "cid10", "res10-crd20261001"},
	ProfileDIDKey:    {"didkey-2cc490c"},
	ProfileDIDWeb:    {"didweb-ea423c1"},
}

// modulePackages lists the package paths of this module that a requirement
// may name as an owner. claims_test.go checks the list against the module
// tree so that it cannot drift.
var modulePackages = []string{
	"conformance",
	"consumer",
	"controller",
	"crypto",
	"dereferencer",
	"did",
	"didkit",
	"document",
	"internal/archtest",
	"internal/multiformats",
	"internal/roundtrip",
	"internal/testutil",
	"internal/wire",
	"jsonld",
	"method",
	"method/key",
	"method/web",
	"producer",
	"relyingparty",
	"representation",
	"resolution",
	"resolution/cache",
	"resolution/compat",
	"resolution/universal",
	"resolver",
	"spec",
	"vm",
}

// Profiles returns the profile names Claims accepts, sorted.
func Profiles() []string {
	out := make([]string, 0, len(profileSpecs))
	for p := range profileSpecs {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// Claims returns, sorted, the ids of the in-scope requirements of a
// conformance profile whose owner packages all exist in this module. This is
// the rule conformance/coverage_test.go enforces: every id returned is named
// by at least one test or test vector. An unknown profile is an error.
func Claims(profile string) ([]string, error) {
	specs, ok := profileSpecs[profile]
	if !ok {
		return nil, fmt.Errorf("conformance: unknown profile %q (known: %s)", profile, strings.Join(Profiles(), ", "))
	}
	reqs, err := load()
	if err != nil {
		return nil, err
	}
	return claimed(reqs, specs, modulePackages), nil
}

// claimed selects the in-scope requirements of specs whose owners are all in
// packages.
func claimed(reqs []Requirement, specs, packages []string) []string {
	out := []string{}
	for _, r := range reqs {
		if r.Scope != InScope || !slices.Contains(specs, r.Spec) || !ownedBy(r.Owners, packages) {
			continue
		}
		out = append(out, r.ID)
	}
	slices.Sort(out)
	return out
}

// ownedBy reports whether every owner is one of packages. A requirement
// without owners is never claimed.
func ownedBy(owners, packages []string) bool {
	if len(owners) == 0 {
		return false
	}
	for _, o := range owners {
		if !slices.Contains(packages, o) {
			return false
		}
	}
	return true
}
