package conformance

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// otherModule reports whether dir holds a go.mod of its own, such as the
// advanced/sage extension: its packages and tests belong to that module.
func otherModule(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "go.mod"))
	return err == nil
}

// packageDirs returns the module directories that hold Go files, skipping
// the same directories as references.
func packageDirs(t *testing.T) []string {
	t.Helper()
	set := map[string]bool{}
	err := filepath.WalkDir(moduleRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != moduleRoot && (strings.HasPrefix(name, ".") || name == "tools" || name == "docs" || name == "testdata" || otherModule(path)) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			rel, err := filepath.Rel(moduleRoot, filepath.Dir(path))
			if err != nil {
				return err
			}
			if rel != "." {
				set[filepath.ToSlash(rel)] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

func TestModulePackagesMatchTree(t *testing.T) {
	got := slices.Clone(modulePackages)
	slices.Sort(got)
	if want := packageDirs(t); !slices.Equal(got, want) {
		t.Fatalf("modulePackages drifted from the module tree:\n got %v\nwant %v", got, want)
	}
}

func TestProfiles(t *testing.T) {
	want := []string{ProfileDID11, ProfileDIDCore10, ProfileDIDKey, ProfileDIDWeb}
	slices.Sort(want)
	if got := Profiles(); !slices.Equal(got, want) {
		t.Fatalf("Profiles() = %v, want %v", got, want)
	}
}

func TestClaimsUnknownProfile(t *testing.T) {
	if ids, err := Claims("did-2.0"); err == nil || ids != nil {
		t.Fatalf("Claims(unknown) = %v, %v; want nil, error", ids, err)
	}
}

// TestClaimsFollowCoverageRule checks that each profile claims exactly the
// in-scope requirements of its specifications whose owners exist, the rule
// of TestInScopeRequirementsAreTested, and that every claim is referenced by
// a test or vector.
func TestClaimsFollowCoverageRule(t *testing.T) {
	reqs, err := Requirements()
	if err != nil {
		t.Fatal(err)
	}
	refs := references(t)
	for _, profile := range Profiles() {
		t.Run(profile, func(t *testing.T) {
			got, err := Claims(profile)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) == 0 {
				t.Fatal("no claims")
			}
			if !slices.IsSorted(got) {
				t.Error("claims are not sorted")
			}
			var want []string
			for _, r := range reqs {
				if r.Scope != InScope || !slices.Contains(profileSpecs[profile], r.Spec) {
					continue
				}
				enforced := true
				for _, o := range r.Owners {
					enforced = enforced && ownerExists(o)
				}
				if enforced {
					want = append(want, r.ID)
				}
			}
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("claims differ from the coverage rule: got %d ids, want %d", len(got), len(want))
			}
			for _, id := range got {
				if len(refs[id]) == 0 {
					t.Errorf("%s claimed but not referenced by any test", id)
				}
			}
		})
	}
}

func TestClaimedSkipsMissingOwners(t *testing.T) {
	reqs := []Requirement{
		{ID: "x#a.1", Spec: "x", Scope: InScope, Owners: []string{"did"}},
		{ID: "x#b.1", Spec: "x", Scope: InScope, Owners: []string{"did", "absent"}},
		{ID: "x#c.1", Spec: "x", Scope: OutOfScope, Owners: []string{"did"}},
		{ID: "x#d.1", Spec: "x", Scope: InScope},
		{ID: "y#e.1", Spec: "y", Scope: InScope, Owners: []string{"did"}},
	}
	got := claimed(reqs, []string{"x"}, []string{"did"})
	if want := []string{"x#a.1"}; !slices.Equal(got, want) {
		t.Fatalf("claimed = %v, want %v", got, want)
	}
}

func TestClaimsDecodeError(t *testing.T) {
	saved := load
	t.Cleanup(func() { load = saved })
	load = func() ([]Requirement, error) { return decode([]byte("{")) }
	if _, err := Claims(ProfileDIDKey); err == nil {
		t.Fatal("decode error not returned")
	}
}
