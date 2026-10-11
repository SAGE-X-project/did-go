package didkit_test

import (
	"go/build"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/sage-x-project/did-go"

// deps returns every package the non-test files of the given root packages
// import, directly or transitively, as `go list -deps` would list them.
// Packages of this module are read from the source tree; others from
// GOROOT.
func deps(t *testing.T, roots ...string) map[string]bool {
	t.Helper()
	type item struct{ path, from string }
	seen := map[string]bool{}
	var queue []item
	for _, r := range roots {
		queue = append(queue, item{path: r})
	}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if seen[it.path] || it.path == "C" || it.path == "unsafe" {
			continue
		}
		seen[it.path] = true
		var (
			pkg *build.Package
			err error
		)
		if rel, ok := strings.CutPrefix(it.path, module+"/"); ok {
			pkg, err = build.ImportDir(filepath.Join("..", filepath.FromSlash(rel)), 0)
		} else {
			// The importer's directory lets GOROOT vendored packages resolve.
			pkg, err = build.Import(it.path, it.from, 0)
		}
		if err != nil {
			t.Fatalf("%s: %v", it.path, err)
		}
		dir := pkg.Dir
		if !pkg.Goroot {
			dir = ""
		}
		for _, imp := range pkg.Imports {
			queue = append(queue, item{path: imp, from: dir})
		}
	}
	return seen
}

// A program that resolves only did:key links didkit and method/key; neither
// may pull in net/http or a driver it did not ask for (docs/14 §1 goal 1,
// §6).
func TestDIDKeyUsersDoNotLinkNetHTTP(t *testing.T) {
	all := deps(t, module+"/didkit", module+"/method/key")
	for _, want := range []string{module + "/resolver", module + "/dereferencer", module + "/resolution/cache", "context"} {
		if !all[want] {
			t.Fatalf("the dependency walk missed %s", want)
		}
	}
	for _, banned := range []string{"net/http", "crypto/tls", module + "/method/web", module + "/resolution/universal", module + "/resolution/compat"} {
		if all[banned] {
			t.Errorf("didkit with method/key depends on %s", banned)
		}
	}
}

// The walk itself must see net/http where it is imported, or the test above
// proves nothing.
func TestDependencyWalkFindsNetHTTP(t *testing.T) {
	if !deps(t, module+"/method/web")["net/http"] {
		t.Fatal("method/web depends on net/http but the walk did not find it")
	}
}
