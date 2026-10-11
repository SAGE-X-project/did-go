package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// idPattern matches a requirement id at the start of a string literal.
var idPattern = regexp.MustCompile(`^((?:core10|did11-cr20260305|cid10|res10-crd20261001|didkey-2cc490c|didweb-ea423c1)#[A-Za-z0-9._-]+)`)

const moduleRoot = ".."

// references collects every requirement id named in a Go test string literal
// or in the "statements" array of a JSON vector file under a testdata
// directory, together with where it was found.
func references(t *testing.T) map[string][]string {
	t.Helper()
	refs := map[string][]string{}
	add := func(id, where string) { refs[id] = append(refs[id], where) }
	err := filepath.WalkDir(moduleRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			// Hidden directories (.git, editor and agent worktrees) are not
			// part of the module, as in internal/archtest.
			if path != moduleRoot && (strings.HasPrefix(name, ".") || name == "tools" || name == "docs") {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(path, "_test.go"):
			return collectGo(path, add)
		case strings.HasSuffix(path, ".json") && strings.Contains(filepath.ToSlash(path), "/testdata/"):
			return collectVector(path, add)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	return refs
}

func collectGo(path string, add func(string, string)) error {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return err
	}
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if m := idPattern.FindStringSubmatch(s); m != nil {
			add(m[1], path)
		}
		return true
	})
	return nil
}

func collectVector(path string, add func(string, string)) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var anyJSON any
	if err := json.Unmarshal(data, &anyJSON); err != nil {
		return err
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if list, ok := x["statements"].([]any); ok {
				for _, item := range list {
					if s, ok := item.(string); ok {
						add(s, path)
					}
				}
			}
			for _, child := range x {
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(anyJSON)
	return nil
}

func ownerExists(owner string) bool {
	info, err := os.Stat(filepath.Join(moduleRoot, filepath.FromSlash(owner)))
	return err == nil && info.IsDir()
}

func TestRegistryIntegrity(t *testing.T) {
	reqs, err := Requirements()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range reqs {
		if seen[r.ID] {
			t.Errorf("duplicate requirement id %s", r.ID)
		}
		seen[r.ID] = true
		sum := sha256.Sum256([]byte(r.Text))
		if hex.EncodeToString(sum[:]) != r.TextSHA256 {
			t.Errorf("%s: textSHA256 does not match its text", r.ID)
		}
		if r.Scope == InScope && len(r.Owners) == 0 {
			t.Errorf("%s: in-scope requirement without owner", r.ID)
		}
		if r.Scope != InScope && r.Scope != OutOfScope {
			t.Errorf("%s: unknown scope %q", r.ID, r.Scope)
		}
	}
}

func TestEveryReferenceExists(t *testing.T) {
	reqs, err := Requirements()
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, r := range reqs {
		known[r.ID] = true
	}
	for id, where := range references(t) {
		if !known[id] {
			t.Errorf("unknown requirement id %s referenced in %v", id, where)
		}
	}
}

// TestInScopeRequirementsAreTested enforces docs/14 §7.2: an in-scope
// requirement must be named by a test or vector once every package that owns
// it exists.
func TestInScopeRequirementsAreTested(t *testing.T) {
	reqs, err := Requirements()
	if err != nil {
		t.Fatal(err)
	}
	refs := references(t)
	var missing []string
	for _, r := range reqs {
		if r.Scope != InScope {
			continue
		}
		enforced := true
		for _, o := range r.Owners {
			if !ownerExists(o) {
				enforced = false
				break
			}
		}
		if enforced && len(refs[r.ID]) == 0 {
			missing = append(missing, r.ID+" ("+strings.Join(r.Owners, ",")+")")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("in-scope requirement without a test: %s", m)
	}
}
