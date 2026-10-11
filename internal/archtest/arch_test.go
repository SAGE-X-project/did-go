// Package archtest checks the import rules of docs/14 §2.
package archtest

import (
	"errors"
	"go/build"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const module = "github.com/sage-x-project/did-go"

type layer int

const (
	layerUnknown layer = iota
	layerVocabulary
	layerTypes
	layerTools
	layerPlayer
	layerWiring
	layerMeta
)

var layers = map[string]layer{
	"spec":                  layerVocabulary,
	"did":                   layerTypes,
	"vm":                    layerTypes,
	"document":              layerTypes,
	"representation":        layerTypes,
	"resolution":            layerTypes,
	"method":                layerTypes,
	"internal/multiformats": layerTypes,
	"internal/wire":         layerTools,
	"jsonld":                layerTools,
	"crypto":                layerTools,
	"producer":              layerPlayer,
	"consumer":              layerPlayer,
	"resolver":              layerPlayer,
	"dereferencer":          layerPlayer,
	"controller":            layerPlayer,
	"relyingparty":          layerPlayer,
	"resolution/compat":     layerPlayer,
	"resolution/universal":  layerPlayer,
	"resolution/cache":      layerPlayer,
	"method/key":            layerPlayer,
	"method/web":            layerPlayer,
	"didkit":                layerWiring,
	"conformance":           layerMeta,
	"internal/archtest":     layerMeta,
	"internal/testutil":     layerMeta,
	"internal/roundtrip":    layerMeta,
}

// allowed reports whether a package of layer from may import a package of
// layer to, following docs/14 §2.
func allowed(from, to layer) bool {
	switch from {
	case layerVocabulary:
		return false
	case layerTypes:
		return to == layerVocabulary || to == layerTypes
	case layerTools:
		return to == layerVocabulary || to == layerTypes || to == layerTools
	case layerPlayer:
		return to == layerVocabulary || to == layerTypes || to == layerTools
	case layerWiring:
		return to != layerMeta && to != layerWiring
	case layerMeta:
		return true
	}
	return false
}

func packages(t *testing.T) []string {
	t.Helper()
	var dirs []string
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if path != "../.." && (strings.HasPrefix(name, ".") || name == "testdata" || name == "docs" || name == "tools") {
			return filepath.SkipDir
		}
		matches, _ := filepath.Glob(filepath.Join(path, "*.go"))
		if len(matches) > 0 {
			rel, _ := filepath.Rel("../..", path)
			dirs = append(dirs, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(dirs)
	return dirs
}

func TestImportRules(t *testing.T) {
	for _, rel := range packages(t) {
		if strings.HasPrefix(rel, "advanced/") {
			continue
		}
		from, known := layers[rel]
		if !known {
			t.Errorf("package %s has no layer in docs/14; add it to the layer table", rel)
			continue
		}
		pkg, err := build.ImportDir(filepath.Join("../..", rel), 0)
		var noGo *build.NoGoError
		if errors.As(err, &noGo) {
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		for _, imp := range pkg.Imports {
			if !strings.Contains(imp, ".") {
				continue // standard library
			}
			if !strings.HasPrefix(imp, module+"/") {
				if from == layerVocabulary || from == layerTypes {
					t.Errorf("%s (layer %d) imports non-standard package %s", rel, from, imp)
				}
				continue
			}
			target := strings.TrimPrefix(imp, module+"/")
			if strings.HasPrefix(target, "advanced/") {
				t.Errorf("%s imports %s; the root module must not import advanced/", rel, imp)
				continue
			}
			to, ok := layers[target]
			if !ok {
				t.Errorf("%s imports %s, which has no layer", rel, target)
				continue
			}
			if !allowed(from, to) {
				t.Errorf("%s (layer %d) must not import %s (layer %d)", rel, from, target, to)
			}
		}
	}
}

func TestRulesRejectPlayerToPlayer(t *testing.T) {
	if allowed(layerPlayer, layerPlayer) {
		t.Fatal("players must not import players")
	}
	if allowed(layerTypes, layerTools) {
		t.Fatal("shared types must not import tools")
	}
	if !allowed(layerWiring, layerPlayer) {
		t.Fatal("didkit must be able to wire players")
	}
}
