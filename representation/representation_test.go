package representation

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/sage-x-project/did-go/spec"
)

type detectionVector struct {
	ID                string  `json:"id"`
	MediaType         string  `json:"mediaType"`
	Context           *string `json:"context"`
	Version           string  `json:"version"`
	JSONLD            bool    `json:"jsonld"`
	Assumed           bool    `json:"assumed"`
	UnexpectedContext string  `json:"unexpectedContext"`
	ErrorStep         int     `json:"errorStep"`
	StrictErrorStep   int     `json:"strictErrorStep"`
	LowPrecision      *struct {
		Declared, Detected string
	} `json:"lowPrecision"`
}

func (v detectionVector) ctx() Context {
	if v.Context == nil {
		return Context{}
	}
	return Context{Present: true, First: *v.Context}
}

func wantStep(t *testing.T, err error, step int) {
	t.Helper()
	var de *DetectError
	if !errors.As(err, &de) || de.Step != step || de.Error() == "" {
		t.Fatalf("got %v, want detection error at step %d", err, step)
	}
}

func TestDetectionVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/detection.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []detectionVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	for _, v := range file.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			info, err := Detect(v.MediaType, v.ctx(), ConsumeOptions{})
			if v.ErrorStep != 0 {
				wantStep(t, err, v.ErrorStep)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if info.DetectedVersion.String() != v.Version || info.IsJSONLD != v.JSONLD || info.Assumed != v.Assumed ||
				info.UnexpectedContext != v.UnexpectedContext {
				t.Fatalf("got %+v", info)
			}
			if (info.LowPrecision == nil) != (v.LowPrecision == nil) {
				t.Fatalf("LowPrecision = %+v", info.LowPrecision)
			}
			if lp := info.LowPrecision; lp != nil && (lp.Declared != v.LowPrecision.Declared || lp.Detected != v.LowPrecision.Detected) {
				t.Fatalf("LowPrecision = %+v", lp)
			}
			if lp := info.LowPrecision; lp == nil && MediaTypeOf(info) != v.MediaType {
				t.Fatalf("MediaTypeOf = %s, want the declared type", MediaTypeOf(info))
			}
			_, err = Detect(v.MediaType, v.ctx(), ConsumeOptions{Strict: true})
			if v.StrictErrorStep != 0 {
				wantStep(t, err, v.StrictErrorStep)
			} else if err != nil {
				t.Fatalf("strict: %v", err)
			}
		})
	}
}

func TestDetectionDetails(t *testing.T) {
	v1 := Context{Present: true, First: spec.ContextURLV10}
	v11 := Context{Present: true, First: spec.ContextURLV11}
	t.Run("Expected decides low-precision input without @context", func(t *testing.T) {
		info, err := Detect("application/json", Context{}, ConsumeOptions{Expected: spec.V10})
		if err != nil || info.DetectedVersion != spec.V10 || !info.Assumed || info.LowPrecision.Detected != spec.MediaTypeDIDJSON {
			t.Fatalf("got %+v %v", info, err)
		}
		_, err = Detect("application/json", Context{}, ConsumeOptions{Expected: spec.Version(9)})
		wantStep(t, err, 4)
	})
	t.Run("Require rejects other versions", func(t *testing.T) {
		if _, err := Detect("application/did+json", Context{}, ConsumeOptions{Require: spec.V10}); err != nil {
			t.Fatal(err)
		}
		_, err := Detect("application/did", v11, ConsumeOptions{Require: spec.V10})
		wantStep(t, err, 6)
		_, err = Detect("application/json", Context{}, ConsumeOptions{Require: spec.V11})
		wantStep(t, err, 6)
	})
	t.Run("a low-precision @context that is not a DID context is an error", func(t *testing.T) {
		_, err := Detect("application/ld+json", Context{Present: true, First: "https://www.w3.org/ns/cid/v1"}, ConsumeOptions{})
		wantStep(t, err, 5)
	})
	t.Run("did+json records a non-string first @context", func(t *testing.T) {
		info, err := Detect("application/did+json", Context{Present: true}, ConsumeOptions{})
		if err != nil || info.UnexpectedContext != nonStringContext {
			t.Fatalf("got %+v %v", info, err)
		}
		info, err = Detect("application/did+json", v1, ConsumeOptions{Strict: true})
		if err != nil || info.UnexpectedContext != "" {
			t.Fatal("the v1 context is expected")
		}
	})
	t.Run("media type parameters and case are ignored; malformed types are errors", func(t *testing.T) {
		info, err := Detect("Application/DID; charset=utf-8", v11, ConsumeOptions{})
		if err != nil || info.DetectedVersion != spec.V11 {
			t.Fatalf("got %+v %v", info, err)
		}
		_, err = Detect("application/did;;", v11, ConsumeOptions{})
		wantStep(t, err, 5)
		_, err = Detect("application/did", Context{Present: true}, ConsumeOptions{})
		wantStep(t, err, 3)
	})
}

func TestMediaTypes(t *testing.T) {
	if !IsDIDMediaType(spec.MediaTypeDIDJSON) || IsDIDMediaType(spec.MediaTypeJSON) || !IsLowPrecision(spec.MediaTypeLDJSON) || IsLowPrecision(spec.MediaTypeDID) {
		t.Fatal("classification")
	}
	if v, ok := VersionOf(spec.MediaTypeDIDLDJSON); !ok || v != spec.V10 {
		t.Fatal("VersionOf")
	}
	if MediaTypeFor(spec.VUnknown, false) != spec.MediaTypeDID || MediaTypeFor(spec.V10, true) != spec.MediaTypeDIDLDJSON {
		t.Fatal("MediaTypeFor")
	}
	c := CoreMediaTypes()
	c[0] = "x"
	if !slices.Equal(CoreMediaTypes(), []string{spec.MediaTypeDID, spec.MediaTypeDIDLDJSON, spec.MediaTypeDIDJSON}) {
		t.Fatal("CoreMediaTypes must be fresh")
	}
	for mt, want := range map[string]ProduceOptions{
		spec.MediaTypeDID:       {Version: spec.V11, JSONLD: true},
		spec.MediaTypeDIDLDJSON: {Version: spec.V10, JSONLD: true},
		spec.MediaTypeDIDJSON:   {Version: spec.V10},
	} {
		got, err := OptionsFor(mt)
		if err != nil || got != want {
			t.Errorf("%s: %+v %v", mt, got, err)
		}
		if MediaTypeFor(got.Version, got.JSONLD) != mt {
			t.Errorf("%s does not round trip", mt)
		}
	}
	for _, bad := range []string{"application/json", "", "a/b;;"} {
		if _, err := OptionsFor(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
