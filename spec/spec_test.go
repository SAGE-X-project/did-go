package spec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestVersion(t *testing.T) {
	for _, c := range []struct {
		v Version
		s string
	}{{V10, "1.0"}, {V11, "1.1"}} {
		if c.v.String() != c.s {
			t.Errorf("%d.String() = %q", c.v, c.v.String())
		}
		got, err := ParseVersion(c.s)
		if err != nil || got != c.v {
			t.Errorf("ParseVersion(%q) = %v, %v", c.s, got, err)
		}
		if !c.v.IsSupported() {
			t.Errorf("%s not supported", c.v)
		}
	}
	if VUnknown.String() != "unknown" || VUnknown.IsSupported() {
		t.Error("VUnknown must be unknown and unsupported")
	}
	if _, err := ParseVersion("2.0"); err == nil {
		t.Error("ParseVersion(2.0): want error")
	}
	if Latest != V11 {
		t.Error("Latest must be V11")
	}
	s := Supported()
	s[0] = VUnknown
	if Supported()[0] != V10 {
		t.Error("Supported must return a fresh slice")
	}
}

func TestProfiles(t *testing.T) {
	p10, err := ProfileOf(V10)
	if err != nil {
		t.Fatal(err)
	}
	p11, err := ProfileOf(V11)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProfileOf(VUnknown); err == nil {
		t.Fatal("VUnknown must have no profile")
	}
	if p10.ContextURL != ContextURLV10 || p11.ContextURL != ContextURLV11 {
		t.Fatal("context URLs")
	}
	if !slices.Equal(p10.Produces(), []string{MediaTypeDIDJSON, MediaTypeDIDLDJSON}) {
		t.Fatalf("V10 produces %v", p10.Produces())
	}
	if !slices.Equal(p11.Accepts(), []string{MediaTypeDID}) {
		t.Fatalf("V11 accepts %v", p11.Accepts())
	}
	if !p10.ServiceIDRequired || p11.ServiceIDRequired || !p10.ServiceIDMustBeURI {
		t.Fatal("service.id rule: required in V10 only")
	}
	if p10.RelativeMethodIDs || !p11.RelativeMethodIDs || p10.MetadataNumbers || !p11.MetadataNumbers {
		t.Fatal("version rules")
	}
	if !p11.DefinesTerm("expires") || p10.DefinesTerm("expires") || !p10.DefinesTerm("service") {
		t.Fatal("DefinesTerm")
	}
	terms := p10.Terms()
	terms[0] = "x"
	if p10.Terms()[0] == "x" {
		t.Fatal("Terms must return a fresh slice")
	}
	if !slices.Equal(LowPrecisionMediaTypes(), []string{MediaTypeJSON, MediaTypeLDJSON}) {
		t.Fatal("low precision types")
	}
}

// contextTerms returns every term defined in a JSON-LD context, including
// terms of scoped contexts, without keywords.
func contextTerms(ctx map[string]any, into map[string]bool) {
	for k, v := range ctx {
		if strings.HasPrefix(k, "@") {
			continue
		}
		into[k] = true
		if def, ok := v.(map[string]any); ok {
			if scoped, ok := def["@context"].(map[string]any); ok {
				contextTerms(scoped, into)
			}
		}
	}
}

func TestTermsMatchPinnedContexts(t *testing.T) {
	cases := []struct {
		file, sha string
		v         Version
	}{
		{"testdata/did-v1.jsonld", "4f3eae5568c9c5f036a082088f9e192019ee06faa78973c87ff91d5421b88dad", V10},
		{"testdata/did-v1.1.jsonld", "ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85", V11},
	}
	for _, c := range cases {
		data, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != c.sha {
			t.Fatalf("%s: SHA-256 differs from docs/10 §3", c.file)
		}
		var doc struct {
			Context map[string]any `json:"@context"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		set := map[string]bool{}
		contextTerms(doc.Context, set)
		var want []string
		for k := range set {
			want = append(want, k)
		}
		sort.Strings(want)
		p, _ := ProfileOf(c.v)
		if !slices.Equal(p.Terms(), want) {
			t.Fatalf("%s terms:\n got %v\nwant %v", c.v, p.Terms(), want)
		}
	}
}

func TestKeys(t *testing.T) {
	if len(Keys()) != 6 {
		t.Fatal("six keys")
	}
	if !slices.Equal(ConformanceProfile(V11), []Key{KeyDID11, KeyCID10, KeyRes10}) {
		t.Fatal("V11 conformance profile")
	}
	if !slices.Equal(ConformanceProfile(V10), []Key{KeyCore10}) || ConformanceProfile(VUnknown) != nil {
		t.Fatal("V10 conformance profile")
	}
}

func TestTimestamp(t *testing.T) {
	t.Run("res10-crd20261001#datetime.2 written in UTC without sub-seconds", func(t *testing.T) {
		loc := time.FixedZone("x", 9*3600)
		got := FormatTimestamp(time.Date(2020, 12, 21, 4, 17, 47, 999, loc))
		if got != "2020-12-20T19:17:47Z" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("res10-crd20261001#datetime.2 parse rejects offsets and fractions", func(t *testing.T) {
		ok, err := ParseTimestamp("2020-12-20T19:17:47Z")
		if err != nil || !ok.Equal(time.Date(2020, 12, 20, 19, 17, 47, 0, time.UTC)) {
			t.Fatalf("got %v %v", ok, err)
		}
		for _, bad := range []string{"2020-12-20T19:17:47.5Z", "2020-12-20T19:17:47+00:00", "2020-12-20 19:17:47Z", "2020-13-20T19:17:47Z", ""} {
			if _, err := ParseTimestamp(bad); err == nil {
				t.Fatalf("%q: want error", bad)
			}
		}
	})
	if IsTimestamp(time.Time{}) || IsTimestamp(time.Unix(1, 5)) || !IsTimestamp(time.Unix(1, 0)) {
		t.Fatal("IsTimestamp")
	}
}
