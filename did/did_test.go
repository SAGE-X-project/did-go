package did

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/spec"
)

type syntaxVectors struct {
	Valid []struct {
		ID, Input, Method, Msid, String string
	} `json:"valid"`
	Invalid []struct {
		ID, Input   string
		Pos         int
		Restriction bool
	} `json:"invalid"`
}

func loadJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

func TestDIDSyntaxVectors(t *testing.T) {
	var v syntaxVectors
	loadJSON(t, "testdata/did-syntax.json", &v)
	for _, c := range v.Valid {
		t.Run(c.ID, func(t *testing.T) {
			d, err := Parse(c.Input)
			if err != nil {
				t.Fatalf("Parse(%q): %v", c.Input, err)
			}
			want := c.Input
			if c.String != "" {
				want = c.String
			}
			if d.Method() != c.Method || d.MSID() != c.Msid || d.String() != want {
				t.Fatalf("got %q %q %q", d.Method(), d.MSID(), d.String())
			}
			if !d.URL().IsDID() || d.URL().String() != want {
				t.Fatal("URL form")
			}
		})
	}
	for _, c := range v.Invalid {
		t.Run(c.ID, func(t *testing.T) {
			_, err := Parse(c.Input)
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Fatalf("Parse(%q) = %v, want *SyntaxError", c.Input, err)
			}
			if se.Pos != c.Pos {
				t.Fatalf("pos = %d, want %d (%s)", se.Pos, c.Pos, se.Msg)
			}
			if errors.Is(err, ErrIdentifierRestriction) != c.Restriction {
				t.Fatalf("restriction = %v, want %v", !c.Restriction, c.Restriction)
			}
			if se.Error() == "" {
				t.Fatal("empty message")
			}
		})
	}
}

type urlVectors struct {
	Valid []struct {
		ID, Input, DID, Path, Query, Fragment string
		HasQuery, HasFragment                 bool
	} `json:"valid"`
	Relative []struct {
		ID, Ref, Base, Want string
	} `json:"relative"`
	Invalid []struct {
		ID, Input string
		Pos       int
	} `json:"invalid"`
}

func TestDIDURLVectors(t *testing.T) {
	var v urlVectors
	loadJSON(t, "testdata/did-url.json", &v)
	for _, c := range v.Valid {
		t.Run(c.ID, func(t *testing.T) {
			u, err := ParseURL(c.Input)
			if err != nil {
				t.Fatalf("ParseURL(%q): %v", c.Input, err)
			}
			if u.DID().String() != c.DID || u.Path() != c.Path || u.Query() != c.Query ||
				u.Fragment() != c.Fragment || u.HasQuery() != c.HasQuery || u.HasFragment() != c.HasFragment {
				t.Fatalf("components: %q %q %q %q", u.DID(), u.Path(), u.Query(), u.Fragment())
			}
			if u.String() != c.Input || u.IsRelative() {
				t.Fatalf("String = %q", u.String())
			}
		})
	}
	for _, c := range v.Relative {
		t.Run(c.ID, func(t *testing.T) {
			base, err := Parse(c.Base)
			if err != nil {
				t.Fatal(err)
			}
			u, err := ParseRef(c.Ref, base)
			if err != nil || u.String() != c.Want {
				t.Fatalf("ParseRef = %q, %v; want %q", u, err, c.Want)
			}
		})
	}
	for _, c := range v.Invalid {
		t.Run(c.ID, func(t *testing.T) {
			_, err := ParseURL(c.Input)
			var se *SyntaxError
			if !errors.As(err, &se) || se.Pos != c.Pos {
				t.Fatalf("ParseURL(%q) = %v, want position %d", c.Input, err, c.Pos)
			}
		})
	}
}

func TestDIDURLSyntaxDetails(t *testing.T) {
	valid := []string{
		"did:example:123/a/b:c@d!$&'()*+,;=~",
		"did:example:123?",
		"did:example:123#",
		"did:example:123?a=b/c?d#e/f?g",
		"did:example:123/%41%7e",
	}
	invalid := []string{
		"did:example:123?q=é",
		"did:example:123/a b",
		"did:example:123/%4",
		"did:example:123?%zz",
		"did:example:123#%",
		"did:example:123@x",
		"did:example:123[",
	}
	t.Run("core10#did-url-syntax.1 path, query and fragment characters", func(t *testing.T) {
		for _, s := range valid {
			if _, err := ParseURL(s); err != nil {
				t.Errorf("%q: %v", s, err)
			}
		}
		for _, s := range invalid {
			if _, err := ParseURL(s); err == nil {
				t.Errorf("%q: want error", s)
			}
		}
	})
	t.Run("did11-cr20260305#did-url-syntax.1 the scheme is case-insensitive and written in lowercase", func(t *testing.T) {
		for _, s := range []string{"DID:example:123/p?q#f", "dId:example:123/p?q#f"} {
			u, err := ParseURL(s)
			if err != nil || u.String() != "did:example:123/p?q#f" {
				t.Fatalf("%q: %q %v", s, u, err)
			}
			r, err := ParseReference(s)
			if err != nil || r.IsRelative() {
				t.Fatalf("ParseReference(%q): %v", s, err)
			}
		}
		if _, err := ParseURL("DID:Example:123"); err == nil {
			t.Fatal("method names stay lowercase")
		}
	})
	t.Run("did11-cr20260305#did-url-syntax.1 empty query and fragment are kept", func(t *testing.T) {
		u, _ := ParseURL("did:example:123?#")
		if !u.HasQuery() || !u.HasFragment() || u.String() != "did:example:123?#" {
			t.Fatalf("got %q", u)
		}
		if u.WithoutFragment().String() != "did:example:123?" {
			t.Fatal("WithoutFragment")
		}
	})
	t.Run("length limit", func(t *testing.T) {
		long := "did:example:" + strings.Repeat("a", MaxLength)
		if _, err := Parse(long); err == nil {
			t.Fatal("Parse: want error")
		}
		if _, err := ParseURL(long); err == nil {
			t.Fatal("ParseURL: want error")
		}
		if _, err := ParseReference("#" + strings.Repeat("a", MaxLength)); err == nil {
			t.Fatal("ParseReference: want error")
		}
	})
	t.Run("core10#did-syntax.1 identifier restriction covers paths and queries", func(t *testing.T) {
		for _, s := range []string{"did:example:123/p", "did:example:123?q"} {
			if _, err := Parse(s); !errors.Is(err, ErrIdentifierRestriction) {
				t.Errorf("%q: %v", s, err)
			}
		}
		if _, err := Parse("did:example:123^"); err == nil || errors.Is(err, ErrIdentifierRestriction) {
			t.Error("invalid tail must be a plain syntax error")
		}
	})
}

func TestMethodNameAndZero(t *testing.T) {
	if !IsMethodName("web") || !IsMethodName("0x1") || IsMethodName("") || IsMethodName("Web") || IsMethodName("a-b") {
		t.Fatal("IsMethodName")
	}
	var d DID
	var u DIDURL
	if !d.IsZero() || d.String() != "" || !u.IsZero() || u.IsRelative() || u.IsDID() {
		t.Fatal("zero values")
	}
	if ErrIdentifierRestriction.Error() == "" {
		t.Fatal("message")
	}
}

func TestRelativeReferences(t *testing.T) {
	t.Run("core10#relative-did-urls.1 path, query and fragment references parse", func(t *testing.T) {
		for _, s := range []string{"#key-1", "?versionId=1", "path/sub", "/abs?x=1#y", "./a", "../b", "%41"} {
			u, err := ParseReference(s)
			if err != nil || !u.IsRelative() || u.String() != s {
				t.Errorf("%q: %v %q", s, err, u)
			}
		}
	})
	t.Run("did11-cr20260305#relative-did-urls.1 malformed references are rejected", func(t *testing.T) {
		for _, s := range []string{"", "//host/x", "a:b", "a b", "#a#b", "%4"} {
			if _, err := ParseReference(s); err == nil {
				t.Errorf("%q: want error", s)
			}
		}
	})
	base, err := ParseURL("did:example:123/a/b/c?q")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ ref, want string }{
		{"g", "did:example:123/a/b/g"},
		{"./g", "did:example:123/a/b/g"},
		{"g/", "did:example:123/a/b/g/"},
		{"?y", "did:example:123/a/b/c?y"},
		{"g?y", "did:example:123/a/b/g?y"},
		{"#s", "did:example:123/a/b/c?q#s"},
		{"g#s", "did:example:123/a/b/g#s"},
		{".", "did:example:123/a/b/"},
		{"..", "did:example:123/a/"},
		{"../g", "did:example:123/a/g"},
		{"../..", "did:example:123/"},
		{"../../g", "did:example:123/g"},
		{"g/./h/../i", "did:example:123/a/b/g/i"},
		{"did:other:1/x/../y#k", "did:other:1/y#k"},
		{"/g", "did:example:123/g"},
		{"../../../g", "did:example:123/g"},
	}
	t.Run("core10#relative-did-urls.2 RFC 3986 §5.4 examples on a DID URL base", func(t *testing.T) {
		for _, c := range cases {
			r, err := ParseReference(c.ref)
			if err != nil {
				t.Fatalf("%q: %v", c.ref, err)
			}
			got, err := r.Resolve(base)
			if err != nil || got.String() != c.want {
				t.Errorf("%q: got %q, %v; want %q", c.ref, got, err, c.want)
			}
		}
	})
	t.Run("did11-cr20260305#relative-did-urls.2 the DID is the authority of the base", func(t *testing.T) {
		d, _ := Parse("did:example:123")
		for ref, want := range map[string]string{"#key-1": "did:example:123#key-1", "g": "did:example:123/g", "?versionId=2": "did:example:123?versionId=2", "../x": "did:example:123/x"} {
			if u, err := ParseRef(ref, d); err != nil || u.String() != want {
				t.Errorf("ParseRef(%q) = %q, %v; want %q", ref, u, err, want)
			}
		}
		if _, err := ParseRef("a:b", d); err == nil {
			t.Fatal("bad reference: want error")
		}
	})
	t.Run("invalid bases", func(t *testing.T) {
		r, _ := ParseReference("#x")
		if _, err := r.Resolve(r); err == nil {
			t.Fatal("relative base: want error")
		}
		if _, err := (DIDURL{}).Resolve(base); err == nil {
			t.Fatal("zero reference: want error")
		}
	})
}

func TestParameters(t *testing.T) {
	t.Run("res10-crd20261001#did-parameters.1 values are decoded ASCII scalar strings", func(t *testing.T) {
		u, err := ParseURL("did:example:123?service=files&relativeRef=%2Fresume.pdf%3Fversion%3D2&versionId=4&hl=zQm&ext=a%20b")
		if err != nil {
			t.Fatal(err)
		}
		p, err := u.Parameters()
		if err != nil {
			t.Fatal(err)
		}
		if p.Service != "files" || p.RelativeRef != "/resume.pdf?version=2" || p.VersionID != "4" || p.HL != "zQm" {
			t.Fatalf("got %+v", p)
		}
		if v, ok := p.Get("ext"); !ok || v != "a b" {
			t.Fatalf("ext = %q %v", v, ok)
		}
		if _, ok := p.Get("missing"); ok {
			t.Fatal("missing parameter reported present")
		}
		if names := p.Names(); len(names) != 5 || names[0] != "service" {
			t.Fatalf("names %v", names)
		}
	})
	t.Run("core10#did-parameters.2 non-ASCII values are rejected", func(t *testing.T) {
		if _, err := ParseURL("did:example:123?service=ü"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("core10#did-parameters.3 characters that need percent-encoding are rejected", func(t *testing.T) {
		if _, err := ParseURL("did:example:123?relativeRef=/a b"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("res10-crd20261001#did-parameters.3 versionTime uses the datetime format", func(t *testing.T) {
		u, _ := ParseURL("did:example:123?versionTime=2021-05-10T17:00:00Z&serviceType=LinkedDomains")
		p, err := u.Parameters()
		if err != nil || !p.VersionTime.Equal(time.Date(2021, 5, 10, 17, 0, 0, 0, time.UTC)) || p.ServiceType != "LinkedDomains" {
			t.Fatalf("got %v %v", p.VersionTime, err)
		}
	})
	t.Run("core10#did-parameters.6 versionTime must be UTC without sub-second precision", func(t *testing.T) {
		for _, q := range []string{"versionTime=2021-05-10T17:00:00.5Z", "versionTime=2021-05-10T17:00:00%2B01:00", "versionTime=yesterday"} {
			u, _ := ParseURL("did:example:123?" + q)
			if _, err := u.Parameters(); err == nil {
				t.Errorf("%q: want error", q)
			}
		}
	})
	t.Run("malformed parameter lists", func(t *testing.T) {
		for _, q := range []string{"service", "=x", "service=a&service=b"} {
			u, _ := ParseURL("did:example:123?" + q)
			_, err := u.Parameters()
			var pe *ParameterError
			if !errors.As(err, &pe) || pe.Error() == "" {
				t.Errorf("%q: %v", q, err)
			}
		}
		u, _ := ParseURL("did:example:123")
		if p, err := u.Parameters(); err != nil || len(p.Names()) != 0 {
			t.Fatal("no query: no parameters")
		}
	})
	t.Run("datetime parser matches spec.ParseTimestamp", func(t *testing.T) {
		for _, s := range []string{"2021-05-10T17:00:00Z", "2021-05-10T17:00:00.1Z", "2021-02-30T17:00:00Z", "x"} {
			_, ok := parseTimestamp(s)
			_, err := spec.ParseTimestamp(s)
			if ok != (err == nil) {
				t.Errorf("%q: did %v, spec %v", s, ok, err)
			}
		}
	})
}
