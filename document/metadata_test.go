package document

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/spec"
)

func marshal(t *testing.T, m Metadata) map[string]any {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func unmarshal(t *testing.T, s string) (Metadata, error) {
	t.Helper()
	var m Metadata
	err := json.Unmarshal([]byte(s), &m)
	return m, err
}

func TestMetadataDatetimes(t *testing.T) {
	loc := time.FixedZone("KST", 9*3600)
	ts := time.Date(2020, 12, 21, 4, 17, 47, 123, loc)
	whole := time.Date(2020, 12, 20, 19, 17, 47, 0, time.UTC)
	sub := whole.Add(time.Millisecond)
	subject := mustDID(t, "did:example:1")
	for _, c := range []struct {
		name, json string
		set        func(*Metadata, *time.Time)
	}{
		{"core10#did-document-metadata.3 created is a UTC XML datetime without sub-seconds", "created", func(m *Metadata, t *time.Time) { m.Created = t }},
		{"res10-crd20261001#did-document-metadata.3 created uses the datetime format", "created", func(m *Metadata, t *time.Time) { m.Created = t }},
		{"core10#did-document-metadata.5 updated follows the created format", "updated", func(m *Metadata, t *time.Time) { m.Updated = t }},
		{"res10-crd20261001#did-document-metadata.5 updated uses the datetime format", "updated", func(m *Metadata, t *time.Time) { m.Updated = t }},
		{"core10#did-document-metadata.9 nextUpdate follows the created format", "nextUpdate", func(m *Metadata, t *time.Time) { m.NextUpdate = t }},
		{"res10-crd20261001#did-document-metadata.9 nextUpdate uses the datetime format", "nextUpdate", func(m *Metadata, t *time.Time) { m.NextUpdate = t }},
	} {
		t.Run(c.name, func(t *testing.T) {
			var m Metadata
			c.set(&m, &ts)
			if got := marshal(t, m)[c.json]; got != "2020-12-20T19:17:47Z" {
				t.Fatalf("encoded %v", got)
			}
			c.set(&m, &whole)
			if err := m.Check(subject, spec.V11); err != nil {
				t.Fatal(err)
			}
			c.set(&m, &sub)
			if m.Check(subject, spec.V11) == nil {
				t.Fatal("sub-second precision accepted by Check")
			}
			for _, bad := range []string{`"2020-12-20T19:17:47.1Z"`, `"2020-12-20T19:17:47+09:00"`, `1608491867`} {
				if _, err := unmarshal(t, `{"`+c.json+`":`+bad+`}`); err == nil {
					t.Fatalf("decoded %s", bad)
				}
			}
			got, err := unmarshal(t, `{"`+c.json+`":"2020-12-20T19:17:47Z"}`)
			if err != nil || !marshalEq(t, got, `{"`+c.json+`":"2020-12-20T19:17:47Z"}`) {
				t.Fatalf("round trip: %v", err)
			}
		})
	}
	t.Run("res10-crd20261001#datetime.1 datetimes are ASCII XML datetime strings", func(t *testing.T) {
		m := Metadata{Created: &ts}
		s := marshal(t, m)["created"].(string)
		if !isASCII(s) {
			t.Fatal("not ASCII")
		}
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			t.Fatalf("not an XML datetime: %v", err)
		}
	})
	t.Run("res10-crd20261001#datetime.2 adjusted to UTC without sub-second precision", func(t *testing.T) {
		if got := marshal(t, Metadata{Updated: &ts})["updated"]; got != "2020-12-20T19:17:47Z" {
			t.Fatalf("got %v", got)
		}
	})
}

func marshalEq(t *testing.T, m Metadata, want string) bool {
	t.Helper()
	b, err := json.Marshal(m)
	return err == nil && string(b) == want
}

func TestMetadataDeactivated(t *testing.T) {
	t.Run("core10#did-document-metadata.6 a deactivated DID has deactivated true", func(t *testing.T) {
		if got := marshal(t, Metadata{Deactivated: true})["deactivated"]; got != true {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("res10-crd20261001#did-document-metadata.6 deactivated is the boolean true", func(t *testing.T) {
		m, err := unmarshal(t, `{"deactivated":true}`)
		if err != nil || !m.Deactivated {
			t.Fatal(err)
		}
		if _, err := unmarshal(t, `{"deactivated":"true"}`); err == nil {
			t.Fatal("string deactivated accepted")
		}
	})
	t.Run("core10#did-document-metadata.7 otherwise optional, and false if included", func(t *testing.T) {
		if _, ok := marshal(t, Metadata{})["deactivated"]; ok {
			t.Fatal("false is omitted")
		}
		m, err := unmarshal(t, `{"deactivated":false}`)
		if err != nil || m.Deactivated {
			t.Fatal(err)
		}
	})
	t.Run("res10-crd20261001#did-document-metadata.7 a non-boolean deactivated cannot hide in Extra", func(t *testing.T) {
		m := Metadata{Extra: map[string]any{"deactivated": "no"}}
		if m.Check(mustDID(t, "did:example:1"), spec.V11) == nil {
			t.Fatal("Extra deactivated accepted")
		}
		if _, err := json.Marshal(m); err == nil {
			t.Fatal("Extra deactivated encoded")
		}
	})
}

func TestMetadataVersionsAndIDs(t *testing.T) {
	subject := mustDID(t, "did:example:1")
	check := func(m Metadata) error { return m.Check(subject, spec.V11) }
	t.Run("core10#did-document-metadata.8 nextUpdate may be included", func(t *testing.T) {
		ts := time.Unix(1700000000, 0)
		if err := check(Metadata{NextUpdate: &ts}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("res10-crd20261001#did-document-metadata.8 nextUpdate may be included", func(t *testing.T) {
		if _, ok := marshal(t, Metadata{NextUpdate: &time.Time{}})["nextUpdate"]; !ok {
			t.Fatal("nextUpdate not encoded")
		}
	})
	for _, name := range []string{
		"core10#did-document-metadata.11 versionId is ASCII", "res10-crd20261001#did-document-metadata.11 versionId is ASCII",
		"core10#did-document-metadata.13 nextVersionId is ASCII", "res10-crd20261001#did-document-metadata.13 nextVersionId is ASCII",
	} {
		t.Run(name, func(t *testing.T) {
			if err := check(Metadata{VersionID: "4", NextVersionID: "5"}); err != nil {
				t.Fatal(err)
			}
			bad := Metadata{VersionID: "v-ü"}
			if strings.Contains(name, "nextVersionId") {
				bad = Metadata{NextVersionID: "v-ü"}
			}
			if check(bad) == nil {
				t.Fatal("non-ASCII accepted")
			}
		})
	}
	t.Run("core10#did-document-metadata.12 nextVersionId may be included", func(t *testing.T) {
		if marshal(t, Metadata{NextVersionID: "5"})["nextVersionId"] != "5" {
			t.Fatal("nextVersionId not encoded")
		}
	})
	t.Run("res10-crd20261001#did-document-metadata.12 nextVersionId may be included", func(t *testing.T) {
		m, err := unmarshal(t, `{"versionId":"4","nextVersionId":"5"}`)
		if err != nil || m.NextVersionID != "5" || m.VersionID != "4" {
			t.Fatal(err)
		}
	})
	equivalent := []struct{ name, kind string }{
		{"core10#did-document-metadata.14 equivalentId may be included", "may"},
		{"res10-crd20261001#did-document-metadata.14 equivalentId may be included", "may"},
		{"core10#did-document-metadata.15 equivalentId is a set of DIDs", "syntax"},
		{"res10-crd20261001#did-document-metadata.15 equivalentId is a set of DIDs", "syntax"},
		{"core10#did-document-metadata.16 equivalentId DIDs share the subject's method", "method"},
		{"res10-crd20261001#did-document-metadata.16 equivalentId DIDs share the subject's method", "method"},
	}
	for _, c := range equivalent {
		t.Run(c.name, func(t *testing.T) {
			ok := Metadata{EquivalentID: []string{"did:example:2", "did:example:3"}}
			if err := check(ok); err != nil {
				t.Fatal(err)
			}
			got, err := unmarshal(t, `{"equivalentId":["did:example:2"]}`)
			if err != nil || len(got.EquivalentID) != 1 {
				t.Fatal(err)
			}
			bad := map[string][]string{"may": {"did:example:2#x"}, "syntax": {"https://example.com"}, "method": {"did:other:2"}}[c.kind]
			if check(Metadata{EquivalentID: bad}) == nil {
				t.Fatalf("%v accepted", bad)
			}
		})
	}
	canonical := []struct{ name, bad string }{
		{"core10#did-document-metadata.19 canonicalId may be included", "did:example:2?x"},
		{"res10-crd20261001#did-document-metadata.19 canonicalId may be included", "did:example:2?x"},
		{"core10#did-document-metadata.20 canonicalId is a DID", "urn:x:y"},
		{"res10-crd20261001#did-document-metadata.20 canonicalId is a DID", "urn:x:y"},
		{"core10#did-document-metadata.21 canonicalId shares the subject's method", "did:other:2"},
		{"res10-crd20261001#did-document-metadata.21 canonicalId shares the subject's method", "did:other:2"},
	}
	for _, c := range canonical {
		t.Run(c.name, func(t *testing.T) {
			if err := check(Metadata{CanonicalID: "did:example:2"}); err != nil {
				t.Fatal(err)
			}
			if marshal(t, Metadata{CanonicalID: "did:example:2"})["canonicalId"] != "did:example:2" {
				t.Fatal("canonicalId not encoded")
			}
			if check(Metadata{CanonicalID: c.bad}) == nil {
				t.Fatalf("%s accepted", c.bad)
			}
		})
	}
	t.Run("res10-crd20261001#did-document-metadata.23 proof may be included", func(t *testing.T) {
		m, err := unmarshal(t, `{"proof":[{"type":"DataIntegrityProof","created":1}]}`)
		if err != nil || len(m.Proof) != 1 || m.Proof[0]["created"] != json.Number("1") {
			t.Fatalf("got %+v %v", m.Proof, err)
		}
		if err := check(m); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("res10-crd20261001#did-document-metadata.24 proof is a set of maps", func(t *testing.T) {
		if _, err := unmarshal(t, `{"proof":{"type":"x"}}`); err == nil {
			t.Fatal("single proof object accepted")
		}
		if check(Metadata{Proof: []map[string]any{nil}}) == nil {
			t.Fatal("nil proof accepted")
		}
		if check(Metadata{Proof: []map[string]any{{"x": func() {}}}}) == nil {
			t.Fatal("invalid proof value accepted")
		}
		if got := marshal(t, Metadata{Proof: []map[string]any{{"type": "x"}}})["proof"]; got == nil {
			t.Fatal("proof not encoded")
		}
	})
}

func TestMetadataStructure(t *testing.T) {
	m := map[string]any{"s": "x", "b": true, "n": nil, "l": []any{"a", map[string]any{"k": false}}}
	if err := CheckMetadataMap(m, spec.V10); err != nil {
		t.Fatal(err)
	}
	for _, num := range []any{1, int64(2), 1.5, float32(2), json.Number("3"), uint(4)} {
		withNum := map[string]any{"x": []any{num}}
		if err := CheckMetadataMap(withNum, spec.V11); err != nil {
			t.Errorf("%T: %v", num, err)
		}
		if CheckMetadataMap(withNum, spec.V10) == nil {
			t.Errorf("%T accepted under DID Core 1.0", num)
		}
	}
	deep := any("x")
	for i := 0; i < 70; i++ {
		deep = []any{deep}
	}
	for _, bad := range []any{math.NaN(), float32(math.Inf(1)), "\xff", struct{}{}, deep, map[string]any{"a": time.Now()}} {
		if CheckMetadataMap(map[string]any{"x": bad}, spec.V11) == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestMetadataJSON(t *testing.T) {
	ts := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	m := Metadata{
		Created: &ts, Updated: &ts, NextUpdate: &ts, Deactivated: true, VersionID: "1", NextVersionID: "2",
		EquivalentID: []string{"did:example:2"}, CanonicalID: "did:example:3",
		Proof: []map[string]any{{"type": "x"}}, Extra: map[string]any{"contentType": "text/uri-list", "n": json.Number("5")},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back Metadata
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(back)
	if string(again) != string(b) {
		t.Fatalf("round trip:\n%s\n%s", b, again)
	}
	c := m.Clone()
	*c.Created = time.Unix(0, 0)
	c.Extra["contentType"] = "x"
	c.Proof[0]["type"] = "y"
	c.EquivalentID[0] = "z"
	if !m.Created.Equal(ts) || m.Extra["contentType"] != "text/uri-list" || m.Proof[0]["type"] != "x" || m.EquivalentID[0] != "did:example:2" {
		t.Fatal("Clone shares memory")
	}
	if m.IsEmpty() || !(Metadata{}).IsEmpty() || !marshalEq(t, Metadata{}, "{}") {
		t.Fatal("IsEmpty or empty encoding")
	}
	if (Metadata{}).Clone().Proof != nil {
		t.Fatal("nil proof must stay nil")
	}
	for _, bad := range []string{`[]`, `null`, `{"versionId":1}`, `{"x":}`, `{"equivalentId":"did:example:1"}`, `{"x":[1,}`} {
		if _, err := unmarshal(t, bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, err := json.Marshal(Metadata{Extra: map[string]any{"x": func() {}}}); err == nil {
		t.Fatal("non-JSON Extra encoded")
	}
}
