package resolution

import (
	"context"
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/spec"
)

func TestParseAccept(t *testing.T) {
	rs, err := ParseAccept(`application/did;q=0.9, application/did+ld+json; profile="a,b" , */*;q=0, text/*;q=1.000,,`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 4 || rs[0].Weight != 900 || rs[1].Params[0].Value != `"a,b"` || rs[2].Weight != 0 || rs[3].Weight != 1000 {
		t.Fatalf("got %+v", rs)
	}
	if !rs[2].Matches("application/did") || !rs[3].Matches("Text/Plain; charset=x") || rs[0].Matches("application/json") || rs[0].Matches("nonsense") {
		t.Fatal("Matches")
	}
	if rs, err := ParseAccept(""); err != nil || len(rs) != 0 {
		t.Fatal("empty Accept is an empty list")
	}
	bad := []string{"application", "*/did", "app lication/did", "a/b;q=2", "a/b;q=0.1234", "a/b;q=1.1", "a/b;q=x", "a/b;q", "a/b;q=0.5;x=y",
		`a/b;x="unterminated`, `a/b;x="a"b"`, "a/b;x=\"\x01\"", "a/ü", `a/b;x="\`, "a/b;x=", "a/b;q=01"}
	for _, s := range bad {
		if _, err := ParseAccept(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if _, err := ParseAccept(`a/b;x="q\"uoted\\"`); err != nil {
		t.Fatal(err)
	}
}

func TestResolutionOptions(t *testing.T) {
	ts := time.Date(2021, 5, 10, 17, 0, 0, 0, time.UTC)
	t.Run("core10#did-resolution-options.1 the media type is an ASCII string", func(t *testing.T) {
		if (ResolutionOptions{Accept: "application/did"}).Validate() != nil {
			t.Fatal("valid accept rejected")
		}
		if e := (ResolutionOptions{Accept: "application/dïd"}).Validate(); e == nil || e.Code() != CodeInvalidOptions {
			t.Fatal("non-ASCII accept accepted")
		}
	})
	t.Run("res10-crd20261001#did-resolution-options.2 accept is an RFC 9110 Accept value", func(t *testing.T) {
		if (ResolutionOptions{Accept: "application/did+ld+json;q=0.5, application/did"}).Validate() != nil {
			t.Fatal("valid accept rejected")
		}
		if (ResolutionOptions{Accept: "did please"}).Validate() == nil {
			t.Fatal("malformed accept accepted")
		}
	})
	t.Run("res10-crd20261001#did-resolution-options.4 accept is optional", func(t *testing.T) {
		if (ResolutionOptions{}).Validate() != nil {
			t.Fatal("empty options rejected")
		}
		b, _ := json.Marshal(ResolutionOptions{})
		if string(b) != "{}" {
			t.Fatalf("got %s", b)
		}
	})
	t.Run("versionTime must be UTC without sub-seconds, checked and not corrected", func(t *testing.T) {
		if (ResolutionOptions{VersionTime: &ts}).Validate() != nil {
			t.Fatal("valid versionTime rejected")
		}
		sub := ts.Add(time.Millisecond)
		off := ts.In(time.FixedZone("x", 3600))
		zero := time.Time{}
		for _, bad := range []*time.Time{&sub, &off, &zero} {
			if (ResolutionOptions{VersionTime: bad}).Validate() == nil {
				t.Errorf("%v accepted", bad)
			}
		}
		if (ResolutionOptions{VersionID: "ü"}).Validate() == nil {
			t.Fatal("non-ASCII versionId accepted")
		}
	})
	t.Run("Extra is checked", func(t *testing.T) {
		if (ResolutionOptions{Extra: map[string]any{"accept": "x"}}).Validate() == nil ||
			(ResolutionOptions{Extra: map[string]any{"x": math.NaN()}}).Validate() == nil {
			t.Fatal("bad Extra accepted")
		}
	})
	t.Run("JSON round trip", func(t *testing.T) {
		o := ResolutionOptions{Accept: "application/did", ExpandRelativeURLs: true, VersionID: "2", VersionTime: &ts, NoCache: true, Extra: map[string]any{"x": json.Number("1")}}
		b, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"accept":"application/did","expandRelativeUrls":true,"noCache":true,"versionId":"2","versionTime":"2021-05-10T17:00:00Z","x":1}`
		if string(b) != want {
			t.Fatalf("got %s", b)
		}
		var back ResolutionOptions
		if err := json.Unmarshal(b, &back); err != nil || !back.VersionTime.Equal(ts) || !back.NoCache || back.Extra["x"] != json.Number("1") {
			t.Fatalf("got %+v %v", back, err)
		}
		for _, bad := range []string{`{"versionTime":"2021-05-10T17:00:00.1Z"}`, `{"noCache":"yes"}`, `[]`, `{"versionTime":1}`, `{"x":[}`} {
			if err := json.Unmarshal([]byte(bad), &back); err == nil {
				t.Errorf("%s accepted", bad)
			}
		}
		if _, err := json.Marshal(ResolutionOptions{Extra: map[string]any{"noCache": 1}}); err == nil {
			t.Fatal("colliding Extra encoded")
		}
	})
}

func TestDereferenceOptions(t *testing.T) {
	t.Run("core10#did-url-dereferencing-options.2 the media type is an ASCII string", func(t *testing.T) {
		if (DereferenceOptions{Accept: "text/uri-list"}).Validate() != nil || (DereferenceOptions{Accept: "tëxt/uri-list"}).Validate() == nil {
			t.Fatal("accept check")
		}
	})
	t.Run("res10-crd20261001#did-url-dereferencing-options.2 accept is an RFC 9110 Accept value", func(t *testing.T) {
		if (DereferenceOptions{Accept: "text"}).Validate() == nil {
			t.Fatal("malformed accept accepted")
		}
	})
	t.Run("res10-crd20261001#did-url-dereferencing-options.4 verificationRelationship is ASCII", func(t *testing.T) {
		if (DereferenceOptions{VerificationRelationship: "authentication"}).Validate() != nil {
			t.Fatal("valid relationship rejected")
		}
		if (DereferenceOptions{VerificationRelationship: "authentïcation"}).Validate() == nil {
			t.Fatal("non-ASCII relationship accepted")
		}
	})
	t.Run("JSON round trip", func(t *testing.T) {
		o := DereferenceOptions{Accept: "text/uri-list", VerificationRelationship: "authentication", Extra: map[string]any{"y": true}}
		b, err := json.Marshal(o)
		if err != nil || string(b) != `{"accept":"text/uri-list","verificationRelationship":"authentication","y":true}` {
			t.Fatalf("got %s %v", b, err)
		}
		var back DereferenceOptions
		if err := json.Unmarshal(b, &back); err != nil || back.VerificationRelationship != "authentication" || back.Extra["y"] != true {
			t.Fatal(err)
		}
		if json.Unmarshal([]byte(`{"accept":1}`), &back) == nil || json.Unmarshal([]byte(`null`), &back) == nil {
			t.Fatal("bad JSON accepted")
		}
		if _, err := json.Marshal(DereferenceOptions{Extra: map[string]any{"accept": "x"}}); err == nil {
			t.Fatal("colliding Extra encoded")
		}
		if (DereferenceOptions{Extra: map[string]any{"accept": "x"}}).Validate() == nil {
			t.Fatal("colliding Extra validated")
		}
	})
}

type stubResolver struct{}

func (stubResolver) Resolve(context.Context, did.DID, ResolutionOptions) Result {
	return ErrorResult(NewError(CodeMethodNotSupported, ""))
}

type stubDereferencer struct{}

func (stubDereferencer) Dereference(context.Context, did.DIDURL, DereferenceOptions) DereferenceResult {
	return ErrorDereferenceResult(NewError(CodeNotFound, ""))
}

func TestResults(t *testing.T) {
	var r Resolver = stubResolver{}
	res := r.Resolve(context.Background(), did.DID{}, ResolutionOptions{})
	if res.Document != nil || res.ResolutionMetadata.Error == nil || !res.DocumentMetadata.IsEmpty() {
		t.Fatal("error result")
	}
	var d Dereferencer = stubDereferencer{}
	dr := d.Dereference(context.Background(), did.DIDURL{}, DereferenceOptions{})
	if dr.ContentStream != nil || !dr.ContentMetadata.IsEmpty() || dr.DereferencingMetadata.Error.Code() != CodeNotFound {
		t.Fatal("error dereference result")
	}
	if b, _ := json.Marshal(dr.ContentMetadata); string(b) != "{}" {
		t.Fatal("empty content metadata must serialize as {}")
	}
	_ = spec.V11
}
