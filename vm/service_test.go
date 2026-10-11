package vm

import (
	"errors"
	"testing"
)

func svc(id string, endpoints ...Endpoint) Service {
	return Service{ID: id, Type: []string{"LinkedDomains"}, ServiceEndpoint: endpoints}
}

func TestService(t *testing.T) {
	web := Endpoint{URL: "https://example.com/"}
	t.Run("cid10#services.5 the id property is optional", func(t *testing.T) {
		if err := svc("", web).Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cid10#services.6 an id is a URL", func(t *testing.T) {
		for _, id := range []string{"did:example:123#linked-domain", "#linked-domain", "https://example.com/s", "urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66"} {
			if err := svc(id, web).Validate(); err != nil {
				t.Errorf("%q: %v", id, err)
			}
		}
		for _, id := range []string{"not a url", "http://", "1ab:x"} {
			wantStatement(t, svc(id, web).Validate(), "cid10#services.6")
		}
	})
	t.Run("cid10#services.8 type is required", func(t *testing.T) {
		s := svc("", web)
		s.Type = nil
		wantStatement(t, s.Validate(), "cid10#services.8")
	})
	t.Run("cid10#services.9 type is a string or a set of strings", func(t *testing.T) {
		s := svc("", web)
		s.Type = []string{"A", "B"}
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
		for _, bad := range [][]string{{""}, {"A", "A"}} {
			s.Type = bad
			wantStatement(t, s.Validate(), "cid10#services.9")
		}
	})
	t.Run("core10#services.8 the same type rule in DID Core 1.0", func(t *testing.T) {
		s := svc("did:example:1#s", web)
		s.Type = []string{"A", ""}
		if s.Validate() == nil {
			t.Fatal("empty type accepted")
		}
	})
	t.Run("cid10#services.11 serviceEndpoint is required", func(t *testing.T) {
		wantStatement(t, svc("").Validate(), "cid10#services.11")
	})
	t.Run("cid10#services.12 a string, a map or a set of strings and maps", func(t *testing.T) {
		mapEP := Endpoint{Map: map[string]any{"origins": []any{"https://a.example/"}}}
		for _, eps := range [][]Endpoint{{web}, {mapEP}, {web, mapEP}} {
			if err := svc("", eps...).Validate(); err != nil {
				t.Fatal(err)
			}
		}
		for _, bad := range []Endpoint{{}, {URL: "https://a/", Map: map[string]any{}}, {Map: map[string]any{"x": func() {}}}} {
			wantStatement(t, svc("", bad).Validate(), "cid10#services.12")
		}
	})
	t.Run("core10#services.10 the same endpoint forms in DID Core 1.0", func(t *testing.T) {
		if svc("did:example:1#s", Endpoint{}).Validate() == nil {
			t.Fatal("empty endpoint accepted")
		}
	})
	t.Run("cid10#services.13 each endpoint string is a valid URL", func(t *testing.T) {
		wantStatement(t, svc("", Endpoint{URL: "https://exa mple.com"}).Validate(), "cid10#services.13")
	})
	t.Run("did11-cr20260305#core-properties.1 endpoint strings are URL Standard URLs", func(t *testing.T) {
		if err := svc("", Endpoint{URL: "https://example.com/a?b#c"}).Validate(); err != nil {
			t.Fatal(err)
		}
		if svc("", Endpoint{URL: "http:///nohost"}).Validate() == nil {
			t.Fatal("special scheme without host accepted")
		}
	})
	t.Run("cid10#services.4 additional properties are allowed", func(t *testing.T) {
		s := svc("", web)
		s.Extra = map[string]any{"accept": []any{"didcomm/v2"}, "priority": 1}
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
		s.Extra = map[string]any{"serviceEndpoint": "x"}
		wantStatement(t, s.Validate(), "cid10#services.4")
	})
	t.Run("core10#services.4 extensions may add properties", func(t *testing.T) {
		s := svc("did:example:1#s", web)
		s.Extra = map[string]any{"routingKeys": []any{"did:example:2#k"}}
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Clone is deep", func(t *testing.T) {
		s := svc("", Endpoint{Map: map[string]any{"a": []any{"b"}}})
		s.Extra = map[string]any{"x": map[string]any{"y": 1}}
		c := s.Clone()
		c.Type[0] = "changed"
		c.ServiceEndpoint[0].Map["a"].([]any)[0] = "changed"
		c.Extra["x"].(map[string]any)["y"] = 2
		if s.Type[0] != "LinkedDomains" || s.ServiceEndpoint[0].Map["a"].([]any)[0] != "b" || s.Extra["x"].(map[string]any)["y"] != 1 {
			t.Fatal("clone shares memory")
		}
		if (Service{}).Clone().ServiceEndpoint != nil {
			t.Fatal("nil endpoints must stay nil")
		}
	})
}

func TestPurposeAndRelationship(t *testing.T) {
	for _, p := range Purposes() {
		got, err := ParsePurpose(p.String())
		if err != nil || got != p || !p.Valid() {
			t.Fatalf("%v: %v", p, err)
		}
	}
	if _, err := ParsePurpose("signing"); err == nil {
		t.Fatal("unknown relationship accepted")
	}
	if Purpose(0).Valid() || Purpose(9).String() != "Purpose(9)" {
		t.Fatal("invalid purpose")
	}
	m := baseMethod(t, "Multikey")
	m.Extra = map[string]any{"a": map[string]any{"b": 1}}
	t.Run("cid10#authentication.3 elements are embedded or referenced", func(t *testing.T) {
		emb := Embed(m)
		got, ok := emb.Method()
		if !ok || !emb.IsEmbedded() || got.ID != m.ID || emb.ID() != m.ID {
			t.Fatal("embedded")
		}
		got.Extra["a"].(map[string]any)["b"] = 2
		again, _ := emb.Method()
		if again.Extra["a"].(map[string]any)["b"] != 1 {
			t.Fatal("embedded method must be copied")
		}
		if _, ok := emb.Reference(); ok {
			t.Fatal("embedded is not a reference")
		}
		ref := Ref(m.ID)
		u, ok := ref.Reference()
		if !ok || u != m.ID || ref.IsEmbedded() || ref.ID() != m.ID || ref.Validate() != nil {
			t.Fatal("reference")
		}
		if _, ok := ref.Method(); ok {
			t.Fatal("reference has no method")
		}
		if emb.Validate() != nil {
			t.Fatal("valid embedded method rejected")
		}
		var empty Relationship
		if empty.Validate() == nil {
			t.Fatal("empty element accepted")
		}
		bad := m
		bad.Type = ""
		var ve *Error
		if !errors.As(Embed(bad).Validate(), &ve) {
			t.Fatal("invalid embedded method accepted")
		}
	})
}
