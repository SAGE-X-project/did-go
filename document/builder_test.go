package document

import (
	"errors"
	"testing"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/vm"
)

const subject = "did:example:123456789abcdefghi"

func mustDID(t *testing.T, s string) did.DID {
	t.Helper()
	d, err := did.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustRef(t *testing.T, s string) did.DIDURL {
	t.Helper()
	u, err := did.ParseReference(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func key(t *testing.T, id string) vm.Method {
	t.Helper()
	return vm.Method{
		ID: mustRef(t, id), Type: "Multikey", Controller: mustDID(t, subject),
		PublicKeyMultibase: "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu",
	}
}

func builder(t *testing.T) *Builder {
	t.Helper()
	return NewBuilder(mustDID(t, subject))
}

func build(t *testing.T, b *Builder) *Document {
	t.Helper()
	d, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func wantBuildError(t *testing.T, b *Builder, statement string) {
	t.Helper()
	_, err := b.Build()
	var ce *ConformanceError
	if !errors.As(err, &ce) {
		t.Fatalf("Build() = %v, want *ConformanceError citing %q", err, statement)
	}
	if ce.Statement != statement || ce.Code != CodeInvalidControlledIdentifierDocument {
		t.Fatalf("Build() = %v, want statement %q", err, statement)
	}
}

func TestSubject(t *testing.T) {
	t.Run("core10#did-subject.1 id is a DID and is required", func(t *testing.T) {
		d := build(t, builder(t))
		if d.ID().String() != subject {
			t.Fatal("id")
		}
		wantBuildError(t, NewBuilder(did.DID{}), "cid10#subjects.2")
	})
	t.Run("cid10#subjects.1 id is a URL", func(t *testing.T) {
		if !vm.IsURL(build(t, builder(t)).ID().String()) {
			t.Fatal("a DID is a URL")
		}
	})
	t.Run("cid10#subjects.2 id is in the topmost map", func(t *testing.T) {
		wantBuildError(t, NewBuilder(did.DID{}), "cid10#subjects.2")
	})
}

func TestControllers(t *testing.T) {
	a, b := mustDID(t, "did:example:a"), mustDID(t, "did:example:b")
	t.Run("core10#did-controller.1 controller is optional", func(t *testing.T) {
		if d := build(t, builder(t)); d.Controllers() != nil {
			t.Fatal("absent controller")
		}
	})
	t.Run("cid10#controllers.1 controller is optional", func(t *testing.T) {
		build(t, builder(t))
	})
	t.Run("core10#did-controller.2 a DID or a set of DIDs", func(t *testing.T) {
		d := build(t, builder(t).Controller(a, b))
		got := d.Controllers()
		if len(got) != 2 || got[0] != a {
			t.Fatal("controllers")
		}
		got[0] = b
		if d.Controllers()[0] != a {
			t.Fatal("Controllers must return a copy")
		}
		wantBuildError(t, builder(t).Controller(a, a), "core10#did-controller.2")
		wantBuildError(t, builder(t).Controller(did.DID{}), "core10#did-controller.2")
	})
	t.Run("cid10#controllers.3 each entry conforms to URL syntax", func(t *testing.T) {
		for _, c := range build(t, builder(t).Controller(a)).Controllers() {
			if !vm.IsURL(c.String()) {
				t.Fatal("controller is not a URL")
			}
		}
	})
}

func TestAlsoKnownAs(t *testing.T) {
	t.Run("core10#also-known-as.1 alsoKnownAs is optional", func(t *testing.T) {
		if build(t, builder(t)).AlsoKnownAs() != nil {
			t.Fatal("absent")
		}
	})
	t.Run("cid10#also-known-as.1 alsoKnownAs is optional", func(t *testing.T) {
		build(t, builder(t))
	})
	t.Run("core10#also-known-as.2 a set of RFC 3986 URIs", func(t *testing.T) {
		d := build(t, builder(t).AlsoKnownAs("https://example.com/me", "did:example:other"))
		if len(d.AlsoKnownAs()) != 2 {
			t.Fatal("alsoKnownAs")
		}
		wantBuildError(t, builder(t).AlsoKnownAs("not a uri"), "cid10#also-known-as.2")
	})
	t.Run("cid10#also-known-as.2 a set has no duplicates", func(t *testing.T) {
		wantBuildError(t, builder(t).AlsoKnownAs("https://a.example/", "https://a.example/"), "cid10#also-known-as.2")
	})
}

func TestVerificationMethodSet(t *testing.T) {
	t.Run("core10#verification-methods.1 verificationMethod is optional", func(t *testing.T) {
		if build(t, builder(t)).VerificationMethods() != nil {
			t.Fatal("absent")
		}
	})
	t.Run("cid10#verification-methods.1 verificationMethod is optional", func(t *testing.T) {
		build(t, builder(t))
	})
	t.Run("core10#verification-methods.2 a set of verification method maps", func(t *testing.T) {
		d := build(t, builder(t).VerificationMethod(key(t, subject+"#k1"), key(t, "#k2")))
		ms := d.VerificationMethods()
		if len(ms) != 2 {
			t.Fatal("methods")
		}
		ms[0].Type = "changed"
		if d.VerificationMethods()[0].Type != "Multikey" {
			t.Fatal("VerificationMethods must return copies")
		}
	})
	t.Run("cid10#verification-methods.2 no two methods share an id", func(t *testing.T) {
		wantBuildError(t, builder(t).VerificationMethod(key(t, subject+"#k1"), key(t, "#k1")), "cid10#verification-methods.2")
	})
	t.Run("invalid methods keep the vm statement", func(t *testing.T) {
		bad := key(t, "#k1")
		bad.PublicKeyJwk = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "a"}
		wantBuildError(t, builder(t).VerificationMethod(bad), "cid10#verification-material.1")
	})
	t.Run("did11-cr20260305#verification-methods.1 relative ids resolve against the subject", func(t *testing.T) {
		d := build(t, builder(t).VerificationMethod(key(t, "#k1")))
		if !d.VerificationMethods()[0].ID.IsRelative() {
			t.Fatal("a relative id is kept as written")
		}
		wantBuildError(t, builder(t).VerificationMethod(key(t, "#k1"), key(t, subject+"#k1")), "cid10#verification-methods.2")
	})
}

func TestRelationships(t *testing.T) {
	type rel struct {
		p                             vm.Purpose
		optional, oneOrMore, embedRef string
		cidOptional, cidSet, cidEmbed string
	}
	rels := []rel{
		{vm.Authentication, "core10#authentication.1", "core10#authentication.2", "core10#authentication.3",
			"cid10#authentication.1", "cid10#authentication.2", "cid10#authentication.3"},
		{vm.AssertionMethod, "core10#assertion.1", "core10#assertion.2", "core10#assertion.3",
			"cid10#assertion.1", "cid10#assertion.2", "cid10#assertion.3"},
		{vm.KeyAgreement, "core10#key-agreement.1", "core10#key-agreement.2", "core10#key-agreement.3",
			"cid10#key-agreement.1", "cid10#key-agreement.2", "cid10#key-agreement.3"},
		{vm.CapabilityInvocation, "core10#capability-invocation.1", "core10#capability-invocation.2", "core10#capability-invocation.3",
			"cid10#capability-invocation.1", "cid10#capability-invocation.2", "cid10#capability-invocation.3"},
		{vm.CapabilityDelegation, "core10#capability-delegation.1", "core10#capability-delegation.2", "core10#capability-delegation.3",
			"cid10#capability-delegation.1", "cid10#capability-delegation.2", "cid10#capability-delegation.3"},
	}
	for _, r := range rels {
		optional := func(t *testing.T) {
			if build(t, builder(t)).Relationship(r.p) != nil {
				t.Fatal("absent relationship must be nil")
			}
		}
		oneOrMore := func(t *testing.T) {
			wantBuildError(t, builder(t).Relationship(r.p), r.cidSet)
			wantBuildError(t, builder(t).Relationship(r.p, vm.Ref(mustRef(t, "#a")), vm.Ref(mustRef(t, subject+"#a"))), r.cidSet)
		}
		embedRef := func(t *testing.T) {
			d := build(t, builder(t).VerificationMethod(key(t, "#k1")).
				Relationship(r.p, vm.Ref(mustRef(t, "#k1")), vm.Embed(key(t, "#k2"))))
			got := d.Relationship(r.p)
			if len(got) != 2 || got[0].IsEmbedded() || !got[1].IsEmbedded() {
				t.Fatal("embedded and referenced elements")
			}
			bad := key(t, "#k3")
			bad.Type = ""
			wantBuildError(t, builder(t).Relationship(r.p, vm.Embed(bad)), "cid10#verification-methods.6")
			wantBuildError(t, builder(t).Relationship(r.p, vm.Relationship{}), "cid10#authentication.3")
		}
		t.Run(r.optional, optional)
		t.Run(r.cidOptional, optional)
		t.Run(r.oneOrMore, oneOrMore)
		t.Run(r.cidSet, oneOrMore)
		t.Run(r.embedRef, embedRef)
		t.Run(r.cidEmbed, embedRef)
	}
	t.Run("core10#verification-relationships.1 any of the relationships may be included", func(t *testing.T) {
		b := builder(t).VerificationMethod(key(t, "#k1"))
		for _, p := range vm.Purposes() {
			b.Relationship(p, vm.Ref(mustRef(t, "#k1")))
		}
		d := build(t, b)
		for _, p := range vm.Purposes() {
			if len(d.Relationship(p)) != 1 {
				t.Fatalf("%s missing", p)
			}
		}
		if d.Relationship(vm.Purpose(0)) != nil {
			t.Fatal("invalid purpose")
		}
	})
	t.Run("cid10#verification-relationships.1 other relationship properties are extensions", func(t *testing.T) {
		d := build(t, builder(t).Extension("customRelationship", String("did:example:1#k")))
		if _, ok := d.Extensions().Get("customRelationship"); !ok {
			t.Fatal("extension relationship lost")
		}
		if _, err := builder(t).Relationship(vm.Purpose(7)).Build(); err == nil {
			t.Fatal("unknown purpose accepted")
		}
	})
	t.Run("embedded methods are unique across the document, identical repeats allowed", func(t *testing.T) {
		k := key(t, "#k1")
		build(t, builder(t).VerificationMethod(k).Relationship(vm.Authentication, vm.Embed(k)))
		other := k
		other.PublicKeyMultibase = ""
		wantBuildError(t, builder(t).VerificationMethod(k).Relationship(vm.Authentication, vm.Embed(other)), "cid10#verification-methods.2")
	})
}

func TestServiceSet(t *testing.T) {
	s := func(id string) vm.Service {
		return vm.Service{ID: id, Type: []string{"LinkedDomains"}, ServiceEndpoint: []vm.Endpoint{{URL: "https://example.com/"}}}
	}
	t.Run("core10#services.1 service is optional", func(t *testing.T) {
		if build(t, builder(t)).Services() != nil {
			t.Fatal("absent")
		}
	})
	t.Run("cid10#services.1 service is optional", func(t *testing.T) {
		build(t, builder(t))
	})
	t.Run("core10#services.2 a set of service maps", func(t *testing.T) {
		d := build(t, builder(t).Service(s("#a"), s("#b")))
		got := d.Services()
		got[0].Type[0] = "changed"
		if len(got) != 2 || d.Services()[0].Type[0] != "LinkedDomains" {
			t.Fatal("Services must return copies")
		}
	})
	t.Run("cid10#services.2 each service is valid", func(t *testing.T) {
		bad := s("#a")
		bad.Type = nil
		wantBuildError(t, builder(t).Service(bad), "cid10#services.8")
	})
	t.Run("cid10#services.7 no two services share an id", func(t *testing.T) {
		wantBuildError(t, builder(t).Service(s("#a"), s(subject+"#a")), "cid10#services.7")
		build(t, builder(t).Service(s(""), s("")))
	})
}

func TestEntries(t *testing.T) {
	ctx, _ := NewList(String("https://www.w3.org/ns/did/v1.1"))
	d := build(t, builder(t).Extension("fooExtension", Integer(42)).RepresentationEntry("@context", ctx))
	if v, ok := d.Extensions().Get("fooExtension"); !ok || v != Integer(42) {
		t.Fatal("extension")
	}
	if _, ok := d.RepresentationEntries().Get("@context"); !ok {
		t.Fatal("representation entry")
	}
	for _, b := range []*Builder{
		builder(t).Extension("service", String("x")),
		builder(t).Extension("", String("x")),
		builder(t).Extension("a", String("x")).RepresentationEntry("a", String("y")),
		builder(t).Extension("a", Double(1)/Double(zero())),
		builder(t).RepresentationEntry("@context", nil),
	} {
		if _, err := b.Build(); err == nil {
			t.Error("invalid entry accepted")
		}
	}
}

func zero() float64 { return 0 }

func TestBuilderFrom(t *testing.T) {
	orig := build(t, builder(t).Controller(mustDID(t, "did:example:c")).AlsoKnownAs("https://a.example/").
		VerificationMethod(key(t, "#k1")).Relationship(vm.Authentication, vm.Ref(mustRef(t, "#k1"))).
		Service(vm.Service{Type: []string{"X"}, ServiceEndpoint: []vm.Endpoint{{URL: "https://e.example/"}}}).
		Extension("x", Boolean(true)))
	copied := build(t, NewBuilderFrom(orig).Relationship(vm.AssertionMethod, vm.Ref(mustRef(t, "#k1"))))
	if len(copied.Relationship(vm.Authentication)) != 1 || len(copied.Relationship(vm.AssertionMethod)) != 1 ||
		orig.Relationship(vm.AssertionMethod) != nil || len(copied.Services()) != 1 || copied.Extensions().Len() != 1 {
		t.Fatal("NewBuilderFrom must copy every property and leave the original unchanged")
	}
	var ce *ConformanceError
	if _, err := builder(t).Controller(did.DID{}).Build(); !errors.As(err, &ce) || ce.Error() == "" {
		t.Fatal("error message")
	}
}
