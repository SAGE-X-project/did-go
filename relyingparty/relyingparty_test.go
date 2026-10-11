package relyingparty

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method/key"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

func newRP(t *testing.T, d resolution.Dereferencer, opts ...Option) *RelyingParty {
	t.Helper()
	rp, err := New(d, append([]Option{WithClock(clock)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

// wantCode checks that err carries a *resolution.Error of the given code.
func wantCode(t *testing.T, err error, code resolution.Code) {
	t.Helper()
	var e *resolution.Error
	if !errors.As(err, &e) || e.Code() != code {
		t.Fatalf("got %v, want %s", err, code)
	}
}

func TestNew(t *testing.T) {
	d := newDereferencer()
	bad := []struct {
		name string
		d    resolution.Dereferencer
		opts []Option
	}{
		{"no dereferencer", nil, nil},
		{"unsupported version", d, []Option{WithVersion(spec.Version(9))}},
		{"no clock", d, []Option{WithClock(nil)}},
		{"core10#did-controller.4 controller documents with DID 1.1", d, []Option{WithControllerDocuments(), WithVersion(spec.V11)}},
		{"core10#did-controller.4 controller documents without a version or a resolver", d, []Option{WithControllerDocuments()}},
		{"invalid dereference options", d, []Option{WithDereferenceOptions(resolution.DereferenceOptions{VerificationRelationship: "authentificationé"})}},
	}
	for _, c := range bad {
		if _, err := New(c.d, c.opts...); err == nil {
			t.Errorf("%s: New succeeded", c.name)
		}
	}
	for _, opts := range [][]Option{
		{WithControllerDocuments(), WithVersion(spec.V10)},
		{WithControllerDocuments(), WithResolver(fakeResolver{})},
		{},
	} {
		if _, err := New(d, opts...); err != nil {
			t.Errorf("New: %v", err)
		}
	}
}

func TestVerificationMethod(t *testing.T) {
	ctx := context.Background()
	k := newDIDKey(t, spec.V11)
	d := newDereferencer()
	d.put(k.doc)
	opts := resolution.DereferenceOptions{Accept: spec.MediaTypeDID}
	rp := newRP(t, d, WithDereferenceOptions(opts))

	t.Run("cid10#retrieve-verification-method.4 the document URL is dereferenced with the supplied options", func(t *testing.T) {
		m, err := rp.VerificationMethod(ctx, k.vmID, vm.Authentication)
		if err != nil {
			t.Fatal(err)
		}
		if m.ID != k.vmID || d.urls[len(d.urls)-1] != k.id.String() || d.opts[len(d.opts)-1].Accept != opts.Accept {
			t.Fatalf("got %v after dereferencing %v", m.ID, d.urls)
		}
		msg := []byte("challenge")
		if err := verifyWith(t, m, msg, ed25519.Sign(k.priv, msg)); err != nil {
			t.Fatalf("the retrieved key must verify the holder's signature: %v", err)
		}
		if verifyWith(t, m, []byte("other"), ed25519.Sign(k.priv, msg)) == nil {
			t.Fatal("a signature over another message must fail")
		}
	})
	t.Run("cid10#retrieve-verification-method.12 the method is returned as a copy", func(t *testing.T) {
		m, _ := rp.VerificationMethod(ctx, k.vmID, vm.AssertionMethod)
		m.Type = "changed"
		if again, _ := rp.VerificationMethod(ctx, k.vmID, vm.AssertionMethod); again.Type != vm.TypeMultikey {
			t.Fatal("the stored document changed")
		}
	})
	t.Run("an unknown purpose is refused", func(t *testing.T) {
		if _, err := rp.VerificationMethod(ctx, k.vmID, vm.Purpose(0)); !errors.Is(err, ErrInvalidPurpose) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cid10#retrieve-verification-method.1 the reference must be an absolute DID URL with a fragment", func(t *testing.T) {
		for _, ref := range []did.DIDURL{{}, mustURL(t, "#key-1"), k.id.URL(), mustURL(t, k.id.String()+"#")} {
			_, err := rp.VerificationMethod(ctx, ref, vm.Authentication)
			wantCode(t, err, resolution.CodeInvalidVerificationMethodURL)
		}
	})
	t.Run("cid10#retrieve-verification-method.4 a failed dereference is reported", func(t *testing.T) {
		_, err := rp.VerificationMethod(ctx, mustURL(t, "did:example:nobody#k"), vm.Authentication)
		if !errors.Is(err, resolution.NewError(resolution.CodeNotFound, "")) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cid10#retrieve-verification-method.11 the method must be in the relationship", func(t *testing.T) {
		_, err := rp.VerificationMethod(ctx, k.vmID, vm.KeyAgreement)
		wantCode(t, err, resolution.CodeInvalidRelationshipForVerificationMethod)
		var ce *document.ConformanceError
		if !errors.As(err, &ce) || ce.Statement != "cid10#retrieve-verification-method.11" {
			t.Fatalf("the selector's error must stay visible: %v", err)
		}
		x := newDIDKey(t, spec.V11, key.WithEncryptionKeyDerivation(true))
		d.put(x.doc)
		ka := x.doc.Relationship(vm.KeyAgreement)[0].ID()
		if _, err := rp.VerificationMethod(ctx, ka, vm.KeyAgreement); err != nil {
			t.Fatalf("the derived key agreement method: %v", err)
		}
		if _, err := rp.VerificationMethod(ctx, ka, vm.Authentication); err == nil {
			t.Fatal("a key agreement method must not authenticate")
		}
	})
}

func TestRetrievedDocument(t *testing.T) {
	ctx := context.Background()
	ref := mustURL(t, alice+"#key-1")
	t.Run("cid10#retrieve-verification-method.5 content that is not a DID document", func(t *testing.T) {
		for _, content := range []any{nil, method(t, "key-1"), []byte("{}")} {
			d := newDereferencer()
			d.results[alice] = resolution.DereferenceResult{ContentStream: content}
			_, err := newRP(t, d).VerificationMethod(ctx, ref, vm.Authentication)
			wantCode(t, err, resolution.CodeInvalidControlledIdentifierDocument)
		}
	})
	t.Run("cid10#retrieve-verification-method.5 a document that does not conform to the version applied", func(t *testing.T) {
		d := newDereferencer()
		d.put(aliceDoc(t, nil, vm.Service{Type: []string{"X"}, ServiceEndpoint: []vm.Endpoint{{URL: "https://alice.example/"}}}))
		_, err := newRP(t, d, WithVersion(spec.V10)).VerificationMethod(ctx, ref, vm.Authentication)
		wantCode(t, err, resolution.CodeInvalidControlledIdentifierDocument)
		if _, err := newRP(t, d).VerificationMethod(ctx, ref, vm.Authentication); err != nil {
			t.Fatalf("service.id is optional in DID 1.1: %v", err)
		}
	})
	t.Run("cid10#subjects.4 a document whose id is not the dereferenced URL is not authoritative", func(t *testing.T) {
		d := newDereferencer()
		d.results[alice] = resolution.DereferenceResult{ContentStream: newDIDKey(t, spec.V11).doc}
		_, err := newRP(t, d).VerificationMethod(ctx, ref, vm.Authentication)
		wantCode(t, err, resolution.CodeInvalidControlledIdentifierDocumentID)
	})
	t.Run("cid10#retrieve-verification-method.6 a reference with a path names another document", func(t *testing.T) {
		d := newDereferencer()
		doc := aliceDoc(t, nil)
		d.results[alice+"/path"] = resolution.DereferenceResult{ContentStream: doc}
		_, err := newRP(t, d).VerificationMethod(ctx, mustURL(t, alice+"/path#key-1"), vm.Authentication)
		wantCode(t, err, resolution.CodeInvalidControlledIdentifierDocumentID)
	})
	t.Run("a deactivated DID yields no verification method", func(t *testing.T) {
		d := newDereferencer()
		d.results[alice] = resolution.DereferenceResult{ContentMetadata: document.Metadata{Deactivated: true}}
		if _, err := newRP(t, d).VerificationMethod(ctx, ref, vm.Authentication); !errors.Is(err, ErrDeactivated) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cid10#retrieve-verification-method.10 a method claiming another controller", func(t *testing.T) {
		d := newDereferencer()
		d.put(aliceDoc(t, nil))
		_, err := newRP(t, d).VerificationMethod(ctx, mustURL(t, alice+"#foreign"), vm.Authentication)
		wantCode(t, err, resolution.CodeInvalidVerificationMethod)
	})
}

func TestMethodLifetime(t *testing.T) {
	ctx := context.Background()
	d := newDereferencer()
	d.put(aliceDoc(t, nil))
	rp := newRP(t, d)
	t.Run("cid10#verification-methods.11 a revoked method must not be used", func(t *testing.T) {
		if _, err := rp.VerificationMethod(ctx, mustURL(t, alice+"#revoked"), vm.Authentication); !errors.Is(err, ErrRevoked) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cid10#verification-methods.9 an expired method ceases to be used", func(t *testing.T) {
		if _, err := rp.VerificationMethod(ctx, mustURL(t, alice+"#expired"), vm.Authentication); !errors.Is(err, ErrExpired) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cid10#verification-methods.9 cid10#verification-methods.11 times in the future do not stop use", func(t *testing.T) {
		if _, err := rp.VerificationMethod(ctx, mustURL(t, alice+"#later"), vm.Authentication); err != nil {
			t.Fatal(err)
		}
	})
}

// controlled returns a dereferencer holding a did:key controller document
// and alice's DID Core 1.0 document that lists it as controller.
func controlled(t *testing.T) (*fakeDereferencer, didKey, *document.Document) {
	t.Helper()
	k := newDIDKey(t, spec.V10)
	a := aliceDoc(t, []did.DID{k.id})
	d := newDereferencer()
	d.put(k.doc)
	d.put(a)
	return d, k, a
}

func TestVerificationMethodFor(t *testing.T) {
	ctx := context.Background()
	subject := mustDID(t, alice)
	t.Run("a method of the subject's own document", func(t *testing.T) {
		d, _, _ := controlled(t)
		if _, err := newRP(t, d).VerificationMethodFor(ctx, subject, mustURL(t, alice+"#key-1"), vm.Authentication); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("core10#did-controller.4 controller documents are not accepted unless enabled", func(t *testing.T) {
		d, k, _ := controlled(t)
		if _, err := newRP(t, d, WithVersion(spec.V10)).VerificationMethodFor(ctx, subject, k.vmID, vm.Authentication); !errors.Is(err, ErrNotAuthoritative) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("core10#did-controller.4 methods of a controller's document are authoritative for the subject", func(t *testing.T) {
		d, k, _ := controlled(t)
		rp := newRP(t, d, WithVersion(spec.V10), WithControllerDocuments())
		m, err := rp.VerificationMethodFor(ctx, subject, k.vmID, vm.Authentication)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("signed by the controller")
		if err := verifyWith(t, m, msg, ed25519.Sign(k.priv, msg)); err != nil {
			t.Fatal(err)
		}
		_, err = rp.VerificationMethodFor(ctx, subject, k.vmID, vm.KeyAgreement)
		wantCode(t, err, resolution.CodeInvalidRelationshipForVerificationMethod)
	})
	t.Run("core10#did-controller.4 the version comes from the resolver's detection", func(t *testing.T) {
		d, k, a := controlled(t)
		r := fakeResolver{alice: {Document: a, Info: representation.ConsumeInfo{DetectedVersion: spec.V10}}}
		rp := newRP(t, d, WithResolver(r), WithControllerDocuments())
		if _, err := rp.VerificationMethodFor(ctx, subject, k.vmID, vm.Authentication); err != nil {
			t.Fatal(err)
		}
		r[alice] = resolution.Result{Document: a, Info: representation.ConsumeInfo{DetectedVersion: spec.V11}}
		if _, err := rp.VerificationMethodFor(ctx, subject, k.vmID, vm.Authentication); !errors.Is(err, ErrNotAuthoritative) {
			t.Fatalf("a DID 1.1 subject document: %v", err)
		}
	})
	t.Run("core10#did-controller.4 only DIDs listed as controllers count", func(t *testing.T) {
		d, _, _ := controlled(t)
		other := newDIDKey(t, spec.V10)
		d.put(other.doc)
		rp := newRP(t, d, WithVersion(spec.V10), WithControllerDocuments())
		if _, err := rp.VerificationMethodFor(ctx, subject, other.vmID, vm.Authentication); !errors.Is(err, ErrNotAuthoritative) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("the subject document must be usable", func(t *testing.T) {
		d, k, _ := controlled(t)
		d.results[alice] = resolution.DereferenceResult{ContentMetadata: document.Metadata{Deactivated: true}}
		rp := newRP(t, d, WithVersion(spec.V10), WithControllerDocuments())
		if _, err := rp.VerificationMethodFor(ctx, subject, k.vmID, vm.Authentication); !errors.Is(err, ErrDeactivated) {
			t.Fatalf("deactivated through the dereferencer: %v", err)
		}
		results := map[string]resolution.Result{
			"deactivated": {DocumentMetadata: document.Metadata{Deactivated: true}},
			"error":       resolution.ErrorResult(resolution.NewError(resolution.CodeInternalError, "")),
			"no document": {},
		}
		for name, res := range results {
			rp := newRP(t, d, WithResolver(fakeResolver{alice: res}), WithControllerDocuments())
			if _, err := rp.VerificationMethodFor(ctx, subject, k.vmID, vm.Authentication); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
		bad := aliceDoc(t, []did.DID{k.id}, vm.Service{Type: []string{"X"}, ServiceEndpoint: []vm.Endpoint{{URL: "https://a.example/"}}})
		d.put(bad)
		_, err := rp.VerificationMethodFor(ctx, subject, k.vmID, vm.Authentication)
		wantCode(t, err, resolution.CodeInvalidControlledIdentifierDocument)
	})
	t.Run("a subject and a reference are required", func(t *testing.T) {
		d, k, _ := controlled(t)
		rp := newRP(t, d)
		if _, err := rp.VerificationMethodFor(ctx, did.DID{}, k.vmID, vm.Authentication); !errors.Is(err, ErrNotAuthoritative) {
			t.Fatalf("got %v", err)
		}
		_, err := rp.VerificationMethodFor(ctx, subject, mustURL(t, "#key-1"), vm.Authentication)
		wantCode(t, err, resolution.CodeInvalidVerificationMethodURL)
		if _, err := rp.VerificationMethodFor(ctx, subject, k.vmID, vm.Purpose(99)); !errors.Is(err, ErrInvalidPurpose) {
			t.Fatalf("got %v", err)
		}
	})
}
