package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/sage-x-project/did-go/crypto"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/method/key"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

func newController(t *testing.T, m method.Method, opts ...Option) *Controller {
	t.Helper()
	c, err := New(m, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func serviceWithoutID() vm.Service {
	return vm.Service{Type: []string{"LinkedDomains"}, ServiceEndpoint: []vm.Endpoint{{URL: "https://alice.example/"}}}
}

func TestNew(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("a nil driver must be refused")
	}
	if _, err := New(newFakeMethod(), WithVersion(spec.VUnknown)); err == nil {
		t.Fatal("an unsupported version must be refused")
	}
	for _, id := range []string{"#key-1", alice} {
		_, err := New(newFakeMethod(), WithSigner(newSigner(t, id)))
		if !errors.Is(err, ErrInvalidSigner) {
			t.Fatalf("signer %s: %v, want ErrInvalidSigner", id, err)
		}
	}
	c := newController(t, newFakeMethod(), WithSigner(newSigner(t, alice+"#key-1")), WithVersion(spec.V10))
	if c.Method() != "example" {
		t.Fatalf("Method() = %q", c.Method())
	}
}

func TestCreate(t *testing.T) {
	ctx := context.Background()
	t.Run("the driver creates the DID with the signer's proof", func(t *testing.T) {
		m := newFakeMethod()
		c := newController(t, m, WithSigner(newSigner(t, alice+"#key-1")))
		extra := map[string]any{"anchor": map[string]any{"chain": "test"}}
		res, err := c.Create(ctx, doc(t, alice, nil), extra)
		if err != nil {
			t.Fatal(err)
		}
		if res.DID.String() != alice || len(m.proofs) != 1 {
			t.Fatalf("got %v with %d proofs", res.DID, len(m.proofs))
		}
		m.lastExtra["anchor"].(map[string]any)["chain"] = "changed"
		if extra["anchor"].(map[string]any)["chain"] != "test" {
			t.Fatal("the controller must pass a copy of extra")
		}
	})
	t.Run("a document that does not conform to the target version is never submitted", func(t *testing.T) {
		m := newFakeMethod()
		c := newController(t, m, WithSigner(newSigner(t, alice+"#key-1")), WithVersion(spec.V10))
		_, err := c.Create(ctx, doc(t, alice, nil, serviceWithoutID()), nil)
		var ve *ValidationError
		if !errors.Is(err, ErrInvalidDocument) || !errors.As(err, &ve) || ve.Findings[0].Statement != "core10#services.3" {
			t.Fatalf("got %v, want a ValidationError citing core10#services.3", err)
		}
		if !strings.Contains(err.Error(), "core10#services.3") || len(m.docs) != 0 {
			t.Fatalf("message %q, %d documents stored", err, len(m.docs))
		}
		if _, err := newController(t, m, WithSigner(newSigner(t, alice+"#key-1"))).Create(ctx, doc(t, alice, nil, serviceWithoutID()), nil); err != nil {
			t.Fatalf("the same document conforms to DID 1.1: %v", err)
		}
	})
	t.Run("a document of another method is refused", func(t *testing.T) {
		c := newController(t, newFakeMethod())
		if _, err := c.Create(ctx, doc(t, "did:other:alice", nil), nil); !errors.Is(err, ErrMethodMismatch) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("the driver's authorization failure is passed on", func(t *testing.T) {
		c := newController(t, newFakeMethod())
		if _, err := c.Create(ctx, doc(t, alice, nil), nil); !errors.Is(err, method.ErrUnauthorized) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("an inconsistent driver result is refused", func(t *testing.T) {
		m := newFakeMethod()
		m.bad = doc(t, bob, nil)
		c := newController(t, m, WithSigner(newSigner(t, alice+"#key-1")))
		if _, err := c.Create(ctx, doc(t, alice, nil), nil); !errors.Is(err, ErrInvalidResult) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a cancelled context stops before the driver", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := newController(t, newFakeMethod()).Create(cctx, nil, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	})
}

// TestDIDKey drives the controller with the did:key driver: Create derives
// the DID from a public key without any private key reaching the library,
// and Update and Deactivate report method.ErrNotSupported unchanged.
func TestDIDKey(t *testing.T) {
	ctx := context.Background()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := crypto.FromCryptoKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	c := newController(t, key.New(nil))
	res, err := c.Create(ctx, nil, map[string]any{key.ExtraPublicKey: k})
	if err != nil {
		t.Fatal(err)
	}
	if res.DID.Method() != "key" || res.Document.ID() != res.DID {
		t.Fatalf("created %v", res.DID)
	}
	if _, err := c.Update(ctx, res.Document, nil); !errors.Is(err, method.ErrNotSupported) {
		t.Fatalf("Update: %v, want method.ErrNotSupported", err)
	}
	if _, err := c.Deactivate(ctx, res.DID, nil); !errors.Is(err, method.ErrNotSupported) {
		t.Fatalf("Deactivate: %v, want method.ErrNotSupported", err)
	}
	if _, err := c.Create(ctx, nil, nil); !errors.Is(err, method.ErrInvalidInput) {
		t.Fatalf("Create without a key: %v", err)
	}
}

// registered returns a driver holding alice's document with the given
// controllers, and a controller over it.
func registered(t *testing.T, controllers []string, opts ...Option) (*fakeMethod, *Controller) {
	t.Helper()
	m := newFakeMethod()
	m.docs[mustDID(t, alice)] = doc(t, alice, controllers)
	return m, newController(t, m, opts...)
}

func TestUpdate(t *testing.T) {
	ctx := context.Background()
	t.Run("the driver replaces the document", func(t *testing.T) {
		m, c := registered(t, nil, WithSigner(newSigner(t, alice+"#key-1")))
		next := doc(t, alice, []string{bob})
		res, err := c.Update(ctx, next, nil)
		if err != nil || res.Document != next || m.docs[mustDID(t, alice)] != next {
			t.Fatalf("got %v %v", res, err)
		}
	})
	t.Run("nil and non-conforming documents are refused", func(t *testing.T) {
		_, c := registered(t, nil, WithSigner(newSigner(t, alice+"#key-1")), WithVersion(spec.V10))
		if _, err := c.Update(ctx, nil, nil); !errors.Is(err, ErrInvalidDocument) {
			t.Fatalf("nil: %v", err)
		}
		if _, err := c.Update(ctx, doc(t, alice, nil, serviceWithoutID()), nil); !errors.Is(err, ErrInvalidDocument) {
			t.Fatalf("no service id: %v", err)
		}
	})
	t.Run("a DID of another method is refused", func(t *testing.T) {
		_, c := registered(t, nil)
		if _, err := c.Update(ctx, doc(t, "did:other:alice", nil), nil); !errors.Is(err, ErrMethodMismatch) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("driver errors are passed on", func(t *testing.T) {
		_, c := registered(t, nil)
		if _, err := c.Update(ctx, doc(t, alice, nil), nil); !errors.Is(err, method.ErrUnauthorized) {
			t.Fatalf("got %v", err)
		}
		if _, err := c.Update(ctx, doc(t, bob, nil), nil); !errors.Is(err, method.ErrNotFound) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("an empty driver result is refused", func(t *testing.T) {
		m, c := registered(t, nil, WithSigner(newSigner(t, alice+"#key-1")))
		m.bad = doc(t, bob, nil)
		if _, err := c.Update(ctx, doc(t, alice, nil), nil); !errors.Is(err, ErrInvalidResult) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a cancelled context stops before the driver", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		_, c := registered(t, nil)
		if _, err := c.Update(cctx, doc(t, alice, nil), nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestControllersRule(t *testing.T) {
	ctx := context.Background()
	t.Run("cid10#controllers.4 a signer of a listed controller may update", func(t *testing.T) {
		m := newFakeMethod()
		m.docs[mustDID(t, alice)] = doc(t, alice, []string{bob})
		c := newController(t, m, WithSigner(newSigner(t, bob+"#key-1")), WithResolver(fakeResolver{m: m}))
		if _, err := c.Update(ctx, doc(t, alice, []string{bob}), nil); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Deactivate(ctx, mustDID(t, alice), nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cid10#controllers.4 a signer outside the listed controllers is refused", func(t *testing.T) {
		m := newFakeMethod()
		m.docs[mustDID(t, alice)] = doc(t, alice, []string{bob})
		c := newController(t, m, WithSigner(newSigner(t, alice+"#key-1")), WithResolver(fakeResolver{m: m}))
		if _, err := c.Update(ctx, doc(t, alice, nil), nil); !errors.Is(err, ErrNotController) {
			t.Fatalf("the subject is not a controller when the property names others: %v", err)
		}
		if _, err := c.Deactivate(ctx, mustDID(t, alice), nil); !errors.Is(err, ErrNotController) {
			t.Fatalf("got %v", err)
		}
		if len(m.proofs) != 0 {
			t.Fatal("the driver must not be asked")
		}
		noSigner := newController(t, m, WithResolver(fakeResolver{m: m}))
		if _, err := noSigner.Update(ctx, doc(t, alice, nil), nil); !errors.Is(err, ErrNotController) {
			t.Fatalf("no signer: %v", err)
		}
	})
	t.Run("cid10#controllers.4 without a controller property the method decides", func(t *testing.T) {
		m := newFakeMethod()
		m.docs[mustDID(t, alice)] = doc(t, alice, nil)
		c := newController(t, m, WithSigner(newSigner(t, "did:example:anyone#k")), WithResolver(fakeResolver{m: m}))
		if _, err := c.Update(ctx, doc(t, alice, nil), nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a deactivated DID cannot be changed", func(t *testing.T) {
		m := newFakeMethod()
		m.docs[mustDID(t, alice)] = doc(t, alice, nil)
		m.deactivated[mustDID(t, alice)] = true
		c := newController(t, m, WithSigner(newSigner(t, alice+"#key-1")), WithResolver(fakeResolver{m: m}))
		if _, err := c.Update(ctx, doc(t, alice, nil), nil); !errors.Is(err, ErrDeactivated) {
			t.Fatalf("got %v", err)
		}
		if _, err := c.Deactivate(ctx, mustDID(t, alice), nil); !errors.Is(err, ErrDeactivated) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("an unresolvable current document is reported", func(t *testing.T) {
		m := newFakeMethod()
		c := newController(t, m, WithSigner(newSigner(t, alice+"#key-1")), WithResolver(fakeResolver{m: m}))
		_, err := c.Update(ctx, doc(t, alice, nil), nil)
		if !errors.Is(err, ErrCurrentDocument) || !errors.Is(err, resolution.NewError(resolution.CodeNotFound, "")) {
			t.Fatalf("got %v", err)
		}
		other := resolution.Result{Document: doc(t, bob, nil)}
		c = newController(t, m, WithResolver(fakeResolver{m: m, result: &other}))
		if _, err := c.Deactivate(ctx, mustDID(t, alice), nil); !errors.Is(err, ErrCurrentDocument) {
			t.Fatalf("a document of another DID: %v", err)
		}
	})
}

func TestDeactivate(t *testing.T) {
	ctx := context.Background()
	t.Run("the driver deactivates the DID", func(t *testing.T) {
		m, c := registered(t, nil, WithSigner(newSigner(t, alice+"#key-1")))
		res, err := c.Deactivate(ctx, mustDID(t, alice), map[string]any{"reason": "rotation"})
		if err != nil || !res.Metadata.Deactivated || !m.deactivated[mustDID(t, alice)] || m.lastExtra["reason"] != "rotation" {
			t.Fatalf("got %v %v", res, err)
		}
	})
	t.Run("errors", func(t *testing.T) {
		m, c := registered(t, nil, WithSigner(newSigner(t, alice+"#key-1")))
		if _, err := c.Deactivate(ctx, mustDID(t, "did:other:alice"), nil); !errors.Is(err, ErrMethodMismatch) {
			t.Fatalf("method: %v", err)
		}
		if _, err := c.Deactivate(ctx, mustDID(t, bob), nil); !errors.Is(err, method.ErrNotFound) {
			t.Fatalf("driver: %v", err)
		}
		m.bad = doc(t, bob, nil)
		if _, err := c.Deactivate(ctx, mustDID(t, alice), nil); !errors.Is(err, ErrInvalidResult) {
			t.Fatalf("metadata without deactivated: %v", err)
		}
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := c.Deactivate(cctx, mustDID(t, alice), nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("context: %v", err)
		}
	})
}

func TestNoKeyCustody(t *testing.T) {
	// The controller reaches keys only through method.Signer: the signer's
	// key id names a verification method and the private key stays with the
	// caller's signer.
	s := newSigner(t, alice+"#key-1")
	m, c := registered(t, nil, WithSigner(s))
	if _, err := c.Update(context.Background(), doc(t, alice, nil), nil); err != nil {
		t.Fatal(err)
	}
	pub := s.priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, []byte("update "+alice), m.proofs[0]) {
		t.Fatal("the driver's proof must come from the caller's signer")
	}
}
