package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/vm"
)

const (
	alice = "did:example:alice"
	bob   = "did:example:bob"
	// keyMultibase is the did:key specification's Ed25519 test vector.
	keyMultibase = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
)

func mustDID(t *testing.T, s string) did.DID {
	t.Helper()
	d, err := did.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustURL(t *testing.T, s string) did.DIDURL {
	t.Helper()
	u, err := did.ParseReference(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// doc builds a document for subject with one Multikey method usable for
// authentication and capabilityInvocation, the given controllers and
// services.
func doc(t *testing.T, subject string, controllers []string, services ...vm.Service) *document.Document {
	t.Helper()
	id := mustDID(t, subject)
	m := vm.Method{ID: mustURL(t, subject+"#key-1"), Type: vm.TypeMultikey, Controller: id, PublicKeyMultibase: keyMultibase}
	b := document.NewBuilder(id).VerificationMethod(m).
		Relationship(vm.Authentication, vm.Ref(m.ID)).
		Relationship(vm.CapabilityInvocation, vm.Ref(m.ID)).
		Service(services...)
	for _, c := range controllers {
		b = b.Controller(mustDID(t, c))
	}
	d, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// fakeSigner signs with an Ed25519 key held by the test, standing in for a
// key store outside the library.
type fakeSigner struct {
	id   did.DIDURL
	priv ed25519.PrivateKey
}

func newSigner(t *testing.T, keyID string) *fakeSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeSigner{id: mustURL(t, keyID), priv: priv}
}

func (s *fakeSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, msg), nil
}

func (s *fakeSigner) KeyID() did.DIDURL { return s.id }

// fakeMethod is an in-memory did:example registry. It requires a signer for
// every operation, as a method whose authorization is a signature would.
type fakeMethod struct {
	mu          sync.Mutex
	docs        map[did.DID]*document.Document
	deactivated map[did.DID]bool
	proofs      [][]byte
	lastExtra   map[string]any
	// bad, when set, makes every operation return an inconsistent result;
	// Create returns it as the document of another DID.
	bad *document.Document
}

var _ method.Method = (*fakeMethod)(nil)

func newFakeMethod() *fakeMethod {
	return &fakeMethod{docs: map[did.DID]*document.Document{}, deactivated: map[did.DID]bool{}}
}

func (f *fakeMethod) Name() string       { return "example" }
func (f *fakeMethod) Produces() []string { return nil }

func (f *fakeMethod) Read(context.Context, did.DID, method.ReadOptions) (*method.ReadResult, error) {
	return nil, method.ErrNotSupported
}

func (f *fakeMethod) prove(ctx context.Context, s method.Signer, op string, d did.DID) error {
	if s == nil {
		return fmt.Errorf("%w: %s needs a signature", method.ErrUnauthorized, op)
	}
	sig, err := s.Sign(ctx, []byte(op+" "+d.String()))
	if err != nil {
		return err
	}
	f.proofs = append(f.proofs, sig)
	return nil
}

func (f *fakeMethod) Create(ctx context.Context, input *document.Document, opts method.CreateOptions) (*method.CreateResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastExtra = opts.Extra
	if input == nil {
		return nil, fmt.Errorf("%w: did:example needs an input document", method.ErrInvalidInput)
	}
	if err := f.prove(ctx, opts.Signer, "create", input.ID()); err != nil {
		return nil, err
	}
	if f.bad != nil {
		return &method.CreateResult{DID: input.ID(), Document: f.bad}, nil
	}
	f.docs[input.ID()] = input
	return &method.CreateResult{DID: input.ID(), Document: input}, nil
}

func (f *fakeMethod) Update(ctx context.Context, d did.DID, next *document.Document, opts method.UpdateOptions) (*method.UpdateResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastExtra = opts.Extra
	if _, ok := f.docs[d]; !ok {
		return nil, method.ErrNotFound
	}
	if err := f.prove(ctx, opts.Signer, "update", d); err != nil {
		return nil, err
	}
	if f.bad != nil {
		return nil, nil
	}
	f.docs[d] = next
	return &method.UpdateResult{Document: next}, nil
}

func (f *fakeMethod) Deactivate(ctx context.Context, d did.DID, opts method.DeactivateOptions) (*method.DeactivateResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastExtra = opts.Extra
	if _, ok := f.docs[d]; !ok {
		return nil, method.ErrNotFound
	}
	if err := f.prove(ctx, opts.Signer, "deactivate", d); err != nil {
		return nil, err
	}
	if f.bad != nil {
		return &method.DeactivateResult{}, nil
	}
	f.deactivated[d] = true
	return &method.DeactivateResult{Metadata: document.Metadata{Deactivated: true}}, nil
}

// fakeResolver resolves from the fakeMethod's registry, as a resolver over
// that driver would.
type fakeResolver struct {
	m *fakeMethod
	// result, when set, is returned for every DID.
	result *resolution.Result
}

func (r fakeResolver) Resolve(_ context.Context, d did.DID, _ resolution.ResolutionOptions) resolution.Result {
	if r.result != nil {
		return *r.result
	}
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	if r.m.deactivated[d] {
		return resolution.Result{DocumentMetadata: document.Metadata{Deactivated: true}}
	}
	cur, ok := r.m.docs[d]
	if !ok {
		return resolution.ErrorResult(resolution.NewError(resolution.CodeNotFound, d.String()))
	}
	return resolution.Result{Document: cur}
}
