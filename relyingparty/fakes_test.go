package relyingparty

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/crypto"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method/key"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

const alice = "did:example:alice"

// now is the fixed clock of the tests.
var now = time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)

func clock() time.Time { return now }

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

// fakeDereferencer returns stored results by DID URL and NOT_FOUND for any
// other URL. It records the requests it receives.
type fakeDereferencer struct {
	results map[string]resolution.DereferenceResult
	urls    []string
	opts    []resolution.DereferenceOptions
}

func newDereferencer() *fakeDereferencer {
	return &fakeDereferencer{results: map[string]resolution.DereferenceResult{}}
}

func (f *fakeDereferencer) Dereference(_ context.Context, u did.DIDURL, opts resolution.DereferenceOptions) resolution.DereferenceResult {
	f.urls = append(f.urls, u.String())
	f.opts = append(f.opts, opts)
	if r, ok := f.results[u.String()]; ok {
		return r
	}
	return resolution.ErrorDereferenceResult(resolution.NewError(resolution.CodeNotFound, u.String()))
}

// put stores a document as the result of dereferencing its DID.
func (f *fakeDereferencer) put(d *document.Document) {
	f.results[d.ID().String()] = resolution.DereferenceResult{ContentStream: d}
}

// fakeResolver returns stored results by DID and NOT_FOUND otherwise.
type fakeResolver map[string]resolution.Result

func (f fakeResolver) Resolve(_ context.Context, d did.DID, _ resolution.ResolutionOptions) resolution.Result {
	if r, ok := f[d.String()]; ok {
		return r
	}
	return resolution.ErrorResult(resolution.NewError(resolution.CodeNotFound, d.String()))
}

// didKey is a did:key DID with its document, expanded by the did:key
// driver, and the private key, which stays in the test.
type didKey struct {
	id   did.DID
	vmID did.DIDURL
	doc  *document.Document
	priv ed25519.PrivateKey
}

func newDIDKey(t *testing.T, v spec.Version, opts ...key.Option) didKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := crypto.FromCryptoKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	id, err := key.DIDFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	d, err := key.New(nil, opts...).Document(id.String(), representation.ProduceOptions{Version: v})
	if err != nil {
		t.Fatal(err)
	}
	return didKey{id: id, vmID: mustURL(t, id.String()+"#"+id.MSID()), doc: d, priv: priv}
}

// method returns a Multikey method of alice with the given fragment.
func method(t *testing.T, fragment string) vm.Method {
	t.Helper()
	return vm.Method{
		ID: mustURL(t, alice+"#"+fragment), Type: vm.TypeMultikey, Controller: mustDID(t, alice),
		PublicKeyMultibase: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
	}
}

func at(t time.Time) *time.Time { return &t }

// aliceDoc builds alice's document: controlled by the given DIDs, with an
// authentication method key-1, a revoked, an expired and a not yet expired
// method, a method claiming another controller, and the given services.
func aliceDoc(t *testing.T, controllers []did.DID, services ...vm.Service) *document.Document {
	t.Helper()
	revoked := method(t, "revoked")
	revoked.Revoked = at(now.Add(-time.Hour))
	expired := method(t, "expired")
	expired.Expires = at(now.Add(-time.Hour))
	later := method(t, "later")
	later.Expires = at(now.Add(time.Hour))
	later.Revoked = at(now.Add(time.Hour))
	foreign := method(t, "foreign")
	foreign.Controller = mustDID(t, "did:example:mallory")
	ms := []vm.Method{method(t, "key-1"), revoked, expired, later, foreign}
	b := document.NewBuilder(mustDID(t, alice)).Controller(controllers...).VerificationMethod(ms...).Service(services...)
	for _, m := range ms {
		b = b.Relationship(vm.Authentication, vm.Ref(m.ID))
	}
	d, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// verifyWith is the optional helper the package leaves to callers: it
// decodes the retrieved method's key with package crypto and verifies a
// signature.
func verifyWith(t *testing.T, m *vm.Method, msg, sig []byte) error {
	t.Helper()
	k, err := crypto.FromMethod(*m)
	if err != nil {
		return err
	}
	return k.Verify(msg, sig)
}
