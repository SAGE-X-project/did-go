package sage

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/sage-x-project/did-go/did"
)

const (
	testDID      = "did:sage:web:registry.example:agent-1"
	testObserved = int64(1_800_000_000)
)

// Deterministic public keys for the four chapter 11 algorithms.
var (
	edKey  = ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	xKey   = mustX25519()
	p256   = mustP256()
	k1Base = mustHex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
		"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8") // the secp256k1 generator
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustX25519() []byte {
	k, err := ecdh.X25519().NewPrivateKey(append(make([]byte, 31), 9))
	if err != nil {
		panic(err)
	}
	return k.PublicKey().Bytes()
}

func mustP256() []byte {
	k, err := ecdh.P256().NewPrivateKey(append(make([]byte, 31), 7))
	if err != nil {
		panic(err)
	}
	return k.PublicKey().Bytes()
}

func mustDID(t testing.TB, s string) did.DID {
	t.Helper()
	d, err := did.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func issued(n int64) *int64 { return &n }

// activeRecord is an active record with an Ed25519 signing key, an X25519
// key-agreement key and one A2A interface service.
func activeRecord(t testing.TB) Record {
	return Record{
		DID:        mustDID(t, testDID),
		Controller: "controller-1",
		State:      StateActive,
		Version:    "7",
		Keys: []Key{
			{Name: "agree", Alg: AlgX25519, Material: xKey, State: KeyAccepted},
			{Name: "sign", Alg: AlgEd25519, Material: edKey, State: KeyAccepted},
		},
		Services: []Service{{Name: "a2a", Type: "A2AInterface", URI: "https://agent.example/a2a"}},
		Observation: Observation{
			Issued: issued(1_799_999_000), Source: "web-registry-1", Time: testObserved,
		},
	}
}

// fakeSource returns records and errors by DID and counts observations.
type fakeSource struct {
	mu      sync.Mutex
	records map[string]Record
	errs    map[string]error
	calls   int
}

func newSource(recs ...Record) *fakeSource {
	s := &fakeSource{records: map[string]Record{}, errs: map[string]error{}}
	for _, r := range recs {
		s.records[r.DID.String()] = r
	}
	return s
}

func (s *fakeSource) Observe(_ context.Context, d did.DID) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if err, ok := s.errs[d.String()]; ok {
		return Record{}, err
	}
	if r, ok := s.records[d.String()]; ok {
		return r, nil
	}
	return Record{}, NewError(CodeRecordNotFound, "no record")
}

func (s *fakeSource) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}
