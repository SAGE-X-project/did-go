package method

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
)

type fake struct{ name string }

func (f fake) Name() string       { return f.name }
func (f fake) Produces() []string { return []string{"application/did"} }
func (f fake) Create(context.Context, *document.Document, CreateOptions) (*CreateResult, error) {
	return nil, ErrNotSupported
}
func (f fake) Read(_ context.Context, d did.DID, _ ReadOptions) (*ReadResult, error) {
	return nil, fmt.Errorf("read %s: %w", d, ErrNotFound)
}
func (f fake) Update(context.Context, did.DID, *document.Document, UpdateOptions) (*UpdateResult, error) {
	return nil, ErrNotSupported
}
func (f fake) Deactivate(context.Context, did.DID, DeactivateOptions) (*DeactivateResult, error) {
	return nil, ErrUnauthorized
}

func TestRegistry(t *testing.T) {
	r, err := NewRegistry(fake{"web"}, fake{"key"})
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := r.Lookup("key"); !ok || m.Name() != "key" {
		t.Fatal("Lookup")
	}
	if _, ok := r.Lookup("peer"); ok {
		t.Fatal("unknown method found")
	}
	names := r.Names()
	if !slices.Equal(names, []string{"key", "web"}) {
		t.Fatalf("names %v", names)
	}
	names[0] = "x"
	if r.Names()[0] != "key" {
		t.Fatal("Names must be fresh")
	}
	for _, ms := range [][]Method{{nil}, {fake{"Key"}}, {fake{""}}, {fake{"key"}, fake{"key"}}} {
		if _, err := NewRegistry(ms...); err == nil {
			t.Errorf("%v accepted", ms)
		}
	}
	var nilReg *Registry
	if _, ok := nilReg.Lookup("key"); ok || nilReg.Names() != nil {
		t.Fatal("nil registry")
	}
	empty, err := NewRegistry()
	if err != nil || len(empty.Names()) != 0 {
		t.Fatal("empty registry")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.Lookup("web")
			_ = r.Names()
		}()
	}
	wg.Wait()
}

func TestErrors(t *testing.T) {
	m := fake{"key"}
	d, _ := did.Parse("did:key:z6Mk")
	if _, err := m.Read(context.Background(), d, ReadOptions{}); !errors.Is(err, ErrNotFound) {
		t.Fatal("wrapped ErrNotFound")
	}
	if _, err := m.Create(context.Background(), nil, CreateOptions{}); !errors.Is(err, ErrNotSupported) || err.Error() == "" {
		t.Fatal("ErrNotSupported")
	}
	if _, err := m.Update(context.Background(), d, nil, UpdateOptions{}); !errors.Is(err, ErrNotSupported) {
		t.Fatal("Update")
	}
	if _, err := m.Deactivate(context.Background(), d, DeactivateOptions{}); !errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrInvalidInput) {
		t.Fatal("Deactivate")
	}
	if len(m.Produces()) != 1 {
		t.Fatal("Produces")
	}
}
