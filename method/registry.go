package method

import (
	"fmt"
	"slices"

	"github.com/sage-x-project/did-go/did"
)

// Registry maps method names to drivers. It is built once by NewRegistry and
// never changes, so it is safe for concurrent use. There is no global
// registry: callers pass drivers explicitly (docs/12 §6.2).
type Registry struct {
	methods map[string]Method
}

// NewRegistry returns a registry of the given drivers. A nil driver, a name
// that is not a method-name (DID Core 1.0 §3.1) or a name given twice is an
// error.
func NewRegistry(ms ...Method) (*Registry, error) {
	r := &Registry{methods: make(map[string]Method, len(ms))}
	for i, m := range ms {
		if m == nil {
			return nil, fmt.Errorf("method: driver %d is nil", i)
		}
		name := m.Name()
		if !did.IsMethodName(name) {
			return nil, fmt.Errorf("method: %q is not a method name", name)
		}
		if _, dup := r.methods[name]; dup {
			return nil, fmt.Errorf("method: %q registered twice", name)
		}
		r.methods[name] = m
	}
	return r, nil
}

// Lookup returns the driver for a method name.
func (r *Registry) Lookup(name string) (Method, bool) {
	if r == nil {
		return nil, false
	}
	m, ok := r.methods[name]
	return m, ok
}

// Names returns the registered method names, sorted, in a fresh slice.
func (r *Registry) Names() []string {
	if r == nil {
		return nil
	}
	names := make([]string, 0, len(r.methods))
	for n := range r.methods {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}
