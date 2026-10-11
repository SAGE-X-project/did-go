package wire

import (
	"fmt"
	"slices"

	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// PropertyError reports a value of a verification method or a service that
// cannot be written as JSON.
type PropertyError struct {
	// Property locates the value inside the method or service, for example
	// "publicKeyJwk" or "serviceEndpoint[1]".
	Property string
	// Err says what is wrong.
	Err error
}

// Error describes the value.
func (e *PropertyError) Error() string { return "wire: " + e.Property + ": " + e.Err.Error() }

// Unwrap returns the cause.
func (e *PropertyError) Unwrap() error { return e.Err }

// StringNode returns the JSON string s.
func StringNode(s string) Node { return Node{Kind: String, Text: s} }

// Shaped writes one element as itself under vm.ShapeSingle and the elements
// as an array otherwise.
func Shaped(s vm.Shape, items []Node) Node {
	if s.Resolve(len(items)) == vm.ShapeSingle {
		return items[0]
	}
	return Node{Kind: Array, Items: items}
}

type members []Member

func (m *members) add(name string, n Node) { *m = append(*m, Member{Name: name, Value: n}) }

// anyValue adds the plain Go JSON value v under name.
func (m *members) anyValue(name string, v any) error {
	n, err := FromAny(v)
	if err != nil {
		return &PropertyError{Property: name, Err: err}
	}
	m.add(name, n)
	return nil
}

// extra adds additional properties sorted by name.
func (m *members) extra(extra map[string]any) error {
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if err := m.anyValue(k, extra[k]); err != nil {
			return err
		}
	}
	return nil
}

// FromMethod writes a verification method as a JSON object by the
// production rules of DID Core 1.0 §6.2.1 and DID 1.1 §6.2.1: the members of
// MethodProperties in that order, then the additional properties sorted by
// name. Secret key material is written only when includeSecret is set. A
// value that cannot be written is reported as a *PropertyError.
func FromMethod(m vm.Method, includeSecret bool) (Node, error) {
	var out members
	out.add(PropID, StringNode(m.ID.String()))
	out.add(PropType, StringNode(m.Type))
	out.add(PropController, StringNode(m.Controller.String()))
	if m.Expires != nil {
		out.add(PropExpires, StringNode(spec.FormatTimestamp(*m.Expires)))
	}
	if m.Revoked != nil {
		out.add(PropRevoked, StringNode(spec.FormatTimestamp(*m.Revoked)))
	}
	if m.PublicKeyMultibase != "" {
		out.add(PropPublicKeyMultibase, StringNode(m.PublicKeyMultibase))
	}
	if m.PublicKeyJwk != nil {
		if err := out.anyValue(PropPublicKeyJwk, m.PublicKeyJwk); err != nil {
			return Node{}, err
		}
	}
	if includeSecret {
		if m.SecretKeyMultibase != "" {
			out.add(PropSecretKeyMultibase, StringNode(m.SecretKeyMultibase))
		}
		if m.SecretKeyJwk != nil {
			if err := out.anyValue(PropSecretKeyJwk, m.SecretKeyJwk); err != nil {
				return Node{}, err
			}
		}
	}
	if err := out.extra(m.Extra); err != nil {
		return Node{}, err
	}
	return Node{Kind: Object, Members: out}, nil
}

// FromService writes a service as a JSON object: id when set, type and
// serviceEndpoint in their recorded shapes, then the additional properties
// sorted by name. A value that cannot be written is reported as a
// *PropertyError.
func FromService(s vm.Service) (Node, error) {
	var out members
	if s.ID != "" {
		out.add(PropID, StringNode(s.ID))
	}
	types := make([]Node, len(s.Type))
	for i, t := range s.Type {
		types[i] = StringNode(t)
	}
	out.add(PropType, Shaped(s.TypeShape, types))
	eps := make([]Node, len(s.ServiceEndpoint))
	for i, e := range s.ServiceEndpoint {
		if e.Map == nil {
			eps[i] = StringNode(e.URL)
			continue
		}
		n, err := FromAny(e.Map)
		if err != nil {
			return Node{}, &PropertyError{Property: fmt.Sprintf("%s[%d]", PropServiceEndpoint, i), Err: err}
		}
		eps[i] = n
	}
	out.add(PropServiceEndpoint, Shaped(s.EndpointShape, eps))
	if err := out.extra(s.Extra); err != nil {
		return Node{}, err
	}
	return Node{Kind: Object, Members: out}, nil
}
