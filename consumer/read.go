package consumer

import (
	"fmt"
	"time"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/wire"
	"github.com/sage-x-project/did-go/jsonld"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// reader turns JSON nodes into the data model by the consumption rules of
// DID Core 1.0 §6.2.2 and DID 1.1 §6.2.2.
type reader struct {
	terms   jsonld.Terms
	drop    bool
	dropped []string
}

// context checks the @context of a JSON-LD representation and prepares the
// undefined-term drop. Detection has already checked its first value.
func (r *reader) context(root wire.Node, v spec.Version, keep bool) error {
	statement := "did11-cr20260305#json-ld-processors.1"
	if v == spec.V10 {
		statement = "core10#consumption-0.1"
	}
	n, _ := root.Get(jsonld.ContextEntry)
	value, err := wire.ToValue(n)
	if err != nil {
		return errorf(jsonld.ContextEntry, statement, "%v", err)
	}
	c, err := jsonld.ParseContext(value)
	if err != nil {
		return errorf(jsonld.ContextEntry, statement, "%v", err)
	}
	if !keep {
		r.terms, r.drop = c.Terms()
	}
	return nil
}

// drops reports whether name, found at path, is a term to drop, and records
// path when it is.
func (r *reader) drops(path, name string) bool {
	if !r.drop || r.terms.Defines(name) {
		return false
	}
	r.dropped = append(r.dropped, path)
	return true
}

func want(n wire.Node, k wire.Kind, where, statement string) error {
	if n.Kind != k {
		return errorf(where, statement, "expected a JSON %s, found a JSON %s", k, n.Kind)
	}
	return nil
}

func (r *reader) document(root wire.Node) (*document.Document, error) {
	var subject did.DID
	if n, ok := root.Get(wire.PropID); ok {
		if err := want(n, wire.String, wire.PropID, "cid10#subjects.2"); err != nil {
			return nil, err
		}
		id, err := did.Parse(n.Text)
		if err != nil {
			return nil, errorf(wire.PropID, "cid10#subjects.2", "the id is not a DID: %v", err)
		}
		subject = id
	}
	b := document.NewBuilder(subject)
	for _, m := range root.Members {
		if err := r.entry(b, m); err != nil {
			return nil, err
		}
	}
	return b.Build()
}

// entry reads one member of the root object.
func (r *reader) entry(b *document.Builder, m wire.Member) error {
	switch m.Name {
	case wire.PropID:
		return nil
	case jsonld.ContextEntry:
		v, err := wire.ToValue(m.Value)
		if err != nil {
			return errorf(m.Name, "", "%v", err)
		}
		b.RepresentationEntry(m.Name, v)
		return nil
	case wire.PropController:
		return r.controllers(b, m.Value)
	case wire.PropAlsoKnownAs:
		return r.alsoKnownAs(b, m.Value)
	case wire.PropVerificationMethod:
		return r.methods(b, m.Value)
	case wire.PropService:
		return r.services(b, m.Value)
	}
	if p, err := vm.ParsePurpose(m.Name); err == nil {
		return r.relationship(b, p, m.Value)
	}
	if r.drops(m.Name, m.Name) { // core properties are defined by every base context
		return nil
	}
	v, err := wire.ToValue(m.Value)
	if err != nil {
		return errorf(m.Name, "", "%v", err)
	}
	b.Extension(m.Name, v)
	return nil
}

// controllers reads "a string or a set of strings that conform to the rules
// in 3.1 DID Syntax" (DID Core 1.0 §5.1.2) and records which form it was.
func (r *reader) controllers(b *document.Builder, n wire.Node) error {
	const statement = "core10#did-controller.2"
	items, shape := []wire.Node{n}, vm.ShapeSingle
	if n.Kind == wire.Array {
		items, shape = n.Items, vm.ShapeSet
	}
	b.ControllerShape(shape)
	for i, item := range items {
		where := fmt.Sprintf("controller[%d]", i)
		if err := want(item, wire.String, where, statement); err != nil {
			return err
		}
		c, err := did.Parse(item.Text)
		if err != nil {
			return errorf(where, statement, "not a DID: %v", err)
		}
		b.Controller(c)
	}
	return nil
}

func (r *reader) alsoKnownAs(b *document.Builder, n wire.Node) error {
	const statement = "cid10#also-known-as.2"
	if err := want(n, wire.Array, wire.PropAlsoKnownAs, statement); err != nil {
		return err
	}
	for i, item := range n.Items {
		if err := want(item, wire.String, fmt.Sprintf("alsoKnownAs[%d]", i), statement); err != nil {
			return err
		}
		b.AlsoKnownAs(item.Text)
	}
	return nil
}

func (r *reader) methods(b *document.Builder, n wire.Node) error {
	if err := want(n, wire.Array, wire.PropVerificationMethod, "cid10#verification-methods.1"); err != nil {
		return err
	}
	for i, item := range n.Items {
		m, err := r.method(item, fmt.Sprintf("verificationMethod[%d]", i))
		if err != nil {
			return err
		}
		b.VerificationMethod(m)
	}
	return nil
}

// relationship reads a verification relationship: a set whose elements are
// DID URL references or embedded verification methods (CID 1.0 §2.3).
func (r *reader) relationship(b *document.Builder, p vm.Purpose, n wire.Node) error {
	if err := want(n, wire.Array, p.String(), "cid10#authentication.3"); err != nil {
		return err
	}
	elems := make([]vm.Relationship, 0, len(n.Items))
	for i, item := range n.Items {
		where := fmt.Sprintf("%s[%d]", p, i)
		switch item.Kind {
		case wire.String:
			ref, err := did.ParseReference(item.Text)
			if err != nil {
				return errorf(where, "cid10#authentication.3", "not a DID URL: %v", err)
			}
			elems = append(elems, vm.Ref(ref))
		case wire.Object:
			m, err := r.method(item, where)
			if err != nil {
				return err
			}
			elems = append(elems, vm.Embed(m))
		default:
			return errorf(where, "cid10#authentication.3", "an element is a string or a verification method map, not a JSON %s", item.Kind)
		}
	}
	b.Relationship(p, elems...)
	return nil
}

func (r *reader) services(b *document.Builder, n wire.Node) error {
	if err := want(n, wire.Array, wire.PropService, "cid10#services.2"); err != nil {
		return err
	}
	for i, item := range n.Items {
		s, err := r.service(item, fmt.Sprintf("service[%d]", i))
		if err != nil {
			return err
		}
		b.Service(s)
	}
	return nil
}

// readTime reads a datetime ("JSON String where data model entry value is a
// datetime: A datetime"). Expires and revoked are XML Schema dateTimeStamp
// values (CID 1.0 §2.2), which carry a time zone; RFC 3339 is that form.
func readTime(n wire.Node, where, statement string) (*time.Time, error) {
	if err := want(n, wire.String, where, statement); err != nil {
		return nil, err
	}
	t, err := time.Parse(time.RFC3339, n.Text)
	if err != nil {
		return nil, errorf(where, statement, "not a dateTimeStamp")
	}
	return &t, nil
}

func (r *reader) method(n wire.Node, where string) (vm.Method, error) {
	var m vm.Method
	if err := want(n, wire.Object, where, "cid10#verification-methods.1"); err != nil {
		return m, err
	}
	for _, mem := range n.Members {
		if err := r.methodMember(&m, mem, where+"."+mem.Name); err != nil {
			return vm.Method{}, err
		}
	}
	return m, nil
}

func (r *reader) methodMember(m *vm.Method, mem wire.Member, where string) error {
	if r.drops(where, mem.Name) {
		return nil
	}
	var err error
	switch mem.Name {
	case wire.PropID:
		err = stringInto(mem.Value, where, "cid10#verification-methods.3", func(s string) (e error) {
			m.ID, e = did.ParseReference(s)
			return e
		})
	case wire.PropType:
		err = stringInto(mem.Value, where, "cid10#verification-methods.6", func(s string) error { m.Type = s; return nil })
	case wire.PropController:
		err = stringInto(mem.Value, where, "cid10#verification-methods.3", func(s string) (e error) {
			m.Controller, e = did.Parse(s)
			return e
		})
	case wire.PropExpires:
		m.Expires, err = readTime(mem.Value, where, "cid10#verification-methods.9")
	case wire.PropRevoked:
		m.Revoked, err = readTime(mem.Value, where, "cid10#verification-methods.11")
	case wire.PropPublicKeyMultibase:
		err = stringInto(mem.Value, where, "core10#verification-material.7", func(s string) error { m.PublicKeyMultibase = s; return nil })
	case wire.PropSecretKeyMultibase:
		err = stringInto(mem.Value, where, "cid10#Multikey.5", func(s string) error { m.SecretKeyMultibase = s; return nil })
	case wire.PropPublicKeyJwk:
		m.PublicKeyJwk, err = jwk(mem.Value, where, "cid10#JsonWebKey.3")
	case wire.PropSecretKeyJwk:
		m.SecretKeyJwk, err = jwk(mem.Value, where, "cid10#JsonWebKey.11")
	default:
		m.Extra = withExtra(m.Extra, mem)
	}
	return err
}

// stringInto checks that n is a string and passes it to set; an error from
// set is reported at where.
func stringInto(n wire.Node, where, statement string, set func(string) error) error {
	if err := want(n, wire.String, where, statement); err != nil {
		return err
	}
	if err := set(n.Text); err != nil {
		return errorf(where, statement, "%v", err)
	}
	return nil
}

func jwk(n wire.Node, where, statement string) (map[string]any, error) {
	if err := want(n, wire.Object, where, statement); err != nil {
		return nil, err
	}
	m, _ := wire.ToAny(n).(map[string]any)
	return m, nil
}

func withExtra(extra map[string]any, mem wire.Member) map[string]any {
	if extra == nil {
		extra = map[string]any{}
	}
	extra[mem.Name] = wire.ToAny(mem.Value)
	return extra
}

func (r *reader) service(n wire.Node, where string) (vm.Service, error) {
	var s vm.Service
	if err := want(n, wire.Object, where, "cid10#services.2"); err != nil {
		return s, err
	}
	for _, mem := range n.Members {
		var err error
		at := where + "." + mem.Name
		switch mem.Name {
		case wire.PropID:
			err = stringInto(mem.Value, at, "cid10#services.6", func(v string) error { s.ID = v; return nil })
		case wire.PropType:
			s.Type, s.TypeShape, err = serviceTypes(mem.Value, at)
		case wire.PropServiceEndpoint:
			s.ServiceEndpoint, s.EndpointShape, err = endpoints(mem.Value, at)
		default:
			if !r.drops(at, mem.Name) { // id, type and serviceEndpoint are defined by every base context
				s.Extra = withExtra(s.Extra, mem)
			}
		}
		if err != nil {
			return vm.Service{}, err
		}
	}
	return s, nil
}

// serviceTypes reads "a string or a set of strings" (CID 1.0 §2.1.4).
func serviceTypes(n wire.Node, where string) ([]string, vm.Shape, error) {
	const statement = "cid10#services.9"
	items, shape := []wire.Node{n}, vm.ShapeSingle
	if n.Kind == wire.Array {
		items, shape = n.Items, vm.ShapeSet
	}
	out := make([]string, len(items))
	for i, item := range items {
		if err := want(item, wire.String, where, statement); err != nil {
			return nil, 0, err
		}
		out[i] = item.Text
	}
	return out, shape, nil
}

// endpoints reads "a single string, a single map, or a set composed of one
// or more strings and/or maps" (CID 1.0 §2.1.4).
func endpoints(n wire.Node, where string) ([]vm.Endpoint, vm.Shape, error) {
	const statement = "cid10#services.12"
	items, shape := []wire.Node{n}, vm.ShapeSingle
	if n.Kind == wire.Array {
		items, shape = n.Items, vm.ShapeSet
	}
	out := make([]vm.Endpoint, len(items))
	for i, item := range items {
		switch item.Kind {
		case wire.String:
			out[i] = vm.Endpoint{URL: item.Text}
		case wire.Object:
			m, _ := wire.ToAny(item).(map[string]any)
			out[i] = vm.Endpoint{Map: m}
		default:
			return nil, 0, errorf(where, statement, "an endpoint is a string or a map, not a JSON %s", item.Kind)
		}
	}
	return out, shape, nil
}
