package producer

import (
	"fmt"
	"slices"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/wire"
	"github.com/sage-x-project/did-go/jsonld"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// writer turns the data model into JSON nodes by the production rules of
// DID Core 1.0 §6.2.1 and DID 1.1 §6.2.1.
type writer struct {
	includeSecret bool
}

func str(s string) wire.Node { return wire.Node{Kind: wire.String, Text: s} }

func strs(ss []string) wire.Node {
	items := make([]wire.Node, len(ss))
	for i, s := range ss {
		items[i] = str(s)
	}
	return wire.Node{Kind: wire.Array, Items: items}
}

// shaped writes one element as itself under vm.ShapeSingle and the
// elements as an array otherwise.
func shaped(s vm.Shape, items []wire.Node) wire.Node {
	if s.Resolve(len(items)) == vm.ShapeSingle {
		return items[0]
	}
	return wire.Node{Kind: wire.Array, Items: items}
}

type members []wire.Member

func (m *members) add(name string, n wire.Node) { *m = append(*m, wire.Member{Name: name, Value: n}) }

// document writes the root object: all entries of the document in the root
// JSON object (DID Core 1.0 §6.2.1 "All entries of a DID document MUST be
// included in the root JSON Object").
// For JSON-LD it also returns the @context written.
func (w writer) document(d *document.Document, v spec.Version, ld bool) (wire.Node, document.Value, error) {
	var root members
	var ctx document.Value
	repr := d.RepresentationEntries()
	if ld {
		existing, _ := repr.Get(jsonld.ContextEntry)
		var err error
		if ctx, err = jsonld.ProductionContext(v, existing); err != nil {
			return wire.Node{}, nil, errorf(jsonld.ContextEntry, contextStatement(v), "%v", err)
		}
		if err := root.value(jsonld.ContextEntry, ctx); err != nil {
			return wire.Node{}, nil, err
		}
	}
	root.add(wire.PropID, str(d.ID().String()))
	w.controllers(&root, d)
	if aka := d.AlsoKnownAs(); aka != nil {
		root.add(wire.PropAlsoKnownAs, strs(aka))
	}
	if err := w.coreSets(&root, d); err != nil {
		return wire.Node{}, nil, err
	}
	if err := w.entries(&root, repr, d.Extensions()); err != nil {
		return wire.Node{}, nil, err
	}
	return wire.Node{Kind: wire.Object, Members: root}, ctx, nil
}

// contextStatement is the statement that fixes the @context value of v.
func contextStatement(v spec.Version) string {
	if v == spec.V10 {
		return "core10#production-0.3"
	}
	return "did11-cr20260305#json-ld-processors.4"
}

func (w writer) controllers(root *members, d *document.Document) {
	cs := d.Controllers()
	shape := d.ControllerShape()
	if len(cs) == 0 && shape != vm.ShapeSet {
		return
	}
	items := make([]wire.Node, len(cs))
	for i, c := range cs {
		items[i] = str(c.String())
	}
	root.add(wire.PropController, shaped(shape, items))
}

// coreSets writes verificationMethod, the verification relationships and
// service.
func (w writer) coreSets(root *members, d *document.Document) error {
	if ms := d.VerificationMethods(); ms != nil {
		items := make([]wire.Node, len(ms))
		for i, m := range ms {
			n, err := w.method(m, fmt.Sprintf("verificationMethod[%d]", i))
			if err != nil {
				return err
			}
			items[i] = n
		}
		root.add(wire.PropVerificationMethod, wire.Node{Kind: wire.Array, Items: items})
	}
	for _, p := range vm.Purposes() {
		rs := d.Relationship(p)
		if rs == nil {
			continue
		}
		items := make([]wire.Node, len(rs))
		for i, r := range rs {
			n, err := w.relationship(r, fmt.Sprintf("%s[%d]", p, i))
			if err != nil {
				return err
			}
			items[i] = n
		}
		root.add(p.String(), wire.Node{Kind: wire.Array, Items: items})
	}
	if ss := d.Services(); ss != nil {
		items := make([]wire.Node, len(ss))
		for i, s := range ss {
			n, err := w.service(s, fmt.Sprintf("service[%d]", i))
			if err != nil {
				return err
			}
			items[i] = n
		}
		root.add(wire.PropService, wire.Node{Kind: wire.Array, Items: items})
	}
	return nil
}

func (w writer) relationship(r vm.Relationship, where string) (wire.Node, error) {
	if m, ok := r.Method(); ok {
		return w.method(m, where)
	}
	ref, _ := r.Reference()
	return str(ref.String()), nil
}

// entries writes the representation-specific entries other than @context
// and the extensions, each in map order. An extension that has the name of
// a representation-specific entry would be read back as that entry, so it is
// refused.
func (w writer) entries(root *members, repr, ext document.Map) error {
	for _, e := range repr.Entries() {
		if e.Key == jsonld.ContextEntry {
			continue
		}
		if err := root.value(e.Key, e.Value); err != nil {
			return err
		}
	}
	for _, e := range ext.Entries() {
		if jsonld.IsRepresentationEntry(e.Key) {
			return errorf(e.Key, "", "an extension cannot be named like a representation-specific entry")
		}
		if err := root.value(e.Key, e.Value); err != nil {
			return err
		}
	}
	return nil
}

func (m *members) value(name string, v document.Value) error {
	n, err := wire.FromValue(v)
	if err != nil {
		return errorf(name, "", "%v", err)
	}
	m.add(name, n)
	return nil
}

func (w writer) method(m vm.Method, where string) (wire.Node, error) {
	var out members
	out.add(wire.PropID, str(m.ID.String()))
	out.add(wire.PropType, str(m.Type))
	out.add(wire.PropController, str(m.Controller.String()))
	if m.Expires != nil {
		out.add(wire.PropExpires, str(spec.FormatTimestamp(*m.Expires)))
	}
	if m.Revoked != nil {
		out.add(wire.PropRevoked, str(spec.FormatTimestamp(*m.Revoked)))
	}
	if m.PublicKeyMultibase != "" {
		out.add(wire.PropPublicKeyMultibase, str(m.PublicKeyMultibase))
	}
	if err := out.json(wire.PropPublicKeyJwk, m.PublicKeyJwk, where); err != nil {
		return wire.Node{}, err
	}
	if w.includeSecret {
		if m.SecretKeyMultibase != "" {
			out.add(wire.PropSecretKeyMultibase, str(m.SecretKeyMultibase))
		}
		if err := out.json(wire.PropSecretKeyJwk, m.SecretKeyJwk, where); err != nil {
			return wire.Node{}, err
		}
	}
	if err := out.extra(m.Extra, where); err != nil {
		return wire.Node{}, err
	}
	return wire.Node{Kind: wire.Object, Members: out}, nil
}

// json writes a JSON Web Key map when it is set.
func (m *members) json(name string, jwk map[string]any, where string) error {
	if jwk == nil {
		return nil
	}
	n, err := wire.FromAny(jwk)
	if err != nil {
		return errorf(where+"."+name, "", "%v", err)
	}
	m.add(name, n)
	return nil
}

// extra writes additional properties sorted by name.
func (m *members) extra(extra map[string]any, where string) error {
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		n, err := wire.FromAny(extra[k])
		if err != nil {
			return errorf(where+"."+k, "", "%v", err)
		}
		m.add(k, n)
	}
	return nil
}

func (w writer) service(s vm.Service, where string) (wire.Node, error) {
	var out members
	if s.ID != "" {
		out.add(wire.PropID, str(s.ID))
	}
	types := make([]wire.Node, len(s.Type))
	for i, t := range s.Type {
		types[i] = str(t)
	}
	out.add(wire.PropType, shaped(s.TypeShape, types))
	eps := make([]wire.Node, len(s.ServiceEndpoint))
	for i, e := range s.ServiceEndpoint {
		if e.Map == nil {
			eps[i] = str(e.URL)
			continue
		}
		n, err := wire.FromAny(e.Map)
		if err != nil {
			return wire.Node{}, errorf(fmt.Sprintf("%s.serviceEndpoint[%d]", where, i), "", "%v", err)
		}
		eps[i] = n
	}
	out.add(wire.PropServiceEndpoint, shaped(s.EndpointShape, eps))
	if err := out.extra(s.Extra, where); err != nil {
		return wire.Node{}, err
	}
	return wire.Node{Kind: wire.Object, Members: out}, nil
}
