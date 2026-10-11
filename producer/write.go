package producer

import (
	"errors"
	"fmt"

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

func str(s string) wire.Node { return wire.StringNode(s) }

func strs(ss []string) wire.Node {
	items := make([]wire.Node, len(ss))
	for i, s := range ss {
		items[i] = str(s)
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
	root.add(wire.PropController, wire.Shaped(shape, items))
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

// method writes a verification method (wire.FromMethod), locating a value
// that cannot be written under where.
func (w writer) method(m vm.Method, where string) (wire.Node, error) {
	n, err := wire.FromMethod(m, w.includeSecret)
	return n, located(where, err)
}

// service writes a service (wire.FromService), locating a value that
// cannot be written under where.
func (w writer) service(s vm.Service, where string) (wire.Node, error) {
	n, err := wire.FromService(s)
	return n, located(where, err)
}

// located turns a *wire.PropertyError into an *Error whose Property is the
// full path of the value.
func located(where string, err error) error {
	var pe *wire.PropertyError
	if errors.As(err, &pe) {
		return errorf(where+"."+pe.Property, "", "%v", pe.Err)
	}
	return err
}
