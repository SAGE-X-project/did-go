package resolver

import (
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/vm"
)

// expand implements the expandRelativeUrls step of DID Resolution §4.4
// (step 6): it iterates over the services, verification methods,
// verification relationships and extension-defined properties of d, and
// replaces every id of an object that is a relative DID URL, and every
// verification relationship entry that is a relative DID URL, with the
// absolute DID URL obtained by the rules of DID Core 1.0 §3.2.2 (RFC 3986 §5
// with the DID of the document as base). It returns a new document; d does
// not change.
func expand(d *document.Document) (*document.Document, error) {
	base := d.ID().URL()
	b := document.NewBuilder(d.ID()).Controller(d.Controllers()...).AlsoKnownAs(d.AlsoKnownAs()...)
	if d.ControllerShape() != vm.ShapeDefault {
		b.ControllerShape(d.ControllerShape())
	}
	if ms := d.VerificationMethods(); ms != nil {
		b.VerificationMethod() // keep an empty set present
		for _, m := range ms {
			b.VerificationMethod(expandMethod(m, base))
		}
	}
	for _, p := range vm.Purposes() {
		rels := d.Relationship(p)
		if rels == nil {
			continue
		}
		out := make([]vm.Relationship, len(rels))
		for i, r := range rels {
			if m, ok := r.Method(); ok {
				out[i] = vm.Embed(expandMethod(m, base))
				continue
			}
			ref, _ := r.Reference()
			out[i] = vm.Ref(absolute(ref, base))
		}
		b.Relationship(p, out...)
	}
	if ss := d.Services(); ss != nil {
		b.Service() // keep an empty set present
		for _, s := range ss {
			s.ID = absoluteString(s.ID, base)
			s.Extra = expandJSONMap(s.Extra, base)
			for i := range s.ServiceEndpoint {
				s.ServiceEndpoint[i].Map = expandJSONMap(s.ServiceEndpoint[i].Map, base)
			}
			b.Service(s)
		}
	}
	for _, e := range d.Extensions().Entries() {
		b.Extension(e.Key, expandValue(e.Value, base))
	}
	for _, e := range d.RepresentationEntries().Entries() {
		b.RepresentationEntry(e.Key, e.Value)
	}
	return b.Build()
}

func expandMethod(m vm.Method, base did.DIDURL) vm.Method {
	m.ID = absolute(m.ID, base)
	m.PublicKeyJwk = expandJSONMap(m.PublicKeyJwk, base)
	m.Extra = expandJSONMap(m.Extra, base)
	return m
}

// absolute resolves u against base when u is a relative DID URL.
func absolute(u did.DIDURL, base did.DIDURL) did.DIDURL {
	if !u.IsRelative() {
		return u
	}
	if abs, err := u.Resolve(base); err == nil {
		return abs
	}
	return u
}

// absoluteString resolves s against base when s is a relative DID URL; any
// other string, such as an absolute URL, is returned unchanged.
func absoluteString(s string, base did.DIDURL) string {
	u, err := did.ParseReference(s)
	if err != nil || !u.IsRelative() {
		return s
	}
	return absolute(u, base).String()
}

// expandValue walks an extension value and makes the id of every map whose
// id is a relative DID URL absolute. Rebuilding cannot fail: keys stay
// unique and values stay non-nil.
func expandValue(v document.Value, base did.DIDURL) document.Value {
	switch t := v.(type) {
	case document.Map:
		entries := t.Entries()
		for i, e := range entries {
			if s, ok := e.Value.(document.String); ok && e.Key == "id" {
				entries[i].Value = document.String(absoluteString(string(s), base))
			} else {
				entries[i].Value = expandValue(e.Value, base)
			}
		}
		m, _ := document.NewMap(entries...)
		return m
	case document.List:
		items := t.Items()
		for i, item := range items {
			items[i] = expandValue(item, base)
		}
		l, _ := document.NewList(items...)
		return l
	}
	return v
}

// expandJSONMap traverses a public typed map without converting its JSON
// numbers to document.Value or float64. Only string-valued id properties are
// resolved. Every map/list is copied; scalar types and values remain intact.
// Typed secret method fields and representation entries are not public maps.
func expandJSONMap(input map[string]any, base did.DIDURL) map[string]any {
	if input == nil {
		return nil
	}
	out := make(map[string]any, len(input))
	for name, value := range input {
		if id, ok := value.(string); name == "id" && ok {
			out[name] = absoluteString(id, base)
		} else {
			out[name] = expandJSONValue(value, base)
		}
	}
	return out
}

func expandJSONValue(value any, base did.DIDURL) any {
	switch v := value.(type) {
	case map[string]any:
		return expandJSONMap(v, base)
	case []any:
		if v == nil {
			return []any(nil)
		}
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = expandJSONValue(item, base)
		}
		return out
	}
	return value
}
