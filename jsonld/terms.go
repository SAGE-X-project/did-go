package jsonld

import (
	"fmt"
	"strings"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/spec"
)

// ContextEntry is the representation-specific entry of the JSON-LD
// representation (DID Core 1.0 §6.3: "The JSON-LD representation defines the
// following representation-specific entries: @context").
const ContextEntry = "@context"

// RepresentationEntries returns the names of every known
// representation-specific entry, in a fresh slice. The JSON representation
// defines none and the JSON-LD representation defines @context (DID Core 1.0
// §6.2, §6.3; DID 1.1 §6.2.3).
func RepresentationEntries() []string { return []string{ContextEntry} }

// IsRepresentationEntry reports whether name is a known
// representation-specific entry.
func IsRepresentationEntry(name string) bool { return name == ContextEntry }

// IsKeyword reports whether name has the form of a JSON-LD keyword. Keywords
// are not terms, so the rules on undefined terms never drop them.
func IsKeyword(name string) bool { return strings.HasPrefix(name, "@") }

// Context is a parsed @context value: a string, a map, or a list of strings
// and maps (DID 1.1 §6.2.3: "either a string or a list containing any
// combination of strings and/or ordered maps").
type Context struct {
	items []document.Value
	list  bool
}

// ParseContext checks that v has a JSON-LD @context form and returns it.
// Strings must not be empty.
func ParseContext(v document.Value) (Context, error) {
	switch x := v.(type) {
	case document.List:
		for i, item := range x.Items() {
			if err := checkItem(item); err != nil {
				return Context{}, fmt.Errorf("jsonld: @context item %d: %w", i, err)
			}
		}
		return Context{items: x.Items(), list: true}, nil
	default:
		if err := checkItem(v); err != nil {
			return Context{}, fmt.Errorf("jsonld: @context: %w", err)
		}
		return Context{items: []document.Value{v}}, nil
	}
}

func checkItem(v document.Value) error {
	switch x := v.(type) {
	case document.String:
		if x == "" {
			return fmt.Errorf("a context URL is not empty")
		}
		return nil
	case document.Map:
		return nil
	}
	return fmt.Errorf("a context is a string or a map, not %T", v)
}

// First returns the first item when it is a string.
func (c Context) First() (string, bool) {
	if len(c.items) == 0 {
		return "", false
	}
	s, ok := c.items[0].(document.String)
	return string(s), ok
}

// IsList reports whether the value was a list.
func (c Context) IsList() bool { return c.list }

// Len returns the number of contexts.
func (c Context) Len() int { return len(c.items) }

// Value returns the @context value in the form it was read.
func (c Context) Value() document.Value {
	if !c.list && len(c.items) == 1 {
		return c.items[0]
	}
	l, _ := document.NewList(c.items...)
	return l
}

// ProductionContext returns the @context to write for a JSON-LD
// representation of version v (DID Core 1.0 §6.3.1, DID 1.1 §6.2.3): the
// version's base context URL first, followed by the other items of
// existing, in order. A leading DID base context of existing (the base
// context of the version it was read or built as) is replaced, and the base
// context of v is not repeated; a DID base context of another version that
// existing names after its first item was added on purpose, as the did:key
// Context Creation Algorithm adds https://www.w3.org/ns/did/v1.1 to a DID
// Core 1.0 document, and is kept. The result is the JSON String of the base
// context when nothing follows and existing was not a list; otherwise it is
// a list. existing may be nil.
func ProductionContext(v spec.Version, existing document.Value) (document.Value, error) {
	p, err := spec.ProfileOf(v)
	if err != nil {
		return nil, fmt.Errorf("jsonld: %w", err)
	}
	base := document.String(p.ContextURL)
	if existing == nil {
		return base, nil
	}
	c, err := ParseContext(existing)
	if err != nil {
		return nil, err
	}
	items := []document.Value{base}
	for i, item := range c.items {
		if s, ok := item.(document.String); ok {
			if _, isBase := VersionOfContext(string(s)); isBase && (i == 0 || s == base) {
				continue
			}
		}
		items = append(items, item)
	}
	if len(items) == 1 && !c.list {
		return base, nil
	}
	l, _ := document.NewList(items...)
	return l, nil
}

// Terms is a set of terms defined by a @context.
type Terms struct{ set map[string]bool }

// Defines reports whether term is defined. Keywords are always reported as
// defined, because the undefined-term rules apply to terms only.
func (t Terms) Defines(term string) bool { return IsKeyword(term) || t.set[term] }

// Terms returns the terms defined by the contexts and true, or false when
// some context cannot be resolved locally (a URL other than a DID base
// context). A DID base context contributes the terms spec lists for its
// version; an inline map contributes its term definitions, including those
// of scoped contexts.
func (c Context) Terms() (Terms, bool) {
	t := Terms{set: map[string]bool{}}
	for _, item := range c.items {
		switch x := item.(type) {
		case document.String:
			v, ok := VersionOfContext(string(x))
			if !ok {
				return Terms{}, false
			}
			p, _ := spec.ProfileOf(v)
			for _, term := range p.Terms() {
				t.set[term] = true
			}
		case document.Map:
			addInline(x, t.set)
		}
	}
	return t, true
}

// addInline adds the term definitions of an inline context map.
func addInline(m document.Map, into map[string]bool) {
	for _, e := range m.Entries() {
		if IsKeyword(e.Key) {
			continue
		}
		into[e.Key] = true
		def, ok := e.Value.(document.Map)
		if !ok {
			continue
		}
		if scoped, ok := def.Get(ContextEntry); ok {
			if sm, ok := scoped.(document.Map); ok {
				addInline(sm, into)
			}
		}
	}
}
