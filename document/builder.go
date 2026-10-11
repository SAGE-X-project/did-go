package document

import (
	"errors"
	"reflect"
	"slices"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/vm"
)

// relationshipStatement returns the "set of one or more verification
// methods" statement of CID 1.0 §2.3.1 to §2.3.5 for p.
func relationshipStatement(p vm.Purpose) string {
	switch p {
	case vm.Authentication:
		return "cid10#authentication.2"
	case vm.AssertionMethod:
		return "cid10#assertion.2"
	case vm.KeyAgreement:
		return "cid10#key-agreement.2"
	case vm.CapabilityInvocation:
		return "cid10#capability-invocation.2"
	}
	return "cid10#capability-delegation.2"
}

// Builder accumulates the properties of a DID document. Every value is
// copied when it is added, and Build returns a new Document each time. A
// Builder is not safe for concurrent use.
type Builder struct {
	id            did.DID
	controllers   []did.DID
	ctrlShape     vm.Shape
	alsoKnownAs   []string
	methods       []vm.Method
	relationships [6][]vm.Relationship
	present       [6]bool
	services      []vm.Service
	extensions    []Entry
	repr          []Entry
	errs          []error
}

// NewBuilder starts a document for the DID subject id.
func NewBuilder(id did.DID) *Builder { return &Builder{id: id} }

// NewBuilderFrom starts a builder with every property of d.
func NewBuilderFrom(d *Document) *Builder {
	b := &Builder{
		id: d.id, controllers: slices.Clone(d.controllers), ctrlShape: d.ctrlShape,
		alsoKnownAs: slices.Clone(d.alsoKnownAs), methods: cloneMethods(d.methods), services: d.Services(),
		extensions: d.extensions.Entries(), repr: d.repr.Entries(),
	}
	for _, p := range vm.Purposes() {
		b.relationships[p] = cloneRelationships(d.relationships[p])
		b.present[p] = d.relationships[p] != nil
	}
	return b
}

// Controller adds DID controllers.
func (b *Builder) Controller(c ...did.DID) *Builder {
	b.controllers = append(b.controllers, c...)
	return b
}

// ControllerShape sets whether the controller property is written as a
// single string or as a set. Without it, Build writes a single string for one
// controller and a set for more; vm.ShapeSet with no controller is the empty
// set "controller": [].
func (b *Builder) ControllerShape(s vm.Shape) *Builder {
	b.ctrlShape = s
	return b
}

// AlsoKnownAs adds alsoKnownAs URIs.
func (b *Builder) AlsoKnownAs(u ...string) *Builder {
	b.alsoKnownAs = append(b.alsoKnownAs, u...)
	return b
}

// VerificationMethod adds verificationMethod entries.
func (b *Builder) VerificationMethod(m ...vm.Method) *Builder {
	for _, x := range m {
		b.methods = append(b.methods, x.Clone())
	}
	return b
}

// Relationship adds elements to a verification relationship. Calling it
// with no element makes the property present and empty, which Build rejects
// ("a set of one or more verification methods").
func (b *Builder) Relationship(p vm.Purpose, r ...vm.Relationship) *Builder {
	if !p.Valid() {
		b.errs = append(b.errs, invalidDoc("relationship", "", "unknown verification relationship %v", p))
		return b
	}
	b.present[p] = true
	b.relationships[p] = append(b.relationships[p], cloneRelationships(r)...)
	return b
}

// Service adds service entries.
func (b *Builder) Service(s ...vm.Service) *Builder {
	for _, x := range s {
		b.services = append(b.services, x.Clone())
	}
	return b
}

// Extension adds a property that is not a core property (DID Core 1.0 §4.1
// extensibility).
func (b *Builder) Extension(name string, v Value) *Builder {
	b.extensions = append(b.extensions, Entry{name, v})
	return b
}

// RepresentationEntry adds a representation-specific entry such as
// @context (DID Core 1.0 §6.1).
func (b *Builder) RepresentationEntry(name string, v Value) *Builder {
	b.repr = append(b.repr, Entry{name, v})
	return b
}

// Build checks the rules that hold in every DID version and returns a new
// Document, or the first violation as a *ConformanceError. Version-specific
// rules are reported by Validate.
func (b *Builder) Build() (*Document, error) {
	if len(b.errs) > 0 {
		return nil, b.errs[0]
	}
	checks := []func() error{b.checkSubject, b.checkControllers, b.checkAlsoKnownAs,
		b.checkMethods, b.checkRelationships, b.checkServices, b.checkEntries}
	for _, check := range checks {
		if err := check(); err != nil {
			return nil, err
		}
	}
	return b.document()
}

func (b *Builder) document() (*Document, error) {
	ext, err := NewMap(b.extensions...)
	if err != nil {
		return nil, invalidDoc("extension", "", "%v", err)
	}
	repr, err := NewMap(b.repr...)
	if err != nil {
		return nil, invalidDoc("representation entry", "", "%v", err)
	}
	d := &Document{
		id: b.id, controllers: slices.Clone(b.controllers), alsoKnownAs: slices.Clone(b.alsoKnownAs),
		methods: cloneMethods(b.methods), extensions: ext, repr: repr,
	}
	if len(b.controllers) > 0 || b.ctrlShape == vm.ShapeSet {
		d.ctrlShape = b.ctrlShape.Resolve(len(b.controllers))
	}
	for _, s := range b.services {
		c := s.Clone()
		c.TypeShape = s.TypeShape.Resolve(len(s.Type))
		c.EndpointShape = s.EndpointShape.Resolve(len(s.ServiceEndpoint))
		d.services = append(d.services, c)
	}
	for _, p := range vm.Purposes() {
		if b.present[p] {
			d.relationships[p] = cloneRelationships(b.relationships[p])
		}
	}
	return d, nil
}

func (b *Builder) checkSubject() error {
	if b.id.IsZero() {
		return invalidDoc("id", "cid10#subjects.2", "a DID document has an id that is a DID")
	}
	return nil
}

func (b *Builder) checkControllers() error {
	if err := vm.CheckShape("controller", "core10#did-controller.2", b.ctrlShape, len(b.controllers)); err != nil {
		return invalidDoc("controller", "core10#did-controller.2", "%v", err)
	}
	for i, c := range b.controllers {
		if c.IsZero() {
			return invalidDoc("controller", "core10#did-controller.2", "a controller is a DID")
		}
		if slices.Contains(b.controllers[:i], c) {
			return invalidDoc("controller", "core10#did-controller.2", "a set of controllers has no duplicates")
		}
	}
	return nil
}

func (b *Builder) checkAlsoKnownAs() error {
	for i, u := range b.alsoKnownAs {
		if !vm.IsURI(u) {
			return invalidDoc("alsoKnownAs", "cid10#also-known-as.2", "%q is not an RFC 3986 URI", u)
		}
		if slices.Contains(b.alsoKnownAs[:i], u) {
			return invalidDoc("alsoKnownAs", "cid10#also-known-as.2", "a set has no duplicates")
		}
	}
	return nil
}

// absolute resolves a method or reference id against the subject so that
// "#k" and "did:example:1#k" compare equal.
func (b *Builder) absolute(property string, u did.DIDURL) (did.DIDURL, error) {
	if !u.IsRelative() {
		return u, nil
	}
	abs, err := u.Resolve(b.id.URL())
	if err != nil {
		return did.DIDURL{}, invalidDoc(property, "did11-cr20260305#verification-methods.1", "%v", err)
	}
	return abs, nil
}

func (b *Builder) checkMethods() error {
	seen := map[did.DIDURL]vm.Method{}
	for _, m := range b.methods {
		if err := b.checkMethod("verificationMethod", m, seen, false); err != nil {
			return err
		}
	}
	return nil
}

// checkMethod validates m and records its absolute id. Two methods with the
// same id are an error, except that an embedded method may repeat an
// identical method (allowSame).
func (b *Builder) checkMethod(property string, m vm.Method, seen map[did.DIDURL]vm.Method, allowSame bool) error {
	if err := m.Validate(); err != nil {
		return fromVM(property, err)
	}
	abs, err := b.absolute(property, m.ID)
	if err != nil {
		return err
	}
	if prev, ok := seen[abs]; ok && (!allowSame || !reflect.DeepEqual(prev, m)) {
		return invalidDoc(property, "cid10#verification-methods.2", "verification method id %s is not unique", abs)
	}
	seen[abs] = m
	return nil
}

func (b *Builder) checkRelationships() error {
	seen := map[did.DIDURL]vm.Method{}
	for _, m := range b.methods {
		abs, _ := b.absolute("verificationMethod", m.ID)
		seen[abs] = m
	}
	for _, p := range vm.Purposes() {
		if b.present[p] && len(b.relationships[p]) == 0 {
			return invalidDoc(p.String(), relationshipStatement(p), "a verification relationship is a set of one or more verification methods")
		}
		var ids []did.DIDURL
		for _, r := range b.relationships[p] {
			id, err := b.checkElement(p, r, seen)
			if err != nil {
				return err
			}
			if slices.Contains(ids, id) {
				return invalidDoc(p.String(), relationshipStatement(p), "%s appears twice in the set", id)
			}
			ids = append(ids, id)
		}
	}
	return nil
}

func (b *Builder) checkElement(p vm.Purpose, r vm.Relationship, seen map[did.DIDURL]vm.Method) (did.DIDURL, error) {
	if err := r.Validate(); err != nil {
		return did.DIDURL{}, fromVM(p.String(), err)
	}
	if m, ok := r.Method(); ok {
		if err := b.checkMethod(p.String(), m, seen, true); err != nil {
			return did.DIDURL{}, err
		}
	}
	return b.absolute(p.String(), r.ID())
}

func (b *Builder) checkServices() error {
	var ids []string
	for _, s := range b.services {
		if err := s.Validate(); err != nil {
			return fromVM("service", err)
		}
		if s.ID == "" {
			continue
		}
		id := s.ID
		if ref, err := did.ParseReference(id); err == nil {
			if abs, err := ref.Resolve(b.id.URL()); err == nil {
				id = abs.String()
			}
		}
		if slices.Contains(ids, id) {
			return invalidDoc("service", "cid10#services.7", "service id %s is not unique", s.ID)
		}
		ids = append(ids, id)
	}
	return nil
}

func (b *Builder) checkEntries() error {
	names := map[string]bool{}
	for _, n := range coreProperties() {
		names[n] = true
	}
	for _, group := range []struct {
		property string
		entries  []Entry
	}{{"extension", b.extensions}, {"representation entry", b.repr}} {
		for _, e := range group.entries {
			if e.Key == "" || names[e.Key] {
				return invalidDoc(group.property, "", "%q is empty, a core property or already used", e.Key)
			}
			names[e.Key] = true
			if err := CheckValue(e.Value); err != nil {
				return invalidDoc(group.property, "", "%s: %v", e.Key, err)
			}
		}
	}
	return nil
}

// fromVM converts a vm.Error into a ConformanceError that keeps its
// statement.
func fromVM(property string, err error) *ConformanceError {
	var ve *vm.Error
	if errors.As(err, &ve) {
		return &ConformanceError{
			Code: CodeInvalidControlledIdentifierDocument, Property: property + "." + ve.Property,
			Statement: ve.Statement, Reason: ve.Reason,
		}
	}
	return invalidDoc(property, "", "%v", err)
}
