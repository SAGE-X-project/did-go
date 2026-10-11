package document

import (
	"slices"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/vm"
)

// Document is a DID document. It is created only by Builder.Build, which
// validates it, and it never changes: every accessor returns a copy.
type Document struct {
	id            did.DID
	controllers   []did.DID
	alsoKnownAs   []string
	methods       []vm.Method
	relationships [6][]vm.Relationship
	services      []vm.Service
	extensions    Map
	repr          Map
}

// ID returns the DID subject (DID Core 1.0 §5.1.1).
func (d *Document) ID() did.DID { return d.id }

// Controllers returns the DID controllers, in a fresh slice; nil when the
// controller property is absent.
func (d *Document) Controllers() []did.DID { return slices.Clone(d.controllers) }

// AlsoKnownAs returns the alsoKnownAs URIs, in a fresh slice.
func (d *Document) AlsoKnownAs() []string { return slices.Clone(d.alsoKnownAs) }

// VerificationMethods returns copies of the verificationMethod entries.
func (d *Document) VerificationMethods() []vm.Method {
	return cloneMethods(d.methods)
}

// Relationship returns copies of the elements of one verification
// relationship; nil when the property is absent.
func (d *Document) Relationship(p vm.Purpose) []vm.Relationship {
	if !p.Valid() {
		return nil
	}
	return cloneRelationships(d.relationships[p])
}

// Services returns copies of the service entries.
func (d *Document) Services() []vm.Service {
	if d.services == nil {
		return nil
	}
	out := make([]vm.Service, len(d.services))
	for i, s := range d.services {
		out[i] = s.Clone()
	}
	return out
}

// Extensions returns the properties that are not core properties and not
// representation-specific (DID Core 1.0 §6.1 consumer rule: they are part of
// the data model).
func (d *Document) Extensions() Map { return d.extensions }

// RepresentationEntries returns the representation-specific entries, such as
// @context, that a consumer kept (DID Core 1.0 §6.1).
func (d *Document) RepresentationEntries() Map { return d.repr }

func cloneMethods(in []vm.Method) []vm.Method {
	if in == nil {
		return nil
	}
	out := make([]vm.Method, len(in))
	for i, m := range in {
		out[i] = m.Clone()
	}
	return out
}

func cloneRelationships(in []vm.Relationship) []vm.Relationship {
	if in == nil {
		return nil
	}
	out := make([]vm.Relationship, len(in))
	for i, r := range in {
		if m, ok := r.Method(); ok {
			out[i] = vm.Embed(m)
		} else {
			out[i] = r
		}
	}
	return out
}

// coreProperties are the property names of DID Core 1.0 §5 and CID 1.0 §2.1
// that Document models.
func coreProperties() []string {
	return []string{"id", "controller", "alsoKnownAs", "verificationMethod", "authentication",
		"assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation", "service"}
}
