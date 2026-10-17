package dereferencer

import (
	"bytes"
	"strings"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/wire"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// fragment is DID Resolution §5.4.2, applied to the result of §5.4.1.
//
// The verificationRelationship option requires the DID URL to dereference
// to a verification method that the relationship authorizes (§5.1: "If the
// DID URL does not dereference to a verificationMethod, or the DID document
// does not authorize the verificationMethod for the specified
// verificationRelationship, then an error MUST be raised"). A DID URL
// without a fragment, or one whose resource is a URL list, therefore fails
// with INVALID_VERIFICATION_METHOD.
func (d *Dereferencer) fragment(u did.DIDURL, out resolution.DereferenceResult, opts resolution.DereferenceOptions) resolution.DereferenceResult {
	rel := opts.VerificationRelationship
	switch content := out.ContentStream.(type) {
	case *document.Document:
		switch {
		case rel != "" && !u.HasFragment():
			return failed(resolution.CodeInvalidVerificationMethod, "the DID URL has no fragment, so it does not dereference to a verification method")
		case rel != "":
			return verificationMethod(content, u.Fragment(), rel, out.DereferencingMetadata.ContentType)
		case u.HasFragment():
			return resolveFragment(content, u.Fragment(), out.DereferencingMetadata.ContentType)
		}
	case []string:
		if rel != "" {
			return failed(resolution.CodeInvalidVerificationMethod, "the DID URL dereferences to service endpoint URLs, not a verification method")
		}
		if u.HasFragment() {
			return inheritFragment(content, u.Fragment())
		}
	}
	return out
}

// fragmentMediaType returns the media type of a fragment of a document in
// representation docType. DID Resolution §5.4.2: "if the resource is a
// representation of a DID document with media type application/did, then
// the fragment is treated according to the rules associated with the
// JSON-LD 1.1: application/ld+json media type"; the same holds for
// application/did+ld+json, and a fragment of application/did+json, which is
// plain JSON, is application/json (did-go interpretation).
func fragmentMediaType(docType string) string {
	if docType == spec.MediaTypeDIDJSON {
		return "application/json"
	}
	return "application/ld+json"
}

// verificationMethod dereferences the fragment to a verification method and
// checks that the relationship rel authorizes it (DID Resolution §5.4.2
// steps 1 to 6), with document.SelectMethod: a fragment that selects no
// conforming verification method is INVALID_VERIFICATION_METHOD, and one
// that rel does not reference or embed is
// INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD. A rel that is not a
// verification relationship of the data model selects no relationship
// array, so no method can be associated with it.
func verificationMethod(doc *document.Document, frag, rel, docType string) resolution.DereferenceResult {
	p, err := vm.ParsePurpose(rel)
	if err != nil {
		return failed(resolution.CodeInvalidRelationshipForVerificationMethod, rel+" is not a verification relationship")
	}
	ref, err := did.ParseURL(doc.ID().String() + "#" + frag)
	if err != nil {
		return failed(resolution.CodeInvalidVerificationMethod, err.Error())
	}
	m, ce := document.SelectMethod(doc, ref, p)
	if ce != nil {
		return failed(resolution.Code(ce.Code), ce.Reason)
	}
	return resolution.DereferenceResult{
		ContentStream:         *m,
		DereferencingMetadata: resolution.DereferencingMetadata{ContentType: fragmentMediaType(docType)},
	}
}

// resolveFragment runs the Fragment Resolution algorithm of CID 1.0 §3.4 on
// the data model of doc: canonicalDocumentUrl is the document id,
// fullyQualifiedFragment is that id with "#" and the fragment appended, and
// every map of the document (verification methods, embedded verification
// methods, services and maps inside extension properties, in that order) is
// checked depth first for an id equal to fullyQualifiedFragment or to the
// fragment
// identifier "#" + frag. The first match is returned as a vm.Method, a
// vm.Service or a document.Map. A JSON map whose numeric values cannot
// round-trip through document.Value is returned as a plain JSON map without
// narrowing its numbers. Private method material is excluded from the public
// fragment traversal, as it is from the HTTP fragment writer. No match is
// NOT_FOUND (docs/07 §2.1(b); the specification gives no error type).
func resolveFragment(doc *document.Document, frag, docType string) resolution.DereferenceResult {
	full, short := doc.ID().String()+"#"+frag, "#"+frag
	match := func(id string) bool { return id == full || id == short }
	found, ok := findFragment(doc, match)
	if !ok {
		return failed(resolution.CodeNotFound, "no part of the DID document has the id "+full)
	}
	return resolution.DereferenceResult{
		ContentStream:         found,
		DereferencingMetadata: resolution.DereferencingMetadata{ContentType: fragmentMediaType(docType)},
	}
}

func findFragment(doc *document.Document, match func(string) bool) (any, bool) {
	for _, m := range doc.VerificationMethods() {
		if found, ok := findMethodFragment(m, match); ok {
			return found, true
		}
	}
	for _, p := range vm.Purposes() {
		for _, r := range doc.Relationship(p) {
			if m, ok := r.Method(); ok {
				if found, ok := findMethodFragment(m, match); ok {
					return found, true
				}
			}
		}
	}
	for _, s := range doc.Services() {
		if match(s.ID) {
			return s, true
		}
		n, err := wire.FromService(s)
		if err == nil {
			if found, ok := findJSONFragment(n, match); ok {
				return found, true
			}
		}
	}
	for _, e := range doc.Extensions().Entries() {
		if m, ok := findMap(e.Value, match); ok {
			return m, true
		}
	}
	return nil, false
}

// findMethodFragment keeps typed method results and searches every public
// map held by the method, including JWK and additional properties. Methods
// come from immutable validated documents; an unwritable value is not searched.
func findMethodFragment(m vm.Method, match func(string) bool) (any, bool) {
	if match(m.ID.String()) {
		return m, true
	}
	n, err := wire.FromMethod(m, false)
	if err != nil {
		return nil, false
	}
	return findJSONFragment(n, match)
}

// findJSONFragment walks public JSON maps without first narrowing the entire
// container to the int64/double document.Value model. Unrelated large numbers
// must not hide a matching child. Sorting is supplied by wire's JSON maps;
// arrays keep their order. Return immediately on the first matching map.
func findJSONFragment(n wire.Node, match func(string) bool) (any, bool) {
	if n.Kind == wire.Object {
		if id, ok := n.Get("id"); ok && id.Kind == wire.String && match(id.Text) {
			value, err := wire.ToValue(n)
			if err == nil {
				encoded, err := wire.FromValue(value)
				if err == nil && bytes.Equal(wire.Encode(encoded), wire.Encode(n)) {
					return value, true
				}
			}
			// ToAny retains exact json.Number text in a fresh, independent map.
			return wire.ToAny(n), true
		}
		for _, member := range n.Members {
			if found, ok := findJSONFragment(member.Value, match); ok {
				return found, true
			}
		}
	}
	if n.Kind == wire.Array {
		for _, item := range n.Items {
			if found, ok := findJSONFragment(item, match); ok {
				return found, true
			}
		}
	}
	return nil, false
}

// findMap searches an extension value depth first for a map whose id
// matches.
func findMap(v document.Value, match func(string) bool) (document.Map, bool) {
	switch t := v.(type) {
	case document.Map:
		if id, ok := t.Get("id"); ok {
			if s, ok := id.(document.String); ok && match(string(s)) {
				return t, true
			}
		}
		for _, e := range t.Entries() {
			if m, ok := findMap(e.Value, match); ok {
				return m, true
			}
		}
	case document.List:
		for _, item := range t.Items() {
			if m, ok := findMap(item, match); ok {
				return m, true
			}
		}
	}
	return document.Map{}, false
}

// inheritFragment appends the DID fragment to every selected DID service
// endpoint URL (DID Resolution §5.4.2: the URL "inherits" the DID fragment).
// "If the selected DID service endpoint URL contains a fragment component,
// raise an error": the specification names no error type, and did-go raises
// INVALID_DID_URL because the fragment of the DID URL cannot be applied.
func inheritFragment(urls []string, frag string) resolution.DereferenceResult {
	out := make([]string, len(urls))
	for i, u := range urls {
		if strings.Contains(u, "#") {
			return failed(resolution.CodeInvalidDIDURL, "the service endpoint URL "+u+" already has a fragment")
		}
		out[i] = u + "#" + frag
	}
	return uriList(out)
}
