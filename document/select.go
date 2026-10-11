package document

import (
	"fmt"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/vm"
)

func selectErr(code Code, statement, format string, args ...any) *ConformanceError {
	return &ConformanceError{Code: code, Property: "verificationMethod", Statement: statement, Reason: fmt.Sprintf(format, args...)}
}

// SelectMethod runs the steps of the CID 1.0 §3.3 Retrieve Verification
// Method algorithm that need no I/O, on d, which the caller obtained by
// dereferencing ref without its fragment (steps 4 and 5 are the caller's):
//
//   - ref must be an absolute DID URL with a fragment
//     (INVALID_VERIFICATION_METHOD_URL, step 1);
//   - ref without its fragment must equal d's id
//     (INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID, steps 2 and 6);
//   - the fragment must select a conforming verification method whose
//     absolute id equals ref and whose controller equals d's id
//     (INVALID_VERIFICATION_METHOD, steps 3, 7 to 10);
//   - the method must be in the relationship p by reference or by value
//     (INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD, step 11).
//
// It returns a copy of the method (step 12).
func SelectMethod(d *Document, ref did.DIDURL, p vm.Purpose) (*vm.Method, *ConformanceError) {
	if ref.IsRelative() || ref.IsZero() || !ref.HasFragment() || ref.Fragment() == "" {
		return nil, selectErr(CodeInvalidVerificationMethodURL, "cid10#retrieve-verification-method.1",
			"%q is not an absolute DID URL with a fragment", ref.String())
	}
	if d == nil {
		return nil, &ConformanceError{Code: CodeInvalidControlledIdentifierDocument, Property: "document", Reason: "no document"}
	}
	docURL := ref.WithoutFragment()
	if docURL != d.id.URL() {
		return nil, &ConformanceError{Code: CodeInvalidControlledIdentifierDocumentID, Property: "id",
			Statement: "cid10#retrieve-verification-method.6", Reason: fmt.Sprintf("document %s is not %s", d.id, docURL)}
	}
	m, found := findMethod(d, ref)
	if !found {
		return nil, selectErr(CodeInvalidVerificationMethod, "cid10#retrieve-verification-method.8",
			"no verification method has the id %s", ref)
	}
	if err := m.Validate(); err != nil {
		return nil, selectErr(CodeInvalidVerificationMethod, "cid10#retrieve-verification-method.8", "%v", err)
	}
	if abs, _ := m.ID.Resolve(d.id.URL()); abs != ref {
		return nil, selectErr(CodeInvalidVerificationMethod, "cid10#retrieve-verification-method.9", "id %s is not %s", abs, ref)
	}
	if m.Controller.URL() != docURL {
		return nil, selectErr(CodeInvalidVerificationMethod, "cid10#retrieve-verification-method.10",
			"controller %s is not %s", m.Controller, docURL)
	}
	if !inRelationship(d, ref, p) {
		return nil, &ConformanceError{Code: CodeInvalidRelationshipForVerificationMethod, Property: p.String(),
			Statement: "cid10#retrieve-verification-method.11", Reason: fmt.Sprintf("%s is not in %s", ref, p)}
	}
	return &m, nil
}

// findMethod dereferences the fragment of ref in d (step 7): the method,
// listed or embedded, whose absolute id equals ref, or else the first whose
// id has the same fragment. Step 9 then rejects a method found only by its
// fragment.
func findMethod(d *Document, ref did.DIDURL) (vm.Method, bool) {
	ms, _ := allMethods(d)
	for _, m := range ms {
		if abs, err := m.ID.Resolve(d.id.URL()); err == nil && abs == ref {
			return m.Clone(), true
		}
	}
	for _, m := range ms {
		if m.ID.HasFragment() && m.ID.Fragment() == ref.Fragment() {
			return m.Clone(), true
		}
	}
	return vm.Method{}, false
}

// inRelationship reports whether ref is referenced from, or embedded in,
// relationship p of d.
func inRelationship(d *Document, ref did.DIDURL, p vm.Purpose) bool {
	if !p.Valid() {
		return false
	}
	for _, r := range d.relationships[p] {
		if abs, err := r.ID().Resolve(d.id.URL()); err == nil && abs == ref {
			return true
		}
	}
	return false
}
