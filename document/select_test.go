package document

import (
	"testing"

	"github.com/sage-x-project/did-go/vm"
)

func selectDoc(t *testing.T) *Document {
	t.Helper()
	foreign := key(t, "did:other:9#k9")
	wrongCtl := key(t, "#k4")
	wrongCtl.Controller = mustDID(t, "did:example:someone-else")
	return build(t, builder(t).
		VerificationMethod(key(t, "#k1"), key(t, subject+"#k2"), foreign, wrongCtl).
		Relationship(vm.Authentication, vm.Ref(mustRef(t, "#k1")), vm.Embed(key(t, "#k3")), vm.Ref(mustRef(t, "did:other:9#k9")), vm.Ref(mustRef(t, "#k4"))).
		Relationship(vm.AssertionMethod, vm.Ref(mustRef(t, subject+"#k2"))).
		Service(vm.Service{ID: "#svc", Type: []string{"X"}, ServiceEndpoint: []vm.Endpoint{{URL: "https://e.example/"}}}))
}

func wantSelect(t *testing.T, ref string, p vm.Purpose, code Code, statement string) {
	t.Helper()
	m, err := SelectMethod(selectDoc(t), mustRef(t, ref), p)
	if code == "" {
		if err != nil || m == nil {
			t.Fatalf("SelectMethod(%s) = %v", ref, err)
		}
		return
	}
	if err == nil || err.Code != code || err.Statement != statement {
		t.Fatalf("SelectMethod(%s) = %v, want %s citing %s", ref, err, code, statement)
	}
}

func TestSelectMethod(t *testing.T) {
	t.Run("cid10#retrieve-verification-method.1 the reference must be an absolute URL with a fragment", func(t *testing.T) {
		for _, ref := range []string{"#k1", subject, subject + "#"} {
			wantSelect(t, ref, vm.Authentication, CodeInvalidVerificationMethodURL, "cid10#retrieve-verification-method.1")
		}
	})
	t.Run("cid10#retrieve-verification-method.2 the document URL is the reference without its fragment", func(t *testing.T) {
		wantSelect(t, subject+"/path#k1", vm.Authentication, CodeInvalidControlledIdentifierDocumentID, "cid10#retrieve-verification-method.6")
	})
	t.Run("cid10#retrieve-verification-method.3 the fragment selects the method", func(t *testing.T) {
		m, err := SelectMethod(selectDoc(t), mustRef(t, subject+"#k2"), vm.AssertionMethod)
		if err != nil || m.ID.String() != subject+"#k2" {
			t.Fatalf("got %v %v", m, err)
		}
	})
	t.Run("cid10#retrieve-verification-method.6 document id must match", func(t *testing.T) {
		wantSelect(t, "did:example:other#k1", vm.Authentication, CodeInvalidControlledIdentifierDocumentID, "cid10#retrieve-verification-method.6")
	})
	t.Run("cid10#retrieve-verification-method.7 listed, relative and embedded methods are found", func(t *testing.T) {
		wantSelect(t, subject+"#k1", vm.Authentication, "", "")
		wantSelect(t, subject+"#k3", vm.Authentication, "", "")
	})
	t.Run("cid10#retrieve-verification-method.8 a fragment that is not a verification method", func(t *testing.T) {
		wantSelect(t, subject+"#svc", vm.Authentication, CodeInvalidVerificationMethod, "cid10#retrieve-verification-method.8")
		wantSelect(t, subject+"#nothing", vm.Authentication, CodeInvalidVerificationMethod, "cid10#retrieve-verification-method.8")
	})
	t.Run("cid10#retrieve-verification-method.9 the absolute method id must equal the reference", func(t *testing.T) {
		wantSelect(t, subject+"#k9", vm.Authentication, CodeInvalidVerificationMethod, "cid10#retrieve-verification-method.9")
	})
	t.Run("cid10#retrieve-verification-method.10 the controller must be the document", func(t *testing.T) {
		wantSelect(t, subject+"#k4", vm.Authentication, CodeInvalidVerificationMethod, "cid10#retrieve-verification-method.10")
	})
	t.Run("cid10#retrieve-verification-method.11 the method must be in the relationship", func(t *testing.T) {
		wantSelect(t, subject+"#k1", vm.AssertionMethod, CodeInvalidRelationshipForVerificationMethod, "cid10#retrieve-verification-method.11")
		wantSelect(t, subject+"#k2", vm.KeyAgreement, CodeInvalidRelationshipForVerificationMethod, "cid10#retrieve-verification-method.11")
		wantSelect(t, subject+"#k1", vm.Purpose(0), CodeInvalidRelationshipForVerificationMethod, "cid10#retrieve-verification-method.11")
	})
	t.Run("cid10#retrieve-verification-method.12 the method is returned as a copy", func(t *testing.T) {
		d := selectDoc(t)
		m, err := SelectMethod(d, mustRef(t, subject+"#k1"), vm.Authentication)
		if err != nil {
			t.Fatal(err)
		}
		m.Type = "changed"
		again, _ := SelectMethod(d, mustRef(t, subject+"#k1"), vm.Authentication)
		if again.Type != "Multikey" {
			t.Fatal("selected method shares memory with the document")
		}
	})
	t.Run("nil document", func(t *testing.T) {
		if _, err := SelectMethod(nil, mustRef(t, subject+"#k1"), vm.Authentication); err == nil || err.Code != CodeInvalidControlledIdentifierDocument {
			t.Fatal("want INVALID_CONTROLLED_IDENTIFIER_DOCUMENT")
		}
	})
}
