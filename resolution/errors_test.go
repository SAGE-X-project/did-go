package resolution

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestErrors(t *testing.T) {
	table := map[Code]int{
		CodeInvalidDID: 400, CodeInvalidDIDURL: 400, CodeInvalidOptions: 400, CodeNotFound: 404,
		CodeRepresentationNotSupported: 406, CodeInvalidDIDDocument: 500, CodeMethodNotSupported: 501,
		CodeFeatureNotSupported: 501, CodeInternalError: 500,
	}
	t.Run("res10-crd20261001#errors.1 errors are RFC 9457 problem details", func(t *testing.T) {
		e := NewError(CodeNotFound, "no such DID")
		e.Instance = "urn:uuid:1"
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]any
		_ = json.Unmarshal(b, &obj)
		if obj["type"] != NamespaceDID+"NOT_FOUND" || obj["title"] != "Not found" || obj["detail"] != "no such DID" ||
			obj["status"] != float64(404) || obj["instance"] != "urn:uuid:1" {
			t.Fatalf("got %s", b)
		}
		if _, ok := obj["Refines"]; ok || len(obj) != 5 {
			t.Fatalf("unexpected members in %s", b)
		}
		var back Error
		if err := json.Unmarshal(b, &back); err != nil || back.Type != e.Type || back.Detail != e.Detail {
			t.Fatal(err)
		}
	})
	t.Run("res10-crd20261001#errors.2 the type is a URL", func(t *testing.T) {
		for c := range table {
			if u := c.TypeURL(); !strings.HasPrefix(u, "https://") {
				t.Errorf("%s: %s", c, u)
			}
		}
		ext := Code("https://example.com/errors#RATE_LIMITED")
		if NewError(ext, "").Type != string(ext) || NewError("urn:example:x", "").Type != "urn:example:x" {
			t.Fatal("URL codes are used as they are")
		}
	})
	t.Run("res10-crd20261001#errors.3 non-URL values get the did namespace", func(t *testing.T) {
		for c := range table {
			if NewError(c, "").Type != NamespaceDID+string(c) {
				t.Errorf("%s", c)
			}
		}
		if NewError("EXTENSION_ERROR", "").Type != NamespaceDID+"EXTENSION_ERROR" {
			t.Fatal("extension name")
		}
	})
	t.Run("res10-crd20261001#errors.4 title is short and specific", func(t *testing.T) {
		for c := range table {
			if title := NewError(c, "").Title; title == "" || len(title) > 40 || title == string(c) {
				t.Errorf("%s: %q", c, title)
			}
		}
	})
	t.Run("res10-crd20261001#errors.5 detail carries the longer explanation", func(t *testing.T) {
		e := NewError(CodeInvalidDID, "the method-specific-id is empty")
		if e.Detail != "the method-specific-id is empty" || !strings.Contains(e.Error(), e.Detail) {
			t.Fatal("detail")
		}
		if NewError(CodeInvalidDID, "").Error() != "resolution: "+NamespaceDID+"INVALID_DID" {
			t.Fatal("message without detail")
		}
	})
	t.Run("res10-crd20261001#errors.6 an extension type may refine a core type", func(t *testing.T) {
		e := NewError("https://example.com/errors#KEY_GONE", "")
		e.Refines = CodeNotFound.TypeURL()
		if e.HTTPStatus() != 404 {
			t.Fatalf("status %d", e.HTTPStatus())
		}
		e.Refines = "https://example.com/other"
		e.Status = 429
		if e.HTTPStatus() != 429 {
			t.Fatal("own status after Refines")
		}
		e.Status = 0
		if e.HTTPStatus() != 500 {
			t.Fatal("500 last")
		}
	})
	t.Run("res10-crd20261001#errors.7 FEATURE_NOT_SUPPORTED describes the feature", func(t *testing.T) {
		if e := NewError(CodeFeatureNotSupported, "versionTime is not supported by did:key"); e.Detail != "versionTime is not supported by did:key" {
			t.Fatal("detail lost")
		}
		if NewError(CodeFeatureNotSupported, "").Detail == "" {
			t.Fatal("a default description is given")
		}
		a := NewAcceptNotSupported("text/html")
		if !a.IsAcceptNotSupported() || !strings.Contains(a.Detail, "text/html") || a.Code() != CodeFeatureNotSupported {
			t.Fatal("accept detail")
		}
		if NewError(CodeFeatureNotSupported, "").IsAcceptNotSupported() || (*Error)(nil).IsAcceptNotSupported() {
			t.Fatal("only NewAcceptNotSupported is recognized")
		}
	})
	t.Run("cid10#processing-errors.2 CID types start with https://w3id.org/security#", func(t *testing.T) {
		for _, c := range []Code{CodeInvalidVerificationMethodURL, CodeInvalidControlledIdentifierDocument,
			CodeInvalidControlledIdentifierDocumentID, CodeInvalidVerificationMethod, CodeInvalidRelationshipForVerificationMethod} {
			e := NewError(c, "")
			if e.Type != NamespaceSecurity+string(c) || e.Code() != c {
				t.Errorf("%s: %s", c, e.Type)
			}
			if e.Refines != NamespaceDID+"INVALID_DID_URL" || e.HTTPStatus() != 400 {
				t.Errorf("%s refines %s, status %d", c, e.Refines, e.HTTPStatus())
			}
		}
	})
	t.Run("cid10#processing-errors.3 CID titles are short and specific", func(t *testing.T) {
		if title := NewError(CodeInvalidVerificationMethod, "").Title; title != "Invalid verification method" {
			t.Fatalf("got %q", title)
		}
	})
	t.Run("cid10#processing-errors.4 CID details carry the explanation", func(t *testing.T) {
		if e := NewError(CodeInvalidRelationshipForVerificationMethod, "key-1 is not in assertionMethod"); e.Detail != "key-1 is not in assertionMethod" {
			t.Fatal("detail")
		}
	})
	t.Run("binding table statuses cannot be overridden", func(t *testing.T) {
		for c, want := range table {
			e := NewError(c, "")
			e.Status, e.Refines = 418, CodeNotFound.TypeURL()
			if e.HTTPStatus() != want {
				t.Errorf("%s: %d", c, e.HTTPStatus())
			}
		}
		if (*Error)(nil).HTTPStatus() != 500 {
			t.Fatal("nil")
		}
		if (&Error{Type: NamespaceDID + "INVALID_VERIFICATION_METHOD"}).HTTPStatus() != 500 {
			t.Fatal("CID names under the did namespace are not table types")
		}
	})
	t.Run("Is compares types", func(t *testing.T) {
		var err error = NewError(CodeNotFound, "x")
		if !errors.Is(err, NewError(CodeNotFound, "")) || errors.Is(err, NewError(CodeInvalidDID, "")) || errors.Is(err, errors.New("x")) {
			t.Fatal("Is")
		}
		if (&Error{Type: "urn:x"}).Code() != "urn:x" {
			t.Fatal("Code of a URL type")
		}
	})
}
