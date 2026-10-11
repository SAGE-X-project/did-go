package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"

	"github.com/sage-x-project/did-go/did"
)

// relationshipNames are the verification relationship properties whose
// entries are DID URLs or embedded verification methods.
func relationshipNames() []string {
	return []string{"authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"}
}

// checkDocument parses data as one JSON object and checks the two rules the
// did:web specification states for a fetched document: its id is the DID
// being resolved (read-resolve.8), and every DID URL in it is absolute
// (§key-material-and-document-handling). Full conformance checking is left
// to the resolver's consumer.
func checkDocument(data []byte, d did.DID) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return raise(CodeInvalidDidDocument, stmtVerifyID, "the response is not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return raise(CodeInvalidDidDocument, stmtVerifyID, "the response has content after the JSON object")
	}
	id, _ := doc["id"].(string)
	if id != d.String() {
		return raise(CodeInvalidDidDocument, stmtVerifyID, "the document id is not the DID being resolved")
	}
	return checkAbsolute(doc)
}

// checkAbsolute requires absolute URLs at the DID URL positions of a DID
// document: controller, verification method id and controller, verification
// relationship entries (references and embedded methods) and service id.
func checkAbsolute(doc map[string]any) error {
	if err := absoluteValues("controller", doc["controller"]); err != nil {
		return err
	}
	if err := absoluteMethods("verificationMethod", doc["verificationMethod"], false); err != nil {
		return err
	}
	for _, name := range relationshipNames() {
		if err := absoluteMethods(name, doc[name], true); err != nil {
			return err
		}
	}
	services, _ := doc["service"].([]any)
	for _, s := range services {
		if m, ok := s.(map[string]any); ok {
			if err := absoluteValues("service.id", m["id"]); err != nil {
				return err
			}
		}
	}
	return nil
}

// absoluteMethods checks a list of verification methods; references are
// allowed where refs is true.
func absoluteMethods(property string, v any, refs bool) error {
	list, _ := v.([]any)
	for _, item := range list {
		switch x := item.(type) {
		case string:
			if refs {
				if err := absoluteValues(property, x); err != nil {
					return err
				}
			}
		case map[string]any:
			if err := absoluteValues(property+".id", x["id"]); err != nil {
				return err
			}
			if err := absoluteValues(property+".controller", x["controller"]); err != nil {
				return err
			}
		}
	}
	return nil
}

// absoluteValues checks a string or a list of strings; other values are left
// to the consumer.
func absoluteValues(property string, v any) error {
	var values []string
	switch x := v.(type) {
	case string:
		values = []string{x}
	case []any:
		for _, item := range x {
			if s, ok := item.(string); ok {
				values = append(values, s)
			}
		}
	}
	for _, s := range values {
		u, err := url.Parse(s)
		if err != nil || !u.IsAbs() {
			return raise(CodeInvalidDidDocument, sectionKeys, "%s holds a relative URL; DID URLs in a did:web document must be absolute", property)
		}
	}
	return nil
}
