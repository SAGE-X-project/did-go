// Package universal is the HTTP(S) binding of DID Resolution v1.0 CRD
// 2026-10-01 §12.1 (docs/07 §6, docs/14 §5). It is transport only: Client
// implements resolution.Resolver and resolution.Dereferencer by calling a
// remote DID resolver over the binding, and Handler exposes any
// resolution.Resolver and resolution.Dereferencer as an HTTP endpoint. Neither
// resolves a DID itself.
//
// Request form. The request URL is the DID resolver HTTP(S) endpoint
// followed by the DID or DID URL. The accept option travels in the Accept
// header; Accept application/did-resolution (or application/did-url-
// dereferencing) asks for the complete result, any other value asks for the
// didDocument (or contentStream) alone in that representation. Other options
// are query parameters of a GET request, with the DID or DID URL percent-
// encoded (RFC 3986 §2.1), or a JSON body of a POST request.
//
// Response form (Handler):
//   - an error: the status code of the binding table (resolution.Error
//     HTTPStatus), and the error as an RFC 9457 problem details object
//     (application/problem+json), or the complete result when it was asked
//     for;
//   - a deactivated DID: 410 with the complete result, so that the
//     didDocumentMetadata carrying deactivated reaches the client;
//   - a dereferenced text/uri-list: 303 with Location set to the selected
//     service endpoint URL and an empty body;
//   - otherwise 200 with Content-Type equal to the contentType metadata
//     property and the document or content in that representation.
//
// Remote binding. DID Resolution §8.2 says that a remote binding SHOULD use a
// trusted DID resolver, ideally under the client's own control (for example
// self-hosted), and SHOULD use a secure channel such as a VPN and/or TLS with
// mutual authentication. Client therefore has no default endpoint: the caller
// names the resolver it trusts. Client accepts only https endpoints, and the
// *http.Client the caller injects carries the TLS configuration, including a
// client certificate for mutual authentication and the root CAs or pinned
// certificates of the trusted resolver. Client sends no cookies.
//
// Proxied resolution. When a Handler serves a Client (a downstream resolver
// invoking an upstream one), the didResolutionMetadata and
// didDocumentMetadata of the upstream result, including proofs and
// properties did-go does not model, pass through unchanged (§8.2.2).
//
// Choices where the specification leaves room are listed on Client and
// Handler.
package universal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
)

// DefaultPathPrefix is the path of the DID resolver HTTP(S) endpoint that
// Handler serves, as in the examples of DID Resolution §12.
const DefaultPathPrefix = "/1.0/identifiers/"

// MediaTypeProblem is the RFC 9457 problem details media type.
const MediaTypeProblem = "application/problem+json"

// resolutionResult is the JSON form of a DID resolution result (DID
// Resolution §9).
type resolutionResult struct {
	DIDDocument           json.RawMessage               `json:"didDocument"`
	DIDResolutionMetadata resolution.ResolutionMetadata `json:"didResolutionMetadata"`
	DIDDocumentMetadata   document.Metadata             `json:"didDocumentMetadata"`
}

// dereferencingResult is the JSON form of a DID URL dereferencing result. The
// specification's examples disagree on the name of the content member
// (docs/07 caveat 7); did-go writes "content" and also reads
// "contentStream".
type dereferencingResult struct {
	Content               json.RawMessage                  `json:"content"`
	ContentStream         json.RawMessage                  `json:"contentStream,omitempty"`
	DereferencingMetadata resolution.DereferencingMetadata `json:"dereferencingMetadata"`
	ContentMetadata       document.Metadata                `json:"contentMetadata"`
}

// contentType returns the contentType of a dereferencing result: the one in
// dereferencingMetadata, or the one the dereferencing algorithm writes into
// contentMetadata (docs/07 caveat 8).
func contentType(md resolution.DereferencingMetadata, cm document.Metadata) string {
	if md.ContentType != "" {
		return md.ContentType
	}
	s, _ := cm.Extra["contentType"].(string)
	return s
}

// isURIList reports whether a media type is text/uri-list.
func isURIList(mt string) bool {
	t, _, _ := strings.Cut(mt, ";")
	return strings.EqualFold(strings.TrimSpace(t), spec.MediaTypeURIList)
}

// isNull reports whether a raw JSON value is absent or null.
func isNull(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || bytes.Equal(t, []byte("null"))
}

// encodeIdentifier percent-encodes every octet of s that is not unreserved
// (RFC 3986 §2.1, §2.3).
func encodeIdentifier(s string) string {
	const hex = "0123456789ABCDEF"
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			sb.WriteByte(c)
			continue
		}
		sb.WriteByte('%')
		sb.WriteByte(hex[c>>4])
		sb.WriteByte(hex[c&0x0f])
	}
	return sb.String()
}

// queryValue writes an extension option value as a query parameter value:
// strings as they are, other values as JSON text.
func queryValue(v any) (string, error) {
	if s, ok := v.(string); ok {
		return s, nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("universal: option value: %w", err)
	}
	return string(data), nil
}
