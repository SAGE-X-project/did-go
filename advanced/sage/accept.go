package sage

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/representation"
)

// Selection is what a SAGE interface request asks for (chapter 10 DIDP-02).
type Selection int

// Selections.
const (
	// SelectCore10 is the DID Core 1.0 projection alone.
	SelectCore10 Selection = iota + 1
	// SelectDID11 is the DID 1.1 projection alone.
	SelectDID11
	// SelectEnvelope is the RESOLVE-05 three-member resolution envelope with
	// the DID Core 1.0 projection.
	SelectEnvelope
)

// MediaTypeEnvelope is the media type of the three-member envelope.
const MediaTypeEnvelope = "application/json"

// Select applies the DIDP-02 table of the SAGE interface. The value is
// matched as exactly one media type without parameters: absent, "*/*" and
// application/did+json select the DID Core 1.0 projection, application/did
// the DID 1.1 projection and application/json the envelope. A list, a
// parameter or q-value, application/did+ld+json, application/did-resolution
// and any other type are representation.unsupported. Matching follows the
// table literally: a value that differs in any byte, including letter case
// or surrounding space, is another value.
//
// The table binds the SAGE interface only. The DID Resolution interface of
// Driver and Resolver follows DID Resolution instead (DIDP-02).
func Select(accept string) (Selection, *Error) {
	switch accept {
	case "", "*/*", MediaTypeCore10:
		return SelectCore10, nil
	case MediaTypeDID11:
		return SelectDID11, nil
	case MediaTypeEnvelope:
		return SelectEnvelope, nil
	}
	detail := "the SAGE interface serves application/did+json, application/did and application/json"
	if strings.ContainsAny(accept, ",;") {
		detail = "the SAGE interface takes one media type without parameters, q-values or lists"
	}
	return 0, NewError(CodeRepresentationUnsupported, detail)
}

// Request is a SAGE interface resolution request: the identifier and the
// resolution accept option or HTTP Accept header value.
type Request struct {
	DID    did.DID
	Accept string
}

// Response is a SAGE interface answer: the bytes and their media type, or
// the problem when the request failed (its Status is the HTTP status).
type Response struct {
	Body        []byte
	ContentType string
	Problem     *Error
}

// Respond answers one SAGE interface resolution: it selects the response
// with Select, observes the record once through source and writes the
// selected projection or envelope from that observation. A created or
// deactivated record resolves for inspection (RESOLVE-03); it never
// authorizes a protected operation, which is not decided here.
func Respond(ctx context.Context, source Source, r Request, producer representation.Producer) Response {
	sel, e := Select(r.Accept)
	if e != nil {
		return Response{Problem: e}
	}
	if e := checkID(r.DID.String()); e != nil {
		return Response{Problem: e}
	}
	rec, err := source.Observe(ctx, r.DID)
	if err != nil {
		return Response{Problem: codeOf(err)}
	}
	if rec.DID != r.DID {
		return Response{Problem: NewError(CodeRecordInvalid, "the observed record is not the requested identifier")}
	}
	p := Core10
	if sel == SelectDID11 {
		p = DID11
	}
	data, e := Produce(rec, p, producer)
	if e != nil {
		return Response{Problem: e}
	}
	if sel != SelectEnvelope {
		return Response{Body: data, ContentType: p.MediaType()}
	}
	body, err := envelope(data, Metadata(rec))
	if err != nil {
		return Response{Problem: NewError(CodeRecordInvalid, err.Error())}
	}
	if len(body) > maxResponse {
		return Response{Problem: NewError(CodeSizeExceeded, "the resolution envelope exceeds the response bound")}
	}
	return Response{Body: body, ContentType: MediaTypeEnvelope}
}

// envelope writes the RESOLVE-05 three-member resolution envelope:
// didDocument, didDocumentMetadata and didResolutionMetadata with the
// contentType of the document (RESOLVE-03).
func envelope(doc []byte, md document.Metadata) ([]byte, error) {
	return json.Marshal(struct {
		Document           json.RawMessage   `json:"didDocument"`
		DocumentMetadata   document.Metadata `json:"didDocumentMetadata"`
		ResolutionMetadata map[string]string `json:"didResolutionMetadata"`
	}{doc, md, map[string]string{"contentType": MediaTypeCore10}})
}
