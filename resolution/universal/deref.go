package universal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
)

// dereference runs the dereferencer and writes its result.
func (h *Handler) dereference(ctx context.Context, w http.ResponseWriter, req *request) {
	if h.deref == nil {
		writeProblem(w, resolution.NewError(resolution.CodeFeatureNotSupported, "this endpoint does not dereference DID URLs"))
		return
	}
	var opts resolution.DereferenceOptions
	if e := decodeOptions(req.options, &opts); e != nil {
		writeProblem(w, e)
		return
	}
	opts.Accept = req.accept
	if e := opts.Validate(); e != nil {
		writeProblem(w, e)
		return
	}
	res := h.deref.Dereference(ctx, req.url, opts)
	e := res.DereferencingMetadata.Error
	ct := contentType(res.DereferencingMetadata, res.ContentMetadata)
	switch {
	case req.full || (e == nil && res.ContentMetadata.Deactivated):
		h.writeDereferencingResult(w, res, ct)
	case e != nil:
		writeProblem(w, e)
	case isURIList(ct):
		loc, err := firstURL(res.ContentStream)
		if err != nil {
			writeProblem(w, resolution.NewError(resolution.CodeInternalError, err.Error()))
			return
		}
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusSeeOther)
	default:
		data, err := h.contentBytes(res.ContentStream, ct)
		if err != nil {
			writeProblem(w, resolution.NewError(resolution.CodeInternalError, err.Error()))
			return
		}
		writeBody(w, http.StatusOK, ct, data)
	}
}

// writeDereferencingResult writes the complete result as
// application/did-url-dereferencing.
func (h *Handler) writeDereferencingResult(w http.ResponseWriter, res resolution.DereferenceResult, ct string) {
	dr := dereferencingResult{
		Content:               json.RawMessage("null"),
		DereferencingMetadata: res.DereferencingMetadata,
		ContentMetadata:       res.ContentMetadata,
	}
	if res.DereferencingMetadata.Error == nil && res.ContentStream != nil {
		data, err := h.contentJSON(res.ContentStream, ct)
		if err != nil {
			writeProblem(w, resolution.NewError(resolution.CodeInternalError, err.Error()))
			return
		}
		dr.Content = data
	}
	body, err := json.Marshal(dr)
	if err != nil {
		writeProblem(w, resolution.NewError(resolution.CodeInternalError, "the result cannot be written: "+err.Error()))
		return
	}
	writeBody(w, resolutionStatus(res.DereferencingMetadata.Error, res.ContentMetadata.Deactivated), spec.MediaTypeDIDURLDereferencing, body)
}

// firstURL returns the selected service endpoint URL of text/uri-list
// content.
func firstURL(content any) (string, error) {
	var list []string
	switch x := content.(type) {
	case []string:
		list = x
	case string:
		list = uriList(x)
	case []byte:
		list = uriList(string(x))
	}
	if len(list) == 0 {
		return "", fmt.Errorf("the text/uri-list content has no URL")
	}
	if u, err := url.Parse(list[0]); err != nil || !u.IsAbs() {
		return "", fmt.Errorf("the selected service endpoint is not an absolute URL")
	}
	return list[0], nil
}

// contentBytes serializes content in the representation named by ct.
func (h *Handler) contentBytes(content any, ct string) ([]byte, error) {
	if ct == "" {
		return nil, fmt.Errorf("the dereferencing result has no contentType")
	}
	switch x := content.(type) {
	case []byte:
		return x, nil
	case string:
		return []byte(x), nil
	case []string:
		return []byte(strings.Join(x, "\r\n") + "\r\n"), nil
	case *document.Document:
		return h.produce(x, ct)
	case json.RawMessage:
		return x, nil
	case json.Marshaler, map[string]any, []any:
		return json.Marshal(x)
	case nil:
		return nil, fmt.Errorf("the dereferencing result has no content")
	}
	return nil, fmt.Errorf("content of type %T cannot be written", content)
}

// contentJSON writes content as the JSON value of a dereferencing result:
// JSON bytes as they are, other bytes and strings as a JSON string, a URL
// list as an array.
func (h *Handler) contentJSON(content any, ct string) (json.RawMessage, error) {
	switch x := content.(type) {
	case []string:
		return json.Marshal(x)
	case string:
		return json.Marshal(x)
	case []byte:
		if json.Valid(x) {
			return x, nil
		}
		if !utf8.Valid(x) {
			return nil, fmt.Errorf("the %s content is not text and cannot be embedded in a JSON result", ct)
		}
		return json.Marshal(string(x))
	}
	data, err := h.contentBytes(content, ct)
	if err != nil {
		return nil, err
	}
	if !json.Valid(data) {
		return nil, fmt.Errorf("the %s content cannot be embedded in a JSON result", ct)
	}
	return data, nil
}

// produce serializes a document in the DID media type ct.
func (h *Handler) produce(d *document.Document, ct string) ([]byte, error) {
	if h.cfg.producer == nil {
		return nil, fmt.Errorf("the result carries a document without bytes and no producer is configured")
	}
	opts, err := representation.OptionsFor(ct)
	if err != nil {
		return nil, err
	}
	data, _, err := h.cfg.producer.Produce(d, opts)
	if err != nil {
		return nil, fmt.Errorf("the document cannot be produced: %w", err)
	}
	return data, nil
}
