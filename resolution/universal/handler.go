package universal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
)

// DefaultRequestLimit is the largest POST body Handler reads.
const DefaultRequestLimit = 64 << 10

type handlerConfig struct {
	prefix    string
	producer  representation.Producer
	limit     int64
	plaintext bool
	noPOST    bool
}

// HandlerOption configures a Handler.
type HandlerOption func(*handlerConfig)

// WithPathPrefix sets the path of the endpoint (default DefaultPathPrefix).
// A missing trailing slash is added.
func WithPathPrefix(prefix string) HandlerOption {
	return func(c *handlerConfig) {
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		c.prefix = prefix
	}
}

// WithProducer sets the producer that serializes a document when a result
// carries a *document.Document but no bytes.
func WithProducer(p representation.Producer) HandlerOption {
	return func(c *handlerConfig) { c.producer = p }
}

// WithRequestLimit sets the largest POST body (default 64 KiB). A value
// below 1 keeps the default.
func WithRequestLimit(n int64) HandlerOption {
	return func(c *handlerConfig) {
		if n > 0 {
			c.limit = n
		}
	}
}

// WithPlaintext lets the handler answer requests that did not arrive over
// TLS. All HTTPS bindings MUST use TLS, so use it only behind a component
// that terminates TLS, such as a reverse proxy.
func WithPlaintext(allow bool) HandlerOption {
	return func(c *handlerConfig) { c.plaintext = allow }
}

// WithoutPOST turns off the POST version of the binding, which a resolver
// MAY implement; GET is always served.
func WithoutPOST() HandlerOption {
	return func(c *handlerConfig) { c.noPOST = true }
}

// Handler exposes a resolution.Resolver and a resolution.Dereferencer over
// the HTTP(S) binding. It is immutable and safe for concurrent use.
//
// Choices where the specification leaves room:
//   - The identifier after the path prefix is percent-decoded once when it
//     starts with "did%3A" (the encoded form the binding uses with options);
//     otherwise it is taken as written, and the query of the request URL is
//     the query of the DID URL (Example 25 of DID Resolution §12.1).
//   - A DID URL with a path, query or fragment, or an Accept header that
//     prefers application/did-url-dereferencing, is dereferenced; a plain
//     DID is resolved.
//   - An empty Accept header, or one whose preferred range is a wildcard,
//     asks for the complete result.
//   - Query parameter values of extension options are passed on as strings.
//   - An option named accept in the query or body is INVALID_OPTIONS: the
//     binding carries accept in the Accept header.
//   - A deactivated DID is answered with 410 and the complete result.
//   - text/uri-list content asked for alone is answered with 303; asked for
//     as part of the complete result, it is answered with 200 and the result,
//     because the binding gives both rules without saying which wins.
//   - A request that did not arrive over TLS is refused with 403 unless
//     WithPlaintext is set.
//   - Content is written by its Go type, so that every content type the
//     dereferencer package returns reaches the client: a *document.Document
//     through the producer in the representation of contentType; a
//     vm.Method, a vm.Service or a document.Map (a fragment, whose
//     contentType is application/ld+json or application/json) as its JSON
//     object, without secret key material; a []string as text/uri-list
//     lines (or a 303 when text/uri-list is asked for alone) and as a JSON
//     array inside the complete result; []byte, string and json.RawMessage
//     as they are; other json.Marshaler values, map[string]any and []any
//     with encoding/json. Content of any other type is INTERNAL_ERROR.
type Handler struct {
	resolver resolution.Resolver
	deref    resolution.Dereferencer
	cfg      handlerConfig
}

// NewHandler returns a handler serving r and d. Either may be nil; a
// request for a missing function is answered with FEATURE_NOT_SUPPORTED.
func NewHandler(r resolution.Resolver, d resolution.Dereferencer, opts ...HandlerOption) *Handler {
	cfg := handlerConfig{prefix: DefaultPathPrefix, limit: DefaultRequestLimit}
	for _, o := range opts {
		o(&cfg)
	}
	return &Handler{resolver: r, deref: d, cfg: cfg}
}

// request is a parsed binding request.
type request struct {
	url     did.DIDURL
	full    bool
	deref   bool
	accept  string
	options map[string]json.RawMessage
}

// ServeHTTP answers one binding request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && (r.Method != http.MethodPost || h.cfg.noPOST) {
		allow := "GET, POST"
		if h.cfg.noPOST {
			allow = "GET"
		}
		w.Header().Set("Allow", allow)
		writeProblem(w, &resolution.Error{Type: "about:blank", Title: "Method not allowed", Status: http.StatusMethodNotAllowed})
		return
	}
	if r.TLS == nil && !h.cfg.plaintext {
		writeProblem(w, &resolution.Error{Type: "about:blank", Title: "TLS required", Status: http.StatusForbidden,
			Detail: "all HTTPS bindings must use TLS"})
		return
	}
	req, e := h.parse(r)
	if e != nil {
		writeProblem(w, e)
		return
	}
	if req.deref {
		h.dereference(r.Context(), w, req)
		return
	}
	h.resolve(r.Context(), w, req)
}

// parse reads the identifier, the Accept header and the options.
func (h *Handler) parse(r *http.Request) (*request, *resolution.Error) {
	raw, ok := strings.CutPrefix(r.URL.EscapedPath(), h.cfg.prefix)
	if !ok || raw == "" {
		return nil, &resolution.Error{Type: "about:blank", Title: "Not found", Status: http.StatusNotFound,
			Detail: "the path does not name a DID under " + h.cfg.prefix}
	}
	encoded := len(raw) >= 6 && strings.EqualFold(raw[:6], "did%3A")
	ident, query := raw, ""
	if encoded {
		var err error
		if ident, err = url.PathUnescape(raw); err != nil {
			return nil, resolution.NewError(resolution.CodeInvalidDIDURL, "the identifier is not percent-encoded correctly")
		}
		query = r.URL.RawQuery
	} else if r.URL.RawQuery != "" || r.URL.ForceQuery {
		ident += "?" + r.URL.RawQuery
	}
	u, err := did.ParseURL(ident)
	if err != nil {
		code := resolution.CodeInvalidDIDURL
		if !strings.ContainsAny(ident, "/?#") {
			code = resolution.CodeInvalidDID
		}
		return nil, resolution.NewError(code, err.Error())
	}
	accept := r.Header.Get("Accept")
	pref, err := preferred(accept)
	if err != nil {
		return nil, resolution.NewError(resolution.CodeInvalidOptions, "Accept: "+err.Error())
	}
	req := &request{url: u, deref: !u.IsDID() || pref == spec.MediaTypeDIDURLDereferencing}
	result := spec.MediaTypeDIDResolution
	if req.deref {
		result = spec.MediaTypeDIDURLDereferencing
	}
	req.full = pref == "" || pref == result || strings.HasSuffix(pref, "/*")
	if !req.full {
		req.accept = accept
	}
	if req.options, err = h.options(r, query, encoded); err != nil {
		return nil, resolution.NewError(resolution.CodeInvalidOptions, err.Error())
	}
	if _, ok := req.options["accept"]; ok {
		return nil, resolution.NewError(resolution.CodeInvalidOptions, "accept is conveyed in the Accept header")
	}
	return req, nil
}

// preferred returns the media range with the highest weight in an Accept
// value ("" when there is none).
func preferred(accept string) (string, error) {
	ranges, err := resolution.ParseAccept(accept)
	if err != nil {
		return "", err
	}
	best, weight := "", 0
	for _, mr := range ranges {
		if mr.Weight > weight {
			best, weight = mr.Type+"/"+mr.Subtype, mr.Weight
		}
	}
	return best, nil
}

// options reads the options of a request as JSON values: query parameters
// of a GET request with an encoded identifier, or the JSON body of a POST
// request.
func (h *Handler) options(r *http.Request, query string, encoded bool) (map[string]json.RawMessage, error) {
	out := map[string]json.RawMessage{}
	if r.Method == http.MethodPost {
		if encoded && query != "" {
			return nil, fmt.Errorf("the POST binding carries options in the body")
		}
		data, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, h.cfg.limit))
		if err != nil {
			return nil, fmt.Errorf("the request body is not readable or too large")
		}
		if strings.TrimSpace(string(data)) == "" {
			return out, nil
		}
		if err := json.Unmarshal(data, &out); err != nil || out == nil {
			return nil, fmt.Errorf("the request body is not a JSON object")
		}
		return out, nil
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, fmt.Errorf("the query is not valid: %w", err)
	}
	for k, vs := range values {
		if len(vs) != 1 {
			return nil, fmt.Errorf("option %q is given more than once", k)
		}
		v := vs[0]
		switch k {
		case "expandRelativeUrls", "noCache":
			if v != "true" && v != "false" {
				return nil, fmt.Errorf("option %q must be true or false", k)
			}
			out[k] = json.RawMessage(v)
		default:
			data, _ := json.Marshal(v)
			out[k] = data
		}
	}
	return out, nil
}

// resolve runs the resolver and writes its result.
func (h *Handler) resolve(ctx context.Context, w http.ResponseWriter, req *request) {
	if h.resolver == nil {
		writeProblem(w, resolution.NewError(resolution.CodeFeatureNotSupported, "this endpoint does not resolve DIDs"))
		return
	}
	var opts resolution.ResolutionOptions
	if e := decodeOptions(req.options, &opts); e != nil {
		writeProblem(w, e)
		return
	}
	opts.Accept = req.accept
	if e := opts.Validate(); e != nil {
		writeProblem(w, e)
		return
	}
	res := h.resolver.Resolve(ctx, req.url.DID(), opts)
	e := res.ResolutionMetadata.Error
	switch {
	case req.full || (e == nil && res.DocumentMetadata.Deactivated):
		h.writeResolutionResult(w, res)
	case e != nil:
		writeProblem(w, e)
	default:
		data, err := h.documentBytes(res)
		if err != nil {
			writeProblem(w, resolution.NewError(resolution.CodeInternalError, err.Error()))
			return
		}
		writeBody(w, http.StatusOK, res.ResolutionMetadata.ContentType, data)
	}
}

// decodeOptions turns the option values into the options type.
func decodeOptions(values map[string]json.RawMessage, dst json.Unmarshaler) *resolution.Error {
	data, _ := json.Marshal(values)
	if err := dst.UnmarshalJSON(data); err != nil {
		return resolution.NewError(resolution.CodeInvalidOptions, err.Error())
	}
	return nil
}

// resolutionStatus is the status code of a resolution result.
func resolutionStatus(e *resolution.Error, deactivated bool) int {
	switch {
	case e != nil:
		return e.HTTPStatus()
	case deactivated:
		return http.StatusGone
	}
	return http.StatusOK
}

// writeResolutionResult writes the complete result as
// application/did-resolution.
func (h *Handler) writeResolutionResult(w http.ResponseWriter, res resolution.Result) {
	rr := resolutionResult{
		DIDDocument:           json.RawMessage("null"),
		DIDResolutionMetadata: res.ResolutionMetadata,
		DIDDocumentMetadata:   res.DocumentMetadata,
	}
	if res.ResolutionMetadata.Error == nil && (res.Raw != nil || res.Document != nil) {
		data, err := h.documentBytes(res)
		if err == nil && !json.Valid(data) {
			err = fmt.Errorf("the %s representation cannot be embedded in a JSON result", res.ResolutionMetadata.ContentType)
		}
		if err != nil {
			writeProblem(w, resolution.NewError(resolution.CodeInternalError, err.Error()))
			return
		}
		rr.DIDDocument = data
	}
	body, err := json.Marshal(rr)
	if err != nil {
		writeProblem(w, resolution.NewError(resolution.CodeInternalError, "the result cannot be written: "+err.Error()))
		return
	}
	writeBody(w, resolutionStatus(res.ResolutionMetadata.Error, res.DocumentMetadata.Deactivated), spec.MediaTypeDIDResolution, body)
}

// documentBytes returns the bytes of the resolved document in the
// representation named by contentType.
func (h *Handler) documentBytes(res resolution.Result) ([]byte, error) {
	ct := res.ResolutionMetadata.ContentType
	if ct == "" {
		return nil, fmt.Errorf("the resolution result has no contentType")
	}
	if res.Raw != nil {
		return res.Raw, nil
	}
	if res.Document == nil {
		return nil, fmt.Errorf("the resolution result has no didDocument")
	}
	return h.produce(res.Document, ct)
}

// writeProblem writes e as an RFC 9457 problem details object with the
// status code of the binding table.
func writeProblem(w http.ResponseWriter, e *resolution.Error) {
	status := e.HTTPStatus()
	p := *e
	p.Status = status
	body, _ := json.Marshal(&p) // an Error has only string and int fields
	writeBody(w, status, MediaTypeProblem, body)
}

func writeBody(w http.ResponseWriter, status int, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
