package sage

import (
	"bytes"
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/universal"
	"github.com/sage-x-project/did-go/spec"
)

// Handler serves a Resolver over the DID Resolution HTTP(S) binding (DID
// Resolution v1.0 §12.1) with the standard universal.Handler, and adds the
// sageCode member of DIDP-05 to the problem details of a failed did:sage
// request: to the application/problem+json body, or to
// didResolutionMetadata.error of a complete result. Status codes, request
// parsing and every other response are those of the standard handler.
type Handler struct {
	inner  *universal.Handler
	prefix string
}

// NewHandler returns a handler for r. The options configure the standard
// handler; universal.WithPathPrefix also sets the prefix this handler uses
// to find the identifier.
func NewHandler(r *Resolver, prefix string, opts ...universal.HandlerOption) *Handler {
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	opts = append([]universal.HandlerOption{universal.WithPathPrefix(prefix)}, opts...)
	return &Handler{inner: universal.NewHandler(r, r, opts...), prefix: prefix}
}

// ServeHTTP answers one binding request. A request whose identifier does
// not name the sage method goes to the standard handler unchanged and
// unbuffered.
func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	id := h.identifier(req)
	if len(id) < len(didPrefix) || !strings.EqualFold(id[:len(didPrefix)], didPrefix) {
		h.inner.ServeHTTP(w, req)
		return
	}
	sink := &recorder{}
	ctx := context.WithValue(req.Context(), sinkKey{}, sink)
	// An identifier that breaks ID-01 is preset as the request's error. The
	// standard handler still applies its method and TLS checks first;
	// Resolver then answers with this error without observing a record.
	pre := checkID(id)
	if pre != nil {
		ctx = context.WithValue(ctx, presetKey{}, pre)
	}
	buf := &bufferedWriter{header: http.Header{}}
	h.inner.ServeHTTP(buf, req.WithContext(ctx))
	body := buf.body.Bytes()
	e := sink.get()
	if e == nil {
		e = pre // the standard handler refused the identifier before resolving
	}
	if e != nil {
		body = addSageCode(body, buf.header.Get("Content-Type"), e)
		buf.header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	for k, vs := range buf.header {
		w.Header()[k] = vs
	}
	w.WriteHeader(buf.statusCode())
	_, _ = w.Write(body)
}

// MediaTypeProblemJSON is the RFC 9457 problem details media type.
const MediaTypeProblemJSON = universal.MediaTypeProblem

// identifier returns the decoded identifier after the path prefix, as the
// standard handler reads it, or "".
func (h *Handler) identifier(req *http.Request) string {
	rest, ok := strings.CutPrefix(req.URL.EscapedPath(), h.prefix)
	if !ok {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(rest), "did%3a") {
		if s, err := url.PathUnescape(rest); err == nil {
			return s
		}
	}
	if req.URL.RawQuery != "" {
		rest += "?" + req.URL.RawQuery // the query of the DID URL
	}
	return rest
}

// addSageCode adds the sageCode member of e to the problem object in body:
// the whole body for problem details, didResolutionMetadata.error (or
// dereferencingMetadata.error) for a complete result. Only a problem whose
// type is the DID Resolution type e maps to gets the member, so the standard
// handler's own refusals, such as a request without TLS, stay unchanged. A
// body of another form is returned unchanged.
func addSageCode(body []byte, contentType string, e *Error) []byte {
	mt, _, _ := mime.ParseMediaType(contentType)
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	code, _ := json.Marshal(e.Code)
	if mt == MediaTypeProblemJSON {
		if !problemType(obj["type"], e) {
			return body
		}
		obj[SageCodeMember] = code
		return marshalOr(obj, body)
	}
	if mt != spec.MediaTypeDIDResolution && mt != spec.MediaTypeDIDURLDereferencing {
		return body
	}
	for _, name := range []string{"didResolutionMetadata", "dereferencingMetadata"} {
		var md map[string]json.RawMessage
		if json.Unmarshal(obj[name], &md) != nil || md["error"] == nil {
			continue
		}
		var problem map[string]json.RawMessage
		if json.Unmarshal(md["error"], &problem) != nil || !problemType(problem["type"], e) {
			return body
		}
		problem[SageCodeMember] = code
		md["error"] = marshalOr(problem, md["error"])
		obj[name] = marshalOr(md, obj[name])
		return marshalOr(obj, body)
	}
	return body
}

// problemType reports whether a problem type is one e can produce: the DID
// Resolution type it maps to, or, for an identifier that breaks ID-01,
// INVALID_DID_URL, which the standard handler reports for a malformed DID
// URL before Resolver runs.
func problemType(raw json.RawMessage, e *Error) bool {
	var got string
	if json.Unmarshal(raw, &got) != nil {
		return false
	}
	if got == e.ResolutionError().Type {
		return true
	}
	return (e.Code == CodeIDMalformed || e.Code == CodeSizeExceeded) && got == resolution.CodeInvalidDIDURL.TypeURL()
}

func marshalOr(v any, fallback []byte) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		return fallback
	}
	return data
}

// bufferedWriter holds the standard handler's response until the sageCode
// member is added.
type bufferedWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedWriter) Header() http.Header { return b.header }

func (b *bufferedWriter) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *bufferedWriter) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}

func (b *bufferedWriter) statusCode() int {
	if b.status == 0 {
		return http.StatusOK
	}
	return b.status
}
