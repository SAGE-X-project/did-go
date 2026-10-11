package universal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
)

// Default limits of Client.
const (
	DefaultResponseLimit = 4 << 20
	DefaultTimeout       = 30 * time.Second
)

type clientConfig struct {
	post    bool
	limit   int64
	timeout time.Duration
	consume representation.ConsumeOptions
}

// ClientOption configures a Client.
type ClientOption func(*clientConfig)

// WithPOST makes the client use the POST version of the binding, with the
// options other than accept in a JSON body (default GET).
func WithPOST(post bool) ClientOption {
	return func(c *clientConfig) { c.post = post }
}

// WithResponseLimit sets the largest response body the client reads
// (default 4 MiB). A value below 1 keeps the default.
func WithResponseLimit(n int64) ClientOption {
	return func(c *clientConfig) {
		if n > 0 {
			c.limit = n
		}
	}
}

// WithTimeout sets the time limit of one call (default 30 s), on top of the
// caller's context. A value below 1 keeps the default.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *clientConfig) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithConsumeOptions sets the options the client consumes returned DID
// documents with.
func WithConsumeOptions(o representation.ConsumeOptions) ClientOption {
	return func(c *clientConfig) { c.consume = o }
}

// Client calls a remote DID resolver over the HTTP(S) binding. It implements
// resolution.Resolver and resolution.Dereferencer, is immutable and is safe
// for concurrent use.
//
// Choices where the specification leaves room:
//   - With an empty accept option the client asks for the complete result
//     (application/did-resolution or application/did-url-dereferencing), so
//     that all metadata reaches the caller; with an accept option it asks for
//     the document or content alone, as the binding defines.
//   - The DID or DID URL is percent-encoded when options travel in the
//     query, and also when it contains "?", "#" or "%", so that the server
//     cannot mistake a DID URL query, a fragment or a percent-encoded octet
//     for part of the request URL.
//   - A returned didDocument is parsed with the representation.Consumer given
//     to NewClient, using the contentType of the didResolutionMetadata (or the
//     Content-Type of a document-only response); without a contentType the
//     payload decides (application/json). A document whose id is not the
//     requested DID is INVALID_DID_DOCUMENT.
//   - Dereferenced content with a DID media type that the consumer accepts
//     becomes a *document.Document; text/uri-list content becomes a []string;
//     other content stays []byte.
//   - Error bodies are read as RFC 9457 objects. A response whose error cannot
//     be read gets the error type of its status code (400 INVALID_DID or
//     INVALID_DID_URL, 404 NOT_FOUND, 406 REPRESENTATION_NOT_SUPPORTED, 501
//     FEATURE_NOT_SUPPORTED, anything else INTERNAL_ERROR). Network failures,
//     time-outs and oversized responses are INTERNAL_ERROR.
type Client struct {
	endpoint string
	hc       *http.Client
	consumer representation.Consumer
	cfg      clientConfig
}

var (
	_ resolution.Resolver     = (*Client)(nil)
	_ resolution.Dereferencer = (*Client)(nil)
)

// NewClient returns a client of the DID resolver HTTP(S) endpoint, for
// example https://resolver.example/1.0/identifiers/. The endpoint must be an
// https URL without query or fragment (all HTTPS bindings MUST use TLS); a
// missing trailing slash is added. hc performs every request and carries the
// TLS configuration; c parses returned DID documents.
func NewClient(endpoint string, hc *http.Client, c representation.Consumer, opts ...ClientOption) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("universal: endpoint: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("universal: the endpoint must be an https URL without user information, query or fragment")
	}
	if hc == nil || c == nil {
		return nil, fmt.Errorf("universal: an HTTP client and a representation consumer are required")
	}
	cfg := clientConfig{limit: DefaultResponseLimit, timeout: DefaultTimeout}
	for _, o := range opts {
		o(&cfg)
	}
	ep := u.String()
	if !strings.HasSuffix(ep, "/") {
		ep += "/"
	}
	hcc := *hc
	hcc.Jar = nil
	hcc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{endpoint: ep, hc: &hcc, consumer: c, cfg: cfg}, nil
}

// Resolve resolves d at the remote resolver.
func (c *Client) Resolve(ctx context.Context, d did.DID, opts resolution.ResolutionOptions) resolution.Result {
	if e := opts.Validate(); e != nil {
		return resolution.ErrorResult(e)
	}
	full := opts.Accept == ""
	accept := opts.Accept
	if full {
		accept = spec.MediaTypeDIDResolution
	}
	rest := opts
	rest.Accept = ""
	query, body, err := c.encodeResolutionOptions(rest)
	if err != nil {
		return resolution.ErrorResult(resolution.NewError(resolution.CodeInvalidOptions, err.Error()))
	}
	resp, data, e := c.do(ctx, d.String(), accept, query, body)
	if e != nil {
		return resolution.ErrorResult(e)
	}
	return c.resolutionResult(resp, data, d)
}

// Dereference dereferences u at the remote resolver.
func (c *Client) Dereference(ctx context.Context, u did.DIDURL, opts resolution.DereferenceOptions) resolution.DereferenceResult {
	if e := opts.Validate(); e != nil {
		return resolution.ErrorDereferenceResult(e)
	}
	accept := opts.Accept
	if accept == "" {
		accept = spec.MediaTypeDIDURLDereferencing
	}
	rest := opts
	rest.Accept = ""
	query, body, err := c.encodeDereferenceOptions(rest)
	if err != nil {
		return resolution.ErrorDereferenceResult(resolution.NewError(resolution.CodeInvalidOptions, err.Error()))
	}
	resp, data, e := c.do(ctx, u.String(), accept, query, body)
	if e != nil {
		return resolution.ErrorDereferenceResult(e)
	}
	return c.dereferencingResult(resp, data)
}

// encodeResolutionOptions returns the options other than accept as query
// parameters (GET) or a JSON body (POST); both are empty without options.
func (c *Client) encodeResolutionOptions(o resolution.ResolutionOptions) (url.Values, []byte, error) {
	if !o.ExpandRelativeURLs && o.VersionID == "" && o.VersionTime == nil && !o.NoCache && len(o.Extra) == 0 {
		return nil, nil, nil
	}
	if c.cfg.post {
		body, err := json.Marshal(o)
		return nil, body, err
	}
	q := url.Values{}
	if o.ExpandRelativeURLs {
		q.Set("expandRelativeUrls", "true")
	}
	if o.VersionID != "" {
		q.Set("versionId", o.VersionID)
	}
	if o.VersionTime != nil {
		q.Set("versionTime", spec.FormatTimestamp(*o.VersionTime))
	}
	if o.NoCache {
		q.Set("noCache", "true")
	}
	return q, nil, addExtra(q, o.Extra)
}

func (c *Client) encodeDereferenceOptions(o resolution.DereferenceOptions) (url.Values, []byte, error) {
	if o.VerificationRelationship == "" && len(o.Extra) == 0 {
		return nil, nil, nil
	}
	if c.cfg.post {
		body, err := json.Marshal(o)
		return nil, body, err
	}
	q := url.Values{}
	if o.VerificationRelationship != "" {
		q.Set("verificationRelationship", o.VerificationRelationship)
	}
	return q, nil, addExtra(q, o.Extra)
}

func addExtra(q url.Values, extra map[string]any) error {
	for k, v := range extra {
		s, err := queryValue(v)
		if err != nil {
			return err
		}
		q.Set(k, s)
	}
	return nil
}

// do sends one request and reads the response body within the limit.
func (c *Client) do(ctx context.Context, identifier, accept string, query url.Values, body []byte) (*http.Response, []byte, *resolution.Error) {
	ident := identifier
	if len(query) > 0 || strings.ContainsAny(identifier, "?#%") {
		ident = encodeIdentifier(identifier)
	}
	target := c.endpoint + ident
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.timeout)
	defer cancel()
	method := http.MethodGet
	var reader io.Reader
	if c.cfg.post {
		method = http.MethodPost
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, nil, resolution.NewError(resolution.CodeInternalError, "cannot build the request: "+err.Error())
	}
	req.Header.Set("Accept", accept)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, resolution.NewError(resolution.CodeInternalError, "the remote resolver could not be reached: "+err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ContentLength > c.cfg.limit {
		return nil, nil, resolution.NewError(resolution.CodeInternalError, fmt.Sprintf("the response declares %d bytes, more than the limit of %d", resp.ContentLength, c.cfg.limit))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.limit+1))
	if err != nil {
		return nil, nil, resolution.NewError(resolution.CodeInternalError, "reading the response failed: "+err.Error())
	}
	if int64(len(data)) > c.cfg.limit {
		return nil, nil, resolution.NewError(resolution.CodeInternalError, fmt.Sprintf("the response is larger than the limit of %d bytes", c.cfg.limit))
	}
	return resp, data, nil
}

// mediaType returns the normalized media type of a response, or "".
func mediaType(resp *http.Response) string {
	mt, err := representation.NormalizeMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return ""
	}
	return mt
}

// resolutionResult turns a response into a resolution result.
func (c *Client) resolutionResult(resp *http.Response, data []byte, d did.DID) resolution.Result {
	mt := mediaType(resp)
	switch {
	case mt == spec.MediaTypeDIDResolution:
		return c.fullResolution(resp.StatusCode, data, d)
	case resp.StatusCode == http.StatusGone:
		return resolution.Result{DocumentMetadata: document.Metadata{Deactivated: true}}
	case resp.StatusCode == http.StatusOK:
		ct := strings.TrimSpace(resp.Header.Get("Content-Type"))
		res := c.consumeDocument(data, ct, d)
		if res.ResolutionMetadata.Error == nil {
			res.ResolutionMetadata.ContentType = ct
		}
		return res
	default:
		return resolution.ErrorResult(problemOf(resp, data, resolution.CodeInvalidDID))
	}
}

// fullResolution reads an application/did-resolution body.
func (c *Client) fullResolution(status int, data []byte, d did.DID) resolution.Result {
	var rr resolutionResult
	if err := json.Unmarshal(data, &rr); err != nil {
		return resolution.ErrorResult(resolution.NewError(resolution.CodeInternalError, "the resolution result is not valid: "+err.Error()))
	}
	switch {
	case rr.DIDResolutionMetadata.Error != nil, rr.DIDDocumentMetadata.Deactivated:
		return resolution.Result{ResolutionMetadata: rr.DIDResolutionMetadata, DocumentMetadata: rr.DIDDocumentMetadata}
	case status >= http.StatusBadRequest:
		return resolution.ErrorResult(statusError(status, resolution.CodeInvalidDID))
	case isNull(rr.DIDDocument):
		return resolution.ErrorResult(resolution.NewError(resolution.CodeInternalError, "the resolution result has no didDocument"))
	}
	ct := rr.DIDResolutionMetadata.ContentType
	if ct == "" {
		ct = spec.MediaTypeJSON
	}
	res := c.consumeDocument(rr.DIDDocument, ct, d)
	if res.ResolutionMetadata.Error != nil {
		return res
	}
	res.ResolutionMetadata = rr.DIDResolutionMetadata
	if res.ResolutionMetadata.ContentType == "" {
		res.ResolutionMetadata.ContentType = representation.MediaTypeOf(res.Info)
	}
	res.DocumentMetadata = rr.DIDDocumentMetadata
	return res
}

// consumeDocument parses document bytes with their media type and checks
// that the document is the one of d.
func (c *Client) consumeDocument(data []byte, ct string, d did.DID) resolution.Result {
	doc, info, err := c.consumer.Consume(data, ct, c.cfg.consume)
	if err != nil {
		return resolution.ErrorResult(resolution.NewError(resolution.CodeInvalidDIDDocument, "the returned DID document is not valid: "+err.Error()))
	}
	if doc == nil || doc.ID() != d {
		return resolution.ErrorResult(resolution.NewError(resolution.CodeInvalidDIDDocument, "the returned DID document is not the document of the requested DID"))
	}
	return resolution.Result{Document: doc, Raw: bytes.Clone(data), Info: info}
}

// dereferencingResult turns a response into a dereferencing result.
func (c *Client) dereferencingResult(resp *http.Response, data []byte) resolution.DereferenceResult {
	mt := mediaType(resp)
	switch {
	case mt == spec.MediaTypeDIDURLDereferencing:
		return c.fullDereferencing(resp.StatusCode, data)
	case resp.StatusCode == http.StatusSeeOther:
		return seeOther(resp)
	case resp.StatusCode == http.StatusGone:
		return resolution.DereferenceResult{ContentMetadata: document.Metadata{Deactivated: true}}
	case resp.StatusCode == http.StatusOK:
		ct := strings.TrimSpace(resp.Header.Get("Content-Type"))
		return resolution.DereferenceResult{
			ContentStream:         c.content(data, ct, false),
			DereferencingMetadata: resolution.DereferencingMetadata{ContentType: ct},
		}
	default:
		return resolution.ErrorDereferenceResult(problemOf(resp, data, resolution.CodeInvalidDIDURL))
	}
}

// seeOther reads a 303 response: the Location header is the selected service
// endpoint URL.
func seeOther(resp *http.Response) resolution.DereferenceResult {
	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil || !u.IsAbs() {
		return resolution.ErrorDereferenceResult(resolution.NewError(resolution.CodeInternalError, "a 303 response needs an absolute Location"))
	}
	return resolution.DereferenceResult{
		ContentStream:         []string{loc},
		DereferencingMetadata: resolution.DereferencingMetadata{ContentType: spec.MediaTypeURIList},
		ContentMetadata:       document.Metadata{Extra: map[string]any{"contentType": spec.MediaTypeURIList}},
	}
}

// fullDereferencing reads an application/did-url-dereferencing body.
func (c *Client) fullDereferencing(status int, data []byte) resolution.DereferenceResult {
	var dr dereferencingResult
	if err := json.Unmarshal(data, &dr); err != nil {
		return resolution.ErrorDereferenceResult(resolution.NewError(resolution.CodeInternalError, "the dereferencing result is not valid: "+err.Error()))
	}
	out := resolution.DereferenceResult{DereferencingMetadata: dr.DereferencingMetadata, ContentMetadata: dr.ContentMetadata}
	switch {
	case dr.DereferencingMetadata.Error != nil, dr.ContentMetadata.Deactivated:
		return out
	case status >= http.StatusBadRequest:
		return resolution.ErrorDereferenceResult(statusError(status, resolution.CodeInvalidDIDURL))
	}
	raw := dr.Content
	if isNull(raw) {
		raw = dr.ContentStream
	}
	if isNull(raw) {
		return resolution.ErrorDereferenceResult(resolution.NewError(resolution.CodeInternalError, "the dereferencing result has no content"))
	}
	out.ContentStream = c.content(raw, contentType(dr.DereferencingMetadata, dr.ContentMetadata), true)
	return out
}

// content converts dereferenced content: a document for a DID media type the
// consumer accepts, a URL list for text/uri-list, bytes otherwise. inJSON
// tells whether data is a JSON value of a dereferencing result.
func (c *Client) content(data []byte, ct string, inJSON bool) any {
	if isURIList(ct) {
		if inJSON {
			var list []string
			if json.Unmarshal(data, &list) == nil {
				return list
			}
			var s string
			if json.Unmarshal(data, &s) == nil {
				return uriList(s)
			}
		} else {
			return uriList(string(data))
		}
	}
	if mt, err := representation.NormalizeMediaType(ct); err == nil && representation.IsDIDMediaType(mt) {
		if doc, _, err := c.consumer.Consume(data, ct, c.cfg.consume); err == nil && doc != nil {
			return doc
		}
	}
	return bytes.Clone(data)
}

// uriList parses a text/uri-list body (RFC 2483 §5): one URI per line,
// comment lines start with "#".
func uriList(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// problemOf reads an RFC 9457 error body, or derives the error from the
// status code.
func problemOf(resp *http.Response, data []byte, badRequest resolution.Code) *resolution.Error {
	mt := mediaType(resp)
	if mt == MediaTypeProblem || mt == spec.MediaTypeJSON {
		var e resolution.Error
		if json.Unmarshal(data, &e) == nil && e.Type != "" {
			return &e
		}
	}
	return statusError(resp.StatusCode, badRequest)
}

// statusError returns the error type of a status code of the binding table.
func statusError(status int, badRequest resolution.Code) *resolution.Error {
	detail := fmt.Sprintf("the remote resolver answered status %d", status)
	switch status {
	case http.StatusBadRequest:
		return resolution.NewError(badRequest, detail)
	case http.StatusNotFound:
		return resolution.NewError(resolution.CodeNotFound, detail)
	case http.StatusNotAcceptable:
		return resolution.NewError(resolution.CodeRepresentationNotSupported, detail)
	case http.StatusNotImplemented:
		return resolution.NewError(resolution.CodeFeatureNotSupported, detail)
	}
	return resolution.NewError(resolution.CodeInternalError, detail)
}
