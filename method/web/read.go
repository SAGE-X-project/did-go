package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
)

// redirectError is the type of errRedirect.
type redirectError string

func (e redirectError) Error() string { return string(e) }

// errRedirect is the cause of a refused redirect.
const errRedirect redirectError = "web: redirect refused"

// Read resolves d by the Read (Resolve) algorithm: it forms the URL (steps 1
// to 5), performs an HTTPS GET (step 6) and verifies that the document id is
// d (step 7). It returns the fetched bytes with their media type label and
// the metadata the response allows. did:web has no versions, so VersionID
// and VersionTime are not supported; NoCache sends Cache-Control: no-cache.
func (m *Method) Read(ctx context.Context, d did.DID, opts method.ReadOptions) (*method.ReadResult, error) {
	if opts.VersionID != "" || opts.VersionTime != nil {
		return nil, fmt.Errorf("%w: did:web documents have no versions", method.ErrNotSupported)
	}
	u, err := URL(d)
	if err != nil {
		return nil, err
	}
	client, err := m.httpClient(u)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, m.cfg.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, wrap(CodeFetchFailed, stmtGet, err, "cannot build the request")
	}
	req.Header.Set("Accept", acceptHeader(opts.MediaType))
	if opts.NoCache {
		req.Header.Set("Cache-Control", "no-cache")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, wrap(CodeFetchFailed, stmtGet, err, "GET %s failed", u.Redacted())
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, m.cfg.maxBytes))
		_ = resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, raise(CodeNotFound, stmtGet, "%s answered 404", u.Redacted())
	case http.StatusGone:
		return &method.ReadResult{Metadata: document.Metadata{Deactivated: true}}, nil
	default:
		return nil, raise(CodeFetchFailed, stmtGet, "%s answered status %d", u.Redacted(), resp.StatusCode)
	}
	data, err := m.readBody(resp)
	if err != nil {
		return nil, err
	}
	if err := checkDocument(data, d); err != nil {
		return nil, err
	}
	return &method.ReadResult{
		Data:        data,
		ContentType: contentLabel(resp.Header.Get("Content-Type")),
		Metadata:    metadataOf(resp.Header),
	}, nil
}

// httpClient returns a copy of the injected client with the driver's
// redirect policy and without a cookie jar, after refusing a transport that
// skips certificate verification or allows TLS below 1.2.
func (m *Method) httpClient(origin *url.URL) (*http.Client, error) {
	if m.client == nil {
		return nil, raise(CodeFetchFailed, stmtGet, "no HTTP client was given to New")
	}
	if t, ok := m.client.Transport.(*http.Transport); ok && t.TLSClientConfig != nil {
		c := t.TLSClientConfig
		if c.InsecureSkipVerify {
			return nil, raise(CodeFetchFailed, stmtGet, "the HTTP client skips TLS certificate verification")
		}
		if c.MinVersion != 0 && c.MinVersion < tls.VersionTLS12 {
			return nil, raise(CodeFetchFailed, sectionSecurity, "the HTTP client allows TLS versions below 1.2")
		}
	}
	c := *m.client
	c.Jar = nil
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > m.cfg.maxRedirects {
			return fmt.Errorf("%w: more than %d redirects", errRedirect, m.cfg.maxRedirects)
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("%w: redirect to a %s URL", errRedirect, req.URL.Scheme)
		}
		if !m.cfg.crossHost && !strings.EqualFold(hostPort(req.URL), hostPort(origin)) {
			return fmt.Errorf("%w: redirect to another host", errRedirect)
		}
		return nil
	}
	return &c, nil
}

func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	return u.Hostname() + ":" + port
}

// readBody reads at most the configured number of bytes.
func (m *Method) readBody(resp *http.Response) ([]byte, error) {
	if resp.ContentLength > m.cfg.maxBytes {
		return nil, raise(CodeFetchFailed, sectionSecurity, "the response declares %d bytes, more than the limit of %d", resp.ContentLength, m.cfg.maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, m.cfg.maxBytes+1))
	if err != nil {
		return nil, wrap(CodeFetchFailed, stmtGet, err, "reading the response failed")
	}
	if int64(len(data)) > m.cfg.maxBytes {
		return nil, raise(CodeFetchFailed, sectionSecurity, "the response is larger than the limit of %d bytes", m.cfg.maxBytes)
	}
	return data, nil
}

// acceptHeader prefers the media type the resolver asked for, then the DID
// media types, then the low-precision JSON types a web server usually uses.
func acceptHeader(preferred string) string {
	parts := []string{}
	if mt, err := representation.NormalizeMediaType(preferred); err == nil && preferred != "" {
		parts = append(parts, mt)
	}
	parts = append(parts, representation.CoreMediaTypes()...)
	parts = append(parts, spec.MediaTypeJSON+";q=0.9", spec.MediaTypeLDJSON+";q=0.9", "*/*;q=0.1")
	return strings.Join(parts, ", ")
}

// contentLabel returns the media type Read labels the bytes with.
func contentLabel(header string) string {
	mt, err := representation.NormalizeMediaType(header)
	if err == nil && (representation.IsDIDMediaType(mt) || representation.IsLowPrecision(mt)) {
		return mt
	}
	return spec.MediaTypeJSON
}

// metadataOf maps Last-Modified to updated.
func metadataOf(h http.Header) document.Metadata {
	var md document.Metadata
	if lm := h.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			t = t.UTC().Truncate(time.Second)
			md.Updated = &t
		}
	}
	return md
}
