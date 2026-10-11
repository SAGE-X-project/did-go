// Package web is the did:web method driver (docs/14 §5): it implements
// method.Method for the did:web method specification, W3C CCG draft at
// commit ea423c1 (requirement key didweb-ea423c1).
//
// A did:web DID names a did.json file on a web server. Read turns the DID
// into an HTTPS URL (URL), fetches the file with the *http.Client given to
// New, checks that the document id is the DID, and returns the fetched bytes
// labeled with their media type, so the resolver consumes and validates
// them. Create, Update and Deactivate are performed by the DID controller on
// its web server ("There is intentionally no HTTP API specified for did:web
// method operations"), so the driver returns method.ErrNotSupported for
// them. DIDFromURL and DocumentFile help a controller name its DID and write
// the did.json file.
//
// Security rules the driver enforces (the specification's security and
// privacy considerations are informative; these are did-go choices):
//   - Only https URLs are fetched, also after a redirect. TLS server
//     certificates are verified by the injected client; a client whose
//     *http.Transport skips verification or allows a TLS version below 1.2
//     is refused.
//   - The domain must be a DNS name; IP addresses and names whose last
//     label is numeric are refused. Path segments that decode to "." or ".."
//     or to URL delimiters are refused.
//   - Redirects are limited in number (WithMaxRedirects) and, by default,
//     must stay on the same host and port, so a document is only accepted
//     from the server its DID names (WithCrossHostRedirects).
//   - The response body is limited in size (WithMaxResponseBytes) and the
//     whole request in time (WithTimeout, on top of the caller's context).
//   - No cookies are sent or stored: the client's cookie jar is not used.
//   - The document id must be the DID being resolved, and every DID URL in
//     the document's id, controller, verification method, verification
//     relationship and service positions must be absolute
//     (§key-material-and-document-handling, which prevents key confusion).
//
// Choices where the specification leaves room:
//   - A response labeled with a DID media type, application/json or
//     application/ld+json keeps its label. Any other or missing label is
//     replaced by application/json, because the file is did.json and the
//     specification expects it to be served as application/json; the
//     resolver then decides the representation from the payload.
//   - 404 is NOT_FOUND. 410 (Gone) means the controller removed the
//     document on purpose, which the specification calls Deactivate, so it
//     is reported as a deactivated DID. Every other status is a fetch error.
//   - didDocumentMetadata.updated is taken from the Last-Modified header,
//     because an update is a change of the did.json file. created and
//     versionId cannot be known and are omitted.
//   - DNS resolution is done by the dialer of the injected client. The
//     specification recommends DNS over HTTPS (RFC 8484); a caller who
//     wants it configures the client's transport with such a resolver.
package web

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/representation"
)

// Name is the did:web method name.
const Name = "web"

// Default limits.
const (
	DefaultMaxRedirects     = 3
	DefaultMaxResponseBytes = 1 << 20
	DefaultTimeout          = 10 * time.Second
)

type config struct {
	maxRedirects int
	maxBytes     int64
	timeout      time.Duration
	crossHost    bool
}

// Option configures a Method.
type Option func(*config)

// WithMaxRedirects sets how many redirects Read follows (default 3; 0
// follows none). A negative value is treated as 0.
func WithMaxRedirects(n int) Option {
	return func(c *config) { c.maxRedirects = max(n, 0) }
}

// WithMaxResponseBytes sets the largest response body Read accepts
// (default 1 MiB). A value below 1 keeps the default.
func WithMaxResponseBytes(n int64) Option {
	return func(c *config) {
		if n > 0 {
			c.maxBytes = n
		}
	}
}

// WithTimeout sets the time limit of one Read, redirects included (default
// 10 s). A value below 1 keeps the default.
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithCrossHostRedirects allows redirects to another host or port (default
// false). The target must still be https.
func WithCrossHostRedirects(allow bool) Option {
	return func(c *config) { c.crossHost = allow }
}

// Method is the did:web driver. It is immutable and safe for concurrent use.
type Method struct {
	producer representation.Producer
	client   *http.Client
	cfg      config
}

var _ method.Method = (*Method)(nil)

// New returns a did:web driver that fetches with hc and writes did.json files
// with p (DocumentFile). The driver performs network I/O only through hc.
func New(p representation.Producer, hc *http.Client, opts ...Option) *Method {
	cfg := config{maxRedirects: DefaultMaxRedirects, maxBytes: DefaultMaxResponseBytes, timeout: DefaultTimeout}
	for _, o := range opts {
		o(&cfg)
	}
	return &Method{producer: p, client: hc, cfg: cfg}
}

// Name returns "web".
func (m *Method) Name() string { return Name }

// Produces returns no media type: the driver cannot choose a
// representation, it returns what the web server serves, and the resolver
// transcodes when needed. The slice is fresh.
func (m *Method) Produces() []string { return []string{} }

// Create returns method.ErrNotSupported: a did:web DID is created by the
// controller, who registers a domain and stores did.json on its web server.
func (m *Method) Create(context.Context, *document.Document, method.CreateOptions) (*method.CreateResult, error) {
	return nil, fmt.Errorf("%w: a did:web DID is created by storing did.json on the web server (didweb-ea423c1 §create-register)", method.ErrNotSupported)
}

// Update returns method.ErrNotSupported: the controller updates did.json on
// its web server.
func (m *Method) Update(context.Context, did.DID, *document.Document, method.UpdateOptions) (*method.UpdateResult, error) {
	return nil, fmt.Errorf("%w: a did:web document is updated by changing did.json on the web server (didweb-ea423c1 §update)", method.ErrNotSupported)
}

// Deactivate returns method.ErrNotSupported: the controller removes did.json
// from its web server.
func (m *Method) Deactivate(context.Context, did.DID, method.DeactivateOptions) (*method.DeactivateResult, error) {
	return nil, fmt.Errorf("%w: a did:web DID is deactivated by removing did.json from the web server (didweb-ea423c1 §deactivate-revoke)", method.ErrNotSupported)
}

// DocumentFile writes doc as the content of its did.json file with the
// producer given to New and checks it as Read would: the document id must be
// a did:web DID that forms a URL, and every DID URL in it must be absolute.
// It returns the bytes and their media type.
func (m *Method) DocumentFile(doc *document.Document, opts representation.ProduceOptions) ([]byte, string, error) {
	if doc == nil {
		return nil, "", raise(CodeInvalidDidDocument, stmtVerifyID, "no document")
	}
	if _, err := URL(doc.ID()); err != nil {
		return nil, "", err
	}
	if m.producer == nil {
		return nil, "", fmt.Errorf("web: no representation producer")
	}
	data, mediaType, err := m.producer.Produce(doc, opts)
	if err != nil {
		return nil, "", fmt.Errorf("web: produce %s: %w", doc.ID(), err)
	}
	if err := checkDocument(data, doc.ID()); err != nil {
		return nil, "", err
	}
	return data, mediaType, nil
}
