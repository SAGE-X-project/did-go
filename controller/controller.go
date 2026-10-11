// Package controller is the DID controller player (DID Core 1.0 §2 and
// appendix B, DID 1.1 §2; docs/14 §5). A Controller creates, updates and
// deactivates DIDs through one method.Method driver (docs/00 FR-M1 to
// FR-M5, docs/01 UC-7 to UC-9).
//
// The controller never holds a private key. Where a method requires a proof
// of authorization, the driver asks the method.Signer given to New, which
// keeps its key wherever the caller keeps it (docs/12 §6.3). Verifying that
// proof is the driver's job: the DID method specification defines how
// authorization is performed (DID Core 1.0 §8.2, FR-M5).
//
// Before submitting a document the controller applies document.Validate for
// its target version and refuses any error finding, so a non-conforming
// document never reaches a verifiable data registry. A driver that does not
// support an operation returns method.ErrNotSupported, which the controller
// passes on unchanged for errors.Is.
//
// With a resolution.Resolver (WithResolver) the controller also checks, before
// an update or a deactivation, the rule of CID 1.0 §2.1.2 that each entry in
// the controller property identifies an entity capable of updating the
// canonical document: when the current document lists controllers, the
// signer's key must belong to one of them. When the property is absent,
// control "is determined entirely by its storage location", that is by the
// method, and the controller adds no check of its own.
package controller

import (
	"context"
	"fmt"
	"slices"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// Error is the type of the constant errors of this package. Callers test
// with errors.Is.
type Error string

// Error returns the message.
func (e Error) Error() string { return string(e) }

// Errors of the controller. Errors of the driver, such as
// method.ErrNotSupported and method.ErrUnauthorized, are wrapped and stay
// visible to errors.Is.
const (
	// ErrInvalidDocument: the document is nil or does not conform to the
	// target version; a *ValidationError carries the findings.
	ErrInvalidDocument Error = "controller: document does not conform"
	// ErrMethodMismatch: the DID or document belongs to another DID method
	// than the controller's driver.
	ErrMethodMismatch Error = "controller: DID of another method"
	// ErrInvalidSigner: the signer's key id is not an absolute DID URL with a
	// fragment, so it cannot name a verification method.
	ErrInvalidSigner Error = "controller: signer key id is not a verification method URL"
	// ErrNotController: the current document lists controllers and the
	// signer's key belongs to none of them (CID 1.0 §2.1.2).
	ErrNotController Error = "controller: signer is not a controller of the document"
	// ErrDeactivated: the DID is deactivated and cannot be changed.
	ErrDeactivated Error = "controller: DID is deactivated"
	// ErrCurrentDocument: the current document could not be resolved.
	ErrCurrentDocument Error = "controller: current document not available"
	// ErrInvalidResult: the driver returned a result that contradicts the
	// request, for example a document of another DID.
	ErrInvalidResult Error = "controller: driver returned an inconsistent result"
)

// ValidationError reports the error findings of document.Validate that made
// the controller refuse a document. It unwraps to ErrInvalidDocument.
type ValidationError struct {
	Version  spec.Version
	Findings []document.Finding
}

// Error lists the findings.
func (e *ValidationError) Error() string {
	s := fmt.Sprintf("%s for DID %s", ErrInvalidDocument, e.Version)
	for _, f := range e.Findings {
		s += "; " + f.String()
	}
	return s
}

// Unwrap returns ErrInvalidDocument.
func (e *ValidationError) Unwrap() error { return ErrInvalidDocument }

type config struct {
	version  spec.Version
	signer   method.Signer
	resolver resolution.Resolver
}

// Option configures a Controller.
type Option func(*config)

// WithVersion sets the DID version documents are validated for before they
// are submitted (default spec.Latest).
func WithVersion(v spec.Version) Option {
	return func(c *config) { c.version = v }
}

// WithSigner sets the signer the driver asks for proofs of authorization.
// Without one, a driver that requires a proof returns
// method.ErrUnauthorized.
func WithSigner(s method.Signer) Option {
	return func(c *config) { c.signer = s }
}

// WithResolver lets the controller resolve the current document before an
// update or a deactivation, to refuse a deactivated DID and to apply the
// controllers rule of CID 1.0 §2.1.2.
func WithResolver(r resolution.Resolver) Option {
	return func(c *config) { c.resolver = r }
}

// Controller performs the write operations of one DID method. It is
// immutable and safe for concurrent use when its driver, signer and
// resolver are.
type Controller struct {
	m   method.Method
	cfg config
}

// New returns a controller that writes through m. A nil driver, an
// unsupported version or a signer whose key id cannot name a verification
// method is an error.
func New(m method.Method, opts ...Option) (*Controller, error) {
	if m == nil {
		return nil, fmt.Errorf("controller: no method driver")
	}
	cfg := config{version: spec.Latest}
	for _, o := range opts {
		o(&cfg)
	}
	if !cfg.version.IsSupported() {
		return nil, fmt.Errorf("controller: unsupported DID version %s", cfg.version)
	}
	if cfg.signer != nil {
		if err := checkKeyID(cfg.signer.KeyID()); err != nil {
			return nil, err
		}
	}
	return &Controller{m: m, cfg: cfg}, nil
}

// Method returns the method name of the driver.
func (c *Controller) Method() string { return c.m.Name() }

func checkKeyID(id did.DIDURL) error {
	if id.IsZero() || id.IsRelative() || !id.HasFragment() || id.Fragment() == "" {
		return fmt.Errorf("%w: %q", ErrInvalidSigner, id.String())
	}
	return nil
}

func (c *Controller) checkMethod(d did.DID) error {
	if d.Method() != c.m.Name() {
		return fmt.Errorf("%w: %s is not a did:%s DID", ErrMethodMismatch, d, c.m.Name())
	}
	return nil
}

// validate applies document.Validate for the target version and keeps the
// error findings.
func (c *Controller) validate(d *document.Document) error {
	if d == nil {
		return fmt.Errorf("%w: no document", ErrInvalidDocument)
	}
	var errs []document.Finding
	for _, f := range document.Validate(d, c.cfg.version) {
		if f.Severity == document.SeverityError {
			errs = append(errs, f)
		}
	}
	if len(errs) > 0 {
		return &ValidationError{Version: c.cfg.version, Findings: errs}
	}
	return nil
}

// Create creates a DID through the driver (FR-M1). input is the document to
// register, or nil for a method that generates the document itself, such as
// did:key; a non-nil input is validated first and must name a DID of the
// driver's method. extra holds method-specific options and is copied.
func (c *Controller) Create(ctx context.Context, input *document.Document, extra map[string]any) (*method.CreateResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if input != nil {
		if err := c.checkMethod(input.ID()); err != nil {
			return nil, err
		}
		if err := c.validate(input); err != nil {
			return nil, err
		}
	}
	res, err := c.m.Create(ctx, input, method.CreateOptions{Signer: c.cfg.signer, Extra: vm.CloneJSONMap(extra)})
	if err != nil {
		return nil, fmt.Errorf("controller: create through did:%s: %w", c.m.Name(), err)
	}
	if res == nil || res.DID.Method() != c.m.Name() {
		return nil, fmt.Errorf("%w: create returned no DID of did:%s", ErrInvalidResult, c.m.Name())
	}
	if res.Document != nil && res.Document.ID() != res.DID {
		return nil, fmt.Errorf("%w: create returned the document of %s for %s", ErrInvalidResult, res.Document.ID(), res.DID)
	}
	return res, nil
}

// Update replaces the document of next.ID() with next (FR-M3). next is
// validated first; with a resolver the current document must not be
// deactivated and the signer must be one of its controllers, when it lists
// any. extra holds method-specific options and is copied.
func (c *Controller) Update(ctx context.Context, next *document.Document, extra map[string]any) (*method.UpdateResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.validate(next); err != nil {
		return nil, err
	}
	d := next.ID()
	if err := c.checkMethod(d); err != nil {
		return nil, err
	}
	if err := c.authorize(ctx, d); err != nil {
		return nil, err
	}
	res, err := c.m.Update(ctx, d, next, method.UpdateOptions{Signer: c.cfg.signer, Extra: vm.CloneJSONMap(extra)})
	if err != nil {
		return nil, fmt.Errorf("controller: update %s: %w", d, err)
	}
	if res == nil || (res.Document != nil && res.Document.ID() != d) {
		return nil, fmt.Errorf("%w: update of %s returned no result or another DID's document", ErrInvalidResult, d)
	}
	return res, nil
}

// Deactivate deactivates d (FR-M4). With a resolver the current document
// must not already be deactivated and the signer must be one of its
// controllers, when it lists any. extra holds method-specific options and
// is copied.
func (c *Controller) Deactivate(ctx context.Context, d did.DID, extra map[string]any) (*method.DeactivateResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.checkMethod(d); err != nil {
		return nil, err
	}
	if err := c.authorize(ctx, d); err != nil {
		return nil, err
	}
	res, err := c.m.Deactivate(ctx, d, method.DeactivateOptions{Signer: c.cfg.signer, Extra: vm.CloneJSONMap(extra)})
	if err != nil {
		return nil, fmt.Errorf("controller: deactivate %s: %w", d, err)
	}
	if res == nil || !res.Metadata.Deactivated {
		return nil, fmt.Errorf("%w: deactivation of %s is not reported in the metadata", ErrInvalidResult, d)
	}
	return res, nil
}

// authorize resolves the current document of d, when a resolver is
// configured, and applies the controllers rule of CID 1.0 §2.1.2: each entry
// identifies an entity capable of updating the canonical document, so a
// signer outside a non-empty controller set is refused. The DID subject is
// not added implicitly: a document that lists controllers names who
// controls it.
func (c *Controller) authorize(ctx context.Context, d did.DID) error {
	if c.cfg.resolver == nil {
		return nil
	}
	res := c.cfg.resolver.Resolve(ctx, d, resolution.ResolutionOptions{NoCache: true})
	if res.DocumentMetadata.Deactivated {
		return fmt.Errorf("%w: %s", ErrDeactivated, d)
	}
	if e := res.ResolutionMetadata.Error; e != nil {
		return fmt.Errorf("%w: %s: %w", ErrCurrentDocument, d, e)
	}
	if res.Document == nil || res.Document.ID() != d {
		return fmt.Errorf("%w: resolving %s returned no document of that DID", ErrCurrentDocument, d)
	}
	controllers := res.Document.Controllers()
	if len(controllers) == 0 {
		return nil
	}
	if c.cfg.signer == nil {
		return fmt.Errorf("%w: %s lists controllers and no signer identifies one", ErrNotController, d)
	}
	signer := c.cfg.signer.KeyID().DID()
	if !slices.Contains(controllers, signer) {
		return fmt.Errorf("%w: %s is not among the controllers of %s", ErrNotController, signer, d)
	}
	return nil
}
