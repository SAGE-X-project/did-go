// Package relyingparty is the relying party player (DID Core 1.0 §2, docs/14
// §5): it finds the verification method a proof claims to use and checks
// that the method is authorized for a purpose (docs/01 UC-10). It runs the
// Retrieve Verification Method algorithm of CID 1.0 §3.3 over a
// resolution.Dereferencer: it dereferences the document URL of the method
// reference, refuses a deactivated DID and a document that does not conform
// or whose id is not that URL, and then applies document.SelectMethod for
// the remaining steps (fragment, id, controller and relationship checks).
// A revoked or expired method is refused as well (CID 1.0 §2.2).
//
// It returns a copy of the vm.Method. Verifying a proof of any credential
// format, and decoding the public key with package crypto, is the caller's
// choice and out of scope. The relying party holds no trust decision beyond
// what the specifications state.
//
// DID Core 1.0 §5.1.2 adds that verification methods in the DID documents of
// a document's controllers SHOULD be accepted as authoritative for the DID
// subject. DID 1.1 and CID 1.0 do not repeat this, so it applies to DID Core
// 1.0 documents only and is opt-in (WithControllerDocuments, docs/06 §7).
package relyingparty

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// Error is the type of the constant errors of this package. Callers test
// with errors.Is. Failures of the CID 1.0 algorithm wrap a *resolution.Error
// with the CID 1.0 §3.5 type instead, so errors.As yields the RFC 9457
// object.
type Error string

// Error returns the message.
func (e Error) Error() string { return string(e) }

// Errors of the relying party.
const (
	// ErrInvalidPurpose: the purpose is not one of the five verification
	// relationships.
	ErrInvalidPurpose Error = "relyingparty: unknown verification relationship"
	// ErrDeactivated: the DID that holds the method, or the subject, is
	// deactivated.
	ErrDeactivated Error = "relyingparty: DID is deactivated"
	// ErrNotAuthoritative: the method belongs neither to the subject nor,
	// with WithControllerDocuments, to one of the subject's controllers.
	ErrNotAuthoritative Error = "relyingparty: verification method is not authoritative for the subject"
	// ErrRevoked: the method's revoked time has passed (CID 1.0 §2.2).
	ErrRevoked Error = "relyingparty: verification method is revoked"
	// ErrExpired: the method's expires time has passed (CID 1.0 §2.2).
	ErrExpired Error = "relyingparty: verification method has expired"
)

type config struct {
	version         spec.Version
	resolver        resolution.Resolver
	controllerDocs  bool
	now             func() time.Time
	dereferenceOpts resolution.DereferenceOptions
}

// Option configures a RelyingParty.
type Option func(*config)

// WithVersion sets the DID version whose rules apply to dereferenced
// documents. The default, spec.VUnknown, validates documents as
// spec.Latest and takes the version of a subject document from the
// resolver's detection result.
func WithVersion(v spec.Version) Option {
	return func(c *config) { c.version = v }
}

// WithResolver sets a resolver used to obtain the subject's DID document in
// VerificationMethodFor; its detection result tells the document's DID
// version when WithVersion is not set.
func WithResolver(r resolution.Resolver) Option {
	return func(c *config) { c.resolver = r }
}

// WithControllerDocuments accepts verification methods from the DID
// documents of the subject's controllers as authoritative (DID Core 1.0
// §5.1.2), for DID Core 1.0 subject documents only.
func WithControllerDocuments() Option {
	return func(c *config) { c.controllerDocs = true }
}

// WithClock sets the clock used to compare revoked and expires times
// (default time.Now).
func WithClock(now func() time.Time) Option {
	return func(c *config) { c.now = now }
}

// WithDereferenceOptions sets the options passed when dereferencing a
// document URL ("using the supplied options", CID 1.0 §3.3 step 4).
func WithDereferenceOptions(o resolution.DereferenceOptions) Option {
	return func(c *config) { c.dereferenceOpts = o }
}

// RelyingParty retrieves verification methods. It is immutable and safe for
// concurrent use when its dereferencer and resolver are.
type RelyingParty struct {
	d   resolution.Dereferencer
	cfg config
}

// New returns a relying party that dereferences with d. A nil dereferencer,
// an unsupported version, and WithControllerDocuments when the DID Core 1.0
// profile can never apply (another version is set, or no version and no
// resolver to detect one) are errors.
func New(d resolution.Dereferencer, opts ...Option) (*RelyingParty, error) {
	if d == nil {
		return nil, fmt.Errorf("relyingparty: no dereferencer")
	}
	cfg := config{now: time.Now}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.version != spec.VUnknown && !cfg.version.IsSupported() {
		return nil, fmt.Errorf("relyingparty: unsupported DID version %s", cfg.version)
	}
	if cfg.now == nil {
		return nil, fmt.Errorf("relyingparty: no clock")
	}
	if cfg.controllerDocs && cfg.version != spec.V10 && (cfg.version != spec.VUnknown || cfg.resolver == nil) {
		return nil, fmt.Errorf("relyingparty: controller documents are accepted for DID Core 1.0 only (core10#did-controller.4); set WithVersion(spec.V10) or a resolver that detects the version")
	}
	if e := cfg.dereferenceOpts.Validate(); e != nil {
		return nil, fmt.Errorf("relyingparty: dereference options: %w", e)
	}
	return &RelyingParty{d: d, cfg: cfg}, nil
}

// cidError returns a CID 1.0 §3.5 error citing a statement.
func cidError(code resolution.Code, statement, format string, args ...any) error {
	return fmt.Errorf("relyingparty: %s: %w", statement, resolution.NewError(code, fmt.Sprintf(format, args...)))
}

// checkRef applies step 1: the reference must be an absolute DID URL with a
// fragment.
func checkRef(ref did.DIDURL) error {
	if ref.IsZero() || ref.IsRelative() || !ref.HasFragment() || ref.Fragment() == "" {
		return cidError(resolution.CodeInvalidVerificationMethodURL, "cid10#retrieve-verification-method.1",
			"%q is not an absolute DID URL with a fragment", ref.String())
	}
	return nil
}

// VerificationMethod runs CID 1.0 §3.3 Retrieve Verification Method for ref
// and the verification relationship p, and refuses a deactivated DID and a
// revoked or expired method. It returns a copy of the method.
func (rp *RelyingParty) VerificationMethod(ctx context.Context, ref did.DIDURL, p vm.Purpose) (*vm.Method, error) {
	if !p.Valid() {
		return nil, fmt.Errorf("%w: %d", ErrInvalidPurpose, p)
	}
	if err := checkRef(ref); err != nil {
		return nil, err
	}
	docURL := ref.WithoutFragment()
	doc, err := rp.dereference(ctx, docURL)
	if err != nil {
		return nil, err
	}
	if err := rp.conforms(doc, rp.validationVersion(rp.cfg.version)); err != nil {
		return nil, err
	}
	m, ce := document.SelectMethod(doc, ref, p)
	if ce != nil {
		return nil, fmt.Errorf("relyingparty: %w: %w", resolution.NewError(resolution.Code(ce.Code), ce.Reason), ce)
	}
	if err := rp.usable(m); err != nil {
		return nil, err
	}
	return m, nil
}

// VerificationMethodFor retrieves ref for p as VerificationMethod does and
// also requires that the method speaks for subject: ref must be a method of
// the subject's own document or, with WithControllerDocuments and a DID Core
// 1.0 subject document, of the document of one of the subject's controllers
// (DID Core 1.0 §5.1.2). In the second case the method must be in
// relationship p of the controller's document.
func (rp *RelyingParty) VerificationMethodFor(ctx context.Context, subject did.DID, ref did.DIDURL, p vm.Purpose) (*vm.Method, error) {
	if subject.IsZero() {
		return nil, fmt.Errorf("%w: no subject", ErrNotAuthoritative)
	}
	if !p.Valid() {
		return nil, fmt.Errorf("%w: %d", ErrInvalidPurpose, p)
	}
	if err := checkRef(ref); err != nil {
		return nil, err
	}
	if ref.DID() == subject {
		return rp.VerificationMethod(ctx, ref, p)
	}
	if !rp.cfg.controllerDocs {
		return nil, fmt.Errorf("%w: %s is not a method of %s", ErrNotAuthoritative, ref, subject)
	}
	doc, v, err := rp.subjectDocument(ctx, subject)
	if err != nil {
		return nil, err
	}
	if v != spec.V10 {
		return nil, fmt.Errorf("%w: the document of %s is DID %s; controller documents count for DID Core 1.0 only", ErrNotAuthoritative, subject, v)
	}
	if err := rp.conforms(doc, spec.V10); err != nil {
		return nil, err
	}
	if !slices.Contains(doc.Controllers(), ref.DID()) {
		return nil, fmt.Errorf("%w: %s is not a controller of %s", ErrNotAuthoritative, ref.DID(), subject)
	}
	return rp.VerificationMethod(ctx, ref, p)
}

// subjectDocument obtains the subject's document and the DID version that
// applies to it: through the resolver when there is one, otherwise through
// the dereferencer with the configured version.
func (rp *RelyingParty) subjectDocument(ctx context.Context, subject did.DID) (*document.Document, spec.Version, error) {
	if rp.cfg.resolver == nil {
		doc, err := rp.dereference(ctx, subject.URL())
		return doc, rp.cfg.version, err
	}
	res := rp.cfg.resolver.Resolve(ctx, subject, resolution.ResolutionOptions{})
	if res.DocumentMetadata.Deactivated {
		return nil, spec.VUnknown, fmt.Errorf("%w: %s", ErrDeactivated, subject)
	}
	if e := res.ResolutionMetadata.Error; e != nil {
		return nil, spec.VUnknown, fmt.Errorf("relyingparty: resolve %s: %w", subject, e)
	}
	if err := checkDocument(res.Document, subject.URL()); err != nil {
		return nil, spec.VUnknown, err
	}
	v := rp.cfg.version
	if v == spec.VUnknown {
		v = res.Info.DetectedVersion
	}
	return res.Document, v, nil
}

// dereference applies step 4 to a document URL and checks what comes back:
// a deactivated DID is refused, the content must be a DID document (step 5)
// and its id must be the URL it was retrieved from (CID 1.0 §2.1.1).
func (rp *RelyingParty) dereference(ctx context.Context, u did.DIDURL) (*document.Document, error) {
	res := rp.d.Dereference(ctx, u, rp.cfg.dereferenceOpts)
	if res.ContentMetadata.Deactivated {
		return nil, fmt.Errorf("%w: %s", ErrDeactivated, u)
	}
	if e := res.DereferencingMetadata.Error; e != nil {
		return nil, fmt.Errorf("relyingparty: cid10#retrieve-verification-method.4: dereference %s: %w", u, e)
	}
	doc, _ := res.ContentStream.(*document.Document)
	if err := checkDocument(doc, u); err != nil {
		return nil, err
	}
	return doc, nil
}

// checkDocument requires a document whose base identifier is the canonical
// URL it was retrieved from; any other document is not authoritative and the
// identifier is treated as invalid (CID 1.0 §2.1.1).
func checkDocument(doc *document.Document, u did.DIDURL) error {
	if doc == nil {
		return cidError(resolution.CodeInvalidControlledIdentifierDocument, "cid10#retrieve-verification-method.5",
			"dereferencing %s returned no DID document", u)
	}
	if doc.ID().URL() != u {
		return cidError(resolution.CodeInvalidControlledIdentifierDocumentID, "cid10#subjects.4",
			"dereferencing %s returned the document of %s", u, doc.ID())
	}
	return nil
}

// validationVersion returns the version documents are validated for.
func (rp *RelyingParty) validationVersion(v spec.Version) spec.Version {
	if v == spec.VUnknown {
		return spec.Latest
	}
	return v
}

// conforms applies step 5: a document with an error finding of
// document.Validate for v is not a conforming document.
func (rp *RelyingParty) conforms(doc *document.Document, v spec.Version) error {
	for _, f := range document.Validate(doc, v) {
		if f.Severity == document.SeverityError {
			return cidError(resolution.CodeInvalidControlledIdentifierDocument, "cid10#retrieve-verification-method.5",
				"the document of %s does not conform to DID %s: %s", doc.ID(), v, f)
		}
	}
	return nil
}

// usable refuses a method whose revoked time has passed ("MUST NOT be
// used") or whose expires time has passed ("SHOULD cease to be used"), CID
// 1.0 §2.2.
func (rp *RelyingParty) usable(m *vm.Method) error {
	now := rp.cfg.now()
	if m.Revoked != nil && !now.Before(*m.Revoked) {
		return fmt.Errorf("%w: %s since %s", ErrRevoked, m.ID, m.Revoked.UTC().Format(time.RFC3339))
	}
	if m.Expires != nil && !now.Before(*m.Expires) {
		return fmt.Errorf("%w: %s since %s", ErrExpired, m.ID, m.Expires.UTC().Format(time.RFC3339))
	}
	return nil
}
