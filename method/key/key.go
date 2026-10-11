// Package key is the did:key method driver (docs/14 §5): it implements
// method.Method for the did:key method specification, W3C CCG draft at
// commit 2cc490c (requirement key didkey-2cc490c).
//
// A did:key DID is a public key encoded as a Multikey value. Read expands it
// deterministically into a DID document with the Document Creation
// Algorithm and serializes that document with the representation.Producer
// given to New; Create derives the DID from a public key. The method keeps
// no registry and no state, so Update and Deactivate are not supported.
//
// Choices where the specification leaves room:
//   - The default public key format is Multikey; JsonWebKey and, with
//     experimental public key types enabled, JsonWebKey2020 can be chosen.
//   - Encryption key derivation is off by default. When it is on, an Ed25519
//     key gets an X25519 key agreement method; no derivation is defined for
//     other key types, which then get none.
//   - options.defaultContext is the base context of the produced DID
//     version: https://www.w3.org/ns/did/v1 for DID Core 1.0 (as the
//     specification recommends) and https://www.w3.org/ns/did/v1.1 for DID
//     1.1, whose producers must write that context first. The Context
//     Creation Algorithm then adds the context of each method type. A
//     representation without JSON-LD gets no @context.
//   - A multicodec outside the specification's key table, and secp256k1 keys
//     (no standard library implementation), raise unsupportedPublicKeyType.
//   - The verification method fragment is the multibase value, as in the
//     specification's examples and its encryption method algorithm (the
//     signature method algorithm says "multicodecValue").
package key

import (
	"context"
	stdcrypto "crypto"
	"fmt"
	"slices"

	"github.com/sage-x-project/did-go/crypto"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
)

// Name is the did:key method name.
const Name = "key"

// Public key formats (options.publicKeyFormat).
const (
	FormatMultikey   = "Multikey"
	FormatJsonWebKey = "JsonWebKey"
	// FormatJsonWebKey2020 is an experimental format: the specification
	// allows it only with experimental public key types enabled.
	FormatJsonWebKey2020 = "JsonWebKey2020"
)

// knownFormats returns the public key formats this driver implements.
func knownFormats() []string {
	return []string{FormatMultikey, FormatJsonWebKey, FormatJsonWebKey2020}
}

// ExtraPublicKey is the CreateOptions.Extra key of the public key Create
// encodes: a crypto.PublicKey, a standard library public key accepted by
// crypto.FromCryptoKey, or a publicKeyMultibase string.
const ExtraPublicKey = "publicKey"

type config struct {
	format           string
	experimental     bool
	deriveEncryption bool
	mediaType        string
}

// Option configures a Method.
type Option func(*config)

// WithPublicKeyFormat sets options.publicKeyFormat. A format the driver
// does not know raises unsupportedPublicKeyType when a document is built.
func WithPublicKeyFormat(format string) Option {
	return func(c *config) { c.format = format }
}

// WithExperimentalPublicKeyTypes sets
// options.enableExperimentalPublicKeyTypes (default false, as the
// specification recommends).
func WithExperimentalPublicKeyTypes(enabled bool) Option {
	return func(c *config) { c.experimental = enabled }
}

// WithEncryptionKeyDerivation sets options.enableEncryptionKeyDerivation
// (default false).
func WithEncryptionKeyDerivation(enabled bool) Option {
	return func(c *config) { c.deriveEncryption = enabled }
}

// WithDefaultMediaType sets the representation Read produces when the
// resolver asks for none (default application/did, DID 1.1).
func WithDefaultMediaType(mediaType string) Option {
	return func(c *config) { c.mediaType = mediaType }
}

// Method is the did:key driver. It is immutable and safe for concurrent use.
type Method struct {
	producer representation.Producer
	cfg      config
}

var _ method.Method = (*Method)(nil)

// New returns a did:key driver that serializes documents with p.
func New(p representation.Producer, opts ...Option) *Method {
	cfg := config{format: FormatMultikey, mediaType: spec.MediaTypeDID}
	for _, o := range opts {
		o(&cfg)
	}
	return &Method{producer: p, cfg: cfg}
}

// Name returns "key".
func (m *Method) Name() string { return Name }

// Produces returns the DID media types Read can produce, in a fresh slice.
func (m *Method) Produces() []string { return representation.CoreMediaTypes() }

// produceOptions returns the production options for a media type, or the
// driver default for "".
func (m *Method) produceOptions(mediaType string) (representation.ProduceOptions, error) {
	if mediaType == "" {
		mediaType = m.cfg.mediaType
	}
	opts, err := representation.OptionsFor(mediaType)
	if err != nil {
		return representation.ProduceOptions{}, fmt.Errorf("%w: %w", method.ErrNotSupported, err)
	}
	return opts, nil
}

// Document runs the Document Creation Algorithm for identifier and returns
// the document as data model. opts selects the version and whether a JSON-LD
// @context entry is added.
func (m *Method) Document(identifier string, opts representation.ProduceOptions) (*document.Document, error) {
	return m.cfg.expand(identifier, opts)
}

// Read expands d into its DID document and serializes it. did:key has no
// versions, so VersionID and VersionTime are not supported. The metadata is
// empty: a did:key document is never created, updated or versioned in a
// registry.
func (m *Method) Read(ctx context.Context, d did.DID, opts method.ReadOptions) (*method.ReadResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.VersionID != "" || opts.VersionTime != nil {
		return nil, fmt.Errorf("%w: did:key documents have no versions", method.ErrNotSupported)
	}
	popts, err := m.produceOptions(opts.MediaType)
	if err != nil {
		return nil, err
	}
	doc, err := m.cfg.expand(d.String(), popts)
	if err != nil {
		return nil, err
	}
	if m.producer == nil {
		return nil, fmt.Errorf("key: no representation producer")
	}
	data, mediaType, err := m.producer.Produce(doc, popts)
	if err != nil {
		return nil, fmt.Errorf("key: produce %s: %w", d, err)
	}
	return &method.ReadResult{Data: data, ContentType: mediaType, Metadata: document.Metadata{}}, nil
}

// DIDFromKey returns the did:key DID of a public key:
// did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes)).
func DIDFromKey(k crypto.PublicKey) (did.DID, error) {
	mbv, err := k.Multikey()
	if err != nil {
		return did.DID{}, fmt.Errorf("%w: %w", method.ErrInvalidInput, err)
	}
	return did.Parse("did:key:" + mbv)
}

// publicKeyOf reads the ExtraPublicKey option.
func publicKeyOf(extra map[string]any) (crypto.PublicKey, error) {
	v, ok := extra[ExtraPublicKey]
	if !ok {
		return crypto.PublicKey{}, fmt.Errorf("%w: CreateOptions.Extra[%q] is required", method.ErrInvalidInput, ExtraPublicKey)
	}
	var (
		k   crypto.PublicKey
		err error
	)
	switch x := v.(type) {
	case crypto.PublicKey:
		k = x
	case string:
		k, err = crypto.ParseMultikey(x)
	case stdcrypto.PublicKey:
		k, err = crypto.FromCryptoKey(x)
	}
	if err != nil {
		return crypto.PublicKey{}, fmt.Errorf("%w: %w", method.ErrInvalidInput, err)
	}
	return k, nil
}

// Create derives the DID of the public key in opts.Extra[ExtraPublicKey]
// and expands its document with the driver's default representation
// options. did:key documents are generated, never stored, so input must be
// nil and no signer is needed.
func (m *Method) Create(ctx context.Context, input *document.Document, opts method.CreateOptions) (*method.CreateResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if input != nil {
		return nil, fmt.Errorf("%w: a did:key document is generated from the key; an input document cannot be stored", method.ErrInvalidInput)
	}
	k, err := publicKeyOf(opts.Extra)
	if err != nil {
		return nil, err
	}
	id, err := DIDFromKey(k)
	if err != nil {
		return nil, err
	}
	popts, err := m.produceOptions("")
	if err != nil {
		return nil, err
	}
	doc, err := m.cfg.expand(id.String(), popts)
	if err != nil {
		return nil, err
	}
	return &method.CreateResult{DID: id, Document: doc, Metadata: document.Metadata{}}, nil
}

// Update is not supported: did:key values are not stored in any registry.
func (m *Method) Update(context.Context, did.DID, *document.Document, method.UpdateOptions) (*method.UpdateResult, error) {
	return nil, fmt.Errorf("%w: did:key documents cannot be updated", method.ErrNotSupported)
}

// Deactivate is not supported: did:key values are not stored in any
// registry.
func (m *Method) Deactivate(context.Context, did.DID, method.DeactivateOptions) (*method.DeactivateResult, error) {
	return nil, fmt.Errorf("%w: did:key documents cannot be deactivated", method.ErrNotSupported)
}

// Formats returns the public key formats the driver knows, in a fresh slice.
func Formats() []string { return slices.Clone(knownFormats()) }
