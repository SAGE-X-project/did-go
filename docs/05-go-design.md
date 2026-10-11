# DID Core v1.0/v1.1: Go Design

> Target: Go 1.26.8 toolchain, language version `go 1.26.0`. Module `github.com/sage-x-project/did-go`. The SAGE extension is a separate module, `advanced/sage` ([`12`](12-standard-core-and-sage-extension.md) §3).
> Principle: a dependency-free core (standard library only) plus Ports & Adapters. The delegation boundaries of the spec (Resolution = DID-RESOLUTION, VM/Service = CID, a single media type `application/did`) become package boundaries.
>
> **Delegated specs, as settled:** the exact norms and Go mapping for VM/Service/Relationship are canonical in [`06-cid-data-model.md`](06-cid-data-model.md). The Resolution/Dereferencing contract (options, metadata, RFC9457 errors, DID parameters, HTTP binding) is canonical in [`07-did-resolution-contract.md`](07-did-resolution-contract.md). §5, §6 and §7 below summarize them. Follow those documents for details.
>
> **Dual-version support (v1.0 + v1.1):** the core data model is **one v1.1 superset**. Version branching exists in only three places: (1) the serialization envelope (representation `Options.SpecVersion` plus the validation profile `document.Profile`), (2) the Resolution contract (`resolution/compat`), and (3) DID parameters (`hl`/`serviceType`, handled in compat). The canonical source for the normative comparison, detection rules and error mapping is [`09-v1.0-compat.md`](09-v1.0-compat.md).

---

## 1. Package layout

```
did-go/
├── spec/                # SpecVersion (V10/V11/VUnknown), small, dependency-free  FR-V1
│   └── version.go
├── did/                 # DID / DID URL parsing and validation (dependency-free, version-independent)  FR-S*
│   ├── did.go
│   ├── url.go
│   ├── abnf.go          # ABNF rules (subset of RFC5234/RFC3986)
│   └── relative.go      # relative DID URL absolutization (RFC3986 §5)
├── document/            # DID document data model, Builder, Validator   FR-D*
│   ├── document.go
│   ├── value.go         # INFRA type system
│   ├── builder.go
│   ├── validator.go
│   └── selector.go      # relationship/reference selector
├── vm/                  # VerificationMethod, Relationship, Service  FR-D3/D4/D5
│   ├── method.go
│   ├── relationship.go
│   └── service.go
├── representation/      # application/did Producer/Consumer        FR-R*
│   ├── representation.go
│   ├── json.go
│   └── mediatype.go
├── jsonld/              # @context handling, term filtering, integrity           FR-R3/R6/V5
│   ├── context.go
│   ├── context_v1.go    # v1.0 base context (…/ns/did/v1) + SHA-256
│   └── context_v1_1.go  # v1.1 base context + SHA-256
├── resolution/          # Resolver and Dereferencer interfaces, metadata     FR-X*
│   ├── resolver.go
│   ├── dereferencer.go
│   ├── metadata.go
│   ├── errors.go        # error code catalog
│   └── compat/          # v1.0 contract adapter (resolveRepresentation, string errors)  FR-V4
│       └── v10.go
├── method/              # Method interface, Registry, reference implementations     FR-M*
│   ├── method.go
│   ├── registry.go
│   ├── key/             # did:key reference implementation
│   └── web/             # did:web reference implementation
└── crypto/              # KeyCodec interface (delegated to CID)            FR-D3/P1
    └── codec.go
```

Dependency direction: `method/*` and `crypto` adapters → `resolution`, `method` (contracts) → `document`, `vm`, `representation` → `did` → `spec`. **The core does not import adapters.** (`resolution/compat` is in the adapter layer. The core does not import it.)

### 1.1 `spec`: version model (FR-V1)

```go
package spec

// Version is a property of the representation and contract layers. Document has no version field (09 §3, ADR-12).
type Version int

const (
    VUnknown Version = iota // cannot be detected; processed with v1.1 rules
    V10                     // DID Core v1.0 REC (2022-07-19)
    V11                     // DID Core v1.1 CR (default)
)

func (v Version) ContextURL() string // V10: …/ns/did/v1, V11: …/ns/did/v1.1
```

---

## 2. `did`: syntax (FR-S1~S6)

```go
package did

// DID is a parsed, validated, immutable DID. did = "did:" method-name ":" method-specific-id
type DID struct {
    method string // lowercase ASCII + digit (%x61-7A / DIGIT)
    msid   string // method-specific-id (validated)
}

func (d DID) Method() string { return d.method }
func (d DID) MSID() string   { return d.msid }
func (d DID) String() string { return "did:" + d.method + ":" + d.msid }

// Parse parses a bare DID. It fails if a query or fragment is present (§Identifier Restrictions).
func Parse(s string) (DID, error)

// DIDURL is did-url = did path-abempty ["?" query] ["#" fragment].
type DIDURL struct {
    DID      DID
    Path     string // path-abempty (RFC3986 §3.3), raw text, not decoded
    Query    string // after "?" (RFC3986 §3.4)
    Fragment string // after "#" (RFC3986 §3.5)
}

func (u DIDURL) String() string
func (u DIDURL) IsRelative() bool // true if it does not start with "did:m:msid"

// ParseURL parses a DID URL.
func ParseURL(s string) (DIDURL, error)

// ParseRef takes a relative or absolute DID URL reference and absolutizes it against base (RFC3986 §5).
// Example: ParseRef("#key-1", did) → did:example:123#key-1
func ParseRef(ref string, base DID) (DIDURL, error)
```

**ABNF validation (`abnf.go`)**: uses a state machine and per-character checks, not regular expressions, and produces errors that include the position (pos):

```go
// idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
func isIDChar(s string, i int) (width int, ok bool)
// method-char = %x61-7A / DIGIT
func isMethodChar(b byte) bool
```

Error types:

```go
type SyntaxError struct {
    Input string
    Pos   int
    Msg   string
}
func (e *SyntaxError) Error() string

var ErrIdentifierRestriction = errors.New("did: subject/controller identifier must not contain query or fragment")
```

---

## 3. `document` + `vm`: data model (FR-D1~D7)

### 3.1 INFRA type system (`value.go`)

A thin set of type wrappers that holds the map/list/set/datetime/string/integer/double/boolean/null values of spec §Data Model without loss.

```go
package document

// Value is an INFRA data model value. It guarantees lossless representation round trips.
type Value interface{ isValue() }

type (
    String   string
    Integer  int64          // XSD decimal, no fractional part
    Double   float64        // XSD double
    Boolean  bool
    Null     struct{}
    DateTime time.Time      // serialized as UTC "Z", sub-seconds removed
    List     []Value        // ordered
    Set      []Value        // unordered, no duplicates
    Map      *OrderedMap    // string keys, no duplicates, insertion order preserved
)
```

> The Validator enforces "no duplicates" for `Set`. `Map` preserves insertion order (deterministic output, NFR-1), but consumption does not depend on order.

### 3.2 DID document (`document.go`)

```go
// Document is a conforming DID document. It is created only by Builder and is immutable.
type Document struct {
    id                   did.DID
    controller           []did.DID          // string | set
    alsoKnownAs          []string           // URL | DID
    verificationMethod   []vm.Method
    authentication       []vm.RelValue      // embedded VM or referenced DID-URL
    assertionMethod      []vm.RelValue
    keyAgreement         []vm.RelValue
    capabilityInvocation []vm.RelValue
    capabilityDelegation []vm.RelValue
    service              []vm.Service
    // Two buckets (Production/Consumption consumer rules 3 and 4, FR-D7):
    extensions   document.Map        // rule 4: unknown *non*-representation-specific entries → part of the data model
    reprEntries  map[string]any      // rule 3: *known* representation-specific entries (for example @context)
}
// Note: equivalentId/canonicalId are not in the Core Properties table, context or vocab of this
//   v1.1 document. Their formal definition is didDocumentMetadata in DID-Resolution →
//   resolution.DocumentMetadata (07 §5).
//   However, DID Core §Equivalence Properties (Security chapter) describes them as properties
//   "inside the DID document". This is a tension between specs. See 08-verification-report.md §2.

func (d *Document) ID() did.DID { return d.id }
func (d *Document) Relationship(r vm.Purpose) []vm.RelValue
```

### 3.3 Verification Method / Relationship / Service (`vm`)

```go
package vm

// Method is a CID §2.2 verification method. Detailed norms and mapping: 06-cid-data-model.md §2, §5, §11.
// DID constraints: id=DID-URL, controller=DID. controller is only a *claim* and does not mean
// actual control (a referenced VM can live in an external document). The binding is enforced by
// the CID Retrieve VM algorithm.
// Layering: the CID-general mapping in 06 §11 (id/controller = string) is the CID-layer view.
// DID document implementations use this type (constraints enforced by types). This §3.3 is
// canonical for the DID layer.
type Method struct {
    ID         did.DIDURL // required
    Type       string     // required: "Multikey" | "JsonWebKey"
    Controller did.DID     // required (claim)
    Expires    *time.Time  // XSD dateTimeStamp; proofs are not verified after this time
    Revoked    *time.Time  // must not be used after this time
    // Verification material: exactly one for the same material (CID §2.2.1 MUST NOT both)
    PublicKeyMultibase string          // Multikey: z+base58btc, multicodec prefix
    PublicKeyJwk       map[string]any  // JsonWebKey: RFC7517, private members such as 'd' are forbidden
    // Secret material: excluded from serialization by default (FR-P3). Only with IncludeSecret opt-in.
    SecretKeyMultibase string
    SecretKeyJwk       map[string]any
}

// Validate: key material XOR, required fields, absence of JWK private members, Multikey prefix/length.
func (m Method) Validate() error

// RelValue is an element of a verification relationship: an embedded VM or a reference.
type RelValue struct {
    Ref      *did.DIDURL // referenced (string)
    Embedded *Method     // embedded (map)
}
func (v RelValue) IsReference() bool { return v.Ref != nil }

type Purpose int
const (
    Authentication Purpose = iota
    AssertionMethod
    KeyAgreement
    CapabilityInvocation
    CapabilityDelegation
)

// Service is CID §2.1.4. Only type and serviceEndpoint are required; id is optional (if present, it must not repeat within the document).
// (The CID parent sentence reads as if id were required, but the more specific sub-definition and the spec examples make id optional. See 06 §8.)
type Service struct {
    ID              string          // optional. URL | DID. Must be unique if present.
    Type            []string        // required. string | set
    ServiceEndpoint []Endpoint      // required. string | map | set
}

// Endpoint is polymorphic: a string URL or a map.
type Endpoint struct {
    URL string          // if a string, it must be a valid URL (§Services)
    Map map[string]any  // map form
}
func (s Service) Validate() error
```

### 3.4 Builder & Validator (`builder.go`, `validator.go`)

```go
type Builder struct{ /* internal accumulated state */ }

func NewBuilder(id did.DID) *Builder
func (b *Builder) Controller(c ...did.DID) *Builder
func (b *Builder) AlsoKnownAs(u ...string) *Builder
func (b *Builder) VerificationMethod(m ...vm.Method) *Builder
func (b *Builder) Authentication(v ...vm.RelValue) *Builder
func (b *Builder) Service(s ...vm.Service) *Builder
// ... remaining relationships

// Build validates conformance of the whole document and returns an immutable Document. Returns an error on failure.
func (b *Builder) Build() (*Document, error)

// Validate enforces the §Core Properties and §Data Model norms.
//  - id required, DID syntax
//  - VM key format XOR
//  - service endpoint URL validity
//  - no duplicate set elements
//  - whether relationship references dangle within the document (warning/option)
func Validate(d *Document) error // == ValidateProfile(d, ProfileV11)

// Profile is a per-version validation profile (FR-V3, 09 §5).
type Profile int
const (
    ProfileV11 Profile = iota // default: CID norms, service.id optional
    ProfileV10                // v1.0 REC §5.4: service.id required. Properties undefined in v1.0 (expires etc.) produce warnings
)

func ValidateProfile(d *Document, p Profile) error
```

### 3.5 Selector (`selector.go`), UC-10

```go
// ResolveRef resolves a relationship reference to the actual Method, including relative URL absolutization.
func (d *Document) ResolveRef(ref did.DIDURL) (*vm.Method, error) // ErrDanglingReference

// SelectByID finds the fragment dereference target (VM/Service). (UC-6)
func (d *Document) SelectByID(id did.DIDURL) (any, bool)
```

---

## 4. `representation`: representations (FR-R1~R5)

```go
package representation

const (
    MediaTypeDID       = "application/did"         // v1.1
    MediaTypeDIDJSON   = "application/did+json"    // v1.0 legacy (accepted on consume + V10 production)
    MediaTypeDIDLDJSON = "application/did+ld+json" // v1.0 legacy (accepted on consume + V10 production)
)

// Options are producer/consumer options.
type Options struct {
    SpecVersion   spec.Version // target production version (default V11); decides the @context URL and media type (09 §5)
    JSONLD        bool         // inject @context (FR-R3)
    IncludeSecret bool         // include secret key material (default false, FR-P3)
}

// Producer: data model → serialization. MUST NOT produce non-conforming output.
// With SpecVersion=V10 the v1.0 profile is enforced: service.id required (error), warnings for properties undefined in v1.0 (09 §5).
type Producer interface {
    Produce(doc *document.Document, opts Options) (data []byte, mediaType string, err error)
}

// ConsumeInfo is the detection result on consumption (FR-V1).
// Detection order (09 §4): if @context is present, its first value decides → otherwise did+json is V10, application/did is V11, did+ld+json is an error
//   → for a low-precision type, Expected, or else VUnknown (v1.1 rules), with Assumed=true → anything else is an error.
type ConsumeInfo struct {
    DetectedVersion spec.Version
    IsJSONLD        bool      // whether @context is present
    Mismatch        *Mismatch // set when the declared media type disagrees with the content; nil otherwise
    Assumed         bool      // true when the version was assumed for a low-precision type
}

// Mismatch records a declared media type that differs from the representation detected in the content.
type Mismatch struct {
    Declared string // declared media type
    Detected string // media type of the representation detected in the content
}

// ConsumeOptions are the consumption options.
type ConsumeOptions struct {
    Expected spec.Version // version to use for a low-precision type without @context; VUnknown means none
    Strict   bool         // turns Mismatch and Assumed into errors
}

// Consumer: serialization + media type → data model. MUST error on non-conforming input.
// Accepts all three media types; the result is always normalized to the single core Document (v1.1 superset) (FR-V2).
type Consumer interface {
    Consume(data []byte, mediaType string, opts ConsumeOptions) (*document.Document, ConsumeInfo, error)
}

// MediaTypeOf derives the representation's media type from the detection result (12 §6.2).
// V10 without @context → application/did+json, V10 with @context → application/did+ld+json, otherwise → application/did.
func MediaTypeOf(info ConsumeInfo) string

// CoreMediaTypes are the media types the core Producer can produce from a validated document.
var CoreMediaTypes = []string{MediaTypeDID, MediaTypeDIDLDJSON, MediaTypeDIDJSON}

// OptionsFor returns the production options (SpecVersion, JSONLD) for a target media type (09 §5 table).
func OptionsFor(mediaType string) Options

// JSONRepresentation implements the single application/did representation (JSON, JSON-LD compatible).
type JSONRepresentation struct {
    LD *jsonld.Processor
}

func (r *JSONRepresentation) Produce(doc *document.Document, opts Options) ([]byte, string, error)
func (r *JSONRepresentation) Consume(data []byte, mediaType string, opts ConsumeOptions) (*document.Document, ConsumeInfo, error)
```

**Key points for implementing the norms**
- Producer: place every entry in the root JSON Object. `DateTime` → `time.RFC3339`, then normalize to UTC and truncate sub-seconds (`2020-12-20T19:17:47Z`). `Set`/`List` → JSON Array. Fixed ordering rules give determinism (NFR-1).
- Consumer: use `json.Decoder.UseNumber()` to tell integer from double without loss. If the root is not an Object, return `ErrNonConforming`. **Entry classification (consumer rules 3 and 4)**: *known* representation-specific entries such as `@context` go to `Document.reprEntries` (rule 3). Any other unrecognized property is added to `Document.extensions` as **part of the data model** (rule 4). Unrecognized entries are not put in the representation-specific map (FR-D7).
- `mediatype.go`: heuristic for low-precision types (`application/json`, `application/ld+json`). If `@context[0]` is the v1 or v1.1 context, or the top-level `id` has DID syntax, treat the input as a DID document (informative).
- **Version detection and normalization (FR-V1/V2)**: `@context` is checked first. A first value of `…/did/v1` means V10 and `…/did/v1.1` means V11; a declared DID media type that disagrees is recorded as `Mismatch`. Without `@context`, `did+json` means V10, `application/did` means V11, and `did+ld+json` is an error. For a low-precision type without `@context`, `Expected` is used, or else VUnknown (consumed with v1.1 rules), and `Assumed` is recorded. In every case the result is normalized to the same `Document`. Details in [`09`](09-v1.0-compat.md) §4.

```go
// jsonld/context_v1_1.go (+ context_v1.go has the same shape)
package jsonld

// Per-version base contexts. Both are treated as "already retrieved"; remote fetch is forbidden. (§Remote Resource Integrity, FR-V5)
const (
    BaseContextURLV11 = "https://www.w3.org/ns/did/v1.1"
    BaseContextURLV10 = "https://www.w3.org/ns/did/v1"
)

//go:embed did_v1_1.jsonld did_v1.jsonld
var baseContextFS embed.FS // sources: docs/assets/did-v1.jsonld, did-v1.1.jsonld (10 §3)

// Per-version pinned integrity values, verified at load time. (Derivation and re-pinning procedure: 10 §3)
const (
    // v1.1rc1 snapshot (w3c/did@13626ba6aac9). Must be re-pinned when v1.1 REC is published (release blocker)
    BaseContextSHA256V11 = "ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85"
    // Confirmed to match the official published copy (2026-07-22)
    BaseContextSHA256V10 = "4f3eae5568c9c5f036a082088f9e192019ee06faa78973c87ff91d5421b88dad"
)

type Processor struct{ /* per-version term definition cache */ }

// BaseContext returns the context URL and document for the given version.
func (p *Processor) BaseContext(v spec.Version) (url string, doc []byte)
// InjectContext ensures on produce that the first @context element is the target version's URL.
func (p *Processor) InjectContext(root map[string]any, existing any, v spec.Version) error
// DropUndefinedTerms removes, on consume, terms not defined by that version's @context.
func (p *Processor) DropUndefinedTerms(root map[string]any, v spec.Version)
```

---

## 5. `method`: method interface and registry (FR-M1~M6)

```go
package method

// Method implements CRUD for one method-name (§Method Operations).
// A method that does not support Update/Deactivate returns ErrNotSupported.
type Method interface {
    Name() string // a single method-name

    // Produces: the media types this driver can produce from Read (12 §6.2)
    Produces() []string

    // Create: the controller creates a DID + document (FR-M1)
    Create(ctx context.Context, input *document.Document, opts CreateOptions) (*CreateResult, error)

    // Read: DID → retrieve document + verify authenticity (FR-M2). Called by Resolver.
    Read(ctx context.Context, d did.DID, opts ReadOptions) (*ReadResult, error)

    // Update: update the document, or ErrNotSupported (FR-M3)
    Update(ctx context.Context, d did.DID, next *document.Document, opts UpdateOptions) (*UpdateResult, error)

    // Deactivate: deactivate, or ErrNotSupported (FR-M4)
    Deactivate(ctx context.Context, d did.DID, opts DeactivateOptions) error
}

// ReadResult is the serialized bytes the driver produced, their media type, and document metadata. Authenticity verification is Read's responsibility.
type ReadResult struct {
    Data        []byte // serialized bytes produced by the driver
    ContentType string // media type the driver labels Data with; the resolver consumes Data with this as the declared type
    Metadata    DocumentMetadata
}

type ReadOptions struct {
    VersionID   string
    VersionTime *time.Time
    MediaType   string // format the resolver picked from Produces() to match accept; empty means the driver default
}

type DocumentMetadata struct {
    VersionID   string
    Created     *time.Time
    Updated     *time.Time
    Deactivated bool
    Extra       map[string]any
}

var (
    ErrNotSupported  = errors.New("method: operation not supported")
    ErrUnauthorized  = errors.New("method: authorization failed")
    ErrNotFound      = errors.New("method: DID not found")
)
```

```go
// registry.go: method-name → Method (concurrency-safe, NFR-5)
type Registry struct {
    mu sync.RWMutex
    m  map[string]Method
}

func NewRegistry() *Registry
func (r *Registry) Register(m Method) error // ErrMethodAlreadyRegistered
func (r *Registry) Lookup(name string) (Method, bool)
```

**Authorization contract:** each options struct carries a method-defined proof. The spec allows a choice among `controller`, `authentication`, `capabilityInvocation` and out-of-band mechanisms, so the interface delegates proof verification to the method implementation (FR-M5, FR-P1).

---

## 6. `resolution`: resolver and dereferencer contract (FR-X1~X4)

> **Canonical: [`07-did-resolution-contract.md`](07-did-resolution-contract.md).** The text below is a summary against DID Resolution v1.0, W3C Candidate Recommendation Draft, 2026-10-01 (https://www.w3.org/TR/2026/CRD-did-resolution-1.0-20261001/). It reflects three settled facts:
> (1) `resolveRepresentation()` does **not exist** in this version. It is merged into `resolve()` + the `accept` option + the `contentType` metadata.
> (2) Errors are **RFC9457 Problem Details objects**, and `type` is a `https://www.w3.org/ns/did#<CODE>` URL (not a string code).
> (3) `deactivated` is **not an error**. It is `didDocumentMetadata.deactivated=true` (+ HTTP 410).

```go
package resolution

// Resolver: resolve(did, resolutionOptions) → (metadata, document, documentMetadata)
// The signature is unchanged on the conforming path. There is no ResolveRepresentation.
type Resolver interface {
    Resolve(ctx context.Context, d did.DID, opts ResolutionOptions) Result
}

type ResolutionOptions struct {
    Accept             string     // HTTP Accept value (default application/did)
    ExpandRelativeURLs bool
    VersionID          string     // DID parameter
    VersionTime        *time.Time
    Extra              map[string]any
}

// Result combines the 07 contract's 3-tuple «didResolutionMetadata, didDocument, didDocumentMetadata»
// with Raw, Info and Source in one struct. The 07 §7 Resolver returns this struct too (12 §6.2).
type Result struct {
    Document           *document.Document
    Raw                []byte                     // bytes returned to the caller; representation is ResolutionMetadata.ContentType
    Info               representation.ConsumeInfo // detection result from consuming the driver bytes
    Source             *SourceBytes               // set only when the core transcoded; the driver's original
    ResolutionMetadata ResolutionMetadata
    DocumentMetadata   DocumentMetadata // includes deactivated
}

// SourceBytes holds the bytes the driver originally returned and their media type.
type SourceBytes struct {
    Data        []byte
    ContentType string
}

type ResolutionMetadata struct {
    ContentType string           // media type of the detected representation; not copied from the driver label (12 §6.2)
    Error       *Error           // RFC9457, only on error
    Proof       []map[string]any
    Extra       map[string]any
}

// Error is an RFC9457 Problem Details object. type=https://www.w3.org/ns/did#<CODE>
type Error struct {
    Type, Title, Detail, Instance string
    Status                        int    // HTTP mapping; used only for types not in the binding table (07 §7)
    Refines                       string // type URI in the 07 §4 table that this type refines; empty for a type in the table
}
```

Error catalog (full list in 07 §4): `INVALID_DID` (400), `INVALID_DID_URL` (400), `INVALID_OPTIONS` (400), `NOT_FOUND` (404), `REPRESENTATION_NOT_SUPPORTED` (406), `INVALID_DID_DOCUMENT` (500), `METHOD_NOT_SUPPORTED` (501), `FEATURE_NOT_SUPPORTED` (501), `INTERNAL_ERROR` (500). Fragment dereferencing uses the CID-derived `INVALID_VERIFICATION_METHOD` and `INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD`.

The HTTP status is chosen in this order. First the binding table is looked up by `Type`. If the type is not in the table, the table status of the type named by `Refines` is used. Only if that is also missing is the error's own `Status` used, and finally 500. For an error type that is not in the HTTP binding table, the spec says the status "is determined by the implementation", so the steps from `Refines` on are did-go policy. An extension cannot change a status that the binding table fixes (07 §4, §7).

```go
// dereferencer.go
type Dereferencer interface {
    Dereference(ctx context.Context, u did.DIDURL, opts DereferencingOptions) DereferenceResult
}

type DereferencingOptions struct {
    Accept                   string
    VerificationRelationship string // relationship for which the dereferenced VM must be authorized
    Extra                    map[string]any
}

type DereferenceResult struct {
    ContentStream         any // Document | vm.Method | vm.Service | []string(uri-list) | []byte
    DereferencingMetadata ResolutionMetadata
    ContentMetadata       DocumentMetadata
}
```

**Default composed implementation (`DefaultResolver`)**: the UC-5 sequence in code. Failures are reported in `Metadata.Error` (RFC9457), not as `error`. The steps follow [`12`](12-standard-core-and-sage-extension.md) §6.2.

```go
type DefaultResolver struct {
    Registry *method.Registry
    Consumer representation.Consumer
    Producer representation.Producer // used when transcoding to match accept
}

func (r *DefaultResolver) Resolve(ctx context.Context, d did.DID, opts ResolutionOptions) Result {
    m, ok := r.Registry.Lookup(d.Method())
    if !ok {
        return failed(ErrMethodNotSupported)
    }
    // Pick the format the driver can produce that matches accept; empty if none (driver default).
    want, _ := negotiate(opts.Accept, m.Produces())
    rr, err := m.Read(ctx, d, method.ReadOptions{VersionID: opts.VersionID, VersionTime: opts.VersionTime, MediaType: want})
    switch {
    case errors.Is(err, method.ErrNotFound):
        return failed(ErrNotFound)
    case err != nil:
        return failed(ErrInternal)
    }
    if rr.Metadata.Deactivated { // not an error: document is null, signaled through metadata
        return Result{DocumentMetadata: rr.Metadata}
    }
    // 1. Consume the driver bytes with the driver's media type label and run standard validation. Drivers and profiles cannot disable this step.
    doc, info, err := r.Consumer.Consume(rr.Data, rr.ContentType, representation.ConsumeOptions{})
    if err != nil || doc.ID() != d {
        return failed(ErrInvalidDIDDocument)
    }
    // 2. contentType comes from the detected representation, not the driver label. A disagreement is recorded in Info.
    detected := representation.MediaTypeOf(info)
    if info.Mismatch == nil && rr.ContentType != detected {
        info.Mismatch = &representation.Mismatch{Declared: rr.ContentType, Detected: detected}
    }
    if opts.ExpandRelativeURLs {
        doc = doc.ExpandRelativeURLs() // the bytes no longer match the document, so step 4 produces them again
    }
    res := Result{Document: doc, Info: info, DocumentMetadata: rr.Metadata}
    // 3. accept negotiation (RFC 9110 media ranges and q-values). If acceptable, return the driver bytes as is.
    if !opts.ExpandRelativeURLs && (opts.Accept == "" || acceptable(opts.Accept, detected)) {
        res.Raw = rr.Data
        res.ResolutionMetadata = ResolutionMetadata{ContentType: detected}
        return res
    }
    // 4. The core produces an acceptable representation from the validated document. If it cannot, FEATURE_NOT_SUPPORTED.
    offers := representation.CoreMediaTypes
    if opts.Accept == "" {
        offers = []string{detected}
    }
    target, ok := negotiate(opts.Accept, offers)
    if !ok {
        return failed(ErrFeatureNotSupported)
    }
    data, mt, err := r.Producer.Produce(doc, representation.OptionsFor(target))
    if err != nil { // for example, V10 production with a service that has no service.id
        return failed(ErrFeatureNotSupported)
    }
    res.Raw = data
    res.Source = &SourceBytes{Data: rr.Data, ContentType: rr.ContentType}
    res.ResolutionMetadata = ResolutionMetadata{ContentType: mt}
    return res
}

// negotiate picks the best of offers using the media ranges and q-values of RFC 9110 §12.5.1.
// If accept is empty it picks offers[0].
func negotiate(accept string, offers []string) (string, bool)

// acceptable reports whether mediaType matches some media range in accept with q>0.
func acceptable(accept, mediaType string) bool

func failed(e *Error) Result { return Result{ResolutionMetadata: ResolutionMetadata{Error: e}} }
```

> The `resolution/universal` adapter implements, per the 07 contract, the DID parameters (`service`/`serviceType`/`relativeRef`/`versionId`/`versionTime`), service endpoint URL construction, and the HTTP binding (`/1.0/identifiers/{id}`, GET required, status code mapping, the `application/did-resolution` and `application/did-url-dereferencing` media types).

### 6.1 `resolution/compat`: v1.0 contract adapter (FR-V4)

An adapter for legacy callers that need the abstract functions of v1.0 REC §7.1 (`resolve` + **`resolveRepresentation`**) and the **string error** contract. It does not pollute the core contract (ADR-14). Canonical: [`09`](09-v1.0-compat.md) §6.

```go
package compat

type V10Resolver struct {
    Inner resolution.Resolver // v1.1 core; the core also does accept negotiation and V10 transcoding (12 §6.2)
}

type V10ResolutionMetadata struct {
    ContentType string // set only when resolveRepresentation succeeds (REQUIRED if successful); MUST NOT in resolve (v1.0 §7.1.2)
    Error       string // "invalidDid" | "notFound" | "representationNotSupported" | … ("" on success)
}

func (r *V10Resolver) Resolve(ctx context.Context, d did.DID, opts resolution.ResolutionOptions,
) (V10ResolutionMetadata, *document.Document, resolution.DocumentMetadata)

func (r *V10Resolver) ResolveRepresentation(ctx context.Context, d did.DID, opts resolution.ResolutionOptions,
) (V10ResolutionMetadata, []byte, resolution.DocumentMetadata)
```

- Error mapping: codes that the REC defines for the RFC9457 `type` map exactly (`INVALID_DID`→`invalidDid`, `NOT_FOUND`→`notFound`, `REPRESENTATION_NOT_SUPPORTED`→`representationNotSupported`, `INVALID_DID_URL`→`invalidDidUrl`). The rest follow the SCREAMING_SNAKE→camelCase rule. Full table in 09 §6.1.
- `deactivated` is non-error metadata in both versions and passes through unchanged.
- `accept` option: v1.0 §7.1.1 says **MUST NOT** with `resolve`. The adapter's `Resolve()` ignores `opts.Accept` (with a warning).
- DID parameters: the v1.0-only `hl` is accepted by the adapter (not passed to the core). The v1.1-only `serviceType` yields `featureNotSupported` on the v1.0 path.
- HTTP: there is no separate v1.0 binding. In the v1.1 binding, if Accept is a legacy type, the core returns the V10 representation through accept negotiation and transcoding (09 §6.3, 12 §6.2).

---

## 7. `crypto`: key codecs (delegated to CID, FR-D3/P1)

```go
package crypto

// KeyCodec abstracts Multikey/JWK encoding and signature verification (CID §2.2).
type KeyCodec interface {
    // DecodeMultibase converts publicKeyMultibase → public key bytes.
    DecodeMultibase(s string) (pub []byte, algorithm string, err error)
    // DecodeJWK converts a publicKeyJwk map → public key.
    DecodeJWK(jwk map[string]any) (pub []byte, algorithm string, err error)
    // Verify verifies a signature (authenticity).
    Verify(pub []byte, algorithm string, message, sig []byte) error
}

// Registry maps algorithm/multicodec prefix → KeyCodec.
type Registry struct{ /* ... */ }
func (r *Registry) Register(c KeyCodec)
```

Reference codecs: `ed25519` (public prefix `0xed01`, 34B), `p256` (`0x8024`, 35B), `p384` (`0x8124`, 51B), `bls12-381-g2` (`0xeb01`, 98B), `sm2` (`0x8624`). The full multicodec prefix/length table and the secret key prefixes are in [`06-cid-data-model.md`](06-cid-data-model.md) §5. A secret key header in a public key position MUST be an error.

---

## 8. Error design (NFR-4)

- Every public API returns `(T, error)`. No panics.
- Syntax errors are `*did.SyntaxError` (with position). Conformance errors are `*document.ConformanceError` (violating property and reason).
- Resolution/dereferencing failures are expressed **as `Metadata.Error` codes, not as errors** (DID-RESOLUTION contract). Only infrastructure failures are Go `error` values.
- `errors.Is`/`errors.As` are supported (sentinels + wrapping).

---

## 9. Traceability matrix (FR → package/type)

| FR | Package · type/function |
|----|--------------------|
| FR-S1~S6 | `did.Parse`, `did.ParseURL`, `did.ParseRef`, `abnf.go`, `SyntaxError` |
| FR-D1,D2 | `document.Document`, `document.Value` (INFRA types) |
| FR-D3 | `vm.Method`, `vm.Method.Validate` (key XOR) · norms 06 §2 |
| FR-D4 | `vm.RelValue`, `document.ResolveRef` · CID Retrieve VM 06 §3 |
| FR-D5 | `vm.Service`, `vm.Endpoint`, `Service.Validate` · 06 §8 |
| FR-D6 | `resolution.DocumentMetadata.{EquivalentID,CanonicalID}` (didDocumentMetadata, 07 §5) |
| FR-D7 | `Document.reprEntries` (representation-specific, rule 3) + `Document.extensions` (non-representation-specific extensions, rule 4) |
| FR-R1,R2,R4 | `representation.JSONRepresentation` |
| FR-R3,R6 | `jsonld.Processor`, `BaseContextSHA256` |
| FR-R5 | `representation/mediatype.go`, `MediaTypeDID` |
| FR-M1~M6 | `method.Method`, `method.Registry` |
| FR-X1~X4 | `resolution.Resolver/Dereferencer`, RFC9457 `resolution.Error`, `DefaultResolver` · contract 07 |
| FR-P1,P3 | `method.Method` (integrity), `Options.IncludeSecret`, `crypto.KeyCodec.Verify` |
| FR-P4,P5 | logging policy document, `DocumentMetadata.CanonicalID` re-verification guide |
| FR-V1,V2 | `spec.Version`, `representation.ConsumeInfo`, detection and normalization rules (09 §4) |
| FR-V3 | `representation.Options.SpecVersion`, `document.ValidateProfile(ProfileV10)` |
| FR-V4 | `resolution/compat.V10Resolver` (error mapping 09 §6.1) |
| FR-V5 | `jsonld.BaseContextURLV10/V11`, dual SHA-256 pinning |

---

## 10. Test strategy (NFR-6)

| Layer | Method |
|------|------|
| ABNF parser | Table tests with spec examples + boundary values (invalid idchar, semicolons, uppercase method) |
| Data model | Lossless round-trip property test: Produce∘Consume == identity (FR-R4) |
| Representation conformance | Classify conforming/non-conforming with W3C DID Test Suite vectors |
| JSON-LD | Enforce the first `@context` element, drop undefined terms, base context SHA-256 |
| Methods | Create/Read + Resolve integration with the `did:key`/`did:web` reference implementations |
| Concurrency | Parallel Registry/Resolver calls under `-race` |
| Error paths | Each `Metadata.Error` code is produced in its corresponding state (state diagrams in 04) |
| Version compatibility | Cross round trips (V10↔V11), the full detection table, the full error mapping, contentType rules. Details in 09 §10 |

---

## 11. Design decision summary (ADR style)

| # | Decision | Rationale |
|---|------|------|
| 1 | Dependency-free core, Ports & Adapters | The spec delegates Resolution/CID. Isolating those boundaries absorbs spec changes (NFR-2,3) |
| 2 | Single `application/did` representation, JSON-LD branching via `@context` | Reflects the v1.1 media type unification (fact C in 00 §1) exactly |
| 3 | Introduce INFRA Value type wrappers | Guarantees lossless round trips for integer/double and datetime normalization (FR-R4) |
| 4 | Resolution failures are `Metadata.Error` codes, not `error` | Complies with the DID-RESOLUTION contract and separates them from infrastructure failures |
| 5 | Immutable Document + Builder | Only validated state exists, which prevents partially conforming documents from leaking (§conforming) |
| 6 | Secret key material excluded from serialization by default | Safe default under §Security (labeling secrets) (FR-P3) |
| 7 | Errors as RFC9457 Problem Details (`type`=`…#CODE` URL) | Canonical in DID Resolution v1.0 (W3C Candidate Recommendation Draft, 2026-10-01). String codes are legacy (07 §4 caveat) |
| 8 | Do not introduce `resolveRepresentation()` | It does not exist in this version. Merged into `resolve()`+`accept` (07 §1.2) |
| 9 | `deactivated` as metadata + HTTP 410, not an error | Normative step 5 of the resolve algorithm (07 §1.1) |
| 10 | Place equivalentId/canonicalId in `resolution.DocumentMetadata` | The **formal definition** exists only in DID-Resolution didDocumentMetadata (+OpenAPI). DID Core §Equivalence describes them as "inside the document", but they are absent from the Core Properties table, context and vocab. The implementation therefore uses the metadata location and records the tension in 08 §2. **v1.0 REC §7.1.3 also places them in metadata, so both versions agree** |
| 11 | **Single v1.1 superset core + version adapters** (no duplicated implementations) | The v1.1 data model ⊇ v1.0 (09 §1). Branching exists only in the representation and contract layers |
| 12 | Version is a property of the representation/contract layer, not of Document | The same document must be serializable in both versions (keeps lossless round trips) |
| 13 | Enforce `service.id` as required when producing V10; optional on consume and for V11 | v1.0 §5.4 MUST versus CID optional (T5). Guarantees output that conforms for consumers of each version |
| 14 | Isolate the v1.0 contract in the `resolution/compat` adapter | `resolveRepresentation` and string errors are legacy. The core keeps the single 07 contract |
| 15 | `hl` accepted by the adapter and not passed to the core; `serviceType` rejected on the v1.0 path | Explicit handling of the DID parameter asymmetry (09 §2.5) |
| 16~23 | Standard first with advanced extensions; `advanced/sage` as a separate module; the document does not grant key authority; record detection mismatches; preserve original bytes; exclude staking; the core validates every driver output; accept negotiation and transcoding | [`12`](12-standard-core-and-sage-extension.md) §8 |
