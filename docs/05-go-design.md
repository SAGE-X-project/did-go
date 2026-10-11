# DID Core v1.0/v1.1: Go Design

> Target: Go 1.26.8 toolchain, language version `go 1.26.0`. Module `github.com/sage-x-project/did-go`. The SAGE extension is a separate module, `advanced/sage` ([`12`](12-standard-core-and-sage-extension.md) §3).
> Principle: a dependency-free core (standard library only) plus Ports & Adapters. The delegation boundaries of the spec (Resolution = DID-RESOLUTION, VM/Service = CID, a single media type `application/did`) become package boundaries.
>
> **Delegated specs, as settled:** the exact norms and Go mapping for VM/Service/Relationship are canonical in [`06-cid-data-model.md`](06-cid-data-model.md). The Resolution/Dereferencing contract (options, metadata, RFC9457 errors, DID parameters, HTTP binding) is canonical in [`07-did-resolution-contract.md`](07-did-resolution-contract.md). §5, §6 and §7 below summarize them. Follow those documents for details.
>
> **Dual-version support (v1.0 + v1.1):** the core data model is **one v1.1 superset**. Version branching exists in only three places: (1) the serialization envelope (the production option `representation.ProduceOptions.Version` and per-version validation `document.Validate(d, v)`), (2) the Resolution contract (`resolution/compat`), and (3) DID parameters (`hl`/`serviceType`, handled in compat). The canonical source for the normative comparison, detection rules and error mapping is [`09-v1.0-compat.md`](09-v1.0-compat.md).

---

## 1. Package layout

> The implementation package layout (players, shared types, layers) is defined by [`14`](14-implementation-architecture.md), which supersedes this section where they differ.

```
did-go/
├── spec/                  # layer 0: versions, per-version profile table, media type strings, datetime format, specification keys  FR-V1
├── did/                   # layer 1: DID and DID URL parsing, relative DID URL resolution, DID parameter parsing  FR-S*
├── vm/                    # layer 1: verification method, Relationship, Purpose, Service, Shape, Multikey table, value checks  FR-D3/D4/D5
├── document/              # layer 1: immutable Document, Builder, INFRA values, Metadata, Validate, SelectMethod  FR-D*
├── representation/        # layer 1: Producer and Consumer interfaces, production and consumption options, detection rule Detect  FR-R5, FR-V1
├── resolution/            # layer 1: Resolver and Dereferencer interfaces, options, metadata, RFC 9457 Error, Negotiate  FR-X1~X4
├── method/                # layer 1: Method interface, Signer, errors, immutable Registry  FR-M*
├── internal/wire/         # tool: strict JSON parser and encoder, INFRA value conversion, property name table
├── internal/multiformats/ # layer 1 (internal): Multibase and varint, used by vm and document
├── jsonld/                # tool: embedded base contexts and SHA-256, @context parsing, term lookup  FR-R3/R6/V5
├── crypto/                # tool: immutable PublicKey, Multikey and JWK codecs, signature verification  FR-D3/P1
├── producer/              # player: conforming producer  FR-R1/R3/R4, FR-V3
├── consumer/              # player: conforming consumer  FR-R2/R3, FR-V1/V2
├── resolver/              # player: DefaultResolver
├── dereferencer/          # player: DID URL dereferencer, DID parameter handling
├── controller/            # player: DID controller (create, update, deactivate)
├── relyingparty/          # player: relying party, CID Retrieve VM
├── resolution/compat/     # player: DID Core 1.0 contract adapter (resolveRepresentation, string errors)  FR-V4
├── resolution/universal/  # player: HTTP(S) binding client and handler  FR-X5
├── resolution/cache/      # player: caching decorator around a Resolver
├── method/key/            # player: did:key driver
├── method/web/            # player: did:web driver
├── didkit/                # assembly of players (no logic)
└── conformance/           # published requirement registry
```

Dependencies follow the layer rules of [`14`](14-implementation-architecture.md) §2, and `internal/archtest` checks them. `spec` and `did` import no other did-go package. `vm` → `did`, `internal/multiformats`. `document` → `did`, `vm`, `spec`, `internal/multiformats`. `representation` → `document`, `spec`. `resolution` → `did`, `document`, `representation`, `spec`, `vm`. `method` → `did`, `document`. Tools use only layers 0 and 1: `jsonld` → `document`, `spec`, and `crypto` → `vm`, `internal/multiformats`. Players import only layers 0 and 1 and the tools, never another player. For example, `method/key` uses `crypto` but does not import `producer`; it receives a `representation.Producer` when it is created. Only `didkit` imports players, to assemble them. The Multikey prefix and length table is pure data that uses only the standard library and lives in `vm`. `crypto` imports `vm` to use that table. `vm` does not import `crypto`.

### 1.1 `spec`: version model (FR-V1)

```go
package spec

// Version is a property of the representation and contract layers. Document has no version field (09 §3, ADR-12).
type Version int

const (
    VUnknown Version = iota // not determined; each player states which profile it applies (consumers apply Latest)
    V10                     // DID Core v1.0 REC (2022-07-19)
    V11                     // DID v1.1 CR Snapshot (2026-03-05)
)

const Latest = V11

func ParseVersion(s string) (Version, error) // "1.0" or "1.1"
func Supported() []Version                   // returned in a fresh slice
func (v Version) String() string             // "1.0", "1.1", "unknown"

// Profile holds the facts that differ between versions. VUnknown has no profile.
type Profile struct {
    Version            Version
    ContextURL         string // first @context value of a JSON-LD representation
    JSONMediaType      string // media type of the representation produced without JSON-LD
    JSONLDMediaType    string // media type of the representation produced for JSON-LD processing
    ServiceIDRequired  bool   // DID Core 1.0 §5.4: every service has an id
    ServiceIDMustBeURI bool   // DID Core 1.0 §5.4: a service id is an RFC 3986 URI; endpoint strings are normalized URIs
    RelativeMethodIDs  bool   // DID 1.1 §5.2: a verification method id may be a relative DID URL
    MetadataNumbers    bool   // metadata values may be numbers (DID Core 1.0 §7.3 does not allow them)
}

func ProfileOf(v Version) (Profile, error)
func (p Profile) Produces() []string        // media types a producer of this version emits
func (p Profile) Accepts() []string         // DID media types a consumer maps to this version
func (p Profile) DefinesTerm(term string) bool // whether the base context defines term

// The media type strings (MediaTypeDID, MediaTypeDIDJSON, MediaTypeDIDLDJSON, MediaTypeJSON, MediaTypeLDJSON,
// MediaTypeDIDResolution, MediaTypeDIDURLDereferencing, MediaTypeURIList), ContextURLV10/V11,
// the datetime format (TimestampLayout, FormatTimestamp, ParseTimestamp) and the specification keys (Key, Keys, ConformanceProfile) live here too.
```

---

## 2. `did`: syntax (FR-S1~S6)

```go
package did

// MaxLength bounds any DID or DID URL input, in bytes (12 §6.3). Longer input is rejected before parsing.
const MaxLength = 16 * 1024

// DID is a parsed, immutable DID. did = "did:" method-name ":" method-specific-id. Comparable with ==.
// The zero value is not a valid DID; IsZero reports it.
type DID struct{ /* method, msid (unexported) */ }

func (d DID) Method() string
func (d DID) MSID() string
func (d DID) String() string // "" for the zero value
func (d DID) IsZero() bool
func (d DID) URL() DIDURL    // the DID URL without path, query or fragment

// Parse parses a plain DID. The scheme "did:" is accepted in any case and written in lowercase (10 §1).
// A DID URL with a path, query or fragment is rejected with an error that wraps ErrIdentifierRestriction (§Identifier Restrictions).
func Parse(s string) (DID, error)

// DIDURL is did-url = did path-abempty ["?" query] ["#" fragment], or a relative DID URL reference, which has no DID.
// Path, query and fragment are kept as written, without percent-decoding.
type DIDURL struct{ /* did, path, query, fragment (unexported) */ }

func (u DIDURL) DID() DID          // zero for a relative reference
func (u DIDURL) Path() string
func (u DIDURL) Query() string     // without "?"
func (u DIDURL) HasQuery() bool    // true when "?" is present, even with an empty query
func (u DIDURL) Fragment() string  // without "#"
func (u DIDURL) HasFragment() bool
func (u DIDURL) IsRelative() bool  // true when there is no DID; false for the zero value, which is also the empty reference ""
func (u DIDURL) IsDID() bool       // true for an absolute DID URL without path, query or fragment
func (u DIDURL) WithoutFragment() DIDURL
func (u DIDURL) String() string

// ParseURL parses an absolute DID URL.
func ParseURL(s string) (DIDURL, error)

// ParseReference parses an absolute DID URL or a relative DID URL reference. A network-path reference ("//...") would replace the DID and is rejected.
// The empty reference "" gives the zero DIDURL, which Resolve turns into the base without its fragment (RFC 3986 §5.4.1, 10 §1).
func ParseReference(s string) (DIDURL, error)

// Resolve resolves u against an absolute base with RFC 3986 §5.2. As DID Core 1.0 §3.2.2 states, the authority is
// method-name ":" method-specific-id, so a reference changes only path, query and fragment, never the DID, unless the reference is itself an absolute DID URL (10 §1).
func (u DIDURL) Resolve(base DIDURL) (DIDURL, error)

// ParseRef runs ParseReference and then Resolve against base.URL().
// Example: ParseRef("#key-1", did) → did:example:123#key-1
func ParseRef(ref string, base DID) (DIDURL, error)

// Parameters reads the query as DID parameters. A pair without "=", an empty name, a repeated name,
// or a versionTime that is not UTC or has sub-second precision is a *ParameterError (07 §3). Extension parameters are kept.
func (u DIDURL) Parameters() (DIDParameters, error)

// DIDParameters hold parameter values, percent-decoded once.
type DIDParameters struct {
    Service, ServiceType, RelativeRef, VersionID, HL string
    VersionTime time.Time // zero when absent
}
func (p DIDParameters) Get(name string) (string, bool) // extension parameters included
func (p DIDParameters) Names() []string                // in query order
```

**ABNF validation (`did.go`, `url.go`)**: parsing uses per-character checks, not regular expressions, and errors include the position (pos).

```go
// idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
func idcharWidth(s string, i int) (int, error)
// method-char = %x61-7A / DIGIT
func isMethodChar(c byte) bool
func IsMethodName(s string) bool // exported: method-name = 1*method-char
```

Error types:

```go
type SyntaxError struct {
    Input string
    Pos   int   // byte offset of the first offending character
    Msg   string
    Err   error // an underlying cause such as ErrIdentifierRestriction, or nil
}
func (e *SyntaxError) Error() string
func (e *SyntaxError) Unwrap() error

type ParameterError struct{ Name, Msg string }

type Error string
const ErrIdentifierRestriction Error = "did: a plain DID must not contain a path, query or fragment"
```

---

## 3. `document` + `vm`: data model (FR-D1~D7)

### 3.1 INFRA type system (`value.go`)

A thin set of type wrappers that holds the map/list/set/datetime/string/integer/double/boolean/null values of spec §Data Model without loss.

```go
package document

// Value is a data model value (DID Core 1.0 §4, INFRA). Every Value is immutable.
type Value interface{ /* unexported methods */ }

type (
    String   string
    Integer  int64     // integer without fractional part
    Double   float64   // finite floating point number
    Boolean  bool
    Null     struct{}
    DateTime struct{ /* time.Time (unexported) */ } // NewDateTime(t), Time(). Representations write it in UTC
    List     struct{ /* unexported */ }             // NewList(items...), At, Items, Len. Ordered
    Map      struct{ /* unexported */ }             // NewMap(entries...), Get, Keys, Entries, Len, With. String keys, no duplicates, insertion order kept
)

type Entry struct {
    Key   string
    Value Value
}

// CheckValue reports whether v can be represented: valid UTF-8 strings, finite doubles, datetimes with a four-digit year, nesting of at most 64 levels.
func CheckValue(v Value) error
```

> There is no separate `Set` type. The sets of the data model (`controller`, `alsoKnownAs`, `verificationMethod`, the verification relationships, `service`) are typed slices of `Document`, and `Builder.Build` rejects duplicates. `Value` is used only for extension properties and representation-specific entries. `Map` preserves insertion order (deterministic output, NFR-1), but consumption does not depend on order. `NewMap` and `With` return an error for a duplicate key.

### 3.2 DID document (`document.go`)

```go
// Document is a DID document. It is created only by Builder.Build, which validates it. It never changes, and every accessor returns a copy.
// It is representation-independent: serialization is the job of the producer and consumer players.
type Document struct{ /* unexported fields */ }

func (d *Document) ID() did.DID                               // the DID subject
func (d *Document) Controllers() []did.DID                    // nil when the controller property is absent
func (d *Document) ControllerShape() vm.Shape                 // single string or set; ShapeDefault only when the property is absent
func (d *Document) AlsoKnownAs() []string
func (d *Document) VerificationMethods() []vm.Method
func (d *Document) Relationship(p vm.Purpose) []vm.Relationship // nil when the property is absent
func (d *Document) Services() []vm.Service
// Two buckets (Production/Consumption consumer rules 3 and 4, FR-D7):
func (d *Document) Extensions() Map            // rule 4: properties that are neither core properties nor representation-specific; part of the data model
func (d *Document) RepresentationEntries() Map // rule 3: representation-specific entries a consumer kept (for example @context)
// Note: equivalentId/canonicalId are not in the Core Properties table, context or vocab of this
//   v1.1 document. Their formal definition is didDocumentMetadata in DID-Resolution →
//   document.Metadata (metadata.go; resolution.DocumentMetadata is its alias, 07 §5, §7).
//   However, DID Core §Equivalence Properties (Security chapter) describes them as properties
//   "inside the DID document". This is a tension between specs. See 08-verification-report.md §2.

// expandRelativeUrls (DID Resolution §4.4 step 6, 07 §1.1 step 6) is not a Document method. The resolver player
// uses NewBuilder to make a new document in which relative DID URLs in object ids and relationship entries are absolute (resolver/expand.go).
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
    Type       string     // required: string that references exactly one VM type (CID §2.2). Multikey, JsonWebKey: full validation.
                          // Other types get only the generic form checks (06 §5) and do not verify proofs unless a codec is registered
    Controller did.DID     // required (claim)
    Expires    *time.Time  // XSD dateTimeStamp; proofs are not verified at or after this time
    Revoked    *time.Time  // must not be used at or after this time
    // Verification material: each property is OPTIONAL and chosen by type. At most one per material
    // (DID Core 1.0 §5.2.1, CID §2.2.1 MUST NOT both). Without public key material the VM cannot verify proofs.
    PublicKeyMultibase string          // Multibase string (any type). Multikey: z+base58btc, multicodec prefix
    PublicKeyJwk       map[string]any  // JsonWebKey: RFC7517, private members such as 'd' are forbidden
    // Secret material: excluded from serialization by default (FR-P3). Only with IncludeSecret opt-in. Not both either.
    SecretKeyMultibase string
    SecretKeyJwk       map[string]any  // if present, an RFC7517 JWK map
    // Extra holds additional properties that are not modeled (DID Core 1.0 §5.2, CID §2.2 MAY). The Consumer
    // fills it and the Producer writes it back unchanged. Additional properties alone never cause rejection.
    Extra map[string]any
}

// Validate: required fields, no duplicated material (at most one of publicKeyJwk and publicKeyMultibase,
// at most one secret key property; no material at all is conforming), Multibase form of publicKeyMultibase
// (any type), absence of JWK private members, JWK form of secretKeyJwk, Multikey prefix/length. See 06 §2.1, §5, §11.
func (m Method) Validate() error
func (m Method) Clone() Method      // deep copy; documents store and return copies
func (m Method) HasPublicKey() bool // without public key material the method conforms but cannot verify proofs

// Relationship is an element of a verification relationship: a reference to a verification method (a DID URL, possibly relative) or an embedded method.
type Relationship struct{ /* unexported */ }
func Ref(u did.DIDURL) Relationship   // referenced (string)
func Embed(m Method) Relationship     // embedded (map), a copy of m
func (r Relationship) IsEmbedded() bool
func (r Relationship) Reference() (did.DIDURL, bool)
func (r Relationship) Method() (Method, bool)
func (r Relationship) ID() did.DIDURL // the referenced DID URL or the id of the embedded method

type Purpose int // the zero value is not a relationship
const (
    Authentication Purpose = iota + 1
    AssertionMethod
    KeyAgreement
    CapabilityInvocation
    CapabilityDelegation
)
func ParsePurpose(s string) (Purpose, error) // property name, for example "assertionMethod"

// Shape records how a property that may be one value or a set was written: service type and serviceEndpoint (CID §2.1.4)
// and the DID document controller (DID Core 1.0 §5.1.2). Both forms are the same data in the data model, but for a lossless
// round trip (FR-R4, NFR-1) consumers record the form they read and producers write it back.
type Shape int
const (
    ShapeDefault Shape = iota // single value for one element, set otherwise; Builder resolves it to ShapeSingle or ShapeSet
    ShapeSingle               // single value; exactly one element
    ShapeSet                  // set (JSON array), even with one element
)

// Service is CID §2.1.4. Only type and serviceEndpoint are required; id is optional (if present, it must not repeat within the document).
// (The CID parent sentence reads as if id were required, but the more specific sub-definition and the spec examples make id optional. See 06 §8.)
type Service struct {
    ID              string          // V11: optional, URL | DID. V10: required, RFC 3986 URI of any scheme (urn:uuid etc.). Must be unique if present. "" when absent
    Type            []string        // required. string | set
    TypeShape       Shape           // whether type was a single string or a set
    ServiceEndpoint []Endpoint      // required. string | map | set
    EndpointShape   Shape           // whether serviceEndpoint was a single value or a set
    Extra           map[string]any  // additional properties beyond id, type, serviceEndpoint (MAY). Kept on consume, written back unchanged on produce
}

// Endpoint is polymorphic: a string URL or a map.
type Endpoint struct {
    URL string          // V11: valid URL (URL Standard). V10: valid RFC 3986 URI, normalized per RFC 3986 §6 and its scheme rules (06 §8)
    Map map[string]any  // map form
}
func (s Service) Validate() error
```

### 3.4 Builder & Validator (`builder.go`, `validate.go`)

```go
// Builder copies every value when it is added, and Build returns a new Document each time. It is not safe for concurrent use.
type Builder struct{ /* internal accumulated state */ }

func NewBuilder(id did.DID) *Builder
func NewBuilderFrom(d *Document) *Builder // starts with every property of d
func (b *Builder) Controller(c ...did.DID) *Builder
func (b *Builder) ControllerShape(s vm.Shape) *Builder // ShapeSet with no controller is "controller": []
func (b *Builder) AlsoKnownAs(u ...string) *Builder
func (b *Builder) VerificationMethod(m ...vm.Method) *Builder
func (b *Builder) Relationship(p vm.Purpose, r ...vm.Relationship) *Builder // with no element the property is present and empty, which Build rejects
func (b *Builder) Service(s ...vm.Service) *Builder
func (b *Builder) Extension(name string, v Value) *Builder           // a property that is not a core property (DID Core 1.0 §4.1)
func (b *Builder) RepresentationEntry(name string, v Value) *Builder // a representation-specific entry (for example @context, DID Core 1.0 §6.1)

// Build checks the rules that hold in every DID version and returns a new Document, or the first violation as a *ConformanceError.
//  - id required, DID syntax
//  - VM value checks (vm.Method.Validate), no duplicated material (at most one per material, no material is allowed)
//  - service value checks (vm.Service.Validate)
//  - no duplicate set elements (controller, alsoKnownAs, verification method ids, relationship elements, service ids)
func (b *Builder) Build() (*Document, error)

// Validate checks the rules that differ between versions, which Build does not check, and the SHOULD and RECOMMENDED statements of both (FR-V3, 09 §5).
// VUnknown is validated as spec.Latest. V10: service.id required (RFC 3986 URI), endpoint strings are normalized URIs (errors);
// properties undefined in v1.0 (expires etc.) are warnings. The producer and the controller refuse a document with any error finding.
func Validate(d *Document, v spec.Version) []Finding
func HasErrors(fs []Finding) bool

type Finding struct {
    Severity  Severity // SeverityError (violated MUST) or SeverityWarning (SHOULD, RECOMMENDED, or a value consumers of the version may not understand)
    Statement string   // requirement id; "" for a did-go policy warning without a statement
    Property  string   // for example "service[0].id"
    Message   string
}

// ConformanceError carries the CID 1.0 §3.5 error type in Code and the violated requirement id in Statement.
type ConformanceError struct{ Code Code; Property, Statement, Reason string }
```

### 3.5 Selector (`select.go`), UC-10

```go
// SelectMethod runs the steps of CID 1.0 §3.3 Retrieve Verification Method that need no I/O, on d,
// which the caller obtained by dereferencing ref without its fragment (steps 4 and 5 are the caller's).
//  - ref must be an absolute DID URL with a fragment (INVALID_VERIFICATION_METHOD_URL, step 1)
//  - ref without its fragment must equal d's id (INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID, steps 2 and 6)
//  - the fragment must select a conforming verification method whose absolute id is ref and whose controller is d's id (INVALID_VERIFICATION_METHOD, steps 3, 7 to 10)
//  - the method must be in relationship p by reference or by value (INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD, step 11)
// It returns a copy of the method (step 12). It looks only inside the subject document. Accepting verification methods from
// controller documents (DID Core 1.0 §5.1.2, SHOULD) is the relyingparty player's job (06 §7, DID Core 1.0 documents only, opt-in).
func SelectMethod(d *Document, ref did.DIDURL, p vm.Purpose) (*vm.Method, *ConformanceError)

// For fragment dereferencing (UC-6) the dereferencer player selects the target with CID 1.0 §3.4 Fragment Resolution (07 §2.1(b)).
```

---

## 4. `representation`: representations (FR-R1~R5)

```go
package representation

// The media type strings live in spec: spec.MediaTypeDID (v1.1), spec.MediaTypeDIDJSON and spec.MediaTypeDIDLDJSON
// (v1.0 legacy; accepted on consume and used for V10 production), and the low-precision spec.MediaTypeJSON, spec.MediaTypeLDJSON.

// ProduceOptions select the representation a Producer writes.
type ProduceOptions struct {
    Version       spec.Version // target production version; VUnknown means spec.Latest. Decides the @context URL and media type (09 §5)
    JSONLD        bool         // representation for JSON-LD processing, with the version's base context first in @context (FR-R3)
    IncludeSecret bool         // write secret key material; false by default, and secret material is then never written (FR-P3)
}

// Producer: data model → serialization. It must not produce a non-conforming representation.
// Before writing it applies document.Validate(d, Version) and refuses any error finding, so service.id is required for V10 production (09 §5).
type Producer interface {
    Produce(d *document.Document, opts ProduceOptions) (data []byte, mediaType string, err error)
}

// ConsumeInfo is the detection result on consumption (FR-V1).
// Detection rules (09 §4): a declared DID media type decides the representation and version (did+json, did+ld+json are V10; application/did is V11).
//   did+json is V10 JSON. A present @context is kept as a representation-specific entry; if its first value is not …/did/v1,
//   it is recorded in UnexpectedContext (no spec makes this non-conforming, so it is not an error; Strict makes it one).
//   did+ld+json requires @context with first value …/did/v1, and application/did requires first value …/did/v1.1 if @context is present; otherwise error.
//   For a low-precision type, inspect the payload: the first @context value decides;
//   without @context, Expected, or else VUnknown (v1.1 rules), with Assumed=true. Any other media type, or none, is an error.
type ConsumeInfo struct {
    DetectedVersion   spec.Version
    IsJSONLD          bool          // true for a JSON-LD representation: did+ld+json, or application/did or low-precision input with @context
    LowPrecision      *LowPrecision // set when a low-precision type was received and the payload decided the representation; nil under a DID media type
    Assumed           bool          // true when the version was decided without @context for a low-precision type
    UnexpectedContext string        // for did+json input, the first @context value when it is not …/did/v1; "" otherwise
    // DroppedTerms locates, in input order, the entries a consumer dropped from a JSON-LD representation because its @context
    // does not define their term, for example "foo" or "service[0].bar". DID Core 1.0 §6.3.2, DID 1.1 §6.2.3: consumers SHOULD drop
    // terms not defined via the @context. nil when nothing was dropped.
    DroppedTerms      []string
}

// LowPrecision records how the representation of an input received under a low-precision media type was decided from the payload.
type LowPrecision struct {
    Declared string // received low-precision media type (application/json, application/ld+json)
    Detected string // DID media type of the representation detected in the payload
}

// ConsumeOptions are the consumption options.
type ConsumeOptions struct {
    Expected spec.Version // version to use for a low-precision type without @context; VUnknown means none
    Require  spec.Version // reject input whose detected version is not this one; VUnknown accepts every version (14 §8)
    Strict   bool         // turns the payload decision for a low-precision type, Assumed, and did+json UnexpectedContext into errors
}

// Consumer: serialization + media type → data model. It must produce an error for non-conforming input.
// Accepts all three media types; the result is always normalized to the single core Document (v1.1 superset) (FR-V2).
type Consumer interface {
    Consume(data []byte, mediaType string, opts ConsumeOptions) (*document.Document, ConsumeInfo, error)
}

// Detect is a pure function that applies the 09 §4 detection rule to the declared media type and the @context of the payload.
// A failure is a *DetectError{Step, Reason}, where Step is the step of 09 §4 (1 to 5), or 6 for a Require violation.
func Detect(mediaType string, ctx Context, opts ConsumeOptions) (ConsumeInfo, error)
type Context struct {
    Present bool   // the root map has an @context entry
    First   string // the first @context value when it is a string
}

// MediaTypeOf derives the representation's DID media type from the detection result (12 §6.2).
// V10 with IsJSONLD false → application/did+json, V10 with IsJSONLD → application/did+ld+json, otherwise → application/did.
// When consumed under a DID media type it equals the declared type; for low-precision input it equals LowPrecision.Detected.
func MediaTypeOf(info ConsumeInfo) string

// CoreMediaTypes returns, in a fresh slice, the media types a producer can produce from a validated document:
// application/did, application/did+ld+json, application/did+json.
func CoreMediaTypes() []string

// OptionsFor returns the production options (Version, JSONLD) for a target DID media type (09 §5 table). Any other media type is an error.
func OptionsFor(mediaType string) (ProduceOptions, error)

// Other helpers: NormalizeMediaType, IsDIDMediaType, IsLowPrecision, VersionOf, MediaTypeFor.
// The implementations live in player packages: producer.New(opts ...producer.Option) *producer.Producer and
// consumer.New(opts ...consumer.Option) *consumer.Consumer. Both have no mutable state and are safe for concurrent use.
```

**Key points for implementing the norms**
- Producer (`producer`): place every entry in the root JSON Object. `DateTime` is converted to UTC and truncated to whole seconds with `spec.FormatTimestamp` (`2020-12-20T19:17:47Z`). `List` values and sets become JSON Arrays. A fixed output order gives determinism (NFR-1): the root holds `@context`, the core properties in specification order, then the other representation-specific entries and the extensions in their map order; verification method and service members follow the order of the `internal/wire` tables and then the additional properties sorted by name. `controller`, service `type` and `serviceEndpoint` are written in their recorded `Shape`. There are two options. Without `ProduceOptions.IncludeSecret`, secret key material is not written (FR-P3). By default every entry is written: production-and-consumption.10 requires "MUST serialize all entries", and a document that holds a term its `@context` does not define is still conforming, so refusing it would fail that MUST (08 T10). `producer.RejectUndefinedTerms()` makes JSON-LD production refuse a document that holds a term its `@context` does not define (DID Core 1.0 §6.3.1, DID 1.1 §6.2.3 SHOULD NOT); refusing writes nothing, so no entry is dropped, and the error's `Statement` names that recommendation. The check applies only when every context is known locally.
- Consumer (`consumer`): input is read with the strict JSON parser of `internal/wire`. It follows RFC 8259, rejects invalid UTF-8 and duplicate members, and keeps the exact text of numbers so that integers and doubles are told apart without loss. The default input limits are 1 MiB (`consumer.DefaultMaxBytes`) and a nesting depth of 100 (`consumer.DefaultMaxDepth`); `consumer.WithLimits(maxBytes, maxDepth)` changes them (12 §6.3). A root that is not an Object is a `*consumer.Error`. **Entry classification (consumer rules 3 and 4)**: `@context`, the only known representation-specific entry, goes to `RepresentationEntries` under every media type (rule 3). Any other unrecognized property goes to `Extensions` as **part of the data model** (rule 4). Unrecognized entries are not put in the representation-specific map (FR-D7). There is one exception: in a JSON-LD representation whose contexts are all known locally, terms the `@context` does not define are dropped (SHOULD) and reported in `ConsumeInfo.DroppedTerms`. `consumer.KeepUndefinedTerms()` keeps them as extensions instead. Detection failures are `*representation.DetectError` and data model violations are `*document.ConformanceError`.
- `representation.Detect` (`detect.go`): payload decision for low-precision types (`application/json`, `application/ld+json`), following `09` §4 step 4. A first `@context` value of `…/did/v1.1` gives V11 and `…/did/v1` gives V10. Without `@context`, `Expected` is used, or else VUnknown, and `Assumed` is recorded. Any other first `@context` value is an error (step 5). In every case the top-level `id` must be a valid DID.
- **Version detection and normalization (FR-V1/V2)**: a declared DID media type decides the representation and the version (§6.1 of v1.0 and v1.1, "A conforming consumer MUST determine the representation of a DID document using the Media Type input string."). `did+json` means V10 JSON, `did+ld+json` means V10 JSON-LD (`@context` required, first value `…/did/v1`), and `application/did` means V11 (if `@context` is present, first value `…/did/v1.1`). Reading the `@context` of an `application/did` document as a signal of JSON-LD processing, and so requiring the v1.1 first value, is did-go's interpretation ([`12`](12-standard-core-and-sage-extension.md) §6.1). For `did+ld+json` and `application/did`, a `@context` that does not fit the type is an error. For `did+json`, a present `@context` is kept as a representation-specific entry; if its first value is not `…/did/v1`, it is recorded in `UnexpectedContext` and consumption continues. No spec statement makes such a document non-conforming, and the standard core is not stricter than the specs. With `Strict` it is an error. For a low-precision type the payload is inspected: the first `@context` value decides; without `@context`, `Expected` is used, or else VUnknown (consumed with v1.1 rules), and `Assumed` is recorded. The received type is recorded in `LowPrecision`. Any other media type, or none, is an error. In every case the result is normalized to the same `Document`. Details in [`09`](09-v1.0-compat.md) §4.

```go
// jsonld/context.go, jsonld/terms.go
package jsonld

// Both per-version base contexts are treated as "already retrieved" and never fetched remotely. (§Remote Resource Integrity, FR-V5)
// Their URLs are spec.ContextURLV10 and spec.ContextURLV11. The JSON-LD expansion and compaction algorithms are not run.

//go:embed contexts/did-v1.jsonld contexts/did-v1.1.jsonld
var contexts embed.FS // sources: docs/assets/did-v1.jsonld, did-v1.1.jsonld (10 §3)

// Per-version pinned integrity values, checked on every BaseContext call. (Derivation: 10 §3)
const (
    // Confirmed to match the official published copy (2026-07-22)
    ContextSHA256V10 = "4f3eae5568c9c5f036a082088f9e192019ee06faa78973c87ff91d5421b88dad"
    // The SHA-256 that DID 1.1 §6.2.4 gives (did11-cr20260305#remote-resource-integrity.1)
    ContextSHA256V11 = "ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85"
)

const ContextEntry = "@context" // the representation-specific entry of the JSON-LD representation (DID Core 1.0 §6.3)

// BaseContext returns the context URL and a copy of its bytes for the version. An embedded file that differs from the pinned value is an error.
func BaseContext(v spec.Version) (string, []byte, error)
// ProductionContext returns the @context a producer writes: the version's base context URL first, followed by
// the other items of existing, in order (DID Core 1.0 §6.3.1, DID 1.1 §6.2.3). A leading DID base context of existing is replaced,
// and the base context of v is not repeated. A base context of another version after the first item was added on purpose and is kept
// (the did:key Context Creation Algorithm adds https://www.w3.org/ns/did/v1.1 to a DID Core 1.0 document).
func ProductionContext(v spec.Version, existing document.Value) (document.Value, error)
// ParseContext checks the @context form (a string, a map, or a list of strings and maps).
func ParseContext(v document.Value) (Context, error)
// Terms returns the terms the contexts define and true, or false when a URL other than a DID base context makes a local decision impossible.
// The producer's undefined-term refusal (RejectUndefinedTerms) and the consumer's term dropping act only when this is true.
func (c Context) Terms() (Terms, bool)
func (t Terms) Defines(term string) bool // keywords are not terms, so they always count as defined
func VersionOfContext(url string) (spec.Version, bool)
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

    // Deactivate: deactivate, or ErrNotSupported (FR-M4). The result's Metadata.Deactivated is true
    Deactivate(ctx context.Context, d did.DID, opts DeactivateOptions) (*DeactivateResult, error)
}

// ReadResult is the serialized bytes the driver produced, their media type, and document metadata. Authenticity verification is Read's responsibility.
type ReadResult struct {
    Data        []byte // serialized bytes produced by the driver
    ContentType string // media type the driver labels Data with; the resolver consumes Data with this as the declared type
    // Metadata is the didDocumentMetadata. Its only type is document.Metadata (07 §7); resolution.DocumentMetadata is an
    // alias of it. A driver can set created, updated, deactivated, nextUpdate, versionId, nextVersionId, equivalentId,
    // canonicalId, proof and extension properties (Extra). method does not import resolution.
    Metadata    document.Metadata
}

type ReadOptions struct {
    VersionID   string
    VersionTime *time.Time
    MediaType   string // format the resolver picked from Produces() to match accept; empty means the driver default
    NoCache     bool   // asks the driver to bypass any cache it keeps (07 §1)
}

// Error is the type of the constant errors of this package. Drivers wrap them with fmt.Errorf("...: %w", err) and callers test with errors.Is.
type Error string

const (
    // ErrNotSupported: the operation or an option (for example versionId, versionTime) is not supported. The resolver maps it to FEATURE_NOT_SUPPORTED (§6)
    ErrNotSupported Error = "method: operation not supported"
    // ErrNotFound: the DID does not exist. The resolver maps it to NOT_FOUND
    ErrNotFound Error = "method: DID not found"
    // ErrUnauthorized: the proof of authorization was missing or invalid
    ErrUnauthorized Error = "method: authorization failed"
    // ErrInvalidInput: a DID or document the operation cannot accept. The resolver maps it to INVALID_DID
    ErrInvalidInput Error = "method: invalid input"
    // ErrInvalidDocument: the document the driver obtained from the verifiable data registry does not conform, or its id is not the
    // resolved DID (res10-crd20261001#resolving.7). The DID itself was acceptable. The resolver maps it to INVALID_DID_DOCUMENT
    ErrInvalidDocument Error = "method: invalid DID document"
)

// Signer signs on behalf of a DID controller. The library never holds the private key (12 §6.3); KeyID names the verification method whose key signs.
type Signer interface {
    Sign(ctx context.Context, msg []byte) ([]byte, error)
    KeyID() did.DIDURL
}

type CreateOptions struct {
    Signer Signer         // proves authorization where the method requires it
    Extra  map[string]any // method-specific options
}
type UpdateOptions struct{ Signer Signer; Extra map[string]any }
type DeactivateOptions struct{ Signer Signer; Extra map[string]any }

type CreateResult struct{ DID did.DID; Document *document.Document; Metadata document.Metadata }
type UpdateResult struct{ Document *document.Document; Metadata document.Metadata }
type DeactivateResult struct{ Metadata document.Metadata }
```

```go
// registry.go: method-name → Method. NewRegistry builds it once and it never changes, so it is safe for concurrent use (NFR-5).
// There is no global registry: callers pass drivers explicitly (12 §6.2).
type Registry struct{ /* unexported */ }

// NewRegistry returns a registry of the given drivers. A nil driver, a name that is not a method-name (DID Core 1.0 §3.1)
// or a name given twice is an error.
func NewRegistry(ms ...Method) (*Registry, error)
func (r *Registry) Lookup(name string) (Method, bool)
func (r *Registry) Names() []string // sorted, in a fresh slice
```

**Authorization contract:** each options struct carries a `Signer` and method-specific options. The spec allows a choice among `controller`, `authentication`, `capabilityInvocation` and out-of-band mechanisms, so the interface delegates how proofs are made and verified to the method implementation (FR-M5, FR-P1). The caller keeps the key, and the driver asks the `Signer` to sign.

---

## 6. `resolution`: resolver and dereferencer contract (FR-X1~X4)

> **Canonical: [`07-did-resolution-contract.md`](07-did-resolution-contract.md).** The text below is a summary against DID Resolution v1.0, W3C Candidate Recommendation Draft, 2026-10-01 (https://www.w3.org/TR/2026/CRD-did-resolution-1.0-20261001/). It reflects three settled facts:
> (1) `resolveRepresentation()` does **not exist** in this version. It is merged into `resolve()` + the `accept` option + the `contentType` metadata.
> (2) Errors are **RFC9457 Problem Details objects**, and `type` is a URL (not a string code): `https://www.w3.org/ns/did#<CODE>` for DID Resolution errors and `https://w3id.org/security#<NAME>` for CID-derived errors (07 §4).
> (3) `deactivated` is **not an error**. It is `didDocumentMetadata.deactivated=true` (+ HTTP 410).

```go
package resolution

// Resolver: resolve(did, resolutionOptions) → (metadata, document, documentMetadata)
// The signature is unchanged on the conforming path. There is no ResolveRepresentation.
type Resolver interface {
    Resolve(ctx context.Context, d did.DID, opts ResolutionOptions) Result
}

type ResolutionOptions struct {
    Accept             string     // HTTP Accept value. Empty: the driver bytes are returned unchanged; with ExpandRelativeURLs they are re-produced in the detected representation (12 §6.2)
    ExpandRelativeURLs bool
    VersionID          string     // DID parameter
    // VersionTime uses the 07 §3 datetime format (UTC, no sub-second precision). Serialization reuses the
    // datetime marshaller of document.Metadata. An input with an offset other than Z, or with sub-second
    // precision, is rejected (did-go policy): INVALID_OPTIONS (INVALID_DID_URL from a DID URL parameter).
    VersionTime        *time.Time
    NoCache            bool       // asks for a fresh document instead of a cached one (07 §1, DID Resolution §13.2)
    Extra              map[string]any
}

// Validate returns INVALID_OPTIONS for a malformed option: an accept that is not an RFC 9110 Accept value, a non-ASCII versionId,
// a versionTime that is not UTC or has sub-second precision, or Extra that shadows a modeled option or holds a value a metadata structure cannot hold.
func (o ResolutionOptions) Validate() *Error

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

// DocumentMetadata is an alias of document.Metadata (07 §7). It is the same type as method.ReadResult.Metadata, so it is passed on without conversion.
type DocumentMetadata = document.Metadata

// SourceBytes holds the bytes the driver originally returned and their media type.
type SourceBytes struct {
    Data        []byte
    ContentType string
}

type ResolutionMetadata struct {
    // ContentType is the media type of the bytes actually returned in Raw. The caller parses with it (DID Resolution §4.2 MUST).
    // When the driver bytes are returned it is the DID media type the driver labeled them with, or, for a low-precision label, the
    // precise DID media type of the detected representation; when the core transcoded it is the DID media type the core produced (12 §6.2)
    ContentType string
    Error       *Error           // RFC9457, only on error
    Proof       []map[string]any
    Extra       map[string]any
}

// Error is an RFC9457 Problem Details object. type is https://www.w3.org/ns/did#<CODE> for DID Resolution
// errors and https://w3id.org/security#<NAME> for CID-derived errors (07 §4).
type Error struct {
    Type, Title, Detail, Instance string
    Status                        int    // HTTP mapping; used only when neither the type nor Refines is in the binding table (07 §7)
    Refines                       string // type URI in the 07 §4 table that this type refines; empty for a type in the table
}

// Code names an error type: one of the constants below, an extension name (which gets the NamespaceDID prefix) or a full type URL.
type Code string
const (
    CodeInvalidDID, CodeInvalidDIDURL, CodeInvalidOptions, CodeNotFound Code = "INVALID_DID", "INVALID_DID_URL", "INVALID_OPTIONS", "NOT_FOUND"
    CodeRepresentationNotSupported Code = "REPRESENTATION_NOT_SUPPORTED"
    CodeInvalidDIDDocument, CodeMethodNotSupported Code = "INVALID_DID_DOCUMENT", "METHOD_NOT_SUPPORTED"
    CodeFeatureNotSupported, CodeInternalError Code = "FEATURE_NOT_SUPPORTED", "INTERNAL_ERROR"
    // CID 1.0 §3.5 codes (their type starts with NamespaceSecurity): the five document.Code values such as
    // CodeInvalidVerificationMethodURL, CodeInvalidVerificationMethod and CodeInvalidRelationshipForVerificationMethod
)
func (c Code) TypeURL() string

// Errors are created at each use, not shared mutable sentinels (14 §4). NewError fills the title and the status of a binding table type.
// A CID 1.0 error refines INVALID_DID_URL, so the HTTPS binding uses 400 (did-go policy, 07 §4).
func NewError(code Code, detail string) *Error
// NewAcceptNotSupported is the FEATURE_NOT_SUPPORTED error when no representation acceptable to accept can be produced (12 §6.2 step 4).
// IsAcceptNotSupported recognizes it, so the v1.0 adapter can map it to representationNotSupported.
func NewAcceptNotSupported(accept string) *Error
func (e *Error) IsAcceptNotSupported() bool
func (e *Error) Code() Code
func (e *Error) HTTPStatus() int          // 07 §7
func (e *Error) Is(target error) bool     // true for the same type: errors.Is(err, NewError(CodeNotFound, ""))
func ErrorResult(e *Error) Result         // no document, empty document metadata, e in the resolution metadata

// Negotiate picks the offer accept prefers, following RFC 9110 §12.5.1. An offer gets the weight of the most specific matching
// media range (parameters are not compared); an offer with weight 0 or matched by no range is not acceptable.
// Ties go to the earlier offer. An accept without elements accepts everything, so offers[0] wins; a malformed accept accepts nothing.
func Negotiate(accept string, offers []string) (string, bool)
// Acceptable reports whether accept accepts mediaType (Negotiate with the single offer mediaType).
func Acceptable(accept, mediaType string) bool
func ParseAccept(s string) ([]MediaRange, error)
```

Error catalog (full list in 07 §4): `INVALID_DID` (400), `INVALID_DID_URL` (400), `INVALID_OPTIONS` (400), `NOT_FOUND` (404), `REPRESENTATION_NOT_SUPPORTED` (406), `INVALID_DID_DOCUMENT` (500), `METHOD_NOT_SUPPORTED` (501), `FEATURE_NOT_SUPPORTED` (501), `INTERNAL_ERROR` (500). Fragment dereferencing uses the CID-derived `INVALID_VERIFICATION_METHOD` and `INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD`.

The HTTP status is chosen in this order. First the binding table is looked up by `Type`. If the type is not in the table, the table status of the type named by `Refines` is used. Only if that is also missing is the error's own `Status` used, and finally 500. For an error type that is not in the HTTP binding table, the spec says the status "is determined by the implementation", so the steps from `Refines` on are did-go policy. An extension cannot change a status that the binding table fixes (07 §4, §7).

```go
// resolution.go
type Dereferencer interface {
    Dereference(ctx context.Context, u did.DIDURL, opts DereferenceOptions) DereferenceResult
}

type DereferenceOptions struct {
    Accept                   string
    VerificationRelationship string // relationship for which the dereferenced VM must be authorized
    Extra                    map[string]any
}

type DereferencingMetadata = ResolutionMetadata // spec dereferencingMetadata (DID Resolution §5.2)

// DereferenceResult is «dereferencingMetadata, contentStream, contentMetadata» of dereference() (07 §2).
type DereferenceResult struct {
    ContentStream         any                   // spec contentStream. *document.Document | vm.Method | vm.Service | document.Map | []string(uri-list) | []byte; nil on failure
    DereferencingMetadata DereferencingMetadata // spec dereferencingMetadata
    ContentMetadata       DocumentMetadata      // spec contentMetadata
}

// ErrorDereferenceResult is the result of a failed dereference: no content, empty content metadata, e in the dereferencing metadata.
func ErrorDereferenceResult(e *Error) DereferenceResult
```

**Default composed implementation (`resolver.DefaultResolver`)**: the UC-5 sequence in code, in the `resolver` player package. Failures are reported in `ResolutionMetadata.Error` (RFC9457), not as `error`. After the method lookup and before `Read`, the options are checked (07 §1.1 steps 3 and 4). An unsupported option (an unknown extension option, or an `accept` that no producible representation satisfies) is `FEATURE_NOT_SUPPORTED`, and an invalid option is `INVALID_OPTIONS`. Driver errors are mapped as follows: `method.ErrNotFound` is `NOT_FOUND`, `method.ErrNotSupported` (for example, `versionTime` is not supported) is `FEATURE_NOT_SUPPORTED`, `method.ErrInvalidDocument` is `INVALID_DID_DOCUMENT`, `method.ErrInvalidInput` is `INVALID_DID`, and any other error is `INTERNAL_ERROR`. After `Read`, the document metadata the driver supplied is checked with `document.Metadata.Check` before the `deactivated` check; a violation is `INVALID_DID_DOCUMENT`. The later steps follow [`12`](12-standard-core-and-sage-extension.md) §6.2. `DefaultResolver` keeps no cache, so it honours `noCache` as it is and passes it to the driver in `ReadOptions.NoCache`. `resolution/cache` puts a cache in front of any resolver.

```go
package resolver

// New returns a resolver over the drivers in registry. Driver output is consumed with consumer,
// and producer writes a representation the driver did not produce. A nil argument is an error.
func New(registry *method.Registry, consumer representation.Consumer, producer representation.Producer, opts ...Option) (*DefaultResolver, error)
// AcceptOptions adds extension option names that are accepted and ignored. Accepted by default, DefaultAcceptedOptions():
// the DID parameters service, serviceType, relativeRef and the dereferencing option verificationRelationship (DID Resolution §5.4.1).
func AcceptOptions(names ...string) Option

func (r *DefaultResolver) Resolve(ctx context.Context, d did.DID, opts resolution.ResolutionOptions) resolution.Result {
    m, ok := r.registry.Lookup(d.Method())
    if !ok {
        return failed(resolution.CodeMethodNotSupported, "...")
    }
    // 07 §1.1 step 3: an unknown extension option, or an accept that no producible representation satisfies, is FEATURE_NOT_SUPPORTED.
    if e := r.supported(opts); e != nil {
        return resolution.ErrorResult(e)
    }
    // 07 §1.1 step 4: an invalid option is INVALID_OPTIONS.
    if e := opts.Validate(); e != nil {
        return resolution.ErrorResult(e)
    }
    // Pick the format the driver can produce that matches accept; empty if accept is empty or nothing matches (driver default).
    want := ""
    if opts.Accept != "" {
        want, _ = resolution.Negotiate(opts.Accept, m.Produces())
    }
    rr, err := m.Read(ctx, d, method.ReadOptions{VersionID: opts.VersionID, VersionTime: opts.VersionTime, MediaType: want, NoCache: opts.NoCache})
    switch {
    case errors.Is(err, method.ErrNotFound):
        return failed(resolution.CodeNotFound, "...")
    case errors.Is(err, method.ErrNotSupported): // for example, the driver does not support versionTime
        return failed(resolution.CodeFeatureNotSupported, "...")
    case errors.Is(err, method.ErrInvalidDocument): // the document the driver obtained does not conform or its id is not the DID
        return failed(resolution.CodeInvalidDIDDocument, "...")
    case errors.Is(err, method.ErrInvalidInput): // the DID does not conform to its method
        return failed(resolution.CodeInvalidDID, "...")
    case err != nil:
        return failed(resolution.CodeInternalError, "...")
    }
    // rr.Metadata and Result.DocumentMetadata have the same type (document.Metadata).
    // Driver-supplied metadata is validated before the deactivated check (12 §6.2). A violation is INVALID_DID_DOCUMENT.
    if err := rr.Metadata.Check(d, spec.V11); err != nil {
        return failed(resolution.CodeInvalidDIDDocument, "...")
    }
    if rr.Metadata.Deactivated { // not an error: document is null, signaled through metadata
        return resolution.Result{DocumentMetadata: rr.Metadata.Clone()}
    }
    // 1. Consume the driver bytes with the driver's media type label and run standard validation. Drivers and profiles cannot disable this step.
    doc, info, err := r.consumer.Consume(rr.Data, rr.ContentType, representation.ConsumeOptions{})
    if err != nil || doc.ID() != d {
        return failed(resolution.CodeInvalidDIDDocument, "...")
    }
    // 2. detected is the DID media type of the representation in the driver bytes. If the driver used a DID media type it is that value;
    //    for a low-precision label it is the precise DID media type of the representation detected in the payload, and the received label remains in info.LowPrecision.
    //    The result contentType is the media type of the bytes returned in Raw: detected for driver bytes (step 3), mt after transcoding (step 4).
    detected := representation.MediaTypeOf(info)
    if opts.ExpandRelativeURLs {
        if doc, err = expand(doc); err != nil { // the bytes no longer match the document, so step 4 produces them again
            return failed(resolution.CodeInternalError, "...")
        }
    }
    res := resolution.Result{Document: doc, Info: info, DocumentMetadata: rr.Metadata.Clone()}
    // 3. accept negotiation (RFC 9110 media ranges and q-values). If acceptable, return the driver bytes as is.
    if !opts.ExpandRelativeURLs && (opts.Accept == "" || resolution.Acceptable(opts.Accept, detected)) {
        res.Raw = rr.Data
        res.ResolutionMetadata.ContentType = detected // DID media type of the returned driver bytes
        return res
    }
    // 4. The core produces an acceptable representation from the validated document. If it cannot, the result is FEATURE_NOT_SUPPORTED,
    //    created by resolution.NewAcceptNotSupported (the v1.0 adapter maps it to representationNotSupported, 07 §7).
    //    With an empty accept (expandRelativeUrls) the document is produced again in the detected representation.
    offers := []string{detected}
    if opts.Accept != "" {
        offers = append(offers, representation.CoreMediaTypes()...)
    }
    target, ok := resolution.Negotiate(opts.Accept, offers)
    if !ok {
        return resolution.ErrorResult(resolution.NewAcceptNotSupported(opts.Accept))
    }
    popts, _ := representation.OptionsFor(target)
    data, mt, err := r.producer.Produce(doc, popts)
    if err != nil { // for example, V10 production with a service that has no service.id; with an empty accept (expandRelativeUrls) it is an internal error
        if opts.Accept == "" {
            return failed(resolution.CodeInternalError, "...")
        }
        return resolution.ErrorResult(resolution.NewAcceptNotSupported(opts.Accept))
    }
    res.Raw = data
    res.Source = &resolution.SourceBytes{Data: rr.Data, ContentType: rr.ContentType}
    res.ResolutionMetadata.ContentType = mt // media type of the representation the core produced
    return res
}

// Metadata.Check checks the document metadata the driver supplied (12 §6.2, DID Resolution §4.3).
// Each equivalentId value and canonicalId are DIDs of the same method as d, versionId is ASCII,
// created, updated and nextUpdate can be written in the 07 §3 datetime format (no sub-second precision),
// proofs are maps, and Extra values are metadata structure types (07 §5).

func failed(code resolution.Code, detail string) resolution.Result {
    return resolution.ErrorResult(resolution.NewError(code, detail))
}
```

> The `dereferencer` player implements the DID parameters (`service`/`serviceType`/`relativeRef`/`versionId`/`versionTime`) and service endpoint URL construction per the 07 §2.1 contract. The HTTP binding (`/1.0/identifiers/{id}`, GET required, status code mapping, the `application/did-resolution` and `application/did-url-dereferencing` media types) belongs to `resolution/universal`, and caching and `noCache` belong to `resolution/cache`.

### 6.1 `resolution/compat`: v1.0 contract adapter (FR-V4)

An adapter for legacy callers that need the abstract functions of v1.0 REC §7.1 (`resolve` + **`resolveRepresentation`**) and the **string error** contract. It does not pollute the core contract (ADR-14). Canonical: [`09`](09-v1.0-compat.md) §6.

```go
package compat

type V10Resolver struct {
    Inner resolution.Resolver // v1.1 core; the core also does accept negotiation and V10 transcoding (12 §6.2)
}

type V10ResolutionMetadata struct {
    ContentType string   // set only when resolveRepresentation succeeds (REQUIRED if successful); MUST NOT in resolve (v1.0 §7.1.2). Deactivated DID: DEV-V10-1 (09 §6.1)
    Error       string   // "invalidDid" | "notFound" | "representationNotSupported" | … ("" on success)
    Warnings    []string // inputs the adapter ignored (WarningAcceptIgnored, WarningHLIgnored); not part of the metadata structure, never serialized
}

func (r *V10Resolver) Resolve(ctx context.Context, d did.DID, opts resolution.ResolutionOptions,
) (V10ResolutionMetadata, *document.Document, resolution.DocumentMetadata)

// An empty accept is replaced by the two DID Core 1.0 media types ("application/did+ld+json, application/did+json") (09 §6).
// If the core returns the FEATURE_NOT_SUPPORTED of resolution.NewAcceptNotSupported because it cannot produce a representation
// matching accept, the error is "representationNotSupported" (DID Core 1.0 §7.1.2, an exception to the 09 §6.1 table).
func (r *V10Resolver) ResolveRepresentation(ctx context.Context, d did.DID, opts resolution.ResolutionOptions,
) (V10ResolutionMetadata, []byte, resolution.DocumentMetadata)

// V10Dereferencer provides dereference from v1.0 REC §7.2.
type V10Dereferencer struct {
    Inner resolution.Dereferencer // v1.1 core
}

// V10DereferencingMetadata has the same structure. ContentType is the media type of contentStream on success;
// Error is "invalidDidUrl" | "notFound" | … ("" on success), mapped with the 09 §6.1 table.
type V10DereferencingMetadata = V10ResolutionMetadata

// On failure, contentStream is nil and contentMetadata is an empty metadata structure (v1.0 §7.2 MUST).
func (r *V10Dereferencer) Dereference(ctx context.Context, u did.DIDURL, opts resolution.DereferenceOptions,
) (V10DereferencingMetadata, any, resolution.DocumentMetadata)

func ErrorString(e *resolution.Error) string             // the 09 §6.1 table
func V10Metadata(md document.Metadata) document.Metadata // deep copy with numbers converted to decimal strings
```

- Error mapping: codes that the REC defines for the RFC9457 `type` map exactly (`INVALID_DID`→`invalidDid`, `NOT_FOUND`→`notFound`, `REPRESENTATION_NOT_SUPPORTED`→`representationNotSupported`, `INVALID_DID_URL`→`invalidDidUrl`). The rest follow the SCREAMING_SNAKE→camelCase rule. Full table in 09 §6.1. There is one exception. If `resolveRepresentation` cannot produce the requested `accept` representation and the core returns `FEATURE_NOT_SUPPORTED` (the error made by `resolution.NewAcceptNotSupported`), the v1.0 path returns `representationNotSupported` from DID Core 1.0 §7.1.2, not `featureNotSupported`.
- `deactivated` is non-error metadata in both versions and passes through unchanged.
- Failure results: `ResolveRepresentation` returns an empty didDocumentStream (nil). `V10Dereferencer.Dereference` in the same package returns a nil `contentStream` and an empty `contentMetadata` on failure, and its `dereferencingMetadata.error` is a single keyword ASCII string mapped with the 09 §6.1 table (09 §6).
- Metadata: v1.0 does not allow number values, so the adapter converts numbers to strings, including nested values. `created`, `updated` and `nextUpdate` are written as UTC datetimes without sub-second digits (09 §6, 07 §5).
- `accept` option: v1.0 §7.1.1 says **MUST NOT** with `resolve`. The adapter's `Resolve()` ignores `opts.Accept` (with a warning).
- DID parameters: the v1.0-only `hl` is accepted by the adapter (not passed to the core). The v1.1-only `serviceType` yields `featureNotSupported` on the v1.0 path.
- HTTP: there is no separate v1.0 binding. In the v1.1 binding, if Accept is a legacy type, the core returns the V10 representation through accept negotiation and transcoding (09 §6.3, 12 §6.2).

### 6.2 `didkit`: assembly

`didkit` assembles the standard producer and consumer, a `method.Registry` of the drivers the caller passes, a `resolver.DefaultResolver` over them, an optional `resolution/cache`, and a dereferencer. It has no logic of its own. It never imports a driver itself, so a program that uses only `did:key` does not link `net/http` ([`14`](14-implementation-architecture.md) §6). It does not include `resolution/compat`.

```go
package didkit

// Assemble with the default configuration.
func NewResolver(methods ...method.Method) (resolution.Resolver, error)
func NewDereferencer(r resolution.Resolver) (*dereferencer.Dereferencer, error)

// Kit assembles players with one configuration. It is immutable and safe for concurrent use.
type Kit struct{ /* unexported */ }
func New(opts ...Option) *Kit // a nil option is ignored
func (k *Kit) NewResolver(methods ...method.Method) (resolution.Resolver, error) // wrapped in a cache when WithCache was given
func (k *Kit) NewDereferencer(r resolution.Resolver) (*dereferencer.Dereferencer, error)
func (k *Kit) Producer() *producer.Producer // the producer the players share; build drivers with it too: key.New(k.Producer())

func WithProducerOptions(opts ...producer.Option) Option
func WithConsumerOptions(opts ...consumer.Option) Option
func WithResolverOptions(opts ...resolver.Option) Option
func WithDereferencerOptions(opts ...dereferencer.Option) Option
func WithCache(opts ...cache.Option) Option // without it the resolver keeps no cache
```

---

## 7. `crypto`: key codecs (delegated to CID, FR-D3/P1)

```go
package crypto

// Functions and immutable values only, without an interface or a registry. No private key is held and no key is stored; every value is safe for concurrent use.

type KeyType string // the row names of the Multikey table in vm
const (
    Ed25519 KeyType = "Ed25519" // signatures
    P256    KeyType = "P-256"   // signatures (ECDSA)
    P384    KeyType = "P-384"   // signatures (ECDSA)
    X25519  KeyType = "X25519"  // key agreement
)
func SupportedKeyTypes() []KeyType

// PublicKey is a validated public key. The zero value is not a valid key.
type PublicKey struct{ /* unexported */ }
func NewPublicKey(t KeyType, raw []byte) (PublicKey, error)      // validates the key data of the Multikey encoding
func FromCryptoKey(k stdcrypto.PublicKey) (PublicKey, error)     // ed25519.PublicKey, *ecdsa.PublicKey, *ecdh.PublicKey
func ParseMultikey(value string) (PublicKey, error)              // publicKeyMultibase of a Multikey method (uses the vm table)
func ParseJWK(jwk map[string]any) (PublicKey, error)             // OKP (Ed25519, X25519), EC (P-256, P-384); private members are rejected
func FromMethod(m vm.Method) (PublicKey, error)                  // publicKeyJwk when present, otherwise publicKeyMultibase; m is not changed
func DeriveX25519(k PublicKey) (PublicKey, error)                // Ed25519 → X25519 (RFC 7748 §4.1), the did:key encryption key derivation

func (k PublicKey) Type() KeyType
func (k PublicKey) Raw() []byte
func (k PublicKey) Multikey() (string, error)          // z + base58btc(multicodec prefix ‖ key data)
func (k PublicKey) JWK() map[string]any                // never writes private members such as "d"
func (k PublicKey) CryptoKey() stdcrypto.PublicKey
func (k PublicKey) Equal(o PublicKey) bool
func (k PublicKey) Verify(msg, sig []byte) error       // default Policy
func (k PublicKey) VerifyWithPolicy(msg, sig []byte, p Policy) error

// Policy holds the choices where the standards allow more than one answer. Ed25519 verification is always strict (canonical encodings, small-order points rejected, S range checked).
// ECDSA signatures are fixed-size r ‖ s, and high-S signatures are accepted by default. RejectHighS rejects s > n/2.
type Policy struct{ RejectHighS bool }

type Error string
const (
    ErrUnsupportedKeyType Error = "crypto: unsupported key type" // unknown type, a type the standard library does not implement (BLS12-381 G2, SM2, secp256k1), or signature verification with X25519
    ErrInvalidEncoding    Error = "crypto: invalid key encoding"
    ErrInvalidKey         Error = "crypto: invalid public key"
    ErrInvalidSignature   Error = "crypto: invalid signature"
)
```

Supported key types: Ed25519 (public prefix `0xed01`, 34B), P-256 (`0x8024`, 35B), P-384 (`0x8124`, 51B), X25519 (`0xec01`, 34B, used by did:key for key agreement). BLS12-381 G2 (`0xeb01`, 98B), SM2 (`0x8624`) and secp256k1 are recognized but return `ErrUnsupportedKeyType`, because the standard library has no implementation of them. did-go uses no other cryptographic library. The full multicodec prefix/length table and the secret key prefixes are in [`06-cid-data-model.md`](06-cid-data-model.md) §5. This table is pure data that uses only the standard library and lives in `vm/multikey.go`; `crypto` imports `vm` to use it. So `vm.Method.Validate` checks prefixes and lengths without `crypto`, and the core does not import adapters (§1, NFR-3). A secret key header in a public key position MUST be an error. Multibase encoding and decoding must produce the same output as CID §3.1 and §3.2, and Multihash decoding checks the digest length against both the algorithm's output length and the length written in the value (06 §9).

---

## 8. Error design (NFR-4)

- Every public API returns `(T, error)`. No panics.
- Syntax errors are `*did.SyntaxError` (with position). Conformance errors are `*document.ConformanceError` (violating property and reason).
- Resolution/dereferencing failures are expressed **as `Metadata.Error` codes, not as errors** (DID-RESOLUTION contract). Only infrastructure failures are Go `error` values.
- `errors.Is`/`errors.As` are supported. Sentinels are constant error types, not mutable variables (`did.Error`, `method.Error`, `crypto.Error`, `controller.Error`, `relyingparty.Error`), and callers test wrapped errors with `errors.Is`. A `resolution.Error` is created at each use with `NewError`, and `(*Error).Is` compares the type.

---

## 9. Traceability matrix (FR → package/type)

| FR | Package · type/function |
|----|--------------------|
| FR-S1~S6 | `did.Parse`, `did.ParseURL`, `did.ParseReference`, `did.ParseRef`, `DIDURL.Resolve`, `DIDURL.Parameters`, `SyntaxError` |
| FR-D1,D2 | `document.Document`, `document.Builder`, `document.Value` (INFRA types) |
| FR-D3 | `vm.Method`, `vm.Method.Validate` (at most one public key material property and at most one secret key material property; presence determined by type; a method without public key material cannot verify proofs) · norms 06 §2 |
| FR-D4 | `vm.Relationship`, `document.SelectMethod`, `relyingparty.RelyingParty` · CID Retrieve VM 06 §3 |
| FR-D5 | `vm.Service`, `vm.Endpoint`, `vm.Shape`, `Service.Validate` · 06 §8 |
| FR-D6 | `resolution.DocumentMetadata.{EquivalentID,CanonicalID}` (didDocumentMetadata, 07 §5) |
| FR-D7 | `Document.RepresentationEntries()` (representation-specific, rule 3) + `Document.Extensions()` (non-representation-specific extensions, rule 4) |
| FR-R1,R2,R4 | `producer.Producer`, `consumer.Consumer`, `internal/wire` |
| FR-R3,R6 | `jsonld.ProductionContext`, `jsonld.Context.Terms`, `jsonld.ContextSHA256V10/V11` |
| FR-R5 | `representation.Detect`, `spec.MediaTypeDID` |
| FR-M1~M6 | `method.Method`, `method.Registry`, `method.Signer`, `controller.Controller` |
| FR-X1~X4 | `resolution.Resolver/Dereferencer`, RFC9457 `resolution.Error`, `resolver.DefaultResolver`, `dereferencer.Dereferencer` · contract 07 |
| FR-P1,P3 | `method.Method` (integrity), `ProduceOptions.IncludeSecret`, `crypto.PublicKey.Verify` |
| FR-P4,P5 | logging policy document, `DocumentMetadata.CanonicalID` re-verification guide |
| FR-V1,V2 | `spec.Version`, `representation.ConsumeInfo`, detection and normalization rules (09 §4) |
| FR-V3 | `representation.ProduceOptions.Version`, `document.Validate(d, spec.V10)` |
| FR-V4 | `resolution/compat.V10Resolver`, `V10Dereferencer` (error mapping 09 §6.1) |
| FR-V5 | `spec.ContextURLV10/V11`, `jsonld.BaseContext`, dual SHA-256 pinning |

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
| 16~23 | Standard first with advanced extensions; `advanced/sage` as a separate module; the document does not grant key authority; a declared DID media type decides the representation; preserve original bytes; exclude staking; the core validates every driver output; accept negotiation and transcoding | [`12`](12-standard-core-and-sage-extension.md) §8 |
