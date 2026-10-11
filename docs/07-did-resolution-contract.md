# DID Resolution: Resolver and Dereferencer Contract and Go Mapping

> Source: **DID Resolution v1.0, W3C Candidate Recommendation Draft, 2026-10-01** (<https://www.w3.org/TR/2026/CRD-did-resolution-1.0-20261001/>). The pinned SHA-256 is `2b194843d37f5b7f01a4f5464f64d672dc4be43dafe5f2f49114c6070819586e`; see [standards.md](standards.md). Citations use section ids (`#resolving-algorithm`, `#dereferencing-algorithm-resource`, and so on) instead of line numbers. The OpenAPI definition is the non-normative file that the CRD's `#bindings-https` note points to. It is not part of the pinned CRD.
> Role: Fixes the Resolution and Dereferencing algorithms, options, metadata, errors and HTTP binding that DID Core v1.1 delegates. This document replaces and extends the `resolution` package in `05-go-design.md`.
> **Draft caveats (including internal inconsistencies in the specification):**
> 1. In the algorithm and the HTTP table, error values are **`https://www.w3.org/ns/did#SCREAMING_SNAKE` URLs** (RFC9457 `type`). Some examples still show legacy camelCase strings (`"error":"notFound"`). **RFC9457 object + URL type** is adopted as canonical.
> 2. This version has **no** `resolveRepresentation()` (merged into resolve + accept). Callers that need the v1.0 REC §7.1 contract (`resolveRepresentation`, string errors) use the `resolution/compat` adapter. See [`09-v1.0-compat.md`](09-v1.0-compat.md) §6.
> 3. **AT RISK scope**: the following sections may change substantially or be removed during the CR phase.
>    - Issue 1 in the SOTD says the DID URL dereferencing feature as a whole is at risk and will likely be changed or removed.
>    - `#dereferencing` (section 5, Issue 2) is at risk in its entirety.
>    - `#dereferencing-provisional` (section 6, Issue 3) carries a separate PROVISIONAL dereferencing algorithm that differs from section 5. It is a modular approach that applies "retrieval strategies" in sequence, and it is also at risk. §2.1 of this document follows section 5 (`#dereferencing-algorithm`).
>    - `#architectures` (section 8, Issue 4) is at risk.
>    - `#did-url-dereferencing-result` (section 10, Issue 5) is at risk.
>    - `#did-resolution-result` (section 9) is not at risk.
> 4. **`contentType` placement conflict**: step 7 of the resolve algorithm writes `contentType` into `didDocumentMetadata`, but the property definition in §DID Resolution Metadata and the OpenAPI place it in `didResolutionMetadata`. **`didResolutionMetadata` is adopted as canonical.**
> 5. **`deactivated` type conflict**: the normative HTML and this document use **boolean**. The OpenAPI schema wrongly declares `string`. Boolean is canonical.
> 6. **serviceEndpoint URL construction conflict**: the normative text requires RFC3986 §5, but the worked example shows a result that appends the path (see §2.1).
> 7. **Dereferencing result key names do not match**: the abstract function `dereference()` returns `dereferencingMetadata`, `contentStream` and `contentMetadata`. Example 22 in `#did-url-dereferencing-result` uses the keys `content`, `didUrlDereferencingMetadata` and `contentMetadata`. The HTTP binding example (`#example-returning-a-did-url-dereferencing-result`, Example 35) uses `content`, `dereferencingMetadata` and `contentMetadata`, and the algorithm steps mix `content` and `contentStream`. The names are inconsistent inside the specification, so this is recorded here. did-go uses `content`, `dereferencingMetadata` and `contentMetadata` in the HTTP result body (§6).
> 8. **`contentType` location conflict for `text/uri-list` results**: the algorithm (`#dereferencing-algorithm-resource`) puts `"contentType" → "text/uri-list"` in `contentMetadata`. The HTTP binding (`#bindings-https`) requires 303 when the `contentType` in `dereferencingMetadata` is `text/uri-list`. `#did-url-content-metadata` defines no common properties at all. The binding's 303 rule reads: "The HTTP response MUST contain an Location header. The value of this header MUST be the selected DID service endpoint URL. the HTTP response body MUST be empty." did-go interprets this as follows (this is an interpretation, not spec text). On output, it writes the value into `dereferencingMetadata.contentType` for the binding and also into `contentMetadata` to follow the algorithm (in Go, `DocumentMetadata.Extra["contentType"]`). On input, it accepts the value in either place.

---

## 1. resolve() (§Resolving)

```
resolve(did, resolutionOptions)
  → « didResolutionMetadata, didDocument, didDocumentMetadata »
```
A conforming resolver **does not change** this signature. It must implement at least one method and be able to return a DID document.

**Inputs**
- `did`: REQUIRED, conforms to `did-syntax`.
- `resolutionOptions`: REQUIRED (may be empty).

**resolutionOptions properties**

| Property | Type | Meaning |
|----------|------|---------|
| `accept` | ASCII (HTTP Accept value) | Media type of the preferred DID document representation. (In the HTTP binding it is sent in the `Accept` header.) |
| `expandRelativeUrls` | boolean | Makes relative DID URLs in the document absolute. |
| `versionId` | string | Selects a specific version (§DID Parameters). |
| `versionTime` | datetime string | Latest version before the given time. |

**Outputs**
- `didResolutionMetadata`: REQUIRED. On error it MUST be non-empty and contain `error`.
- `didDocument`: on success, representable in a conforming representation, and its `id` is string-equal to the resolved DID. On failure, `null`.
- `didDocumentMetadata`: a metadata structure on success, an empty structure on failure.

### 1.1 resolve algorithm (§resolving-algorithm)
```
1. did does not conform to did syntax  → error INVALID_DID
2. method not supported                → METHOD_NOT_SUPPORTED
3. option not supported                → FEATURE_NOT_SUPPORTED
4. option invalid                      → INVALID_OPTIONS
5. run the method's Read operation:
     - does not exist                  → NOT_FOUND
     - deactivated                     → no error! didDocument=null,
                                         didDocumentMetadata{deactivated:true}
     - otherwise                       → output DID document (conforming representation)
6. expandRelativeUrls==true → make relative DID URLs in services/VMs/relationships/extensions absolute
7. success → didResolutionMetadata{contentType: representation media type}
        (the spec algorithm text puts it in didDocumentMetadata, which conflicts with §5 and the OpenAPI → caveat 4)
* unexpected error                     → INTERNAL_ERROR
```
> **Key point:** `deactivated` is **not an error**. It is signaled by `didDocumentMetadata.deactivated=true` (+ HTTP 410).

### 1.2 resolveRepresentation()
**Not present** in this version. Representation selection is handled by `resolve()` + the `accept` option + `didResolutionMetadata.contentType`. In the HTTP binding, putting the `accept` option value in the `Accept` header returns only the `didDocument`, in that representation. The value is not limited to `application/did`; it can be any representation the resolver accepts (§6).

---

## 2. dereference() (§Dereferencing) **[AT RISK: SOTD Issue 1, `#dereferencing` Issue 2]**

```
dereference(didUrl, dereferenceOptions)
  → « dereferencingMetadata, contentStream, contentMetadata »
```
All inputs and outputs except `contentStream` must be serializable to JSON.

**Inputs:** `didUrl` (REQUIRED, the complete string including the fragment), `dereferencingOptions` (REQUIRED, may be empty).

**dereferencingOptions**

| Property | Type | Meaning |
|----------|------|---------|
| `accept` | ASCII Accept | Preferred media type of `contentStream`. |
| `verificationRelationship` | ASCII | Relationship for which the dereferenced VM must be authorized. If the URL does not dereference to a VM, or the VM is not authorized for that relationship, an error MUST be raised. |

**Outputs:** `dereferencingMetadata` (REQUIRED; contentType, error, proof), `contentStream` (on success, the resource: DID document, VM, service, or other), `contentMetadata` (didDocumentMetadata when the content is a DID document). `#did-url-content-metadata` defines no common properties for `contentMetadata`.

### 2.1 dereference algorithm (`#dereferencing-algorithm`)
**(a) Dereferencing the resource (`#dereferencing-algorithm-resource`)**
```
1. didUrl does not conform to syntax   → INVALID_DID_URL
2. call resolve(did). Dereferencing options + all DID parameters of the DID URL MUST be passed as resolution options
3. DID does not exist                  → NOT_FOUND
4. separate the fragment if present
5. no path and no query                → contentStream=DID document, contentMetadata=didDocumentMetadata
6. service/serviceType parameters:
     a. service→match id, serviceType→match type (relative references are normalized with RFC3986 §5 before comparison)
     b. if relativeRef is present, resolve each string serviceEndpoint URL
        with RFC3986 §5, base=endpoint, ref=relativeRef
     c. no accept / DID document representation → return the DID document with the service array reduced to the selected services
     d. accept==text/uri-list  → content=list of selected endpoint URLs,
                                  contentMetadata{contentType:text/uri-list}
                                  (303 in the HTTP binding; for the contentType location see caveat 8)
     e. otherwise               → REPRESENTATION_NOT_SUPPORTED
7. path/query only → dereferencing defined by the method, an extension or the client
8. cannot dereference                  → NOT_FOUND
```
**(b) Dereferencing the fragment (`#dereferencing-algorithm-fragment`)**
```
1. DID document + verificationRelationship option → dereference the VM by fragment
     not a conforming VM     → an error MUST be raised,
                               and SHOULD convey the type INVALID_VERIFICATION_METHOD
     relationship not linked → an error MUST be raised,
                               and SHOULD convey the type
                               INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD
2. selected service endpoint URL + fragment:
     endpoint already has a fragment → error (the spec does not specify a type)
     otherwise append the DID URL's fragment to the endpoint URL (inheritance)
3. otherwise → rules of the resource media type (application/did → JSON-LD fragment rules)
```
**Service endpoint URL construction (caveat 6, internal conflict in the spec):**
- The normative text (`#dereferencing-algorithm-resource`) requires **RFC3986 §5 Reference Resolution** with base=endpoint and ref=`relativeRef`.
- The worked example (`#example-dereferencing-to-service-endpoint-url`, Examples 13 and 14) shows `did:ex:123...?service=messages&relativeRef=%2Fsome%2Fpath%3Fquery#frag` + endpoint `https://example.com/messages/8377464` → `https://example.com/messages/8377464/some/path?query#frag` (path **appended**).
- However, when `relativeRef` is `/some/path?query` (a leading `/` makes it an absolute-path reference), RFC3986 §5.2.2 **replaces** the base path, so the result must be `https://example.com/some/path?query#frag`. The spec example does not match the normative text.
- **Implementation guidance:** treat the normative rule (RFC3986 §5) as canonical. An absolute-path reference replaces the base path; only a relative-path reference is merged. The fragment is inherited only when the endpoint has no fragment (if it has one, raise an error).

---

## 3. DID Parameters registry (§did-parameters)

Support for every parameter is OPTIONAL. Values are scalar ASCII (RFC3987 §3.1). Parameters are part of the DID URL identifier.

| Parameter | Type | Effect |
|-----------|------|--------|
| `service` | string (service id) | Selects a service by id match. |
| `serviceType` | string (service type) | Selects a set of services by type match. |
| `relativeRef` | relative URI reference (RFC3986 §4.2) | Resource at the selected service endpoint. Resolved per §5 with the endpoint as base. Path/query delimiters are percent-encoded (for example `%2Fresume.pdf%3Fversion%3D2`); do not decode them during normalization. |
| `versionId` | string | A specific document version. |
| `versionTime` | datetime | Latest version before the given time. MUST use the datetime format. |

**datetime format**: UTC, no sub-second precision, for example `2020-12-20T19:17:47Z`.
**query normalization**: decode unreserved octets and uppercase hex digits; do not decode reserved delimiters (`%26`/`%3D`). Duplicate parameter names are unspecified; treating them as `INVALID_DID_URL` is reasonable.

---

## 4. Error catalog (§errors), RFC9457

`type` is a URL. Non-URL values MUST be prefixed with `https://www.w3.org/ns/did#`. `title` is short, `detail` is long.

**Refinement rule**: a specification that defines an error type not listed in this section may declare which type in this section it refines ("MAY declare that it refines one of the error types defined in this section"). A binding in `#bindings` can use that declaration to decide how to convey the error. did-go stores the declaration in the Go field `Error.Refines` (§7).

The HTTP column is the status code table of `#bindings-https`.

| Name | `type` URI | HTTP |
|------|-----------|------|
| INVALID_DID | `…/ns/did#INVALID_DID` | 400 |
| INVALID_DID_URL | `…#INVALID_DID_URL` | 400 |
| INVALID_OPTIONS | `…#INVALID_OPTIONS` | 400 |
| NOT_FOUND | `…#NOT_FOUND` | 404 |
| REPRESENTATION_NOT_SUPPORTED | `…#REPRESENTATION_NOT_SUPPORTED` | 406 |
| INVALID_DID_DOCUMENT | `…#INVALID_DID_DOCUMENT` | 500 |
| METHOD_NOT_SUPPORTED | `…#METHOD_NOT_SUPPORTED` | 501 |
| FEATURE_NOT_SUPPORTED | `…#FEATURE_NOT_SUPPORTED` | 501 |
| INTERNAL_ERROR | `…#INTERNAL_ERROR` | 500 |
| (type not in the table) | any other URI | Determined by the implementation. did-go uses the code of the type named by `Refines`, and 500 if there is none (local policy) |

For a type not in the table, the spec says the status code "is determined by the implementation". Up to the CR Snapshot, 500 was required; this CRD changed that (Revision History). did-go's 500 is therefore a local policy, not a spec requirement.

`#errors` links `INVALID_DID_DOCUMENT` to §4.4 (`#resolving-algorithm`), but no algorithm step emits this type.

From CID (fragment dereferencing): `INVALID_VERIFICATION_METHOD`, `INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD`. The algorithm says an error MUST be raised and SHOULD convey these types. The error raised when a service endpoint already has a fragment has no specified type.
**`deactivated` is not an error** → metadata `deactivated:true` + HTTP **410**.

---

## 5. Metadata structures

**didResolutionMetadata** (source: the resolver; changes between calls)

| Property | Type | Note |
|----------|------|------|
| `contentType` | ASCII (media type of a conforming representation) | If present, the caller MUST use it to parse `didDocument`. |
| `error` | RFC9457 object | Only on error. |
| `proof` | set of maps | Method-independent proof (trusted resolution). |

**didDocumentMetadata** (source: the controller or the method)

| Property | Type | Level |
|----------|------|-------|
| `created` | datetime | SHOULD |
| `updated` | datetime | SHOULD (when updated) |
| `deactivated` | boolean | MUST be `true` when deactivated |
| `nextUpdate` | datetime | MAY (non-latest version) |
| `versionId` | ASCII | SHOULD |
| `nextVersionId` | ASCII | MAY (non-latest) |
| `equivalentId` | set of DID | MAY. Each DID is logically equivalent, produced by the **same method**, and the method guarantees the equivalence. Stronger than `alsoKnownAs`. |
| `canonicalId` | single DID | MAY. A single canonical DID from the same method. Expected to be used as the primary identifier. |
| `proof` | set of maps | Method-**specific** proof. |

**Metadata structure rules**: a map with string keys; values are string/number/map/list/set/boolean/null. Must be serializable to JSON per INFRA. Non-integers and integers larger than 32 bits should be serialized as strings.

---

## 6. HTTP(S) binding (`#bindings-https` + OpenAPI)

- Endpoint: `https://resolver.example/1.0/identifiers/{identifier}`. **GET is REQUIRED (MUST)**, POST MAY. TLS is required. The spec says: "Use of DNS names in certificates is NOT REQUIRED; resolvers MAY use TLS certificates issued for IP addresses." A certificate does not need a DNS name, and a TLS certificate issued for an IP address may be used.
- **Passing the DID**: `.../identifiers/did:example:1234`. DID URL dereferencing: `.../identifiers/did:example:1234?service=files&relativeRef=/resume.pdf`.
- **Options**: the `accept` option is not sent as a query parameter or in the body; it is expressed in the HTTP `Accept` header. If other options are present, URL-encode the DID (RFC3986 §2.1) and send the options as query parameters. POST uses a JSON body.
- **Accept ↔ response**:
  - `application/did-resolution` → the full Resolution Result `{didDocument, didResolutionMetadata, didDocumentMetadata}`.
  - `application/did-url-dereferencing` → the full Dereferencing Result. did-go uses the keys `{content, dereferencingMetadata, contentMetadata}`. The spec examples disagree on key names (caveat 7).
  - the `accept` option value → resolve returns only `didDocument`, and dereference returns only `contentStream`, in that representation. The value is not limited to `application/did`; it can be any representation the resolver accepts.
- **Content-Type of a 200 response**: when resolve succeeds and returns only `didDocument`, the response MUST contain a `Content-Type` header, and its value MUST equal `didResolutionMetadata.contentType`. The body is the `didDocument` in that representation. The same applies when dereference returns a `contentStream` other than `text/uri-list`; then the reference value is `dereferencingMetadata.contentType`.
- **303 response**: when dereference succeeds and `dereferencingMetadata.contentType` is `text/uri-list`, the status code MUST be 303. The `Location` header value MUST be the selected service endpoint URL, and the body MUST be empty. For the `contentType` location conflict, see caveat 8.
- **Status codes**: 200 success / 303 (text/uri-list) / 400 / 404 / 406 / 410 (deactivated in `didDocumentMetadata` or `contentMetadata`) / 500 / 501. An error type not in the table gets a status chosen by the implementation. See the table in §4.

---

## 7. Go mapping (replaces `05-go-design.md` §6)

```go
package resolution

const (
    MediaTypeDID           = "application/did"
    MediaTypeResolution    = "application/did-resolution"
    MediaTypeDereferencing = "application/did-url-dereferencing"
)

// Error is an RFC9457 Problem Details object.
type Error struct {
    Type     string `json:"type"`              // "https://www.w3.org/ns/did#NOT_FOUND"
    Title    string `json:"title"`
    Status   int    `json:"status,omitempty"`  // HTTP mapping
    Detail   string `json:"detail,omitempty"`
    Instance string `json:"instance,omitempty"`
    // Refines is the type URI from the §4 table that this type refines (§errors refinement rule).
    // Leave it empty for a type that is in the table. Bindings use it to choose the status code.
    Refines  string `json:"-"`
}

// Error type URI constants (§4)
const nsDID = "https://www.w3.org/ns/did#"
var (
    ErrInvalidDID          = &Error{Type: nsDID + "INVALID_DID", Status: 400, Title: "Invalid DID"}
    ErrInvalidDIDURL       = &Error{Type: nsDID + "INVALID_DID_URL", Status: 400, Title: "Invalid DID URL"}
    ErrInvalidOptions      = &Error{Type: nsDID + "INVALID_OPTIONS", Status: 400, Title: "Invalid options"}
    ErrNotFound            = &Error{Type: nsDID + "NOT_FOUND", Status: 404, Title: "Not found"}
    ErrReprNotSupported    = &Error{Type: nsDID + "REPRESENTATION_NOT_SUPPORTED", Status: 406, Title: "Representation not supported"}
    ErrInvalidDIDDocument  = &Error{Type: nsDID + "INVALID_DID_DOCUMENT", Status: 500, Title: "Invalid DID document"}
    ErrMethodNotSupported  = &Error{Type: nsDID + "METHOD_NOT_SUPPORTED", Status: 501, Title: "Method not supported"}
    ErrFeatureNotSupported = &Error{Type: nsDID + "FEATURE_NOT_SUPPORTED", Status: 501, Title: "Feature not supported"}
    ErrInternal            = &Error{Type: nsDID + "INTERNAL_ERROR", Status: 500, Title: "Internal error"}
)

type ResolutionOptions struct {
    Accept             string     `json:"accept,omitempty"`
    ExpandRelativeURLs bool       `json:"expandRelativeUrls,omitempty"`
    VersionID          string     `json:"versionId,omitempty"`
    VersionTime        *time.Time `json:"versionTime,omitempty"`
    Extra              map[string]any `json:"-"`
}

type DereferencingOptions struct {
    Accept                   string `json:"accept,omitempty"`
    VerificationRelationship string `json:"verificationRelationship,omitempty"`
    Extra                    map[string]any `json:"-"`
}

type ResolutionMetadata struct {
    ContentType string           `json:"contentType,omitempty"`
    Error       *Error           `json:"error,omitempty"`
    Proof       []map[string]any `json:"proof,omitempty"`
    Extra       map[string]any   `json:"-"`
}

type DocumentMetadata struct {
    Created       *time.Time       `json:"created,omitempty"`
    Updated       *time.Time       `json:"updated,omitempty"`
    Deactivated   bool             `json:"deactivated,omitempty"`
    NextUpdate    *time.Time       `json:"nextUpdate,omitempty"`
    VersionID     string           `json:"versionId,omitempty"`
    NextVersionID string           `json:"nextVersionId,omitempty"`
    EquivalentID  []string         `json:"equivalentId,omitempty"`
    CanonicalID   string           `json:"canonicalId,omitempty"`
    Proof         []map[string]any `json:"proof,omitempty"`
    Extra         map[string]any   `json:"-"`
}

// DID parameters (§3), parsed from the DID URL and passed as resolve options
type DIDParameters struct {
    Service     string
    ServiceType string
    RelativeRef string
    VersionID   string
    VersionTime *time.Time
    Extra       map[string]string
}

type Resolver interface {
    Resolve(ctx context.Context, did did.DID, opts ResolutionOptions) (*document.Document, ResolutionMetadata, DocumentMetadata)
}

type Dereferencer interface {
    Dereference(ctx context.Context, u did.DIDURL, opts DereferencingOptions) (content any, deref ResolutionMetadata, contentMeta DocumentMetadata)
}

// bindingStatus is the #bindings-https status code table.
var bindingStatus = map[string]int{
    nsDID + "INVALID_DID": 400, nsDID + "INVALID_DID_URL": 400, nsDID + "INVALID_OPTIONS": 400,
    nsDID + "NOT_FOUND": 404, nsDID + "REPRESENTATION_NOT_SUPPORTED": 406,
    nsDID + "INVALID_DID_DOCUMENT": 500, nsDID + "METHOD_NOT_SUPPORTED": 501,
    nsDID + "FEATURE_NOT_SUPPORTED": 501, nsDID + "INTERNAL_ERROR": 500,
}

// HTTP status mapping. The spec leaves the code for a type not in the table to the implementation.
// did-go uses the code of the type named by Refines, and 500 if that is also absent (local policy).
func (e *Error) HTTPStatus() int {
    if e == nil { return 500 }
    if e.Status != 0 { return e.Status }
    if s, ok := bindingStatus[e.Type]; ok { return s }
    if s, ok := bindingStatus[e.Refines]; ok { return s }
    return 500
}
```

**Core implementation rules (to be covered by tests):**
1. The `resolve`/`dereference` signatures do not change (conforming path).
2. `error` is an RFC9457 object with `type`=`https://www.w3.org/ns/did#<CODE>`.
3. `deactivated` is not an error → metadata + HTTP 410.
4. When dereferencing, pass DID parameters as resolve options.
5. Service endpoint URL = RFC3986 §5 (base=endpoint, ref=relativeRef) + fragment inheritance. Reject if the endpoint already has a fragment.
6. HTTP: GET is required, `accept`=Accept header, other options go in the query or body. Follow the status code mapping. The `Content-Type` of a 200 response must equal the `contentType` in the metadata.
7. `text/uri-list` dereferencing → 303. `Location` is the selected service endpoint URL and the body is empty. Write `contentType` into both `dereferencingMetadata` and `contentMetadata`, and accept it from either on input (caveat 8).
8. The HTTP status for an error type not in the table is chosen through `Refines`, and 500 if there is none. The 500 is a did-go local policy.
