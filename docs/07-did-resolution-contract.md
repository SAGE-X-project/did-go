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
> 9. **`@context` and `contentType` in the result example**: Example 21 of `#did-resolution-result` pairs a DID Core 1.0 `@context` (`https://www.w3.org/ns/did/v1`) with `contentType` `application/did`. DID Core 1.0 and DID 1.1 both require a consumer to determine the representation from the media type input (MUST), and DID 1.1 §6.2.3 requires, for production for JSON-LD processing, that the first `@context` value be `https://www.w3.org/ns/did/v1.1`. Reading the presence of `@context` in an `application/did` document as an intent to use JSON-LD processing, so that this requirement applies, is did-go's interpretation. Under that interpretation a conforming consumer must reject this combination. The example is informative, so did-go follows the normative MUST ([`12`](12-standard-core-and-sage-extension.md) §6.1, T7 in `08` §2.2).

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
| `expandRelativeUrls` | boolean | When `true`, replaces each object `id` value and each verification relationship entry that is a relative DID URL with an absolute DID URL (§1.1 step 6). |
| `versionId` | string | Selects a specific version (§DID Parameters). |
| `versionTime` | datetime string | Latest version before the given time. |

`noCache` (OPTIONAL, `#caching`) is also a resolution option. The default `false` allows caching of DID documents; `true` requests that caching is disabled and a fresh DID document is retrieved from the verifiable data registry. A resolver that denies resolution without caching MUST respond with a `FEATURE_NOT_SUPPORTED` error that makes clear that bypassing the cache was not permitted, so the client can resolve again without `noCache`. In did-go, caching belongs to the `resolution/cache` decorator, which wraps any resolver ([`14`](14-implementation-architecture.md) §5). By default it honours `noCache`: it bypasses the cache, passes `noCache` to the inner resolver, and replaces the cached result with the fresh one. With `cache.RefuseNoCache()` it denies the request instead and returns `FEATURE_NOT_SUPPORTED` with a detail (`cache.NoCacheRefusedDetail`) that says bypassing the cache is not permitted. Failed resolutions are never cached. `resolver.DefaultResolver`, which has no cache, honours `noCache` as it is and passes it to the driver in `method.ReadOptions.NoCache`.

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
6. expandRelativeUrls==true → iterate over services, VMs, verification relationships and extension-defined properties.
     If an item is an object whose id value is a relative DID URL, or a verification relationship entry is a relative DID URL,
     resolve it to an absolute DID URL by DID Core v1.0 §Relative DID URLs and update the document.
     These two cases are the only values the spec says to replace
7. success → didResolutionMetadata{contentType: representation media type}
        (the spec algorithm text puts it in didDocumentMetadata, which conflicts with §5 and the OpenAPI → caveat 4)
* unexpected error                     → INTERNAL_ERROR
```
> **Key point:** `deactivated` is **not an error**. It is signaled by `didDocumentMetadata.deactivated=true` (+ HTTP 410).

**Driver error mapping (did-go, `resolver.DefaultResolver`):** in step 5 the `method` errors a driver returns are mapped as follows. `method.ErrNotFound` is `NOT_FOUND`, `method.ErrNotSupported` (for example `versionId` on a method without versions) is `FEATURE_NOT_SUPPORTED`, `method.ErrInvalidDocument` (the document the driver obtained does not conform or its `id` is not the DID) is `INVALID_DID_DOCUMENT`, `method.ErrInvalidInput` (the DID does not follow the rules of its method) is `INVALID_DID`, and any other error is `INTERNAL_ERROR`. For example, the `did:web` driver returns HTTP 404 as `method.ErrNotFound` and 410 (Gone) as a deactivated DID (`deactivated: true`), not as an error ([`14`](14-implementation-architecture.md) §9.1).

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

**Outputs:** `dereferencingMetadata` (REQUIRED; contentType, error, proof), `contentStream` (on success, the resource: DID document, VM, service, or other), `contentMetadata` (didDocumentMetadata when the content is a DID document). `#did-url-content-metadata` defines no common properties for `contentMetadata`. In Go, the `DereferencingMetadata`, `ContentStream` and `ContentMetadata` fields of `DereferenceResult` correspond to the spec's `dereferencingMetadata`, `contentStream` and `contentMetadata` (`05` §6).
- If dereferencing is unsuccessful, `contentStream` MUST be empty and `contentMetadata` MUST be an empty metadata structure. DID Core v1.0 §7.2 has the same two rules. In Go, `ContentStream` is nil and `ContentMetadata` is a zero-value `DocumentMetadata` with no `Extra` entries, serialized as `{}`.
- If dereferencing is successful, `contentMetadata` MUST be a metadata structure, and it MAY be empty.
- If dereferencing is successful, the media type of `contentStream` SHOULD be expressed in `dereferencingMetadata.contentType`. The value MUST be an ASCII string. The HTTP binding uses this value to set `Content-Type` and to decide on 303 (§6, caveat 8), so did-go sets it on every successful dereference.

### 2.1 dereference algorithm (`#dereferencing-algorithm`)
**(a) Dereferencing the resource (`#dereferencing-algorithm-resource`)**
```
1. didUrl does not conform to syntax   → INVALID_DID_URL
2. call resolve(did). Dereferencing options + all DID parameters of the DID URL MUST be passed as resolution options
3. DID does not exist                  → NOT_FOUND
4. separate the fragment if present
5. no path and no query                → contentStream=DID document, contentMetadata=didDocumentMetadata
6. service/serviceType parameters:
     a. service→match id, serviceType→match type. If id or the service value is a relative reference,
        the absolute URIs MUST be resolved with RFC3986 §5 Reference Resolution and DID Core v1.0 §3.2.2
        Relative DID URLs (base=the DID document id) and used for the match
     b. if relativeRef is present:
        - for each selected service, look at serviceEndpoint. If it is a map, skip the service.
          If it is a string, add the value; if it is a set, add only its string items, to the list of selected endpoint URLs
        - replace each URL in the list with the RFC3986 §5 resolution of base=that URL, ref=relativeRef
     c. no accept / DID document representation → return the DID document with the service array reduced to the selected services
     d. accept==text/uri-list  → content=list of selected endpoint URLs,
                                  contentMetadata{contentType:text/uri-list}
                                  (303 in the HTTP binding; for the contentType location see caveat 8)
     e. otherwise               → REPRESENTATION_NOT_SUPPORTED
7. path/query only → dereferencing defined by the method, an extension or the client
8. cannot dereference                  → NOT_FOUND
```
The spec text of step 6a (`#dereferencing-algorithm-resource`) is: "If the id property or the service DID parameter or both contain relative references, the corresponding absolute URIs MUST be resolved and used for determining the match, using the rules specified in RFC3986 Section 5: Reference Resolution and in section Relative DID URLs in Decentralized Identifiers (DIDs) v1.0." The operation is RFC 3986 §5 reference resolution. It is not §6 normalization, so comparing normalized strings does not replace it. DID Core v1.0 §3.2.2 requires the RFC3986 §5 algorithm for resolving a relative DID URL (MUST) and makes the base URI the DID of the DID subject, so the base is the `id` of the DID document being resolved. The `relativeRef` of step 6b is a separate algorithm step: it replaces each selected service endpoint URL with the result of running the RFC3986 §5 algorithm with that URL as base ("The base URI value is the selected DID service endpoint URL. The relative reference is the value of the DID parameter relativeRef.").

Every error step (1, 3, 6e, 8) returns the error object in `dereferencingMetadata` together with `contentStream` = null (the step 6e text says `content: null`) and `contentMetadata` = «[ ]» (an empty map). The spec builds the list of selected endpoint URLs only inside step 6b, that is, only when `relativeRef` is present. It does not say how the list is built when step 6d is reached without `relativeRef`.
**(b) Dereferencing the fragment (`#dereferencing-algorithm-fragment`)**
```
1. DID document + verificationRelationship option → dereference the VM by fragment
     not a conforming VM     → an error MUST be raised,
                               and SHOULD convey the type INVALID_VERIFICATION_METHOD
                               (this includes the case where no id matches the fragment)
     relationship not linked → an error MUST be raised,
                               and SHOULD convey the type
                               INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD
2. selected service endpoint URL + fragment:
     endpoint already has a fragment → error (the spec does not specify a type)
     otherwise append the DID URL's fragment to the endpoint URL (inheritance)
3. otherwise → rules of the resource media type (application/did → JSON-LD fragment rules)
     no id matches the fragment and no verificationRelationship is given → NOT_FOUND
     (the spec specifies no type; did-go policy)
```

**Decisions of the did-go `dereferencer`:** where the spec leaves room, the `dereferencer` player behaves as follows.

- The dereferencing options and every DID parameter are passed as resolution options (step 2). `versionId` and `versionTime` become the options of the same name; the other parameters, `verificationRelationship` and the extension options go to `Extra`. `accept` is always passed unchanged, including `text/uri-list`. Use a separately constructed `resolver.ForDereferencing()` instance for intermediate document retrieval; the default direct resolver remains strict. This explicit instance may choose a real DID representation when a valid final-content preference matches none of the supported DID representations. It does not rewrite the original nested call or suppress an error. See [dereferencing options](dereferencing-options.md). When the resolver answers that it cannot produce a representation acceptable to accept (`resolution.NewAcceptNotSupported`), the dereferencing error is `REPRESENTATION_NOT_SUPPORTED`.
- The `service` parameter is matched against the service `id` after RFC 3986 §5 resolution with the DID as base (6a), and also as a fragment of the DID (`#` + value). DID Resolution Example 13 selects `#messages` with `service=messages`; this is did-go's interpretation of the example. With both `service` and `serviceType`, a service must match both.
- A query made only of `versionId` and `versionTime` dereferences to the resolved document, as for a DID URL without path and query (step 5), because those parameters are passed as resolution options and select that version (did-go interpretation).
- No selected service is `NOT_FOUND`. When `text/uri-list` is selected and no selected service has a string endpoint, the result is also `NOT_FOUND`. Both are did-go policy. Map endpoints are skipped, and when step 6d is reached without `relativeRef` the endpoint URLs are used unchanged.
- A selected endpoint URL that already has a fragment is `INVALID_DID_URL` ((b) step 2). The spec names no type; did-go chose it because the fragment of the DID URL cannot be applied.
- Media type of the content: a DID document is a `*document.Document` whose `contentType` is a representation checked with the producer. The `contentType` of fragment content (`vm.Method`, `vm.Service`, `document.Map`) is `application/ld+json` when the document representation is `application/did` or `application/did+ld+json`, and `application/json` for `application/did+json` (did-go interpretation). A URI list is a `[]string` with `contentType` `text/uri-list`.
- A DID that is deactivated during dereferencing is not an error. There is no content, and `contentMetadata` is the document metadata of the resolution result, with `deactivated: true`.
- A path or another query is handled by the handlers added with `dereferencer.WithResourceHandler`, in order (step 7), and is `NOT_FOUND` when no handler takes it (step 8).

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

**datetime format** (`#datetime`): every datetime value in this spec MUST be an ASCII string that is a valid XML datetime value as defined by the VC Data Model v2.0. Timestamps used in DID Resolution MUST also be adjusted to UTC without sub-second decimal precision, for example `2020-12-20T19:17:47Z`.
**`versionTime` input and output**: a `versionTime` value MUST use this datetime format (UTC, no sub-second precision, §3). When did-go serializes `ResolutionOptions.VersionTime`, it uses `spec.FormatTimestamp`, the function the `document.Metadata` marshaller uses (§5, §7), which converts to UTC and truncates to whole seconds. `did.DIDParameters` only parses DID URLs and is never serialized. On input, did-go checks the form and does not correct the value. A value with an offset other than `Z`, or with sub-second precision, is rejected: `INVALID_OPTIONS` when it comes as a resolution option, `INVALID_DID_URL` when it comes as a DID URL parameter. Rejecting instead of correcting is a did-go policy.
**query normalization**: decode unreserved octets and uppercase hex digits; do not decode reserved delimiters (`%26`/`%3D`). The spec does not cover duplicate parameter names. did-go's `DIDURL.Parameters()` reports a repeated name, a pair without `=` and an empty name as errors, and dereferencing returns them as `INVALID_DID_URL` (did-go policy).

---

## 4. Error catalog (§errors), RFC9457

`type` is a URL. Non-URL values MUST be prefixed with `https://www.w3.org/ns/did#`. `title` is short, `detail` is long. For `FEATURE_NOT_SUPPORTED`, `detail` SHOULD give a longer description of the feature the resolver does not support. A `noCache` denial also uses this type (§1).

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
| (type not in the table) | any other URI | Determined by the implementation. did-go uses the code of the type named by `Refines`, otherwise the error's own `Status`, and 500 if that is also absent (local policy) |

For a type not in the table, the spec says the status code "is determined by the implementation". Up to the CR Snapshot, 500 was required; this CRD changed that (Revision History). did-go's 500 is therefore a local policy, not a spec requirement. The binding fixes the code of a type that is in the table, so an extension cannot change it through `Status`.

`#errors` links `INVALID_DID_DOCUMENT` to §4.4 (`#resolving-algorithm`), but no algorithm step emits this type.

From CID (fragment dereferencing): `INVALID_VERIFICATION_METHOD`, `INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD`. The algorithm says an error MUST be raised and SHOULD convey these types. The error raised when a service endpoint already has a fragment has no specified type. did-go conveys these two CID errors with the type URLs CID defines (`https://w3id.org/security#INVALID_VERIFICATION_METHOD`, `https://w3id.org/security#INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD`, CID §3.5) and sets `Refines` to `https://www.w3.org/ns/did#INVALID_DID_URL`, so the HTTP binding returns them as 400. This refinement declaration is a did-go policy, not a spec requirement.
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

`created`, `updated` and `nextUpdate` all follow the datetime format of §3. DID Core v1.0 §7.1.3 also says `updated` and `nextUpdate` MUST follow the same formatting rules as `created`. The default JSON encoding of Go's `*time.Time` is RFC3339Nano, which can emit sub-second digits and a non-UTC offset, so `DocumentMetadata` has a custom marshaller that converts to UTC and truncates to whole seconds (§7).

**Metadata structure rules**: a map with string keys; values are string/number/map/list/set/boolean/null, and so are the values inside maps and lists. This rule is from DID Resolution v1.0 CRD. DID Core v1.0 does not allow number (for the v1.0 path see [`09`](09-v1.0-compat.md) §6). The entire metadata structure MUST be serializable according to the JSON serialization rules of INFRA. Non-integers and integers larger than 32 bits should be serialized as strings.

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
- **Remote binding and proxied resolution** (`#resolver-architectures`, `#resolver-architectures-proxied`, AT RISK): when `resolution/universal` calls another resolver over a remote binding, it SHOULD use a trusted resolver instance, ideally one the client controls itself (for example self-hosted), and SHOULD use a secure channel such as a VPN and/or TLS with mutual authentication. did-go does not hard-code an upstream resolver address; the caller configures it. When it returns a result from an upstream resolver, `resolution/universal` is the downstream resolver, so it SHOULD pass through all upstream DID resolution metadata and DID document metadata transparently, including any proofs, and MAY add its own resolution metadata about the proxied resolution process. If the 12 §6.2 transcoding changes the `contentType` of the returned bytes, the upstream bytes and media type are kept in `Source`.

---

## 7. Go mapping (replaces `05-go-design.md` §6)

```go
package resolution

// The media type strings live in spec: spec.MediaTypeDID, spec.MediaTypeDIDResolution ("application/did-resolution"),
// spec.MediaTypeDIDURLDereferencing ("application/did-url-dereferencing"), spec.MediaTypeURIList ("text/uri-list").

// Error is an RFC9457 Problem Details object.
type Error struct {
    Type     string `json:"type"`              // "https://www.w3.org/ns/did#NOT_FOUND"
    Title    string `json:"title,omitempty"`
    Status   int    `json:"status,omitempty"`  // HTTP mapping
    Detail   string `json:"detail,omitempty"`
    Instance string `json:"instance,omitempty"`
    // Refines is the type URI from the §4 table that this type refines (§errors refinement rule).
    // Leave it empty for a type that is in the table. Bindings use it to choose the status code.
    Refines  string `json:"-"`
}

// Error type URI prefixes (§4)
const (
    NamespaceDID      = "https://www.w3.org/ns/did#"
    NamespaceSecurity = "https://w3id.org/security#" // prefix of the CID §3.5 error types
)

// Code names an error type. There are no shared mutable sentinels; an error is created at each use with NewError (14 §4).
type Code string
const (
    CodeInvalidDID                 Code = "INVALID_DID"
    CodeInvalidDIDURL              Code = "INVALID_DID_URL"
    CodeInvalidOptions             Code = "INVALID_OPTIONS"
    CodeNotFound                   Code = "NOT_FOUND"
    CodeRepresentationNotSupported Code = "REPRESENTATION_NOT_SUPPORTED"
    CodeInvalidDIDDocument         Code = "INVALID_DID_DOCUMENT"
    CodeMethodNotSupported         Code = "METHOD_NOT_SUPPORTED"
    CodeFeatureNotSupported        Code = "FEATURE_NOT_SUPPORTED"
    CodeInternalError              Code = "INTERNAL_ERROR"
    // CID-derived errors of fragment dereferencing (§2.1(b), §4). The type is the URL that CID defines (NamespaceSecurity + code).
    CodeInvalidVerificationMethod                = Code(document.CodeInvalidVerificationMethod)
    CodeInvalidRelationshipForVerificationMethod = Code(document.CodeInvalidRelationshipForVerificationMethod)
    // Other CID codes: CodeInvalidVerificationMethodURL, CodeInvalidControlledIdentifierDocument, CodeInvalidControlledIdentifierDocumentID
)

// NewError returns a new error whose type is code. It fills the title and the status of a binding table type.
// A CID error points to INVALID_DID_URL with Refines, so the HTTP binding uses 400 (did-go policy).
// A FEATURE_NOT_SUPPORTED error without detail gets one that says a requested feature is not supported (§4 SHOULD).
func NewError(code Code, detail string) *Error

// NewAcceptNotSupported is used when no representation matching accept can be produced (12 §6.2 step 4). Its type is FEATURE_NOT_SUPPORTED;
// IsAcceptNotSupported recognizes it, so the v1.0 adapter maps it to "representationNotSupported" (09 §6).
func NewAcceptNotSupported(accept string) *Error
func (e *Error) IsAcceptNotSupported() bool
func (e *Error) Is(target error) bool // true for the same type

type ResolutionOptions struct {
    Accept             string
    ExpandRelativeURLs bool
    VersionID          string
    VersionTime        *time.Time
    NoCache            bool
    Extra              map[string]any
}
// MarshalJSON/UnmarshalJSON read and write Extra entries as top-level members

type DereferenceOptions struct {
    Accept                   string
    VerificationRelationship string
    Extra                    map[string]any
}
// MarshalJSON/UnmarshalJSON read and write Extra entries as top-level members

type ResolutionMetadata struct {
    ContentType string
    Error       *Error
    Proof       []map[string]any
    Extra       map[string]any
}
// MarshalJSON/UnmarshalJSON read and write Extra entries as top-level members

// DocumentMetadata is the didDocumentMetadata. Its only definition is document.Metadata below;
// here an alias only carries the name. Method drivers fill the same type, so it is passed on without conversion.
type DocumentMetadata = document.Metadata

// The DID parameters (§3) live in package did: DIDURL.Parameters() parses them into did.DIDParameters,
// and the dereferencer passes them as resolve options (§2.1). Extension parameters are read with Get(name) and Names().
//   type DIDParameters struct {
//       Service, ServiceType, RelativeRef, VersionID, HL string
//       VersionTime time.Time // zero when absent
//   }

// Result is «didResolutionMetadata, didDocument, didDocumentMetadata» plus
// the bytes returned (Raw), the detection result (Info) and the pre-transcoding original (Source) (12 §6.2).
type Result struct {
    Document           *document.Document
    Raw                []byte                     // bytes returned to the caller; representation is ResolutionMetadata.ContentType
    Info               representation.ConsumeInfo // detection result from consuming the driver bytes
    Source             *SourceBytes               // set only when the core produced the returned bytes (transcoding or expandRelativeUrls)
    ResolutionMetadata ResolutionMetadata
    DocumentMetadata   DocumentMetadata
}

// SourceBytes holds the bytes the driver originally returned and their media type.
type SourceBytes struct {
    Data        []byte
    ContentType string
}

type Resolver interface {
    Resolve(ctx context.Context, did did.DID, opts ResolutionOptions) Result
}

type Dereferencer interface {
    Dereference(ctx context.Context, u did.DIDURL, opts DereferenceOptions) DereferenceResult // fields: 05 §6
}

// bindingStatus looks up the #bindings-https status code table by type URL; false when the type is not in it.
// INVALID_DID, INVALID_DID_URL, INVALID_OPTIONS 400, NOT_FOUND 404, REPRESENTATION_NOT_SUPPORTED 406,
// INVALID_DID_DOCUMENT 500, METHOD_NOT_SUPPORTED 501, FEATURE_NOT_SUPPORTED 501, INTERNAL_ERROR 500
func bindingStatus(typeURL string) (int, bool)

// HTTP status mapping. The code fixed by the binding table comes first, and an extension cannot change it.
// The spec leaves the code for a type not in the table to the implementation. did-go uses the code of
// the type named by Refines, then the error's own Status, then 500 (local policy).
func (e *Error) HTTPStatus() int {
    if e == nil { return 500 }
    if s, ok := bindingStatus(e.Type); ok { return s }
    if s, ok := bindingStatus(e.Refines); ok { return s }
    if e.Status != 0 { return e.Status }
    return 500
}
```

The Go type for `didDocumentMetadata` is defined once, in package `document`. Both `method` and `resolution` import `document`, so the resolver can return the value a driver filled in without conversion. `method` does not import `resolution`, so there is no import cycle. A driver can set every property in the §5 table.

```go
package document // metadata.go

// Metadata is the didDocumentMetadata of DID Resolution §4.3 (§5 table).
// A custom MarshalJSON converts Created, Updated and NextUpdate to UTC,
// truncates them to whole seconds and writes them as "2020-12-20T19:17:47Z" (§3, §5).
type Metadata struct {
    Created       *time.Time       `json:"created,omitempty"`
    Updated       *time.Time       `json:"updated,omitempty"`
    Deactivated   bool             `json:"deactivated,omitempty"`
    NextUpdate    *time.Time       `json:"nextUpdate,omitempty"`
    VersionID     string           `json:"versionId,omitempty"`
    NextVersionID string           `json:"nextVersionId,omitempty"`
    EquivalentID  []string         `json:"equivalentId,omitempty"`
    CanonicalID   string           `json:"canonicalId,omitempty"`
    Proof         []map[string]any `json:"proof,omitempty"`
    Extra         map[string]any   `json:"-"` // properties not listed above (extensions)
}
```

**Core implementation rules (to be covered by tests):**
1. The `resolve`/`dereference` signatures do not change (conforming path).
2. `error` is an RFC9457 object. Its `type` is `https://www.w3.org/ns/did#<CODE>` for DID Resolution errors and `https://w3id.org/security#<NAME>` for CID-derived errors (§4).
3. `deactivated` is not an error → metadata + HTTP 410.
4. When dereferencing, pass DID parameters as resolve options.
5. Service endpoint URL = RFC3986 §5 (base=endpoint, ref=relativeRef) + fragment inheritance. Reject if the endpoint already has a fragment.
6. HTTP: GET is required, `accept`=Accept header, other options go in the query or body. Follow the status code mapping. The `Content-Type` of a 200 response must equal the `contentType` in the metadata.
7. `text/uri-list` dereferencing → 303. `Location` is the selected service endpoint URL and the body is empty. Write `contentType` into both `dereferencingMetadata` and `contentMetadata`, and accept it from either on input (caveat 8).
8. The HTTP status is looked up first in the binding table by `Type`. If the type is not in the table, the table code of the type named by `Refines` is used, then the error's `Status`, and finally 500. An extension cannot change a code the table fixes. The steps from `Refines` on are did-go local policy.
9. On the resolve path the core always consumes the driver bytes with the driver's `ContentType` and runs standard validation. A failure is `INVALID_DID_DOCUMENT`. If the driver labeled the bytes with a DID media type, that type decides the representation, and bytes that do not conform to it are `INVALID_DID_DOCUMENT`. If the driver used a low-precision type, the payload decides the representation. `accept` is matched with RFC 9110 rules, and the core transcodes when needed. The result `contentType` is the media type of the bytes actually returned in `Result.Raw`, because the spec defines `contentType` as the media type of the returned `didDocument` and the caller MUST use it to parse (§5). So when the driver bytes are returned it is the DID media type the driver labeled them with, or, for a low-precision label, the precise DID media type of the detected representation. When the core transcoded, it is the DID media type of the representation the core produced. If no acceptable representation can be produced, the result is `FEATURE_NOT_SUPPORTED` ([`12`](12-standard-core-and-sage-extension.md) §6.2).
