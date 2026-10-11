# DID Core v1.0/v1.1: Feature Definition

> SAGE-specific behavior is not part of this feature set; it is an opt-in advanced extension defined in [`12-standard-core-and-sage-extension.md`](12-standard-core-and-sage-extension.md).

> Target spec: W3C *Decentralized Identifiers (DIDs) v1.1* (`did/index.html` @ `w3c/did@13626ba6aac9`, see [README provenance](README.md#provenance)), DID JSON-LD Context `https://www.w3.org/ns/did/v1.1` (embedded as `assets/did-v1.1.jsonld`), Vocabulary (`did/vocab/vocabulary.yml`)
> **Plus simultaneous support for DID Core v1.0 REC (2022-07-19).** The canonical source for the v1.0 normative comparison and compatibility design is [`09-v1.0-compat.md`](09-v1.0-compat.md).
> Implementation language: Go 1.26.8 toolchain, language version `go 1.26.0` (module `github.com/sage-x-project/did-go`, [`12`](12-standard-core-and-sage-extension.md) §3)
> Purpose: define the **feature scope, boundaries and acceptance criteria** of a library/service that satisfies all normative requirements of the `did/` folder.

---

## 1. Spec Summary and Design Premises

DID Core v1.1 was heavily refactored from the v1.0 REC. Three core facts determine the **scope** of this implementation.

| # | Fact | Design impact |
|---|------|---------------|
| A | **The Resolution / Dereferencing algorithms are not in this document.** They are delegated to the separate `[[DID-RESOLUTION]]` spec. This document only defines terms and *the obligations a method must define*. | The core provides the `resolve()`/`dereference()` **contract**. The settled contract (options, metadata, **RFC9457 errors**, DID parameters, HTTP binding) is in [`07-did-resolution-contract.md`](07-did-resolution-contract.md). |
| B | **The data model for VM/Service/Relationship is delegated to `[[CID]]` (Controlled Identifier Document 1.0).** A DID document is defined as "an extension of a CID document" and adds only DID-specific *constraints*. | VM/Service structs follow the CID model, and the validation layer enforces the DID constraints that `id` must be a DID URL and `controller` must be a DID. The settled normative rules are in [`06-cid-data-model.md`](06-cid-data-model.md). |
| C | **Media types are unified.** v1.0's `application/did+ld+json` and `application/did+json` do not exist in v1.1. There is a single core media type, **`application/did`**. JSON and JSON-LD are *the same representation*, distinguished only by the presence of `@context`. | Producers/consumers default to `application/did` for v1.1. **For dual-version support, the two v1.0 legacy types are also accepted on consumption and selectable on production** (FR-V2/V3, `09`). |
| D | **Simultaneous v1.0 REC support.** The v1.1 data model is a **superset** of v1.0 (same syntax, added properties, `service.id` relaxed from required to optional). The only divergences are in three places: (1) the serialization envelope (`@context` URL, media type), (2) the Resolution contract (`resolveRepresentation`, string errors), (3) DID parameters (`hl` vs `serviceType`). | **Single v1.1 superset core plus version adapters** strategy (`09` §1). Splitting the implementation in two is forbidden. FR-V1 to V5. **Conformance-level caution**: V10 output is a v1.0 conformance artifact, not a v1.1 conforming production (a v1.1 producer MUST use `application/did`). |

**Resulting implementation targets.** §conformance defines **5 conformance entities** (conforming DID / DID document / producer / consumer / DID method). Below they are grouped into 4 implementation deliverables (producer and consumer combined):
1. **Conforming DID**: DID/DID URL parser and validator matching the ABNF
2. **Conforming DID Document**: INFRA-style typed data model plus deterministic, bidirectional, lossless serialization
3. **Conforming Producer / Consumer**: production/consumption of the `application/did` JSON representation, JSON-LD compatible (two separate entities in the spec)
4. **Conforming DID Method**: CRUD operations and the method interface (plugin)

---

## 2. Functional Requirements

Each feature is identified as `FR-x` and has a normative basis (spec line/section) and acceptance criteria.

### 2.1 DID / DID URL Syntax

| ID | Feature | Normative basis | Acceptance criteria |
|----|---------|-----------------|---------------------|
| FR-S1 | Parse DID string (`did:method:msid`) | §DID Syntax ABNF | `method-name` allows only `%x61-7A` (lowercase) and DIGIT. `idchar` = ALPHA/DIGIT/`.`/`-`/`_`/pct-encoded. Any other character fails parsing. |
| FR-S2 | Parse DID URL (`did path ["?"query] ["#"frag]`) | §DID URL Syntax ABNF (RFC3986 path-abempty/query/fragment) | Split path/query/fragment; each component conforms to RFC3986. `;` (semicolon) is reserved for future use: warning. |
| FR-S3 | Resolve relative DID URLs | §Relative DID URLs | base = DID (subject id); make absolute using the RFC3986 §5 Reference Resolution algorithm. Example: `#key-1` becomes `did:example:123#key-1`. |
| FR-S4 | Percent-encoding handling | §DID Syntax | Encode/decode `%HEXDIG HEXDIG`. Octets outside `idchar` must be encoded. |
| FR-S5 | Syntax validation and normalization | §Method Syntax | Provide a hook so methods can define a more restrictive ABNF/normalization. A DID must be globally unique (method responsibility). |
| FR-S6 | Identifier restriction validation | §Identifier Restrictions | Subject/controller identifiers cannot have a query or fragment (pure `did` ABNF). Only VM/service ids allow DID URLs. |

### 2.2 DID Document Data Model

| ID | Feature | Normative basis | Acceptance criteria |
|----|---------|-----------------|---------------------|
| FR-D1 | Core property representation | §Core Properties | `id` (required, DID), `controller` (string\|set), `alsoKnownAs` (set), `service` (set), `verificationMethod` (set), 5 verification relationships. |
| FR-D2 | INFRA type system | §Data Model | map/list/set/datetime/string/integer/double/boolean/null. Map keys are strings, no duplicates. Sets have no duplicates. |
| FR-D3 | Verification Method model | §Verification Method, CID §2.2 | Required: `id` (DID URL), `type`, `controller` (DID). Key: `publicKeyMultibase` and `publicKeyJwk` are each optional and chosen by `type`. At most one material property per material (both forbidden, DID Core 1.0 §5.2.1, CID §2.2.1). A VM without public key material is conforming but cannot verify proofs. `publicKeyMultibase` is a Multibase string for any type. Additional properties are kept in `Extra`. |
| FR-D4 | Verification Relationship (embedded/referenced) | §Verification Relationships, CID §2.3 | Each element is a DID URL string (reference) or a VM map (embedded). 5 kinds: authentication, assertionMethod, keyAgreement, capabilityInvocation, capabilityDelegation. |
| FR-D5 | Service model | §Services, CID §2.1.4 | **Required: `type` (string\|set), `serviceEndpoint` (string\|map\|set)**. `id` (URL\|DID) is **optional** (if present, no duplicates within the document). A string endpoint must be a valid URL. v1.0 profile: `id` required (RFC 3986 URI, any scheme), endpoint strings are URIs normalized per RFC 3986 §6 and their scheme rules. Additional properties are kept in `Extra` (MAY). |
| FR-D6 | Equivalence properties | §Equivalence Properties (DID Core, Security) / didDocumentMetadata (DID-Resolution) | `equivalentId`, `canonicalId` (method-generated, same trust as the resolved `id`). **The format definition exists only in DID-Resolution didDocumentMetadata**, so the implementation places them in `resolution.DocumentMetadata` (cross-spec tension, `08` §2). `alsoKnownAs` is not trusted equivalence. |
| FR-D7 | Entry classification and preservation | §Production/Consumption consumer rules 3 and 4 | **Two buckets**: (rule 3) *known* representation-specific entries such as `@context` go to the representation-specific-entries map; (rule 4) *unrecognized* non-representation-specific properties are added as **extension properties of the data model**. Unrecognized entries are not put into the representation-specific map. |

### 2.3 Representations (Production/Consumption)

| ID | Feature | Normative basis | Acceptance criteria |
|----|---------|-----------------|---------------------|
| FR-R1 | JSON producer | §JSON | Include all entries in the root JSON Object. datetime is UTC `Z` with no sub-seconds (`2020-12-20T19:17:47Z`). Return media type `application/did`. |
| FR-R2 | JSON consumer | §JSON | Error if the root is not a JSON Object. Consuming a non-conforming DID/document must produce an error. |
| FR-R3 | JSON-LD processing | §JSON-LD | The `@context` value is the string `https://www.w3.org/ns/did/v1.1` or an array whose first element is that string. Undefined terms: producer SHOULD NOT generate / consumer SHOULD drop. |
| FR-R4 | Deterministic, bidirectional, lossless serialization | §conforming DID document | Same data model yields the same serialization; round-trip is lossless. |
| FR-R5 | Media type handling | §Media Types / IANA | `application/did` (extension `.did`). The declared DID media type decides the representation. Only for low-precision types (`application/json`, `application/ld+json`) is the payload inspected (DID 1.1 §6.3.1, informative). Rules in `09` §4. |
| FR-R6 | Base context integrity | §Remote Resource Integrity | Treat `https://www.w3.org/ns/did/v1.1` as "already retrieved" and verify it against a pinned SHA-256 value. Embedded handling. |

### 2.4 DID Method Interface

| ID | Feature | Normative basis | Acceptance criteria |
|----|---------|-----------------|---------------------|
| FR-M1 | Create operation | §Method Operations | Controller creates a DID plus DID document. Authorization procedure specified. |
| FR-M2 | Read/Resolve operation | §Method Operations | DID to DID document. Includes how to verify response authenticity. |
| FR-M3 | Update operation | §Method Operations | Define what an update is and how to do it, *or* state that it is not possible. |
| FR-M4 | Deactivate operation | §Method Operations | Define how to deactivate, *or* state that it is not possible. |
| FR-M5 | Authorization | §Method Operations | Define authorization and cryptographic procedures for every operation. Choose among `controller`/`authentication`/`capabilityInvocation`/out-of-band. |
| FR-M6 | Method registry | §Method Syntax | Register/look up method-name to Method implementation. Single method-name, msid normalization rules. |

### 2.5 Resolution / Dereferencing Contract (settled by DID-Resolution; details in [`07`](07-did-resolution-contract.md))

| ID | Feature | Normative basis | Acceptance criteria |
|----|---------|-----------------|---------------------|
| FR-X1 | Resolver interface | DID-Resolution §Resolving | `resolve(did, resolutionOptions) → (didResolutionMetadata, didDocument, didDocumentMetadata)`. Signature is fixed. There is **no** `resolveRepresentation()` (merged into the accept option). |
| FR-X2 | Options and DID parameters | §DID Parameters, §Resolution Options | `accept`/`expandRelativeUrls`/`versionId`/`versionTime`; DID parameters `service`/`serviceType`/`relativeRef`/`versionId`/`versionTime`. When dereferencing, pass parameters as resolve options. |
| FR-X3 | Dereferencer interface | §Dereferencing (AT RISK) | `dereference(didUrl, {accept, verificationRelationship}) → (dereferencingMetadata, contentStream, contentMetadata)`. Fragment/service endpoint URL composition (RFC3986 §5 plus fragment inheritance). |
| FR-X4 | RFC9457 errors and metadata | §Errors, §Metadata | Errors are **RFC9457 Problem Details**, `type` = `https://www.w3.org/ns/did#<CODE>`: `INVALID_DID` (400) / `INVALID_DID_URL` (400) / `INVALID_OPTIONS` (400) / `NOT_FOUND` (404) / `REPRESENTATION_NOT_SUPPORTED` (406) / `INVALID_DID_DOCUMENT` (500) / `METHOD_NOT_SUPPORTED` (501) / `FEATURE_NOT_SUPPORTED` (501) / `INTERNAL_ERROR` (500). CID-derived errors of fragment dereferencing use `type` = `https://w3id.org/security#<NAME>` (`07` §4). **`deactivated` is not an error**: it is `didDocumentMetadata.deactivated=true` plus HTTP 410. |
| FR-X5 | HTTP binding | §Bindings-HTTPS + OpenAPI | `GET /1.0/identifiers/{id}` (required), media types `application/did`, `application/did-resolution`, `application/did-url-dereferencing`, status code mapping, `text/uri-list` to 303 plus Location. |

> **Boundary principle:** the core provides stable interfaces, data structures and thin orchestration (`DefaultResolver`). Details specific to the DID-Resolution draft (option negotiation, caching, HTTP) are isolated in the `resolution/universal` adapter (DID Resolution v1.0, W3C Candidate Recommendation Draft, 2026-10-01; some features AT RISK).

### 2.6 Version Compatibility (v1.0 + v1.1; details in [`09`](09-v1.0-compat.md))

| ID | Feature | Normative basis | Acceptance criteria |
|----|---------|-----------------|---------------------|
| FR-V1 | Version detection | v1.0 REC §6.2/§6.3, v1.1 §JSON-LD | A declared DID media type decides the representation and the version (§6.1 MUST in v1.0 and v1.1). `did+json` gives V10 JSON, `did+ld+json` gives V10 JSON-LD (first `@context` value `…/did/v1` required), and `application/did` gives V11 (if `@context` is present, first value `…/did/v1.1`). For `did+ld+json` and `application/did`, a `@context` that does not fit the type is an error. For `did+json`, a present `@context` is kept as a representation-specific entry, and if its first value is not `…/did/v1` it is recorded in `ConsumeInfo.UnexpectedContext`. No spec statement makes such a document non-conforming, so it is not an error; only Strict makes it one. For a low-precision type (`application/json`, `application/ld+json`), the payload's `@context[0]` decides; without it, the expected version is used, or else VUnknown (processed with v1.1 rules). The received low-precision type and whether the version was assumed are recorded in `ConsumeInfo`. Any other media type, or none, is an error. The rules are defined in `09` §4. |
| FR-V2 | Dual consumption | Same as above | Accept all 3 media types and **normalize into a single core Document (v1.1 superset)**. The detection result is reported as `ConsumeInfo.DetectedVersion`. |
| FR-V3 | Version-parameterized production | v1.0 §5.4/§6.3.1 | `Options.SpecVersion` selects the `@context` URL and media type (`09` §5 table). **When producing V10, `service.id` is enforced as required**; properties undefined in v1.0 produce a warning (WarnDownlevel). |
| FR-V4 | v1.0 Resolution adapter | v1.0 §7.1/§7.2 | `resolution/compat.V10Resolver`: provides `resolveRepresentation()`, maps RFC9457 to string errors (`09` §6.1), `contentType` only on **successful** resolveRepresentation (REQUIRED if successful; in resolve it is §7.1.2 MUST NOT), the `accept` option is also MUST NOT for resolve (§7.1.1: ignore and warn), accept `hl`, reject `serviceType`. |
| FR-V5 | Dual context integrity | v1.1 §Remote Resource Integrity (policy applied to v1 too); v1.0 §9.15 Content Integrity Protection (informative) recommends the same practice | Embed both the `…/did/v1` and `…/did/v1.1` contexts with pinned SHA-256; remote fetch is forbidden. |

### 2.7 Security & Privacy

| ID | Feature | Normative basis | Acceptance criteria |
|----|---------|-----------------|---------------------|
| FR-P1 | Integrity protection and update authentication | §Security Requirements | Provide integrity protection and update authentication for every method operation (method implementation contract). |
| FR-P2 | Threat documentation hook | §Security Requirements | Provide interface comments/checklist so methods document countermeasures for eavesdropping/replay/insertion/deletion/modification/DoS/amplification/MITM. |
| FR-P3 | Secret data labeling | §Security Requirements | Secret material such as `secretKeyMultibase`/`secretKeyJwk` is excluded from serialization by default; explicit opt-in. |
| FR-P4 | Privacy correlation prevention | §Privacy Requirements (normative: MUST discuss the relevant RFC6973 §5 subsections); multiple DIDs/selective disclosure are in §Privacy Considerations (informative) | Support multiple DIDs/selective disclosure. Minimize identifier correlation in logging. |
| FR-P5 | Equivalence substitution prevention | §Equivalence Properties | Guidance forbidding trust in `equivalentId`/`canonicalId` after verification without re-verification. |

---

## 3. Non-Functional Requirements

| ID | Item | Criterion |
|----|------|-----------|
| NFR-1 | Determinism | Producer output is deterministic (ordering rules specified). Round-trip is lossless. |
| NFR-2 | Extensibility | New VM types/service types/methods/representations can be registered (registry) without code changes. |
| NFR-3 | Dependency-free core | The core parser and data model use only the standard library (crypto and network are in the adapter layer). |
| NFR-4 | Error clarity | Every non-conforming input is returned as a typed error (cause and location). No panics. |
| NFR-5 | Thread safety | Registries and resolvers are safe for concurrent calls (read-heavy). |
| NFR-6 | Test conformance | Each FR is verified by table-driven conformance tests in the style of the W3C DID Test Suite. |

---

## 4. Out of Scope

- **Ledger/network implementations** of specific DID methods (did:web, did:key, did:ethr, etc.). Only the interface is provided; reference implementations are example-level (did:key, did:web).
- The **algorithm body** of the DID-RESOLUTION spec (option and metadata details). Only interfaces and extension points.
- The **cryptographic suite details** of the CID spec (Multikey/JWK byte encoding standards). Delegated to adapters.
- Higher-level protocols such as Verifiable Credentials / DIDComm.

---

## 5. Traceability

| Document | Content |
|----------|---------|
| `01-use-cases.md` | Actors and use cases (UC); each UC references FRs |
| `02-sequence-diagrams.md` | Sequence diagrams of the main flows |
| `03-component-diagram.md` | Component/package structure |
| `04-state-diagrams.md` | DID lifecycle and document processing states |
| `05-go-design.md` | Go package, type and interface design |
| `06-cid-data-model.md` | CID 1.0 data model rules plus Go mapping (VM/Service/Relationship, Multikey/JWK) |
| `07-did-resolution-contract.md` | DID-Resolution contract plus Go mapping (options, RFC9457 errors, DID parameters, HTTP) |
| `09-v1.0-compat.md` | v1.0 REC normative comparison plus dual-version compatibility design (detection, profiles, compat adapter); canonical for FR-V |

The traceability matrix linking each FR to UC, sequence and Go type is in `05-go-design.md` §9. The canonical settled rules of the delegated specs (CID/DID-Resolution) are in `06` and `07`.
