# DID Core v1.0/v1.1: Sequence Diagrams

> Each sequence corresponds to a use case in `01-use-cases.md`. The diagrams are written in Mermaid and render on GitHub and in compatible viewers.

---

## 1. Parse and validate a DID (UC-1)

```mermaid
sequenceDiagram
    autonumber
    actor Dev as App Developer
    participant P as did.Parse
    participant ABNF as syntax (ABNF validator)

    Dev->>P: Parse("did:example:123/path?versionId=1#key-1")
    P->>ABNF: validate scheme "did:"
    ABNF-->>P: ok
    P->>ABNF: validate method-name (lowercase+digit)
    ABNF-->>P: "example"
    P->>ABNF: validate method-specific-id (idchar / pct-encoded)
    ABNF-->>P: "123"
    P->>ABNF: split & validate path / query / fragment (RFC3986)
    alt syntax violation
        ABNF-->>P: error(pos)
        P-->>Dev: nil, ErrInvalidSyntax(pos)
    else valid
        ABNF-->>P: components
        P-->>Dev: DIDURL{DID, Path, Query, Fragment}
    end
```

---

## 2. Build and validate a DID document (UC-2)

```mermaid
sequenceDiagram
    autonumber
    actor Dev as App Developer
    participant B as document.Builder

    Dev->>B: NewBuilder(did)
    Dev->>B: VerificationMethod(m)
    Dev->>B: Service(svc)
    Dev->>B: Relationship(authentication, vm.Ref("#key-1"))  %% by reference
    Dev->>B: Build()
    B->>B: check vm.id is a DID URL and controller is a DID
    B->>B: at most one public key material property, at most one secret key material property (type decides material, no public key material means no proof verification)
    B->>B: check document id required, serviceEndpoint URL validity, sets unique (Build does not require service.id)
    alt a rule is violated
        B-->>Dev: *document.ConformanceError (vm check errors are converted to it, keeping the statement id)
    else ok
        B-->>Dev: Document (immutable)
    end
```

---

## 3. Produce a representation (UC-3)

```mermaid
sequenceDiagram
    autonumber
    actor Dev
    participant Prod as representation.Producer
    participant JSON as json encoder
    participant LD as jsonld rules

    Dev->>Prod: Produce(doc, opts{Version, JSONLD:true, IncludeSecret:false})
    Prod->>Prod: assert doc is conforming (else refuse)
    opt Version == spec.V10
        Prod->>Prod: document.Validate(d, spec.V10) check. service.id required, warn on undefined properties and types (09 §5)
    end
    Prod->>Prod: drop secretKey* unless IncludeSecret
    alt JSON-LD
        Prod->>LD: ensure @context[0] == version URL (V11 ".../did/v1.1" / V10 ".../did/v1")
        LD-->>Prod: @context injected
    end
    Prod->>JSON: encode (map→Object, set→Array, datetime→UTC "Z")
    JSON-->>Prod: bytes
    Prod-->>Dev: (bytes, mediaType)  %% V11: application/did / V10: did+ld+json|did+json
```

---

## 4. Consume a representation (UC-4)

```mermaid
sequenceDiagram
    autonumber
    actor Verifier
    participant Cons as representation.Consumer
    participant JSON as json decoder

    Verifier->>Cons: Consume(bytes, mediaType)  %% application/did | did+json | did+ld+json
    Cons->>Cons: select the representation from the declared media type. Any other type, or none, is an error (09 §4)
    Cons->>JSON: decode root
    alt root is not a JSON Object
        JSON-->>Cons: not object
        Cons-->>Verifier: *consumer.Error
    else
        JSON-->>Cons: object
        Cons->>Cons: settle version: the DID media type decides (did+json, did+ld+json→V10, did→V11). For did+ld+json and did, a @context that does not fit the type is an error. A non-v1 @context on did+json is recorded in UnexpectedContext (error under Strict). Low-precision→@context[0], else Expected or VUnknown (09 §4 steps 1 to 5)
        Cons->>Cons: map JSON types → data model (normalize into the single v1.1 superset model)
        Cons->>Cons: known repr-specific (@context etc.) → representation-specific-entries (rule 3)
        Cons->>Cons: unrecognized non-repr entries → data-model extension properties (rule 4)
        opt @context present
            Cons->>Cons: JSON-LD: drop undefined terms (against the context of the detected version)
        end
        Cons->>Cons: validate conformance
        Cons-->>Verifier: Document + ConsumeInfo{DetectedVersion, LowPrecision, Assumed, UnexpectedContext}
    end
```

---

## 5. Resolve a DID (UC-5)

```mermaid
sequenceDiagram
    autonumber
    actor Verifier
    participant R as resolver.DefaultResolver
    participant Reg as method.Registry
    participant M as Method(example)
    participant VDR as Verifiable Data Registry
    participant Cons as representation.Consumer

    Verifier->>R: ResolveString(did, resolutionOptions)  %% Resolve takes a parsed did.DID
    R->>R: did.Parse(did)  %% UC-1
    alt invalid syntax
        R-->>Verifier: null, meta{error.type=…#INVALID_DID}, {}
    else
        R->>Reg: Lookup(method-name)
        alt not registered
            Reg-->>R: nil
            R-->>Verifier: null, meta{error.type=…#METHOD_NOT_SUPPORTED}, {}
        else
            Reg-->>R: Method
            R->>R: check options (07 §1.1 steps 3 and 4)
            alt unsupported option
                R-->>Verifier: null, meta{error.type=…#FEATURE_NOT_SUPPORTED}, {}
            else invalid option
                R-->>Verifier: null, meta{error.type=…#INVALID_OPTIONS}, {}
            else options supported and valid
                R->>M: Read(did, options)
                M->>VDR: fetch state
                VDR-->>M: raw record
                M->>M: verify authenticity of response
                alt not found
                    M-->>R: ErrNotFound
                    R-->>Verifier: null, meta{error.type=…#NOT_FOUND}, {}
                else driver does not support an option (for example versionTime)
                    M-->>R: ErrNotSupported
                    R-->>Verifier: null, meta{error.type=…#FEATURE_NOT_SUPPORTED}, {}
                else driver obtained an invalid document
                    M-->>R: ErrInvalidDocument
                    R-->>Verifier: null, meta{error.type=…#INVALID_DID_DOCUMENT}, {}
                else the DID does not conform to its method
                    M-->>R: ErrInvalidInput
                    R-->>Verifier: null, meta{error.type=…#INVALID_DID}, {}
                else other driver error
                    M-->>R: error
                    R-->>Verifier: null, meta{error.type=…#INTERNAL_ERROR}, {}
                else driver metadata violation (checked before deactivated, 12 §6.2)
                    M-->>R: ReadResult{Metadata (equivalentId etc. violate the DID Resolution §4.3 constraints)}
                    R-->>Verifier: null, meta{error.type=…#INVALID_DID_DOCUMENT}, {}
                else deactivated (not an error)
                    M-->>R: ReadResult{Metadata{deactivated:true}}
                    R-->>Verifier: null, meta{}, docMeta{deactivated:true}
                else ok
                    M-->>R: ReadResult{Data, ContentType, Metadata{versionId,updated}}
                    R->>Cons: Consume(Data, ContentType)
                    Cons-->>R: Document + ConsumeInfo (INVALID_DID_DOCUMENT on failure)
                    R->>R: accept negotiation, transcode if needed. contentType is the media type of the bytes returned in Raw: for driver bytes the driver's DID media type (for low-precision, the precise type of the detected representation), after transcoding the produced type (12 §6.2)
                    alt no acceptable representation can be produced (resolution.NewAcceptNotSupported)
                        R-->>Verifier: null, meta{error.type=…#FEATURE_NOT_SUPPORTED}, {}
                    else
                        R-->>Verifier: Result{doc, Raw, Info, Source, resolutionMeta{contentType}, docMeta}
                    end
                end
            end
        end
    end
```

---

## 6. Dereference a DID URL (UC-6)

```mermaid
sequenceDiagram
    autonumber
    actor Verifier
    participant DR as resolution.Dereferencer
    participant R as resolution.Resolver
    participant Sel as document.Selector

    Verifier->>DR: Dereference("did:example:123#key-1", {accept, verificationRelationship})
    DR->>DR: split DID / path / query / fragment
    Note over DR,R: pass DID parameters (service/relativeRef/versionId…) as resolve options
    DR->>R: Resolve("did:example:123")
    R-->>DR: Document, meta
    alt resolution error
        DR-->>Verifier: dereferencingMetadata{error(RFC9457)}, null, {}
    else fragment present
        DR->>Sel: selectByID(doc, "did:example:123#key-1")
        Note over Sel: absolutize relative DID URLs, then compare id. Check verificationRelationship authorization
        alt match (with verificationRelationship: a conforming VM that is authorized)
            Sel-->>DR: VerificationMethod / Service
            DR-->>Verifier: meta{contentType}, resource, contentMeta
        else verificationRelationship given, target is not a conforming VM (no match, Service, non-conforming VM)
            Sel-->>DR: nil / Service / non-conforming VM
            Note over DR: DID Resolution §5.4.2: error MUST, type INVALID_VERIFICATION_METHOD SHOULD
            DR-->>Verifier: meta{error.type=https://w3id.org/security#INVALID_VERIFICATION_METHOD}, null, {}
        else verificationRelationship given, not authorized (not in the relationship array)
            Sel-->>DR: unauthorized
            DR-->>Verifier: meta{error.type=https://w3id.org/security#INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD}, null, {}
        else no verificationRelationship, no match
            Sel-->>DR: nil
            DR-->>Verifier: meta{error.type=…/ns/did#NOT_FOUND}, null, {}
        end
    else no fragment
        DR-->>Verifier: meta{contentType: media type of the returned document representation}, wholeDoc, docMeta
    end
```

---

## 7. Create a DID (UC-7)

```mermaid
sequenceDiagram
    autonumber
    actor C as DID Controller
    participant M as Method(example)
    participant KM as Key Manager
    participant VDR as Verifiable Data Registry

    C->>M: Create(inputDoc, options{authz})
    M->>M: authorize (method-defined)
    M->>KM: generate/register key pair
    KM-->>M: publicKeyMultibase
    M->>M: derive method-specific-id (unique within method → DID globally unique)
    M->>M: assemble conforming DID document
    M->>VDR: write record (integrity-protected)
    VDR-->>M: commit (versionId, created)
    M-->>C: did, Document, metadata
```

---

## 8. Update and deactivate (UC-8 / UC-9)

```mermaid
sequenceDiagram
    autonumber
    actor C as DID Controller
    participant M as Method
    participant Auth as Authorization
    participant VDR as Verifiable Data Registry

    rect rgb(235,245,255)
    Note over C,VDR: Update (UC-8)
    C->>M: Update(did, newDoc, proof)
    M->>Auth: verify proof vs controller/capabilityInvocation
    Auth-->>M: authorized
    M->>VDR: apply change
    VDR-->>M: versionId', updated
    M-->>C: Document', metadata
    end

    rect rgb(255,240,240)
    Note over C,VDR: Deactivate (UC-9)
    C->>M: Deactivate(did, proof)
    M->>Auth: verify proof
    M->>VDR: mark deactivated
    VDR-->>M: ok
    M-->>C: metadata{deactivated:true}
    end
```

---

## 9. Select a verification method by purpose (UC-10)

```mermaid
sequenceDiagram
    autonumber
    actor V as Verifier
    participant Doc as Document
    participant Sel as document.SelectMethod

    V->>Doc: Relationship(Authentication)
    Doc-->>V: [ "#key-1" (ref) | VM(embedded) ]
    loop each entry
        alt referenced (string)
            V->>V: absolutize the relative DID URL against doc.ID()
            V->>Sel: SelectMethod(doc, did#key-1, vm.Authentication)
            Sel->>Doc: find verificationMethod by id
            alt not found
                Sel-->>V: *document.ConformanceError (INVALID_VERIFICATION_METHOD)
            else
                Sel-->>V: *vm.Method
            end
        else embedded (map)
            V->>V: use inline VM
        end
    end
    V->>V: parse publicKeyMultibase / publicKeyJwk → verify signature
```

---

## 10. v1.0 contract: resolveRepresentation (UC-12, FR-V4)

This is the `resolution/compat.V10Resolver` flow for legacy callers that need the v1.0 REC §7.1 contract. See [`09`](09-v1.0-compat.md) §6 for details.

```mermaid
sequenceDiagram
    autonumber
    actor L as Legacy Client (v1.0)
    participant C10 as compat.V10Resolver
    participant R as resolution.Resolver (v1.1 core)

    L->>C10: ResolveRepresentation(did, {accept:"application/did+ld+json"})
    C10->>R: Resolve(did, opts)  %% accept passed unchanged
    R->>R: consume and validate driver bytes, transcode to V10 if they do not match accept, record Source (12 §6.2)
    R-->>C10: Result{doc, Raw, Source, resolutionMeta, docMeta}
    alt accept representation cannot be produced (IsAcceptNotSupported)
        C10-->>L: meta{error:"representationNotSupported"}, null, {}  %% v1.0 §7.1.2
    else RFC9457 error
        C10->>C10: map type URL → string code (…#NOT_FOUND → "notFound", 09 §6.1)
        C10-->>L: meta{error:"notFound"}, null, {}
    else deactivated (not an error. The v1.1 core returns no document, so the stream is empty and contentType is absent. Deviation DEV-V10-1 from v1.0 §7.1 and §7.1.2, 09 §6.1)
        C10-->>L: meta{}, null, docMeta{deactivated:true}
    else ok
        C10-->>L: meta{contentType: resolutionMeta.contentType}, Raw, docMeta
    end
    Note over C10: the resolve() path does not set contentType (v1.0 §7.1.2 MUST NOT)
```
